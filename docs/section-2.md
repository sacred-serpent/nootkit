# Nootkit Section 2

## Two Roads Diverged in a Catacomb

There are several ways we could hide a file from userspace directory listings:
we could intercept the information requisition at several stages from the initial syscall code
to filesystem code.

The simplest way would be to intercept the `getdents` and `getdents64` syscalls performed
by usermode utilities such as `ls` (probably through libc's `readdir`), because if we only hide
the file from `getdents`, other syscalls such as `open` and `read` aren't supposed to be affected
as needed.

I have a couple of options in mind of how to filter the output:

1. Hook the initial syscall function itself, run the original routine, and edit the output post-mortem.
2. Hook some inner function, in a way which does not require reiterating over the results and modifying them.

The second option feels like it has potential for a more elegant solution, so let's start off with that.

### Finding an Inner Function To Hook

Let's take a look at the `getdents64` implementation (in the 5.15 version kernel sources),
and see where it would be the easiest to place our hook to filter the output from our hidden file -
preferrably I'd want to place the hook at the beginning of some exported function, as that is easy to
calculate.

```C
// fs/readdir.c

SYSCALL_DEFINE3(getdents64, unsigned int, fd,
        struct linux_dirent64 __user *, dirent, unsigned int, count)
{
    struct fd f;
    struct getdents_callback64 buf = {
        .ctx.actor = filldir64,
        .count = count,
        .current_dir = dirent
    };
    int error;

    f = fdget_pos(fd);
    if (!f.file)
        return -EBADF;

    error = iterate_dir(f.file, &buf.ctx);
    if (error >= 0)
        error = buf.error;
    if (buf.prev_reclen) {
        struct linux_dirent64 __user * lastdirent;
        typeof(lastdirent->d_off) d_off = buf.ctx.pos;

        lastdirent = (void __user *) buf.current_dir - buf.prev_reclen;
        if (put_user(d_off, &lastdirent->d_off))
            error = -EFAULT;
        else
            error = count - buf.count;
    }
    fdput_pos(f);
    return error;
}
```

It seems the syscall passes along some context struct containing a callback function pointer `filldir64` to
`iterate_dir`. Let's look at that:

```C
// fs/readdir.c

int iterate_dir(struct file *file, struct dir_context *ctx) {
    // Happy flow...
    if (shared)
        res = file->f_op->iterate_shared(file, ctx);
    else
        res = file->f_op->iterate(file, ctx);
    // ...
}
```

And then the specific file's `iterate` file operation is called, again with the passed context.

```C
// include/linux/fs.h

struct file_operations {
    // ...
    int (*iterate) (struct file *, struct dir_context *);
    int (*iterate_shared) (struct file *, struct dir_context *);
    // ...
}
```

And this `iterate` file operation is implemented for each filesystem. Let's look at an example
implementation to get an idea for it's inner machinations, as so far we haven't really encountered
the *"loop over file names and properties and write to the user buffer"* behaviour I've been expecting
and hoping to place a hook in.

```C
// fs/ext4/dir.c

const struct file_operations ext4_dir_operations = {
    .llseek = ext4_dir_llseek,
    .read = generic_read_dir,
    .iterate_shared = ext4_readdir,
    .unlocked_ioctl = ext4_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = ext4_compat_ioctl,
#endif
    .fsync = ext4_sync_file,
    .release = ext4_release_dir,
};
```

I'll spare the additional code snippets, but it appears that the `actor` in the `dir_context` struct does
indeed get called for every entry - and in the case of our syscall we have the following actor:

```C
// fs/readdir.c

static int filldir64(struct dir_context *ctx, const char *name, int namlen,
     loff_t offset, u64 ino, unsigned int d_type) {
    // ...
    unsafe_put_user(offset, &prev->d_off, efault_end);
    unsafe_put_user(ino, &dirent->d_ino, efault_end);
    unsafe_put_user(reclen, &dirent->d_reclen, efault_end);
    unsafe_put_user(d_type, &dirent->d_type, efault_end);
    unsafe_copy_dirent_name(dirent->d_name, name, namlen, efault_end);
    user_write_access_end();
    // ...
}
```

This seems pretty indicative of writing the dir entry information to userspace, and additionally this is exactly
the type of function which would be easy to hook into for our cause. But alas, it is static - to find it's
location we'll have to jump through some hoops using `kallsyms` (as that is a way I know to get symbol addresses
for static symbols).

`filldir64` also isn't used anywhere outside of serving the `getdents64` syscall, so we won't be changing anything
else if we only hide files from this specific function.

## Setting Function Hooks (x86_64)

Our method will be simple - we'll just replace the first bytes of a function address with a `jmp` to the absolute
address of our hook function.

### Absolute Jump

We'll create a patchable assembly for jumping to a 64 bit address:

```C
mov rax, 0xa1a2a3a4a5a6a7a8
jmp rax
```

Assembles to:

```C
{ 0x48, 0xB8, 0xA8, 0xA7, 0xA6, 0xA5, 0xA4, 0xA3, 0xA2, 0xA1, 0xFF, 0xE0 }
```

Where we have to replace indexes `2` to `9` (inclusive) with out little-endian 64 bit hook address.

`rax` is safe to clobber in this way at the entry point of functions - as it's not used as a parameter register
in any used calling convention, and is caller saved.

Check out [src/arch/x86_64/hook.c](../src/arch/x86_64/hook.c) to see how it's done.

### Overwriting The Original Function

There's a little thing called *Write Protection* preventing us from going willy nilly around executable
kernel addresses.

We could disable it for the specific pages we want to write to and then restore write protection for them
when we're done with the hook placement; or we could go the even simpler route and just disable/enable WP
as a CPU feature alltogether. On x86_64, this can be done by writing to the register `cr0` and setting a certain bit.

Check out [src/arch/x86_64/mm.c](../src/arch/x86_64/mm.c) to see my implementation.

## Finding Unexported Kernel Functions

If we want to hook `filldir64`, we'll have to find where it is first.

As said before, `/proc/kallsyms` has that ability - we could simply pass all required symbol addresses from usermode
at module load time, and go to town.
But that complicates load-time logic quite a bit, and I'd rather keep it simple where I can - we'll can get by with
the address of the unexported symbol `kallsyms_lookup_name`, and use it within the module to find the rest of the
needed unexported symbols.

See [src/ksyms.c](../src/ksyms.c) and [src/ksyms.h](../src/ksyms.h) for the implementation.

## Passing Arguments From Usermode

So we need to resolve a symbol in usermode using `/proc/kallsyms` at load time. How do we pass it to the kernel?

Luckily there's this feature called *Module Parameters*, which allows setting parameters for modules at load time
*through the command line*, and even updating them at run time!

See [src/nootkit_main.c](../src/nootkit_main.c).

This means we can load our module like so:

```sh
insmod /nootkit.ko \
kallsyms_lookup_name=0x$(cat /proc/kallsyms | grep "\bkallsyms_lookup_name\b" | cut -d " " -f 1)
```

And get a fresh context to jumpstart off of.

## Actually Hiding Files

Since by placing a hook on the original `filldir64` we are essentially blocking ourselves from it's functionality,
we have to find some other way to get back to the *"intended flow"* after performing our hook logic at the beginning
of the function.

Luckily, I have the kernel source for just our used version (don't ask me where I got it), and we can copy, splice, dice,
and resolve away unexported symbols to replicate `filldir64`'s behaviour *in exactitude*, while introducing our hook code
gracefully.

See [src/hide/readdir.c](../src/hide/readdir.c) for the implementation.

This method is *highly* unresistant to kernel version changes, and a better hook logic which allows to return to the
original function flow will be preferred in the future. However, we can get by with this for now without getting too
complicated.

### The Pitfalls of Man, and `filldir64`

I am young, and therefore somewhat stupid; the `name` argument to `filldir64` contains only the bare filename,
and *not* the full path to it. We do get an inode number though, which can be used just as well as a path
(actually better in a way) to hide a specific file. Two files which are hardlinks to the same one will share an inode number,
but will differ paths - hiding the inode number will hide both files (for better or worse).

Instructions didn't specify hiding the file by path it's full path, so I don't feel like there's a need to also
write hook logic for the `getdents64` syscall function itself, which does grant access to the full path (in a way).

Here is a 4-liner for loading the module with filename and inode hide parameters:

```sh
insmod /nootkit.ko \
kallsyms_lookup_name=0x$(cat /proc/kallsyms | grep "\bkallsyms_lookup_name\b" | cut -d " " -f 1) \
hide_filenames=hello,q \
hide_inodes=138210,17635
```
