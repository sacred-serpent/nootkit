# Nootkit Section 6 - Hiding The Module Itself

This isn't completely foreign ground for me - I've seen in the past `THIS_MODULE` pointing to a linked
list which is used when listing modules. I would guess some code responsible for iterating this would be
in the sysfs implementation of `/sys/module`, which as we saw in [section 1](section-1.md) is the interface
used by `lsmod`. I liked the explaination found [here](https://www.win.tue.nl/~aeb/linux/lk/lk-13.html) of
the whole sysfs krazam.

It seems the `/sys/modules` kset itself gets created here:

```C
/*
 * param_sysfs_init - wrapper for built-in params support
 */
static int __init param_sysfs_init(void)
{
    module_kset = kset_create_and_add("module", &module_uevent_ops, NULL);
    if (!module_kset) {
        printk(KERN_WARNING "%s (%d): error creating kset\n",
            __FILE__, __LINE__);
        return -ENOMEM;
    }
    module_sysfs_initialized = 1;

    version_sysfs_builtin();
    param_sysfs_builtin();

    return 0;
}
```

And the addition of any inserted module to that kset happens in `load_module`, which calls `mod_sysfs_setup`,
which calls `mod_sysfs_init`, which does this:

```C
kobj = kset_find_obj(module_kset, mod->name);
if (kobj) {
    pr_err("%s: module is already loaded\n", mod->name);
    kobject_put(kobj);
    err = -EINVAL;
    goto out;
}
```

The module list referred to by `THIS_MODULE` however seems to be at a lower level than the kobject - also at `load_module`, a list member
is added by `add_unformed_module` to a static `struct list_head` named `modules` in `kernel/module.c`.
This list is also iterated by the syscall `remove_module` to find a module before unloading it.
This will be a hurdle as we'll have to make sure the module is removable - maybe I'll hook the syscall itself
to handle the case.

However, how does the kset which is `/sys/modules` related? Why would removing a module from the `modules`
list also remove it from the `kset`?

It seems that the procfs `/proc/modules` is in fact linked to that list:

```C
/* Called by the /proc file system to return a list of modules. */
static void *m_start(struct seq_file *m, loff_t *pos)
{
    mutex_lock(&module_mutex);
    return seq_list_start(&modules, *pos);
}
```

I took a secondary look at the strace output for `lsmod` - and it seems indeed that before iterating `/sys/module`,
`lsmod` reads `/proc/modules`. Now, my eyes are open. I have modified the section 1 document to contain this information.

So to completely hide our module, would we have to also modify data related to sysfs (maybe removing the relevant
kobject)? We'll see.

Now to work.

## Hiding A Module From `/proc/modules`

`struct module`s contain a pointer to their list entry, so it's easy as pie. See [src/hide/module.c](../src/hide/module.c).

And just from this, we are unseen in `lsmod`:

```sh
lsmod | grep nootkit
>>> 
```

However, as expected we can't remove the module:

```sh
rmmod nootkit
>>> rmmod: ERROR: ../libkmod/libkmod-module.c:799 kmod_module_remove_module() could not remove 'nootkit': No such file or directory
>>> rmmod: ERROR: could not remove module nootkit: No such file or directory

rmmod blabla
>>> rmmod: ERROR: Module blabla is not currently loaded
```

Which yields a different error than other modules which don't exist. My suspicions were correct, and we are still visible
in `/sys/module`:

```sh
ls /sys/module/nootkit/
>>> coresize  initsize   notes   sections    taint
>>> holders   initstate  refcnt  srcversion  uevent
```

Adding a syscall hook to `delete_module` proved interesting:
We can't call the original delete_module from within this hook; upon returning, the hook's function memory will
have been deallocated. So instead, the first time the module is `rmmod`ed, the module hiding is canceled,
and the hook is unset.
Upon a second `rmmod` the module will be removed regularly.

See the hook implemetnation at [src/arch/x86_64/hide/module_sys.c](../src/arch/x86_64/hide/module_sys.c).

## Hiding A Module From `/sys/module`

I think this is counter to the section's instructions; The requirement to be able to uninstall the module,
to my understanding is with `rmmod` - whereas if we hide the module from `/sys/module`, `rmmod` won't
event get to calling the `delete_module` syscall, preventing module deletion. Of course, we could add
an extra trigger to unset the `/sys/module` hiding as well; but correct me if I'm wrong, that feels a little
over what was requested :)
