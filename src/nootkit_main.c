#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

int nootkit_init(void) {
    printk(KERN_INFO "Hello world!\n");
    return 0;
}

void nootkit_exit(void) {
    printk(KERN_INFO "Goodbye World!\n");
}

module_init(nootkit_init);
module_exit(nootkit_exit);

MODULE_LICENSE("KOFIF");
