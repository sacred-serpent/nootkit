#include <linux/types.h>

#include "license.h"
#include "mm.h"
#include "arch/x86_64/special_insns.h"

void disable_write_protect(void) {
    __write_cr0(__read_cr0() & (~CR0_WP));
}

void enable_write_protect(void) {
    __write_cr0(__read_cr0() | CR0_WP);
}