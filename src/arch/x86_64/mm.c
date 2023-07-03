#include <linux/types.h>

#include "license.h"
#include "arch/mm.h"

#define __FORCE_ORDER "m"(*(unsigned int *)0x1000UL)
#define CR0_WP 0x10000

static inline void __write_cr0(u64 cr0) {
    asm volatile("mov %0, %%cr0" : : "r"(cr0) : "memory");
}

static inline u64 __read_cr0(void) {
    u64 cr0;
    asm volatile("mov %%cr0,%0\n\t" : "=r" (cr0) : __FORCE_ORDER);
    return cr0;
}

void inline disable_write_protect(void) {
    __write_cr0(__read_cr0() & (~CR0_WP));
}

void inline enable_write_protect(void) {
    __write_cr0(__read_cr0() | CR0_WP);
}