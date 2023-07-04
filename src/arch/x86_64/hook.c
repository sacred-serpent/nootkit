#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>

#include "license.h"
#include "common.h"
#include "arch/hook.h"
#include "arch/mm.h"

/* Assembly of:
    movabs rax, 0  ; a correct hook address should be patched in
    jmp rax
*/
static u8 jmp_gadget[12] = { 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0 };

static u8 last_replaced[sizeof(jmp_gadget)] = {0};

struct view hook_set(void *addr, void *hook) {
    struct view restore;

    // patch hook address into the jmp gadget
    *(void **)&jmp_gadget[2] = hook;
    
    // save copy of starting bytes at addr
    memcpy(last_replaced, addr, sizeof(last_replaced));

    disable_write_protect();
    memcpy(addr, jmp_gadget, sizeof(jmp_gadget));
    enable_write_protect();

    restore.ptr = last_replaced;
    restore.size = sizeof(last_replaced);
    return restore;
}

void hook_unset(void *addr, struct view restore) {
    disable_write_protect();
    memcpy(addr, restore.ptr, restore.size);
    enable_write_protect();
}