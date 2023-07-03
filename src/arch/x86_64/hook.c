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

u8 hook_last_replaced[sizeof(jmp_gadget)] = {0};
size_t hook_last_replaced_sz = sizeof(hook_last_replaced);

void hook_set(void *addr, void *hook) {
    // patch hook address into the jmp gadget
    *(void **)&jmp_gadget[2] = hook;
    
    // save copy of starting bytes at addr
    memcpy(hook_last_replaced, addr, sizeof(jmp_gadget));

    disable_write_protect();
    memcpy(addr, jmp_gadget, sizeof(jmp_gadget));
    enable_write_protect();
}

void hook_unset(void *addr, u8 *restore, size_t restore_sz) {
    disable_write_protect();
    memcpy(addr, restore, restore_sz);
    enable_write_protect();
}