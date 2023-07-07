#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>

#include "license.h"
#include "common.h"
#include "hook.h"
#include "mm.h"

/* Assembly of:
    movabs rax, 0  ; a correct hook address should be patched in
    jmp rax
*/
static u8 jmp_gadget[12] = { 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0 };

static u8 last_replaced[sizeof(jmp_gadget)] = {0};

hook_restore hook_set(void *addr, void *hook) {
    hook_restore restore;

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

void hook_unset(void *addr, hook_restore *restore) {
    disable_write_protect();
    memcpy(addr, restore->ptr, restore->size);
    enable_write_protect();
}

void hook_set_and_store(void *target, void *hook, hook_restore *restore) {
    hook_restore res;

    // only set if not previously set
    if (restore->ptr != NULL)
        return;
    
    res = hook_set(target, hook);

    // allocate space for a persistent copy of the restore bytes
    restore->ptr = kmalloc(res.size, GFP_KERNEL);
    if (!restore->ptr) {
        /* well */
    }

    restore->size = res.size;
    memcpy(restore->ptr, res.ptr, restore->size);
}

void hook_unset_from_restore(void *target, hook_restore *restore) {
    // only unset if previously set
    if (restore->ptr == NULL)
        return;
    
    hook_unset((void *)target, restore);
    
    kfree(restore->ptr);

    // reset the restore context so on the next `hook_set_and_restore` the hook will be re-placed
    restore->ptr = 0;
    restore->size = 0;
}
