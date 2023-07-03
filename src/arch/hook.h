#pragma once

#include <linux/types.h>

#include "common.h"

extern u8 hook_last_replaced[];
extern size_t hook_last_replaced_sz;

/// @brief Replace the first bytes at `addr` with a jmp gadget referring to the 64 bit address `hook`.
/// 
/// Sets `jmp_gadget` and `hook_last_replaced` to the changed bytes,
/// allowing to save them for later hook unsetting.
///
/// This mechanism leaves the target function unusable outside of jumping
/// to the hook, until the hook is unset.
/// 
/// @param addr address to set hook at
/// @param hook address of function to act as a hook
void hook_set(void *addr, void *hook);

/// @brief Restore the replaced bytes at previously hooked `addr`.
/// @param addr address of hooked function to restore bytes at
/// @param restore ptr to saved bytes to restore at `addr`
/// @param restore_sz size of `restore`
void hook_unset(void *addr, u8 *restore, size_t restore_sz);
