#pragma once

#include <linux/types.h>

#include "common.h"

/// @brief Replace the first bytes at `addr` with a jmp gadget referring to the 64 bit address `hook`.
/// @details This mechanism leaves the target function unusable outside of jumping
///     to the hook, until the hook is unset.
/// @param addr address to set hook at
/// @param hook address of function to act as a hook
/// @returns `struct view` pointing to a byte array which can be used to unset the hook.
/// @warning The data pointed to by the returned view may change on subsequent hook_set_* calls,
///     so it should be saved externally before any other hooks are set using this method.
struct view hook_set(void *addr, void *hook);

/// @brief Restore the replaced bytes at previously hooked `addr`.
/// @param addr address of hooked function to restore bytes at
/// @param restore view struct to saved bytes to restore at `addr`
void hook_unset(void *addr, struct view restore);
