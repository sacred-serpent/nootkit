/*
  Access to symbols unexported by the linux kernel for dynamic linking
  with modules.
*/

#pragma once

#include <linux/types.h>
#include <linux/fs.h>

/// @brief Use `kallsyms_lookup_name` to resolve all required unexported symbols
/// @param kallsyms_lookup_name_addr address of the kallsyms_lookup_name_addr unexported symbol
void resolve_ksyms(void *kallsyms_lookup_name_addr);

extern unsigned long (*kallsyms_lookup_name)(const char *name);

extern int (*filldir64)(struct dir_context *ctx, const char *name, int namlen,
    loff_t offset, u64 ino, unsigned int d_type);

extern int (*verify_dirent_name)(const char *name, int len);
