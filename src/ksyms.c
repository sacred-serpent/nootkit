#include <linux/types.h>

#include "ksyms.h"

unsigned long (*kallsyms_lookup_name)(const char *name) = 0;

int (*filldir64)(struct dir_context *ctx, const char *name, int namlen,
    loff_t offset, u64 ino, unsigned int d_type) = 0;

int (*verify_dirent_name)(const char *name, int len) = 0;

void resolve_ksyms(void *kallsyms_lookup_name_p) {
    kallsyms_lookup_name = kallsyms_lookup_name_p;

    filldir64 = (void *)kallsyms_lookup_name("filldir64");
    verify_dirent_name = (void *)kallsyms_lookup_name("verify_dirent_name");
}