#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/printk.h>

#include <ksyms.h>

unsigned long (*ksyms__kallsyms_lookup_name)(const char *name) = 0;

/**
 * Define all symbols as global function pointers initialized to NULL.
 */
#define KSYM_OP(retn, symbol, ...) \
retn (*ksyms__##symbol)(__VA_ARGS__) = NULL
KSYMS_ALL();
#undef KSYM_OP

int resolve_ksyms(void *kallsyms_lookup_name) {
    ksyms__kallsyms_lookup_name = kallsyms_lookup_name;

    /**
     * Resolve all defined symbols, returning on any failure.
     */
    #define KSYM_OP(retn, symbol, ...)                                                  \
    do {                                                                                \
        ksyms__##symbol = (void *)ksyms__kallsyms_lookup_name(#symbol);                 \
        if (ksyms__##symbol == NULL) {                                                  \
            printk(KERN_ERR "nootkit: ksyms: Symbol %s failed to resolve", #symbol);    \
            return 1;                                                                   \
        }                                                                               \
    } while (0)
    KSYMS_ALL();
    #undef KSYM_OP

    return 0;
}
