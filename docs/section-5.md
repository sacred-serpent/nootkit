# Nootkit Section 5 - Hiding Packets

The network stack. I have no jokes at the moment might add some later.

Pretty much ALL of the relevant code which goes into packet RX/TX is explained well in
[this amazing document](https://blog.packagecloud.io/monitoring-tuning-linux-networking-stack-receiving-data/).
I want to thank the folks at Google, and God, for helping me find it.
The doc describes kernel version 3.13.0, however I'm assuming nothing much that is essential to the described structure
has changed.

(Boy, that assumption sure did prove itself [wrong](https://lwn.net/Articles/763056/))

## Packet RX Hook Location

Our goal here is to find a place where we can:

a. Place a filter for packet data.
b. Drop a packet or pass it along regularly.
c. Avoid as many registering mechanisms in the kernel to reduce the visibility of our filtered packets.

### `__netif_receive_skb_core`

This is the function which is (eventually) called by network device drivers and is responsible for
delivering skbs to protocol handlers. We can see it doing just that here:

```C
static int __netif_receive_skb_core(
    struct sk_buff **pskb,
    bool pfmemalloc,
    struct packet_type **ppt_prev)
{
    // ...

    /* Incrementing softirq counter, processing XDP generic BPF */
    __this_cpu_inc(softnet_data.processed);

    if (static_branch_unlikely(&generic_xdp_needed_key)) {
        int ret2;

        migrate_disable();
        ret2 = do_xdp_generic(rcu_dereference(skb->dev->xdp_prog), skb);
        migrate_enable();

        if (ret2 != XDP_PASS) {
            ret = NET_RX_DROP;
            goto out;
        }
    }

    /* Removing VLAN tag? */
    if (eth_type_vlan(skb->protocol)) {
        skb = skb_vlan_untag(skb);
        if (unlikely(!skb))
            goto out;
    }

    // ...

    /* packet delivery to registered protocol hanlers */
    list_for_each_entry_rcu(ptype, &ptype_all, list) {
        if (pt_prev)
            ret = deliver_skb(skb, pt_prev, orig_dev);
        pt_prev = ptype;
    }

    list_for_each_entry_rcu(ptype, &skb->dev->ptype_all, list) {
        if (pt_prev)
            ret = deliver_skb(skb, pt_prev, orig_dev);
        pt_prev = ptype;
    }
    // ...
}
```

Note: _Comments mine_

At first I though it could be nice to just integrate with the exported framework and add a
protocol handler in the `ptype_all` handler list using `dev_add_pack`. However, there is would be some stuff
happening before _and_ after handing packets to our handler, namely:

a. XDP (Generic) BPF seems to be called into action before the protocol handlers.
b. VLAN tags seem to be removed (what if we want to filter based on them?).
c. _Other_ protocol handlers aren't prevented from being called after ours.

So a protocol handler isn't the way - we aren't just another `AF_PACKET`. We have to go deeper. Or higher? Or lower. Many terms fit.
We could:

a. Hook `__netif_receive_skb_core`.
b. Find a function higher up the call stack to hook/integrate with.

Since our current function hooking method requires copying a hunk of the kernel source code to our module,
and I don't like that (since it requires more hacky kallsyms resolutions etc.), I'd rather try and find
another function.

### `netif_receive_skb`

This exported symbol is _the_ thing that gets called by specific drivers' packet RX code:

```C
/**
 *  netif_receive_skb - process receive buffer from network
 *  @skb: buffer to process
 *
 *  netif_receive_skb() is the main receive data processing function.
 *  It always succeeds. The buffer may be dropped during processing
 *  for congestion control or by the protocol layers.
 *
 *  This function may only be called from softirq context and interrupts
 *  should be enabled.
 *
 *  Return values (usually ignored):
 *  NET_RX_SUCCESS: no congestion
 *  NET_RX_DROP: packet was dropped
 */
int netif_receive_skb(struct sk_buff *skb)
{
    int ret;

    trace_netif_receive_skb_entry(skb);

    ret = netif_receive_skb_internal(skb);
    trace_netif_receive_skb_exit(ret);

    return ret;
}
```

It's exported (so always present, no inlining possible), has access to an skb before handing passing it to the rest of the
network stack, can drop packets, _and_ is rather short (hopefully we won't have to copy too many macros). I love it!

## Hooking `netif_receive_skb`

Again, as our current hooking method requires copying kernel code, we have to do as much work as the compiler
did inlining kernel functions. And for each inline we are hacking away by copying it's source code,
we have more ksyms to resolve to implement said inlined function.

A shame, but not one we'll endure forever - see my [proposed method for generic CISC hooking](./generic_CISC_hooking.md)
which I hope I'll get to implement here in `nootkit`, which would simplify hooking a lot.

But after fiddling around with it and getting it to compile, we get... nothing. Weird. Hooking `netif_receive_skb`
does nothing - we can place a jump to NULL at the start of the function and nothing happens.
And it is so also for `__netif_receive_skb`. Verifying that we are hooking the correct address did not help,
as it seems to be correct... Is it not truly called? Is something different now?

We can even make `__netif_receive_skb` just be a printk, and then call it from within the module, and it works.
It just isn't called by the system for some reason.

I have two ideas as to why this happens:

1. `netif_receive_skb` is not used by any driver on my VM - maybe `netif_rx` is used instead.
2. `netif_receive_skb` is only called from within the softirq kthreads - perhaps their memory is copy on write
    and our hooking did not affect their address spaces?

I tested the first theory by hooking `netif_rx` and failed.

The second theory sounds a little weird, but maybe? I'm not sure if it's possible, but don't have other explainations.

I decided to try the only true way to life - brute force. I set a hook to print stuff on every function which looked the part:

```C
hook_set(ksyms__kallsyms_lookup_name("__netif_receive_skb_core.constprop.0"), &hooked);
hook_set(ksyms__kallsyms_lookup_name("__netif_receive_skb_list_core"), &hooked);
hook_set(ksyms__kallsyms_lookup_name("netif_receive_skb_list_internal"), &hooked);
hook_set(ksyms__kallsyms_lookup_name("netif_receive_skb_list"), &hooked);
hook_set(ksyms__kallsyms_lookup_name("__netif_receive_skb_one_core"), &hooked);
hook_set(ksyms__kallsyms_lookup_name("netif_receive_skb_core"), &hooked);
hook_set(ksyms__kallsyms_lookup_name("__netif_receive_skb"), &hooked);
hook_set(ksyms__kallsyms_lookup_name("netif_receive_skb"), &hooked);
```

And indeed packets stopped being received, and stuff was printed. Now we just have to find the culprits.
With a human binary search, it only took 3 tries! It's `netif_receive_skb_list_internal` which works.

But why?

Even hooking the damn `netif_receive_skb_list` which supposedly calls this internal thingy doesn't work.
The only other place that calls the internal is... `gro_normal_list`. GRO is that u again?
Welp turning off GRO didn't help, but was worth a try.

Anyway.

It seems this `_list` thing is just a newer API, and ALLLL the new fancy drivers use it. I am slightly enraged,
but it brought with it a cathartic experience: The hook compiles and runs.

To drop a packet we can call:

```C
skb_list_del_init(skb);
continue;
```

Which is called from other functions within this `skb_list` function group to remove skbs from the list.

Which seemed to be rather final in the flow. [This nice article](https://lwn.net/Articles/715811/) (not documentation exactly
but anyway) highlighted that the correct way to end the life of an skb and deallocate it is either by `kfree_skb` or `consume_skb`,
with the latter does not contribute to packet drop statistics - so I chose it.

## Implementation

For the end implementation see [src/hide/net_rx.c](../src/hide/net_rx.c).

I reused and updated the existing connection configuration mechanism to include all sorts of stuff we can filter packets by -
here for example is how we can filter out all ARP packets, in addition to packets directed to TCP destination ports 1300-1350:

```sh
insmod /nootkit.ko \
kallsyms_lookup_name=0x$(cat /proc/kallsyms | grep "\bkallsyms_lookup_name\b" | cut -d " " -f 1) \
"hide_packets=\" \
ETH PROTO = 0; ETH SRC = 00:00:00:00:00:00; ETH DST = 00:00:00:00:00:00; IP PROTO = 6; IP SRC = 0.0.0.0/0.0.0.0:0-65535; IP DST = 0.0.0.0/0.0.0.0:1300-1350;, \
ETH PROTO = 0806; ETH SRC = 00:00:00:00:00:00; ETHDST = 00:00:00:00:00:00; IPPROTO = 0; IP SRC = 0.0.0.0/0.0.0.0:0-65535; IP DST = 0.0.0.0/0.0.0.0:0-65535; \
\""
```
