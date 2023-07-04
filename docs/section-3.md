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

# UNFINISHED
