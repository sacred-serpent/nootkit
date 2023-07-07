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
- `hide_sockets`: Comma-separated list of connection description strings following the connection format (explained
  [below](#connection-config-format)) - IPv4 socket matching this filter will be hidden from `netstat` commands.

You are also welcome to check out the [makefile](Makefile) for some semi-automatic tests.

#### Connection Config Format

Pretty simple really, just follow this template:

```txt
PROTO = 1; LOCAL = 0.0.0.0/0.0.0.0:1300-1400; FOREIGN = 0.0.0.0/0.0.0.0:0-65535;
```

Where `PROTO` can be:

- `1`: TCP

(That's it for now)

`LOCAL` describes the local IP/Mask:PortRangeStart-PortRangeEnd, and `FOREIGN` does the same for... The foreign address.

Port ranges are *inclusive*. Spaces aren't mandatory anywhere.

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

### Hiding TCP Sockets

Sockets can be hidden by specifying their properties in the connection format shown [above](#connection-config-format).

Example:

#### Hide all sockets bound to local TCP ports 10 to 30, on the local address 192.168.122.122

```sh
insmod /nootkit.ko \
kallsyms_lookup_name=0x$(cat /proc/kallsyms | grep "\bkallsyms_lookup_name\b" | cut -d " " -f 1) \
"hide_sockets=\"PROTO = 1; LOCAL = 192.168.122.122/255.255.255.255:10-30; FOREIGN = 0.0.0.0/0.0.0.0:0-65535;\""
```
