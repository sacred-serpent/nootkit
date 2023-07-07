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

The kernel space address of `kallsyms_lookup_name` must be provided to the module at load time,
as it is used to locate other unexported symbols.

Possible module arguments are:

- `kallsyms_lookup_name`: Must be present, can be obtained via `/proc/kallsyms` as shown above
- `hide_filenames`: Comma-separated list of file names to hide from usermode dir listings
- `hide_inodes`: Comma-separated list of inodes to hide from usermode dir listings
- `hide_sockets`: Comma-separated list of connection description strings following the connection format (explained below) -
  IPv4 socket matching this filter will be hidden from `netstat` commands.

You are also welcome to check out the [makefile](Makefile) for some semi-automatic tests.

### Connection Config Format

Pretty simple really, just follow this template:

```txt
PROTO = 1; LOCAL = 0.0.0.0/0.0.0.0:1300-1400; FOREIGN = 0.0.0.0/0.0.0.0:0-65535;
```

Where `PROTO` can be:

- `1`: TCP

(That's it for now)

`LOCAL` describes the local IP/Mask:PortRangeStart-PortRangeEnd, and `FOREIGN` does the same for... The foreign address.

Port ranges are *inclusive*.