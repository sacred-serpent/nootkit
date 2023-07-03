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
