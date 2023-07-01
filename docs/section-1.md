# Nootkit Section 1

## Environment Setup

I'll be using an ubuntu 22 LTS VM.
Kernel headers come installed on it by default, so I just copied them over to
[kernel-headers/linux-headers-5.15.0-76-generic](../kernel-headers/linux-headers-5.15.0-76-generic)
from the remote /usr/src/linux-headers-* to work locally.

## 1.b. Compiling a Kernel Module

To compile a module for any specific kernel we'll need to interoperate with the Kbuild system for that kernel,
which is really to my understanding just a set of makefiles which can set the correct flags to compile
our own module to work with the running kernel configuration and version.

All of those makefiles, in addition to the correct headers for that kernel source tree and the running kernel configuration
(and other things generated at compilation time of the kernel required to compile modules for it)
are provided by any sane distro (and I think it may be illegal not to provide them..?),
ripe for picking and using.

To actually use Kbuild, we can take a look at [this](https://www.kernel.org/doc/Documentation/kbuild/modules.txt) guide:
Basically:

```sh
# Define final target objects to be generated as ko files
obj-m := nootkit.o
# Define smaller objects to be linked to form each of the above defined objects, if needed
nootkit-y := src/nootkit_main.o ...

# Run `make` in the KDIR
make -C ${KDIR} M=${PWD}
```

With `KDIR` being our kernel headers directory (including a valid config).

I've put it all in a nice `Makefile`.

## 1.a. Printing From The Kernel

To actually print, there's the wonderful `printk` function, which allows us to log format strings at various different
log levels, into a ring buffer accessible from user space by reading running `dmesg` or reading from `/dev/kmsg`.

According to documentation `printk` can be called from any context within the kernel.

Now to actually *call* it we need a context - that will be (and it will also be the context we write code for in the
following sections) the module initialization context.

And now, to make *something* run at module initialization, we can use the provided `module_init` macro to set a
symbol as our module init code:

```C
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

int nootkit_init(void) {
    printk(KERN_INFO "Hello\n");
    return 0;
}

module_init(nootkit_init);
```

In truth this puts a pointer to our symbol in a the ".init" section of the resultant ELF, much like SO constructors.

## 1.c. Listing, Loading, and Unloading Modules

Listing modules can be done with `lsmod`, which gets it's info from sysfs' `/sys/module` directory.

Loading modules can be done either with `modprobe` or `insmod` - `modprobe` being the preferred method for users
as it can also look up and load module dependencies, where `insmod` is just a small wrapper to access
the `finit_module` syscall which loads modules.

*Un*loading modules can also be done with `modprobe`, or alternatively with `rmmod`, both having a similar relationship
as the previous.

## Hello World

Here is a [src/nootkit_main.c](../src/nootkit_main.c) which simply prints to kmsg:

```C
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

int nootkit_init(void) {
    printk(KERN_INFO "Hello world!\n");
    return 0;
}

void nootkit_exit(void) {
    printk(KERN_INFO "Goodbye World!\n");
}

module_init(nootkit_init);
module_exit(nootkit_exit);

MODULE_LICENSE("KOFIF");
```

Of course, we can't forget the module license, as Kbuild complains. I chose the KOFIF license which I wrote myself
in a notebook when I was born.

And we'll also need a module exit routine, otherwise we wont be able to unload our module without rebooting.

### Testing The Module

I've added a small test suite to the Makefile, for building, uploading, loading and unloading the module,
showing whether a correct message is outputted to dmesg:

```makefile
test-load: build
    sshpass -pa scp nootkit.ko root@${TEST_IP}:/
    sshpass -pa ssh root@${TEST_IP} "insmod /nootkit.ko"

test-unload:
    -sshpass -pa ssh root@${TEST_IP} "rmmod /nootkit.ko"

test-hello: test-load
    sshpass -pa ssh root@${TEST_IP} "journalctl -kS -10sec"

test: test-hello test-unload
```
