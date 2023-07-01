KDIR := ${PWD}/kernel-headers/linux-headers-5.15.0-76-generic
obj-m := nootkit.o
nootkit-y := src/nootkit_main.o

TEST_IP := 192.168.122.122

default: build

build:
	make -C ${KDIR} M=${PWD} modules

clean:
	make -C ${KDIR} M=${PWD} clean

test-load: build
	sshpass -pa scp nootkit.ko root@${TEST_IP}:/
	sshpass -pa ssh root@${TEST_IP} "insmod /nootkit.ko"

test-unload:
	-sshpass -pa ssh root@${TEST_IP} "rmmod /nootkit.ko"

test-hello: test-load
	sshpass -pa ssh root@${TEST_IP} "journalctl -kS -10sec"

test: test-hello test-unload
