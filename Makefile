obj-m += kvm_probe_drv.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
	rm -f *.o *.ko *.mod.c *.mod *.order *.symvers

install:
	insmod kvm_probe_drv.ko

uninstall:
	rmmod kvm_probe_drv.ko
