obj-m += sealant.o

sealant-objs := sealant_main.o sealant_ct.o sealant_log.o sealant_rules.o sealant_nat.o sealant_intern.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

ccflags-y += -I$(src)/../include -I$(src)

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
