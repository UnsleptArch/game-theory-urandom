obj-m += gt_urandom.o

KDIR ?= $(abspath $(CURDIR)/../build/linux-src)

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
