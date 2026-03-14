# Owlbear kernel module — standalone Makefile
#
# Usage:
#   make                    Build for current kernel
#   make KDIR=/path/to/src  Build against specific kernel headers
#   make clean              Remove build artifacts

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(CURDIR)

.PHONY: all clean

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
