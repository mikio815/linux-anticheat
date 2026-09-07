# Out-of-tree build. Runs on the KM dev VM (x86_64 Fedora with kernel-debug),
# not on the machine that builds the eBPF and daemon parts -- the module has to
# be compiled against the exact kernel it will be loaded into.
obj-m += anticheat.o
anticheat-y := main.o ebpf_guard.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(CURDIR)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: all clean
