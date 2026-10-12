# srcdynroute — out-of-tree nft expression module (DYNSRCROUTE / DYNRT).
#
# Requires a kernel tree that has patches/kernel/0001..0006 applied
# (see README.md). If /root/srcdynroute/linux-6.12.111 exists it is
# used as the default KDIR; otherwise the running kernel's build tree.
#
# Build:        make [KDIR=/path/to/kernel-tree]
# Install:      make [KDIR=...] install
# Uninstall:    make uninstall
#
# KDIR resolution order:
#   1. explicit KDIR=... on the command line,
#   2. /root/srcdynroute/linux-6.12.111 (the deb13 build tree, if present)
#      — not assumed; only used when the directory exists,
#   3. the running kernel build headers /lib/modules/$(shell uname -r)/build.

obj-m := srcdynroute.o

EXTRA_CFLAGS += -Wno-uninitialized

# Default KDIR: prefer a local 6.12.111 source tree (patches 0001..0006),
# fall back to the kernel currently being used by the build host.
KDIR ?= $(shell \
	if [ -d /root/srcdynroute/linux-6.12.111 ]; then \
		echo /root/srcdynroute/linux-6.12.111; \
	else \
		echo /lib/modules/$$(uname -r)/build; \
	fi)

KVERSION ?= $(shell uname -r)
DESTDIR ?=

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

install: all
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules_install
	depmod -a $(KVERSION)

uninstall:
	rm -f /lib/modules/$(KVERSION)/updates/srcdynroute.ko
	depmod -a $(KVERSION)

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

.PHONY: all install uninstall clean
