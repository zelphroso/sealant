# ─────────────────────────────────────────
# Sealant — root Makefile
# ─────────────────────────────────────────

KDIR    := /lib/modules/$(shell uname -r)/build
PWD     := $(shell pwd)

.PHONY: all clean install uninstall kernel userspace

all: kernel userspace

kernel:
	$(MAKE) -C kernel

userspace:
	$(MAKE) -C userspace

clean:
	$(MAKE) -C kernel clean
	$(MAKE) -C userspace clean

install: all
	sudo $(MAKE) -C userspace install
	sudo mkdir -p /etc/sealant
	sudo mkdir -p /usr/local/share/sealant
	sudo cp userspace/watch.py /usr/local/share/sealant/watch.py
	sudo insmod kernel/sealant.ko 2>/dev/null || true
	@echo ""
	@echo "sealant installed successfully"
	@echo "run: sudo sealant status"

uninstall:
	sudo rmmod sealant 2>/dev/null || true
	sudo rm -f /usr/local/bin/sealant
	sudo rm -rf /usr/local/share/sealant
	@echo "sealant uninstalled"
	@echo "rules preserved at /etc/sealant/rules.slt"
