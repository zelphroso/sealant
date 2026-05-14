# ─────────────────────────────────────────
# Sealant — root Makefile
# ─────────────────────────────────────────
KDIR    := /lib/modules/$(shell uname -r)/build
PWD     := $(shell pwd)
VERSION := 1.0.2.26
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
	sudo mkdir -p /usr/src/sealant-$(VERSION)
	sudo cp kernel/*.c kernel/Makefile kernel/dkms.conf /usr/src/sealant-$(VERSION)/
	sudo cp include/sealant.h /usr/src/sealant-$(VERSION)/
	sudo sed -i 's|../include/sealant.h|sealant.h|g' /usr/src/sealant-$(VERSION)/*.c
	sudo sed -i 's/^PACKAGE_VERSION=.*/PACKAGE_VERSION="$(VERSION)"/' /usr/src/sealant-$(VERSION)/dkms.conf
	@if command -v dnf &>/dev/null; then sudo dnf install -y dkms; \
	elif command -v apt-get &>/dev/null; then sudo apt-get install -y dkms; \
	elif command -v pacman &>/dev/null; then sudo pacman -S --noconfirm dkms; \
	else echo ""; \
	     echo "ERROR: No supported package manager found (dnf/apt-get/pacman)."; \
	     echo "       Install dkms manually, then re-run make install."; \
	     echo ""; \
	     exit 1; fi
	sudo dkms remove sealant --all 2>/dev/null || true
	sudo dkms add sealant/$(VERSION)
	sudo dkms build sealant/$(VERSION)
	sudo dkms install sealant/$(VERSION) --force
	echo "sealant" | sudo tee /etc/modules-load.d/sealant.conf
	sudo rmmod sealant 2>/dev/null || true
	sudo modprobe sealant 2>/dev/null || true
	sudo groupadd -f sealant
	sudo gpasswd -r sealant
	sudo usermod -aG sealant $(SUDO_USER)
	echo 'KERNEL=="sealant", GROUP="sealant", MODE="0660"' | sudo tee /etc/udev/rules.d/99-sealant.rules
	sudo semanage fcontext -a -t etc_t "/etc/sealant(/.*)?" 2>/dev/null || true
	sudo restorecon -rv /etc/sealant/ 2>/dev/null || true
	sudo udevadm control --reload-rules
	sudo udevadm trigger
	@echo ""
	@echo "sealant installed successfully, a reboot might be required for full function."
	@echo "then: sealant status"
uninstall:
	sudo dkms remove sealant --all 2>/dev/null || true
	sudo rm -rf /usr/src/sealant-*
	sudo rm -rf /var/lib/dkms/sealant
	sudo rm -f /lib/modules/$(shell uname -r)/extra/sealant.ko.xz
	sudo depmod -a
	sudo rmmod sealant 2>/dev/null || true
	sudo rm -f /usr/local/bin/sealant
	sudo rm -rf /usr/local/share/sealant
	sudo rm -f /etc/udev/rules.d/99-sealant.rules
	sudo udevadm control --reload-rules
	sudo groupdel sealant 2>/dev/null || true
	@echo "sealant uninstalled"
	@echo "rules preserved at /etc/sealant/rules.slt"
