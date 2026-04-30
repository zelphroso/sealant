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
	sudo mkdir -p /usr/src/sealant-1.0.0.25
	sudo cp kernel/*.c kernel/Makefile kernel/dkms.conf /usr/src/sealant-1.0.0.25/
	sudo cp include/sealant.h /usr/src/sealant-1.0.0.25/
	sudo sed -i 's|../include/sealant.h|sealant.h|g' /usr/src/sealant-1.0.0.25/*.c
	sudo dnf install -y dkms 2>/dev/null || sudo apt-get install -y dkms 2>/dev/null || true
	sudo dkms remove sealant/1.0.0.25 --all 2>/dev/null || true
	sudo dkms add sealant/1.0.0.25
	sudo dkms build sealant/1.0.0.25
	sudo dkms install sealant/1.0.0.25
	echo "sealant" | sudo tee /etc/modules-load.d/sealant.conf
	sudo rmmod sealant 2>/dev/null || true
	sudo modprobe sealant 2>/dev/null || true
	sudo groupadd -f sealant
	sudo gpasswd -r sealant
	sudo usermod -aG sealant $(SUDO_USER)
	echo 'KERNEL=="sealant", GROUP="sealant", MODE="0660"' | sudo tee /etc/udev/rules.d/99-sealant.rules
	sudo semanage fcontext -a -t modules_object_t "/etc/sealant(/.*)?" 2>/dev/null || true
	sudo restorecon -rv /etc/sealant/ 2>/dev/null || true
	sudo udevadm control --reload-rules
	sudo udevadm trigger
	@echo ""
	@echo "sealant installed successfully, a reboot might be required for full functiion."
	@echo "then: sealant status"

uninstall:
	sudo dkms remove sealant/1.0.0.25 --all 2>/dev/null || true
	sudo rm -rf /usr/src/sealant-1.0.0.25
	sudo rmmod sealant 2>/dev/null || true
	sudo rm -f /usr/local/bin/sealant
	sudo rm -rf /usr/local/share/sealant
	sudo rm -f /etc/udev/rules.d/99-sealant.rules
	sudo udevadm control --reload-rules
	sudo groupdel sealant 2>/dev/null || true
	@echo "sealant uninstalled"
	@echo "rules preserved at /etc/sealant/rules.slt"
