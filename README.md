# sealant

A from-scratch iptables replacement written in C.
Serious security, with a softer side.

---

## what it is

Sealant is a Linux firewall built on netfilter, same foundation as iptables, with A LOT of the legacy bloat shimmed. Kernel module + userspace CLI. Everything is built with intent.

To fit with the seal theme I originally went for, it has it's own terminology, but it accepts both iptables and it's own terms to make it easy for everybody.

| sealant | iptables |
|---------|----------|
| pod | table |
| floe | chain |
| whisker | rule |
| pup | conntrack entry |
| HAUL | ACCEPT |
| DIVE | DROP |
| BARK | REJECT |
| BLEAT | LOG |

---

## requirements

- Linux kernel 6.x
- gcc, make
- kernel headers (`linux-headers-$(uname -r)` on Debian, `kernel-devel` on Fedora/RHEL, `linux-headers` on Arch)
- Python 3 (for `sealant watch`)

---

## install

```bash
git clone https://github.com/zelphroso/sealant.git
cd sealant
make
sudo make install
```

That builds the kernel module and CLI, loads the module, and puts `sealant` in your PATH.

---

## usage

```bash
# add a rule
sudo sealant add -f INPUT -p tcp --dport 22 -j HAUL -n "allow-ssh"

# list rules
sealant list

# delete a rule
sudo sealant del -i 0

# flush a floe
sudo sealant flush -f INPUT

# set default policy
sudo sealant policy -f INPUT -j DIVE

# migrate from iptables (dry run)
sudo sealant migrate

# migrate and apply
sudo sealant migrate --apply

# save rules to disk
sudo sealant save

# live TUI
sudo sealant watch

# status
sudo sealant status
```

iptables flags work too — `-A`, `-D`, `-L`, `-F`, `-P`.

---

## persistence

Rules survive reboot. On `rmmod` they save to `/etc/sealant/rules.slt` and reload automatically on `insmod`.

---

## platforms

| distro | status |
|--------|--------|
| Arch Linux | ✓ tested |
| Debian 12 | ✓ tested |
| Fedora 43 | ✓ tested |

Kernel 6.12 — 6.17 confirmed working.

---

## what's coming

- Rust + Iced GUI
- Geo-IP filtering
- Time-based rules
- DKMS packaging
- Windows / macOS (V2, no kernel integration)

---

## license

GPL-3.0. See [LICENSE](LICENSE).

---
