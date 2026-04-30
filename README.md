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

## why sealant

Sealant exists to replace iptables without inheriting its complexity.

* lean rule system that avoids legacy layering and redundant abstractions
* predictable behavior with explicit and consistent rules
* built-in migration, persistence, and live monitoring
* kernel-level performance with no userspace filtering overhead
* familiar iptables flags with simplified terminology

Designed to feel like what iptables would be if it were built today.

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
# add a rule (IPv4 + IPv6 by default)
sealant add -f INPUT -p tcp --dport 22 -j HAUL -n "allow-ssh"

# add an IPv6-only rule
sealant add -f INPUT -p tcp --dport 22 -j HAUL --ipv6 -n "allow-ssh-v6"

# list rules (IPv4 only)
sealant list

# list rules including IPv6 mirrors
sealant list --all

# delete a rule
sealant del -i 0

# flush a floe
sealant flush -f INPUT
sealant flush -f ALL

# set default policy
sealant policy -f INPUT -j DIVE

# migrate from iptables (dry run)
sealant migrate

# migrate and apply
sealant migrate --apply

# migrate with IPv6
sealant migrate --apply --ipv6

# save rules to disk
sealant save

# load rules from disk
sealant load

# hot reload from disk
sealant reload

# live TUI
sealant watch

# status
sealant status

# view log
sealant log

# clear log
sealant flush-log
```

iptables flags work too — `-A`, `-D`, `-L`, `-F`, `-P`.

rules save automatically on shutdown and reload on boot.

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

- Linux kernel module (`/kernel`): GPL-2.0
- CLI / GUI: MIT-2.0

See respective LICENSE files in each directory.
