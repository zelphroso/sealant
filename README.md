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
- kernel headers (linux-headers-$(uname -r) on Debian, kernel-devel on Fedora/RHEL, linux-headers on Arch)
- Python 3 (for sealant watch)

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

# add a time-based rule (active weekdays 9am-5pm)
sealant add -f INPUT -p tcp --dport 22 -j DIVE --tide "M,T,W,TH,F 9a-5p"

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

# view BLEAT log
sealant log

# clear log
sealant flush-log

# set internals verbosity (0=off, 1=warn+error, 2=all)
sealant verb 1

# clear internals feed
sealant flush-intern
```

iptables flags work too — `-A`, `-D`, `-L`, `-F`, `-P`.

Rules save automatically on shutdown and reload on boot. Verbosity level persists across reloads.

---

## sealant watch

`sealant watch` opens a live curses TUI with four tabs:
 
| tab | what it shows |
|-----|---------------|
| Rules | all active whiskers with hit counts, byte counts, tide state |
| Log | BLEAT rule output |
| Internals | kernel diagnostics — errors, warnings, reload events, conntrack pressure, tide ticks |
| Status | summary stats and top whiskers by hits |
 
Press `[6]` to toggle IPv6 mirror visibility. Press `[v]` to cycle verbosity from the TUI.

---

## internals feed
`sealant verb <level>` controls what the kernel writes to `/proc/sealant/internals`:
 
| level | what you get |
|-------|-------------|
| 0 | off — nothing written |
| 1 | WARN + ERROR — actionable alerts only |
| 2 | INFO + WARN + ERROR — everything |
 
Events include: rule load/save/reload results, conntrack table pressure, whisker table capacity, tide state changes, module load/unload, and any internal error paths.

---

## persistence

Rules survive reboot. On `rmmod` they save to `/etc/sealant/rules.slt` and reload automatically on `insmod`. Verbosity level is saved with the rules file and restored on load.

---

## platforms

| distro | status |
|--------|--------|
| Arch Linux | ✓ tested |
| Debian 12 | ✓ tested |
| Fedora 43 | ✓ tested |

Kernel 6.12 — 6.19.12 confirmed working.

---

## what's coming

- Rust GUI
- Geo-IP filtering
- Time-based rules
- Windows / macOS (V2, no kernel integration)

---

## license

- Linux kernel module (`/kernel`): GPL-2.0
- CLI / userspace (`/userspace`): MIT
- Shared header (`/include`): GPL-2.0 OR MIT

See LICENSE, LICENSE.GPL-2.0, and LICENSE.MIT for full terms.
