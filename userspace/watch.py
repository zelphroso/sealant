#!/usr/bin/env python3

import curses
import os
import sys

# ─────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────
OBSERVE_PATH = "/proc/sealant/observe"
LOG_PATH     = "/proc/sealant/log"
REFRESH_MS   = 1000

VERSION = "1.0.0.25"

# ─────────────────────────────────────────
# DATA READERS
# ─────────────────────────────────────────
def read_observe():
    rules = []
    try:
        with open(OBSERVE_PATH, "r") as f:
            lines = f.readlines()
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 12:
                continue
            try:
                rule = {
                    "id":        int(parts[0]),
                    "name":      parts[1],
                    "floe":      int(parts[2]),
                    "action":    int(parts[3]),
                    "protocol":  int(parts[4]),
                    "iface_in":  parts[5] if parts[5] != "-" else "",
                    "iface_out": parts[6] if parts[6] != "-" else "",
                    "dport_min": int(parts[7]),
                    "dport_max": int(parts[8]),
                    "hits":      int(parts[9]),
                    "bytes":     int(parts[10]),
                    "ipv6":      int(parts[11]),
                }
                rules.append(rule)
            except ValueError:
                continue
    except (FileNotFoundError, PermissionError):
        pass
    return rules

def read_log():
    entries = []
    try:
        with open(LOG_PATH, "r") as f:
            lines = f.readlines()
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            try:
                entry = {
                    "timestamp": parts[0],
                    "rule":      parts[1],
                    "floe":      parts[2],
                    "action":    parts[3],
                    "proto":     parts[4],
                    "src":       parts[5],
                    "dst":       parts[6],
                    "len":       parts[7],
                    "iface":     parts[8],
                }
                entries.append(entry)
            except (ValueError, IndexError):
                continue
    except (FileNotFoundError, PermissionError):
        pass
    return entries[-50:]

# ─────────────────────────────────────────
# TRANSLATION
# ─────────────────────────────────────────
FLOE_STR = {
    0: "INPUT",
    1: "OUTPUT",
    2: "FORWARD",
    3: "PREROUTING",
    4: "POSTROUTING",
}

ACTION_STR = {
    0: "HAUL",
    1: "DIVE",
    2: "BARK",
    3: "BLEAT",
}

ACTION_IPTABLES = {
    0: "ACCEPT",
    1: "DROP",
    2: "REJECT",
    3: "LOG",
}

PROTO_STR = {
    0:  "any",
    1:  "icmp",
    6:  "tcp",
    17: "udp",
    58: "icmpv6",
}

def floe_str(n):
    return FLOE_STR.get(n, "?")

def action_str(n):
    a = ACTION_STR.get(n, "?")
    i = ACTION_IPTABLES.get(n, "?")
    return f"{a} ({i})"

def proto_str(n):
    return PROTO_STR.get(n, str(n))

def bytes_human(b):
    if b < 1024:
        return f"{b}B"
    elif b < 1024 * 1024:
        return f"{b // 1024}K"
    else:
        return f"{b // (1024 * 1024)}M"

# ─────────────────────────────────────────
# COLOR PAIRS
# ─────────────────────────────────────────
COLOR_HEADER   = 1
COLOR_HAUL     = 2
COLOR_DIVE     = 3
COLOR_BARK     = 4
COLOR_BLEAT    = 5
COLOR_DIM      = 6
COLOR_TITLE    = 7
COLOR_SELECTED = 8

def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(COLOR_HEADER,   curses.COLOR_BLACK,  curses.COLOR_WHITE)
    curses.init_pair(COLOR_HAUL,     curses.COLOR_GREEN,  -1)
    curses.init_pair(COLOR_DIVE,     curses.COLOR_RED,    -1)
    curses.init_pair(COLOR_BARK,     curses.COLOR_YELLOW, -1)
    curses.init_pair(COLOR_BLEAT,    curses.COLOR_CYAN,   -1)
    curses.init_pair(COLOR_DIM,      curses.COLOR_WHITE,  -1)
    curses.init_pair(COLOR_TITLE,    curses.COLOR_WHITE,  -1)
    curses.init_pair(COLOR_SELECTED, curses.COLOR_BLACK,  curses.COLOR_CYAN)

def action_color(n):
    return {
        0: COLOR_HAUL,
        1: COLOR_DIVE,
        2: COLOR_BARK,
        3: COLOR_BLEAT,
    }.get(n, COLOR_DIM)

# ─────────────────────────────────────────
# TABS
# ─────────────────────────────────────────
TABS = ["Rules", "Log", "Status"]

# ─────────────────────────────────────────
# DRAW HELPERS
# ─────────────────────────────────────────
def safe_addstr(win, y, x, text, attr=0):
    max_y, max_x = win.getmaxyx()
    if y < 0 or y >= max_y - 1:
        return
    if x < 0:
        return
    available = max_x - x - 1
    if available <= 0:
        return
    try:
        win.addstr(y, x, text[:available], attr)
    except curses.error:
        pass

def draw_title(win, tab, show_ipv6=False):
    max_y, max_x = win.getmaxyx()
    title = f" sealant watch v{VERSION} "
    safe_addstr(win, 0, 0, title, curses.color_pair(COLOR_TITLE) | curses.A_BOLD)

    tab_x = len(title) + 2
    for i, t in enumerate(TABS):
        label = f" {t} "
        if i == tab:
            safe_addstr(win, 0, tab_x, label,
                        curses.color_pair(COLOR_SELECTED) | curses.A_BOLD)
        else:
            safe_addstr(win, 0, tab_x, label,
                        curses.color_pair(COLOR_DIM))
        tab_x += len(label) + 1

    ipv6_state = "ON" if show_ipv6 else "OFF"
    help_str = f" [1]Rules [2]Log [3]Status [6]IPv6:{ipv6_state} [q]Quit "
    safe_addstr(win, 0, max_x - len(help_str) - 1, help_str,
                curses.color_pair(COLOR_DIM))

def draw_separator(win, y):
    max_y, max_x = win.getmaxyx()
    try:
        win.hline(y, 0, curses.ACS_HLINE, max_x)
    except curses.error:
        pass

# ─────────────────────────────────────────
# RULES TAB
# ─────────────────────────────────────────
def draw_rules(win, rules, scroll, show_ipv6=False):
    max_y, max_x = win.getmaxyx()

    header = f"{'ID':<4} {'NAME':<24} {'FLOE':<12} {'ACTION':<20} {'PROTO':<8} {'IFACE':<16} {'PORT':<8} {'HITS':<10} {'BYTES':<10}"
    safe_addstr(win, 2, 0, header[:max_x - 1],
                curses.color_pair(COLOR_HEADER))

    draw_separator(win, 3)

    visible = [r for r in rules if show_ipv6 or not r.get("ipv6", 0)]

    if not visible:
        safe_addstr(win, 5, 2, "no whiskers loaded",
                    curses.color_pair(COLOR_DIM) | curses.A_ITALIC)
        safe_addstr(win, 6, 2, "try: sealant add -f INPUT -p tcp --dport 22 -j HAUL -n ssh",
                    curses.color_pair(COLOR_DIM))
        return

    row = 4
    for r in visible[scroll:]:
        if row >= max_y - 2:
            break

        floe   = floe_str(r["floe"])[:12]
        action = action_str(r["action"])[:20]
        proto  = proto_str(r["protocol"])[:8]
        hits   = str(r["hits"])[:10]
        bytesh = bytes_human(r["bytes"])[:10]

        iface = "-"
        if r.get("iface_in") and r.get("iface_out"):
            iface = f"{r['iface_in']}/{r['iface_out']}"
        elif r.get("iface_in"):
            iface = f"in:{r['iface_in']}"
        elif r.get("iface_out"):
            iface = f"out:{r['iface_out']}"

        port = "-"
        if r["dport_min"] > 0:
            if r["dport_min"] == r["dport_max"]:
                port = str(r["dport_min"])
            else:
                port = f"{r['dport_min']}:{r['dport_max']}"

        ipv6_mark = " [6]" if r.get("ipv6") else ""
        display_name = f"{r['name'][:20]}{ipv6_mark}"

        line = f"{r['id']:<4} {display_name:<24} {floe:<12} {action:<20} {proto:<8} {iface:<16} {port:<8} {hits:<10} {bytesh:<10}"
        color = curses.color_pair(action_color(r["action"]))
        safe_addstr(win, row, 0, line[:max_x - 1], color)
        row += 1

    total = len(visible)
    if total > max_y - 6:
        safe_addstr(win, max_y - 2, max_x - 20,
                    f" {scroll + 1}-{min(scroll + max_y - 6, total)}/{total} ",
                    curses.color_pair(COLOR_DIM))

# ─────────────────────────────────────────
# LOG TAB
# ─────────────────────────────────────────
def draw_log(win, entries, scroll):
    max_y, max_x = win.getmaxyx()

    header = f"{'TIMESTAMP':<14} {'RULE':<24} {'FLOE':<12} {'ACTION':<6} {'PROTO':<8} {'SRC':<22} {'DST':<22} {'IFACE'}"
    safe_addstr(win, 2, 0, header[:max_x - 1],
                curses.color_pair(COLOR_HEADER))

    draw_separator(win, 3)

    if not entries:
        safe_addstr(win, 5, 2, "no log entries",
                    curses.color_pair(COLOR_DIM) | curses.A_ITALIC)
        safe_addstr(win, 6, 2, "add a BLEAT rule to start logging",
                    curses.color_pair(COLOR_DIM))
        return

    row = 4
    for e in entries[scroll:]:
        if row >= max_y - 2:
            break
        line = (f"{e['timestamp']:<14} {e['rule']:<24} {e['floe']:<12} "
                f"{e['action']:<6} {e['proto']:<8} {e['src']:<22} "
                f"{e['dst']:<22} {e['iface']}")
        safe_addstr(win, row, 0, line[:max_x - 1],
                    curses.color_pair(COLOR_DIM))
        row += 1

# ─────────────────────────────────────────
# STATUS TAB
# ─────────────────────────────────────────
def draw_status(win, rules, entries):
    max_y, max_x = win.getmaxyx()

    draw_separator(win, 2)

    ipv4_rules  = [r for r in rules if not r.get("ipv6", 0)]
    total_hits  = sum(r["hits"] for r in ipv4_rules)
    total_bytes = sum(r["bytes"] for r in ipv4_rules)
    active      = sum(1 for r in ipv4_rules if r["hits"] > 0)

    stats = [
        ("Version",       f"Sealant v{VERSION}"),
        ("Whiskers",      str(len(ipv4_rules))),
        ("Active rules",  str(active)),
        ("Total hits",    str(total_hits)),
        ("Total traffic", bytes_human(total_bytes)),
        ("Log entries",   str(len(entries))),
        ("Observe",       OBSERVE_PATH),
        ("Log",           LOG_PATH),
    ]

    row = 4
    for label, value in stats:
        safe_addstr(win, row, 2, f"{label:<20}",
                    curses.color_pair(COLOR_DIM) | curses.A_BOLD)
        safe_addstr(win, row, 22, value,
                    curses.color_pair(COLOR_HAUL))
        row += 1

    if ipv4_rules:
        row += 1
        safe_addstr(win, row, 2, "Top whiskers by hits:",
                    curses.color_pair(COLOR_DIM) | curses.A_BOLD)
        row += 1
        sorted_rules = sorted(ipv4_rules, key=lambda r: r["hits"], reverse=True)
        for r in sorted_rules[:5]:
            if row >= max_y - 2:
                break
            line = (f"  {r['name']:<24} {floe_str(r['floe']):<12} "
                    f"{action_str(r['action']):<20} {r['hits']} hits")
            safe_addstr(win, row, 2, line[:max_x - 3],
                        curses.color_pair(action_color(r["action"])))
            row += 1

# ─────────────────────────────────────────
# MAIN LOOP
# ─────────────────────────────────────────
def main(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(REFRESH_MS)
    init_colors()

    tab       = 0
    scroll    = 0
    show_ipv6 = False
    rules     = []
    entries   = []

    while True:
        rules   = read_observe()
        entries = read_log()

        stdscr.erase()
        draw_title(stdscr, tab, show_ipv6)

        if tab == 0:
            draw_rules(stdscr, rules, scroll, show_ipv6)
        elif tab == 1:
            draw_log(stdscr, entries, scroll)
        elif tab == 2:
            draw_status(stdscr, rules, entries)

        max_y, max_x = stdscr.getmaxyx()
        uptime = f" refreshing every {REFRESH_MS // 1000}s "
        safe_addstr(stdscr, max_y - 1, 0, uptime,
                    curses.color_pair(COLOR_DIM))

        stdscr.refresh()

        key = stdscr.getch()

        if key == ord('q') or key == ord('Q'):
            break
        elif key == ord('1'):
            tab = 0
            scroll = 0
        elif key == ord('2'):
            tab = 1
            scroll = 0
        elif key == ord('3'):
            tab = 2
            scroll = 0
        elif key == ord('6'):
            show_ipv6 = not show_ipv6
            scroll = 0
        elif key == curses.KEY_DOWN or key == ord('j'):
            scroll += 1
        elif key == curses.KEY_UP or key == ord('k'):
            if scroll > 0:
                scroll -= 1
        elif key == curses.KEY_PPAGE:
            scroll = max(0, scroll - 10)
        elif key == curses.KEY_NPAGE:
            scroll += 10
        elif key == curses.KEY_HOME:
            scroll = 0

if __name__ == "__main__":
    if not os.path.exists(OBSERVE_PATH):
        print("sealant: kernel module not loaded")
        print("sealant: try: sudo insmod sealant.ko")
        sys.exit(1)

    try:
        curses.wrapper(main)
    except KeyboardInterrupt:
        pass
