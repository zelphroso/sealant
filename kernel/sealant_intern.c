// SPDX-License-Identifier: GPL-2.0
/*
 * Sealant — iptables replacement firewall
 * Copyright (C) 2026 Ven Robinson <zelphroso>
 * https://github.com/zelphroso/sealant
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/printk.h>

#include "../include/sealant.h"

/* ─────────────────────────────────────────
   VERBOSITY LEVEL
   0 = off
   1 = WARN + ERROR only
   2 = INFO + WARN + ERROR (everything)
───────────────────────────────────────── */

uint8_t sealant_verbosity = SEAL_VERB_OFF;

/* ─────────────────────────────────────────
   INTERNALS RING BUFFER
───────────────────────────────────────── */

#define SEALANT_INTERN_MAX   256
#define SEALANT_INTERN_MASK  (SEALANT_INTERN_MAX - 1)

static struct sealant_intern_entry intern_ring[SEALANT_INTERN_MAX];
static uint32_t        intern_head    = 0;
static uint32_t        intern_tail    = 0;
static uint64_t        intern_dropped = 0;
static DEFINE_SPINLOCK(intern_lock);

/* ─────────────────────────────────────────
   STRING HELPERS
───────────────────────────────────────── */

static const char *severity_to_str(uint8_t severity)
{
    switch (severity) {
    case INTERN_INFO:  return "INFO";
    case INTERN_WARN:  return "WARN";
    case INTERN_ERROR: return "ERROR";
    default:           return "?";
    }
}

static const char *subsys_to_str(uint8_t subsystem)
{
    switch (subsystem) {
    case SUBSYS_MODULE:  return "MODULE";
    case SUBSYS_RULES:   return "RULES";
    case SUBSYS_TIDE:    return "TIDE";
    case SUBSYS_CT:      return "CT";
    case SUBSYS_RATE:    return "RATE";
    case SUBSYS_NAT:     return "NAT";
    case SUBSYS_WHISKER: return "WHISKER";
    default:             return "?";
    }
}

/* ─────────────────────────────────────────
   WRITE INTERN ENTRY
   variadic — accepts printf-style format
   safe to call from any kernel context
   gated by verbosity level:
     INFO  only written at SEAL_VERB_FULL
     WARN  written at SEAL_VERB_MATCH+
     ERROR written at SEAL_VERB_MATCH+
───────────────────────────────────────── */

void sealant_intern_write(uint8_t severity,
                           uint8_t subsystem,
                           const char *fmt, ...)
{
    struct sealant_intern_entry *e;
    unsigned long                flags;
    uint32_t                     next_head;
    va_list                      args;
    char                         buf[96];

    /* verbosity gate */
    if (sealant_verbosity == SEAL_VERB_OFF)
        return;
    if (sealant_verbosity == SEAL_VERB_MATCH && severity == INTERN_INFO)
        return;

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    /* mirror to dmesg at appropriate level */
    switch (severity) {
    case INTERN_ERROR:
        printk(KERN_ERR     "sealant[%s]: %s\n",
               subsys_to_str(subsystem), buf);
        break;
    case INTERN_WARN:
        printk(KERN_WARNING "sealant[%s]: %s\n",
               subsys_to_str(subsystem), buf);
        break;
    default:
        printk(KERN_INFO    "sealant[%s]: %s\n",
               subsys_to_str(subsystem), buf);
        break;
    }

    spin_lock_irqsave(&intern_lock, flags);

    next_head = (intern_head + 1) & SEALANT_INTERN_MASK;

    if (next_head == intern_tail) {
        intern_tail = (intern_tail + 1) & SEALANT_INTERN_MASK;
        intern_dropped++;
    }

    e = &intern_ring[intern_head];
    memset(e, 0, sizeof(*e));

    e->timestamp = (uint64_t)jiffies_to_msecs(jiffies);
    e->severity  = severity;
    e->subsystem = subsystem;
    e->valid     = 1;
    strncpy(e->msg, buf, sizeof(e->msg) - 1);

    intern_head = next_head;

    spin_unlock_irqrestore(&intern_lock, flags);
}

/* ─────────────────────────────────────────
   PROC READ (/proc/sealant/internals)
───────────────────────────────────────── */

static int sealant_intern_show(struct seq_file *m, void *v)
{
    unsigned long flags;
    uint32_t      i;

    seq_printf(m, "verbosity: %u  (%s)\n\n",
               sealant_verbosity,
               sealant_verbosity == SEAL_VERB_OFF   ? "off"        :
               sealant_verbosity == SEAL_VERB_MATCH ? "warn+error" :
                                                      "all");

    seq_printf(m, "%-14s %-8s %-8s %s\n",
               "TIMESTAMP", "SEV", "SUBSYS", "MESSAGE");

    spin_lock_irqsave(&intern_lock, flags);

    i = intern_tail;
    while (i != intern_head) {
        struct sealant_intern_entry *e = &intern_ring[i];

        if (!e->valid) {
            i = (i + 1) & SEALANT_INTERN_MASK;
            continue;
        }

        seq_printf(m, "%-14llu %-8s %-8s %s\n",
                   e->timestamp,
                   severity_to_str(e->severity),
                   subsys_to_str(e->subsystem),
                   e->msg);

        i = (i + 1) & SEALANT_INTERN_MASK;
    }

    if (intern_dropped > 0)
        seq_printf(m, "\n# %llu entries dropped (ring overflow)\n",
                   intern_dropped);

    spin_unlock_irqrestore(&intern_lock, flags);

    return 0;
}

static int sealant_intern_open(struct inode *inode, struct file *file)
{
    return single_open(file, sealant_intern_show, NULL);
}

static const struct proc_ops sealant_intern_ops = {
    .proc_open    = sealant_intern_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* ─────────────────────────────────────────
   FLUSH
───────────────────────────────────────── */

void sealant_intern_flush(void)
{
    unsigned long flags;
    spin_lock_irqsave(&intern_lock, flags);
    intern_head    = 0;
    intern_tail    = 0;
    intern_dropped = 0;
    memset(intern_ring, 0, sizeof(intern_ring));
    spin_unlock_irqrestore(&intern_lock, flags);
}

/* ─────────────────────────────────────────
   INIT / EXIT
───────────────────────────────────────── */

int sealant_intern_init(void)
{
    memset(intern_ring, 0, sizeof(intern_ring));
    intern_head       = 0;
    intern_tail       = 0;
    intern_dropped    = 0;
    sealant_verbosity = SEAL_VERB_OFF;

    proc_create("sealant/internals", 0444, NULL, &sealant_intern_ops);

    printk(KERN_INFO "sealant: internals initialized (%u entry ring)\n",
           SEALANT_INTERN_MAX);
    return 0;
}

void sealant_intern_exit(void)
{
    remove_proc_entry("sealant/internals", NULL);
    sealant_intern_flush();
    printk(KERN_INFO "sealant: internals shut down\n");
}
