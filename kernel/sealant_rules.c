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
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>

#include "../include/sealant.h"

/* ─────────────────────────────────────────
   PERSISTENCE PATH
───────────────────────────────────────── */

#define SEALANT_RULES_PATH "/etc/sealant/rules.slt"
#define SEALANT_RULES_MAGIC 0x5EA14E7A /* SEALANT */
#define SEALANT_RULES_VERSION 1

/* ─────────────────────────────────────────
   FILE HEADER
───────────────────────────────────────── */

struct sealant_rules_header {
    uint32_t    magic;
    uint32_t    version;
    uint32_t    whisker_count;
    uint8_t     default_policy[FLOE_MAX];
    uint8_t     _pad[4];
};

/* ─────────────────────────────────────────
   DOUBLE BUFFER
   two whisker tables for atomic hot reload
   active_buf points to the live one
───────────────────────────────────────── */

static struct sealant_whisker buf_a[SEALANT_MAX_WHISKERS];
static struct sealant_whisker buf_b[SEALANT_MAX_WHISKERS];
static struct sealant_whisker *active_buf   = buf_a;
static struct sealant_whisker *standby_buf  = buf_b;
static uint32_t active_count                = 0;

extern struct sealant_whisker whisker_table[SEALANT_MAX_WHISKERS];
extern uint32_t whisker_count;
extern spinlock_t whisker_lock;
extern uint8_t default_policy[FLOE_MAX];

/* ─────────────────────────────────────────
   WRITE RULES TO DISK
   called on rmmod and by sealant save
───────────────────────────────────────── */

int sealant_rules_save(void)
{
    struct file                  *f;
    struct sealant_rules_header   hdr;
    unsigned long                 flags;
    loff_t                        pos = 0;
    int                           ret = 0;
    uint32_t                      count = 0;
    uint32_t                      i;
    struct sealant_whisker        *tmp;

    tmp = vmalloc(SEALANT_MAX_WHISKERS * sizeof(struct sealant_whisker));
    if (!tmp)
        return -ENOMEM;

    /* only save IPv4 rules — IPv6 mirrors are recreated on load */
    spin_lock_irqsave(&whisker_lock, flags);
    for (i = 0; i < whisker_count; i++) {
        if (!whisker_table[i].ipv6)
            tmp[count++] = whisker_table[i];
    }
    spin_unlock_irqrestore(&whisker_lock, flags);

    f = filp_open(SEALANT_RULES_PATH,
                  O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (IS_ERR(f)) {
        printk(KERN_ERR "sealant: cannot open %s for write (%ld)\n",
               SEALANT_RULES_PATH, PTR_ERR(f));
        vfree(tmp);
        return PTR_ERR(f);
    }

    memset(&hdr, 0, sizeof(hdr));
    hdr.magic         = SEALANT_RULES_MAGIC;
    hdr.version       = SEALANT_RULES_VERSION;
    hdr.whisker_count = count;
    memcpy(hdr.default_policy, default_policy, FLOE_MAX);

    ret = kernel_write(f, &hdr, sizeof(hdr), &pos);
    if (ret < 0) {
        printk(KERN_ERR "sealant: header write failed (%d)\n", ret);
        goto out;
    }

    ret = kernel_write(f, tmp,
                       count * sizeof(struct sealant_whisker), &pos);
    if (ret < 0) {
        printk(KERN_ERR "sealant: whisker write failed (%d)\n", ret);
        goto out;
    }

    ret = 0;
    printk(KERN_INFO "sealant: saved %u whiskers to %s\n",
           count, SEALANT_RULES_PATH);

out:
    filp_close(f, NULL);
    vfree(tmp);
    return ret;
}

/* ─────────────────────────────────────────
   LOAD RULES FROM DISK
   called on insmod
───────────────────────────────────────── */
int sealant_rules_load(void)
{
    struct file                  *f;
    struct sealant_rules_header   hdr;
    struct sealant_whisker        *tmp;
    unsigned long                 flags;
    loff_t                        pos = 0;
    int                           ret = 0;
    uint32_t                      k;

    f = filp_open(SEALANT_RULES_PATH, O_RDONLY, 0);
    if (IS_ERR(f)) {
        printk(KERN_INFO "sealant: no rules file found, starting fresh\n");
        return 0;
    }

    ret = kernel_read(f, &hdr, sizeof(hdr), &pos);
    if (ret < (int)sizeof(hdr)) {
        printk(KERN_ERR "sealant: rules file too short\n");
        ret = -EINVAL;
        goto out;
    }

    if (hdr.magic != SEALANT_RULES_MAGIC) {
        printk(KERN_ERR "sealant: rules file magic mismatch\n");
        ret = -EINVAL;
        goto out;
    }

    if (hdr.version != SEALANT_RULES_VERSION) {
        printk(KERN_ERR "sealant: rules file version mismatch "
               "(got %u, want %u)\n",
               hdr.version, SEALANT_RULES_VERSION);
        ret = -EINVAL;
        goto out;
    }

    if (hdr.whisker_count > SEALANT_MAX_WHISKERS / 2) {
        printk(KERN_ERR "sealant: rules file whisker count too large\n");
        ret = -EINVAL;
        goto out;
    }

    tmp = vmalloc(SEALANT_MAX_WHISKERS * sizeof(struct sealant_whisker));
    if (!tmp) {
        ret = -ENOMEM;
        goto out;
    }

    ret = kernel_read(f, tmp,
                      hdr.whisker_count * sizeof(struct sealant_whisker),
                      &pos);
    if (ret < 0) {
        printk(KERN_ERR "sealant: rules file read failed (%d)\n", ret);
        vfree(tmp);
        ret = -EINVAL;
        goto out;
    }

    spin_lock_irqsave(&whisker_lock, flags);

    /* load IPv4 rules */
    memcpy(whisker_table, tmp,
           hdr.whisker_count * sizeof(struct sealant_whisker));
    whisker_count = hdr.whisker_count;
    memcpy(default_policy, hdr.default_policy, FLOE_MAX);

    /* recreate IPv6 mirrors */
    for (k = 0; k < hdr.whisker_count && whisker_count < SEALANT_MAX_WHISKERS; k++) {
        if (!whisker_table[k].ipv6) {
            struct sealant_whisker w6 = whisker_table[k];
            w6.ipv6       = 1;
            w6.id         = whisker_count;
            w6.hit_count  = 0;
            w6.byte_count = 0;
            whisker_table[whisker_count++] = w6;
        }
    }

    /* reassign IDs sequentially */
    for (k = 0; k < whisker_count; k++)
        whisker_table[k].id = k;

    spin_unlock_irqrestore(&whisker_lock, flags);

    vfree(tmp);
    ret = 0;

    printk(KERN_INFO "sealant: loaded %u whiskers from %s\n",
           hdr.whisker_count, SEALANT_RULES_PATH);

out:
    filp_close(f, NULL);
    return ret;
}

/* ─────────────────────────────────────────
   ATOMIC HOT RELOAD
   loads new rules into standby buffer
   then swaps it live with zero packet loss
───────────────────────────────────────── */

int sealant_rules_hot_reload(void)
{
    struct file     *f;
    struct sealant_rules_header hdr;
    unsigned long   flags;
    loff_t          pos = 0;
    int             ret = 0;

    f = filp_open(SEALANT_RULES_PATH, O_RDONLY, 0);
    if (IS_ERR(f)) {
        printk(KERN_ERR "sealant: hot reload - no rules file\n");
        return PTR_ERR(f);
    }

    ret = kernel_read(f, &hdr, sizeof(hdr), &pos);
    if (ret < (int)sizeof(hdr) || hdr.magic != SEALANT_RULES_MAGIC) {
        printk(KERN_ERR "sealant: hot reload - invalid rules file\n");
        filp_close(f, NULL);
        return -EINVAL;
    }

    if (hdr.whisker_count > SEALANT_MAX_WHISKERS) {
        filp_close(f, NULL);
        return -EINVAL;
    }

    memset(standby_buf, 0,
        SEALANT_MAX_WHISKERS * sizeof(struct sealant_whisker));

    ret = kernel_read(f, standby_buf,
        SEALANT_MAX_WHISKERS * sizeof(struct sealant_whisker),
        &pos);

    filp_close(f, NULL);

    if (ret < (int)(hdr.whisker_count * sizeof(struct sealant_whisker))) {
        printk(KERN_ERR "sealant: hot reload - truncated rules file\n");
        return -EINVAL;
    }

    spin_lock_irqsave(&whisker_lock, flags);

    if (active_buf == buf_a) {
        active_buf  = buf_b;
        standby_buf = buf_a;
    } else {
        active_buf  = buf_a;
        standby_buf = buf_b;
    }

    memcpy(whisker_table, active_buf,
        hdr.whisker_count * sizeof(struct sealant_whisker));
    whisker_count = hdr.whisker_count;
    memcpy(default_policy, hdr.default_policy, FLOE_MAX);
    active_count = hdr.whisker_count;

    spin_unlock_irqrestore(&whisker_lock, flags);

    printk(KERN_INFO "sealant: hot reload complete - %u whiskers live\n",
        hdr.whisker_count);
    return 0;
}

/* ─────────────────────────────────────────
   INIT / EXIT
───────────────────────────────────────── */

int sealant_rules_init(void)
{
    memset(buf_a, 0, sizeof(buf_a));
    memset(buf_b, 0, sizeof(buf_b));
    active_buf   = buf_a;
    standby_buf  = buf_b;
    active_count = 0;
    printk(KERN_INFO "sealant: rules engine initialized\n");
    return 0;
}

void sealant_rules_exit(void)
{
    sealant_rules_save();
    printk(KERN_INFO "sealant: rules engine shut down\n");
}
