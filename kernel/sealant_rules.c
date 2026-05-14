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

#define SEALANT_RULES_PATH    "/etc/sealant/rules.slt"
#define SEALANT_RULES_MAGIC   0x5EA14E7A
#define SEALANT_RULES_VERSION 3

/* ─────────────────────────────────────────
   FILE HEADER
───────────────────────────────────────── */

struct sealant_rules_header {
    uint32_t    magic;
    uint32_t    version;
    uint32_t    whisker_count;
    uint8_t     default_policy[FLOE_MAX];
    uint8_t     verbosity;
    uint8_t     _pad[4];
};

/* ─────────────────────────────────────────
   DOUBLE BUFFER
   two whisker tables for atomic hot reload
   active_buf points to the live one
───────────────────────────────────────── */

static struct sealant_whisker  buf_a[SEALANT_MAX_WHISKERS];
static struct sealant_whisker  buf_b[SEALANT_MAX_WHISKERS];
static struct sealant_whisker *active_buf  = buf_a;
static struct sealant_whisker *standby_buf = buf_b;
static uint32_t                active_count = 0;

extern struct sealant_whisker  whisker_table[SEALANT_MAX_WHISKERS];
extern uint32_t                whisker_count;
extern spinlock_t              whisker_lock;
extern uint8_t                 default_policy[FLOE_MAX];
extern uint8_t                 tide_active[SEALANT_MAX_WHISKERS];

/* ─────────────────────────────────────────
   V6 MIRROR HELPER
   must be called with whisker_lock held
   base_count = number of canonical rules
   already loaded into whisker_table
───────────────────────────────────────── */

static void sealant_recreate_mirrors(uint32_t base_count)
{
    uint32_t k;

    for (k = 0; k < base_count; k++) {
        switch (whisker_table[k].ip_family) {

        case SEAL_FAMILY_BOTH:
            if (whisker_count >= SEALANT_MAX_WHISKERS) {
                sealant_intern_write(INTERN_WARN, SUBSYS_RULES,
                    "whisker table full, cannot mirror rule %u as v6",
                    whisker_table[k].id);
                break;
            }
            {
                struct sealant_whisker w6 = whisker_table[k];
                w6.ipv6       = 1;
                w6.hit_count  = 0;
                w6.byte_count = 0;
                w6.id         = whisker_count;
                whisker_table[whisker_count++] = w6;
                tide_active[whisker_count - 1] = w6.tide_enabled ? 0 : 1;
            }
            break;

        case SEAL_FAMILY_V6:
            whisker_table[k].ipv6 = 1;
            tide_active[k] = whisker_table[k].tide_enabled ? 0 : 1;
            break;

        case SEAL_FAMILY_V4:
            whisker_table[k].ipv6 = 0;
            tide_active[k] = whisker_table[k].tide_enabled ? 0 : 1;
            break;

        default:
            sealant_intern_write(INTERN_WARN, SUBSYS_RULES,
                "rule %u has unknown ip_family %u, treating as BOTH",
                whisker_table[k].id, whisker_table[k].ip_family);
            if (whisker_count < SEALANT_MAX_WHISKERS) {
                struct sealant_whisker w6 = whisker_table[k];
                w6.ipv6       = 1;
                w6.hit_count  = 0;
                w6.byte_count = 0;
                w6.id         = whisker_count;
                whisker_table[whisker_count++] = w6;
                tide_active[whisker_count - 1] = w6.tide_enabled ? 0 : 1;
            }
            break;
        }
    }

    for (k = 0; k < whisker_count; k++)
        whisker_table[k].id = k;
}

/* ─────────────────────────────────────────
   WRITE RULES TO DISK
   called on rmmod and by sealant save
───────────────────────────────────────── */

int sealant_rules_save(void)
{
    struct file                 *f;
    struct sealant_rules_header  hdr;
    struct sealant_whisker      *tmp;
    unsigned long                flags;
    loff_t                       pos   = 0;
    int                          ret   = 0;
    uint32_t                     count = 0;
    uint32_t                     i;

    tmp = vmalloc(SEALANT_MAX_WHISKERS * sizeof(struct sealant_whisker));
    if (!tmp)
        return -ENOMEM;

    spin_lock_irqsave(&whisker_lock, flags);
    for (i = 0; i < whisker_count; i++) {
        if (!whisker_table[i].ipv6)
            tmp[count++] = whisker_table[i];
    }
    spin_unlock_irqrestore(&whisker_lock, flags);

    f = filp_open(SEALANT_RULES_PATH,
                  O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (IS_ERR(f)) {
        sealant_intern_write(INTERN_ERROR, SUBSYS_RULES,
            "cannot open %s for write (%ld)",
            SEALANT_RULES_PATH, PTR_ERR(f));
        vfree(tmp);
        return PTR_ERR(f);
    }

    memset(&hdr, 0, sizeof(hdr));
    hdr.magic         = SEALANT_RULES_MAGIC;
    hdr.version       = SEALANT_RULES_VERSION;
    hdr.whisker_count = count;
    hdr.verbosity     = sealant_verbosity;
    memcpy(hdr.default_policy, default_policy, FLOE_MAX);

    ret = kernel_write(f, &hdr, sizeof(hdr), &pos);
    if (ret < 0) {
        sealant_intern_write(INTERN_ERROR, SUBSYS_RULES,
            "header write failed (%d)", ret);
        goto out;
    }

    ret = kernel_write(f, tmp,
                       count * sizeof(struct sealant_whisker), &pos);
    if (ret < 0) {
        sealant_intern_write(INTERN_ERROR, SUBSYS_RULES,
            "whisker write failed (%d)", ret);
        goto out;
    }

    ret = 0;
    sealant_intern_write(INTERN_INFO, SUBSYS_RULES,
        "saved %u whiskers to %s", count, SEALANT_RULES_PATH);

out:
    filp_close(f, NULL);
    vfree(tmp);
    return ret;
}

/* ─────────────────────────────────────────
   LOAD RULES FROM DISK
   called on insmod and by sealant load
───────────────────────────────────────── */

int sealant_rules_load(void)
{
    struct file                 *f;
    struct sealant_rules_header  hdr;
    struct sealant_whisker      *tmp;
    unsigned long                flags;
    loff_t                       pos = 0;
    int                          ret = 0;

    f = filp_open(SEALANT_RULES_PATH, O_RDONLY, 0);
    if (IS_ERR(f)) {
        sealant_intern_write(INTERN_INFO, SUBSYS_RULES,
            "no rules file found, starting fresh");
        return 0;
    }

    ret = kernel_read(f, &hdr, sizeof(hdr), &pos);
    if (ret < (int)sizeof(hdr)) {
        sealant_intern_write(INTERN_ERROR, SUBSYS_RULES,
            "rules file too short");
        ret = -EINVAL;
        goto out;
    }

    if (hdr.magic != SEALANT_RULES_MAGIC) {
        sealant_intern_write(INTERN_ERROR, SUBSYS_RULES,
            "rules file magic mismatch (got 0x%08x, want 0x%08x)",
            hdr.magic, SEALANT_RULES_MAGIC);
        ret = -EINVAL;
        goto out;
    }

    if (hdr.version != SEALANT_RULES_VERSION) {
        sealant_intern_write(INTERN_ERROR, SUBSYS_RULES,
            "rules file version mismatch (got %u, want %u)",
            hdr.version, SEALANT_RULES_VERSION);
        ret = -EINVAL;
        goto out;
    }

    if (hdr.whisker_count > SEALANT_MAX_WHISKERS / 2) {
        sealant_intern_write(INTERN_ERROR, SUBSYS_RULES,
            "rules file whisker count too large (%u > %u)",
            hdr.whisker_count, SEALANT_MAX_WHISKERS / 2);
        ret = -EINVAL;
        goto out;
    }

    tmp = vmalloc(SEALANT_MAX_WHISKERS * sizeof(struct sealant_whisker));
    if (!tmp) {
        sealant_intern_write(INTERN_ERROR, SUBSYS_RULES,
            "vmalloc failed loading rules");
        ret = -ENOMEM;
        goto out;
    }

    ret = kernel_read(f, tmp,
                      hdr.whisker_count * sizeof(struct sealant_whisker),
                      &pos);
    if (ret < (int)(hdr.whisker_count * sizeof(struct sealant_whisker))) {
        sealant_intern_write(INTERN_ERROR, SUBSYS_RULES,
            "rules file read failed or truncated (%d)", ret);
        vfree(tmp);
        ret = -EINVAL;
        goto out;
    }

    spin_lock_irqsave(&whisker_lock, flags);

    memcpy(whisker_table, tmp,
           hdr.whisker_count * sizeof(struct sealant_whisker));
    whisker_count = hdr.whisker_count;
    memcpy(default_policy, hdr.default_policy, FLOE_MAX);
    sealant_verbosity = hdr.verbosity;

    {
        uint32_t k;
        for (k = 0; k < hdr.whisker_count; k++)
            tide_active[k] = whisker_table[k].tide_enabled ? 0 : 1;
    }

    sealant_recreate_mirrors(hdr.whisker_count);

    spin_unlock_irqrestore(&whisker_lock, flags);

    vfree(tmp);
    ret = 0;

    sealant_intern_write(INTERN_INFO, SUBSYS_RULES,
        "loaded %u canonical whiskers (%u total with mirrors) from %s",
        hdr.whisker_count, whisker_count, SEALANT_RULES_PATH);

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
    struct file                 *f;
    struct sealant_rules_header  hdr;
    unsigned long                flags;
    loff_t                       pos = 0;
    int                          ret = 0;
    uint32_t                     prev_count;

    f = filp_open(SEALANT_RULES_PATH, O_RDONLY, 0);
    if (IS_ERR(f)) {
        sealant_intern_write(INTERN_ERROR, SUBSYS_RULES,
            "hot reload failed — no rules file");
        return PTR_ERR(f);
    }

    ret = kernel_read(f, &hdr, sizeof(hdr), &pos);
    if (ret < (int)sizeof(hdr) ||
        hdr.magic   != SEALANT_RULES_MAGIC ||
        hdr.version != SEALANT_RULES_VERSION) {
        sealant_intern_write(INTERN_ERROR, SUBSYS_RULES,
            "hot reload failed — invalid or version-mismatched rules file");
        filp_close(f, NULL);
        return -EINVAL;
    }

    if (hdr.whisker_count > SEALANT_MAX_WHISKERS / 2) {
        sealant_intern_write(INTERN_ERROR, SUBSYS_RULES,
            "hot reload failed — whisker count too large (%u)",
            hdr.whisker_count);
        filp_close(f, NULL);
        return -EINVAL;
    }

    memset(standby_buf, 0,
           SEALANT_MAX_WHISKERS * sizeof(struct sealant_whisker));

    ret = kernel_read(f, standby_buf,
                      hdr.whisker_count * sizeof(struct sealant_whisker),
                      &pos);
    filp_close(f, NULL);

    if (ret < (int)(hdr.whisker_count * sizeof(struct sealant_whisker))) {
        sealant_intern_write(INTERN_ERROR, SUBSYS_RULES,
            "hot reload failed — truncated rules file");
        return -EINVAL;
    }

    spin_lock_irqsave(&whisker_lock, flags);

    prev_count = whisker_count;

    /* swap buffers */
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
    sealant_verbosity = hdr.verbosity;
    active_count  = hdr.whisker_count;

    {
        uint32_t k;
        for (k = 0; k < hdr.whisker_count; k++)
            tide_active[k] = whisker_table[k].tide_enabled ? 0 : 1;
    }

    /* rebuild v6 mirrors for dual-stack and v6-only rules */
    sealant_recreate_mirrors(hdr.whisker_count);

    spin_unlock_irqrestore(&whisker_lock, flags);

    sealant_intern_write(INTERN_INFO, SUBSYS_RULES,
        "hot reload complete — %u canonical whiskers (%u total with mirrors) live, was %u",
        hdr.whisker_count, whisker_count, prev_count);

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
    sealant_intern_write(INTERN_INFO, SUBSYS_RULES,
        "rules engine initialized");
    return 0;
}

void sealant_rules_exit(void)
{
    sealant_rules_save();
    sealant_intern_write(INTERN_INFO, SUBSYS_RULES,
        "rules engine shut down");
}
