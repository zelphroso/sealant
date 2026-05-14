// SPDX-License-Identifier: MIT
/*
 * Sealant — iptables replacement firewall
 * Copyright (C) 2026 Ven Robinson <zelphroso>
 * https://github.com/zelphroso/sealant
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the
 * Software without restriction.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "../include/sealant.h"

/* ─────────────────────────────────────────
   DEVICE
───────────────────────────────────────── */

#define SEALANT_DEV "/dev/sealant"

/* ─────────────────────────────────────────
   OPEN / CLOSE
───────────────────────────────────────── */

int sealant_comm_open(void)
{
    int fd = open(SEALANT_DEV, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "sealant: cannot open %s: %s\n",
            SEALANT_DEV, strerror(errno));
        fprintf(stderr, "sealant: is the kernel module loaded?\n");
        fprintf(stderr, "sealant: try: sudo insmod sealant.ko\n");
        return -1;
    }
    return fd;
}

void sealant_comm_close(int fd)
{
    if (fd >= 0)
        close(fd);
}

/* ─────────────────────────────────────────
   ADD WHISKER
───────────────────────────────────────── */

int sealant_comm_add(struct sealant_whisker *w)
{
    int fd, ret;

    fd = sealant_comm_open();
    if (fd < 0) return -1;

    ret = ioctl(fd, SEALANT_IOC_ADD_WHISKER, w);
    if (ret < 0) {
        fprintf(stderr, "sealant: add whisker failed: %s\n",
            strerror(errno));
        if (errno == ENOMEM)
            fprintf(stderr, "sealant: whisker table full "
                "(max %u)\n", SEALANT_MAX_WHISKERS);
    }

    sealant_comm_close(fd);
    return ret;
}

/* ─────────────────────────────────────────
   DELETE WHISKER
───────────────────────────────────────── */

int sealant_comm_del(uint32_t id)
{
    int fd, ret;

    fd = sealant_comm_open();
    if (fd < 0) return -1;

    ret = ioctl(fd, SEALANT_IOC_DEL_WHISKER, &id);
    if (ret < 0) {
        fprintf(stderr, "sealant: delete whisker failed: %s\n",
            strerror(errno));
        if (errno == EINVAL)
            fprintf(stderr, "sealant: whisker id %u not found\n", id);
    }

    sealant_comm_close(fd);
    return ret;
}

/* ─────────────────────────────────────────
   FLUSH FLOE
───────────────────────────────────────── */

int sealant_comm_flush(uint8_t floe)
{
    int fd, ret;

    fd = sealant_comm_open();
    if (fd < 0) return -1;

    ret = ioctl(fd, SEALANT_IOC_FLUSH_FLOE, &floe);
    if (ret < 0)
        fprintf(stderr, "sealant: flush failed: %s\n",
            strerror(errno));

    sealant_comm_close(fd);
    return ret;
}

/* ─────────────────────────────────────────
   SET POLICY
───────────────────────────────────────── */

int sealant_comm_set_policy(uint8_t floe, uint8_t action)
{
    int     fd, ret;
    uint8_t payload;

    payload = ((floe & 0x0F) << 4) | (action & 0x0F);

    fd = sealant_comm_open();
    if (fd < 0) return -1;

    ret = ioctl(fd, SEALANT_IOC_SET_POLICY, &payload);
    if (ret < 0)
        fprintf(stderr, "sealant: set policy failed: %s\n",
            strerror(errno));

    sealant_comm_close(fd);
    return ret;
}

/* ─────────────────────────────────────────
   HOT RELOAD
───────────────────────────────────────── */

int sealant_comm_reload(void)
{
    int fd, ret;

    fd = sealant_comm_open();
    if (fd < 0) return -1;

    ret = ioctl(fd, SEALANT_IOC_HOT_RELOAD, 0);
    if (ret < 0)
        fprintf(stderr, "sealant: hot reload failed: %s\n",
            strerror(errno));

    sealant_comm_close(fd);
    return ret;
}

/* ─────────────────────────────────────────
   SAVE RULES
───────────────────────────────────────── */

int sealant_comm_save(void)
{
    int fd, ret;

    fd = sealant_comm_open();
    if (fd < 0) return -1;

    ret = ioctl(fd, SEALANT_IOC_SAVE_RULES, 0);
    if (ret < 0)
        fprintf(stderr, "sealant: save failed: %s\n",
            strerror(errno));
    else
        printf("sealant: rules saved to /etc/sealant/rules.slt\n");

    sealant_comm_close(fd);
    return ret;
}

/* ─────────────────────────────────────────
   LOAD RULES
───────────────────────────────────────── */

int sealant_comm_load(void)
{
    int fd, ret;

    fd = sealant_comm_open();
    if (fd < 0) return -1;

    ret = ioctl(fd, SEALANT_IOC_LOAD_RULES, 0);
    if (ret < 0)
        fprintf(stderr, "sealant: load failed: %s\n",
            strerror(errno));
    else
        printf("sealant: rules loaded from /etc/sealant/rules.slt\n");

    sealant_comm_close(fd);
    return ret;
}

/* ─────────────────────────────────────────
   GET STATS
───────────────────────────────────────── */

int sealant_comm_get_stats(struct sealant_stats *stats)
{
    int fd, ret;

    fd = sealant_comm_open();
    if (fd < 0) return -1;

    ret = ioctl(fd, SEALANT_IOC_GET_STATS, stats);
    if (ret < 0)
        fprintf(stderr, "sealant: get stats failed: %s\n",
            strerror(errno));

    sealant_comm_close(fd);
    return ret;
}

/* ─────────────────────────────────────────
   FLUSH LOG
───────────────────────────────────────── */

int sealant_comm_flush_log(void)
{
    int fd, ret;

    fd = sealant_comm_open();
    if (fd < 0) return -1;

    ret = ioctl(fd, SEALANT_IOC_FLUSH_LOG, 0);
    if (ret < 0)
        fprintf(stderr, "sealant: flush log failed: %s\n",
            strerror(errno));
    else
        printf("sealant: log cleared\n");

    sealant_comm_close(fd);
    return ret;
}

/* ─────────────────────────────────────────
   INTERN
───────────────────────────────────────── */

int sealant_comm_set_verbosity(uint8_t level)
{
    int fd, ret;
    fd = sealant_comm_open();
    if (fd < 0) return -1;

    ret = ioctl(fd, SEALANT_IOC_SET_VERBOSITY, &level);
    if (ret < 0)
        fprintf(stderr, "sealant: set verbosity failed: %s\n",
            strerror(errno));

    sealant_comm_close(fd);
    return ret;
}

int sealant_comm_flush_intern(void)
{
    int fd, ret;

    fd = sealant_comm_open();
    if (fd < 0) return -1;

    ret = ioctl(fd, SEALANT_IOC_FLUSH_INTERN, 0);
    if (ret < 0)
        fprintf(stderr, "sealant: flush internals failed: %s\n",
            strerror(errno));
    else
        printf("sealant: internals cleared\n");

    sealant_comm_close(fd);
    return ret;
}
