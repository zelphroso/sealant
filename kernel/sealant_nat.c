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
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/hash.h>
#include <linux/inetdevice.h>
#include <net/ip.h>
#include <net/checksum.h>
#include <net/route.h>

#include "../include/sealant.h"

/* ─────────────────────────────────────────
   NAT TABLE
   tracks active NAT mappings
───────────────────────────────────────── */

#define NAT_TABLE_BITS  14
#define NAT_TABLE_SIZE  (1 << NAT_TABLE_BITS)
#define NAT_TABLE_MASK  (NAT_TABLE_SIZE - 1)

struct nat_entry {
    uint32_t    orig_src_ip;
    uint32_t    orig_dst_ip;
    uint16_t    orig_src_port;
    uint16_t    orig_dst_port;
    uint8_t     proto;

    uint32_t    nat_src_ip;
    uint32_t    nat_dst_ip;
    uint16_t    nat_src_port;
    uint16_t    nat_dst_port;

    uint8_t     nat_type;

    unsigned long expires;
    struct nat_entry *next;
};

static struct nat_entry     *nat_table[NAT_TABLE_SIZE];
static uint32_t             nat_count = 0;
static DEFINE_SPINLOCK(nat_lock);

static uint16_t             nat_port_cursor = 1024;

/* ─────────────────────────────────────────
   HASH
───────────────────────────────────────── */

static uint32_t nat_hash(uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port, uint8_t proto)
{
    uint32_t h = src_ip ^ dst_ip;
    h ^= ((uint32_t)src_port << 16) | dst_port;
    h ^= proto;
    return hash_32(h, NAT_TABLE_BITS);
}

/* ─────────────────────────────────────────
   LOOKUP
───────────────────────────────────────── */

static struct nat_entry *nat_lookup(uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port, uint8_t proto)
{
    uint32_t        bucket = nat_hash(src_ip, dst_ip,
        src_port, dst_port, proto);
    struct nat_entry *e    = nat_table[bucket];

    while (e) {
        if (e->orig_src_ip == src_ip &&
            e->orig_dst_ip == dst_ip &&
            e->orig_src_port == src_port &&
            e->orig_dst_port == dst_port &&
            e->proto       == proto)
            return e;
        e = e->next;
    }
    return NULL;
}

static struct nat_entry *nat_lookup_reply(uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port, uint8_t proto)
{
    struct nat_entry *e;
    uint32_t    i;

    for (i = 0; i < NAT_TABLE_SIZE; i++) {
        e = nat_table[i];
        while (e) {
            if (e->nat_src_ip   == dst_ip   &&
                e->nat_dst_ip   == src_ip   &&
                e->nat_src_port == dst_port &&
                e->nat_dst_port == src_port &&
                e->proto        == proto)
                return e;
            e = e->next;
        }
    }
    return NULL;
}

/* ─────────────────────────────────────────
   PORT ALLOCATOR
   finds a free ephemeral port for SNAT
───────────────────────────────────────── */

static uint16_t nat_alloc_port(void)
{
    uint16_t port = nat_port_cursor;
    nat_port_cursor++;
    if (nat_port_cursor > 65535)
        nat_port_cursor = 1024;
    return port;
}

/* ─────────────────────────────────────────
   CHECKSUM FIXUP
   recalculates IP and TCP/UDP checksums
   after we modify addresses or ports
───────────────────────────────────────── */

static void fixup_checksums(struct sk_buff *skb,
    uint32_t old_ip, uint32_t new_ip,
    uint16_t old_port, uint16_t new_port, uint8_t proto)
{
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph;
    struct udphdr *udph;

    csum_replace4(&iph->check, htonl(old_ip), htonl(new_ip));

    if (proto == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        if (!tcph) return;
        inet_proto_csum_replace4(&tcph->check, skb,
            htonl(old_ip), htonl(new_ip), true);
        if (old_port != new_port) {
            inet_proto_csum_replace2(&tcph->check, skb,
                htons(old_port), htons(new_port),
                false);
        }
    } else if (proto == IPPROTO_UDP) {
        udph = udp_hdr(skb);
        if (!udph) return;
        if (udph->check) {
            inet_proto_csum_replace4(&udph->check, skb,
                htonl(old_ip), htonl(new_ip), true);
            if (old_port != new_port) {
                inet_proto_csum_replace2(&udph->check, skb,
                    htons(old_port), htons(new_port),
                    false);
            }
        }
    }
}

/* ─────────────────────────────────────────
   SNAT
   rewrites source IP (and optionally port)
   on outgoing packets
───────────────────────────────────────── */

static int do_snat(struct sk_buff *skb, struct sealant_whisker *w,
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint8_t proto)
{
    struct iphdr *iph = ip_hdr(skb);
    struct nat_entry *e;
    uint32_t    new_src_ip;
    uint16_t    new_src_port;
    unsigned long flags;

    new_src_ip  = w->nat_ip ? w->nat_ip : src_ip;
    new_src_port = w->nat_port ? w->nat_port : src_port;

    spin_lock_irqsave(&nat_lock, flags);

    e = nat_lookup(src_ip, dst_ip, src_port, dst_port, proto);
    if (!e) {
        e = kmalloc(sizeof(*e), GFP_ATOMIC);
        if (!e) {
            spin_unlock_irqrestore(&nat_lock, flags);
            return -ENOMEM;
        }

        e->orig_src_ip   = src_ip;
        e->orig_dst_ip   = dst_ip;
        e->orig_src_port = src_port;
        e->orig_dst_port = dst_port;
        e->proto         = proto;
        e->nat_src_ip    = new_src_ip;
        e->nat_dst_ip    = dst_ip;
        e->nat_src_port  = new_src_port ? new_src_port : nat_alloc_port();
        e->nat_dst_port  = dst_port;
        e->nat_type      = NAT_SNAT;
        e->expires       = jiffies + 300 * HZ;

        uint32_t bucket  = nat_hash(src_ip, dst_ip,
            src_port, dst_port, proto);

        e->next          = nat_table[bucket];
        nat_table[bucket] = e;
        nat_count++;
    }

    new_src_ip  = e->nat_src_ip;
    new_src_port = e->nat_src_port;

    spin_unlock_irqrestore(&nat_lock, flags);

    iph->saddr = htonl(new_src_ip);
    if (proto == IPPROTO_TCP) {
        tcp_hdr(skb)->source = htons(new_src_port);
    } else if (proto == IPPROTO_UDP) {
        udp_hdr(skb)->source = htons(new_src_port);
    }

    fixup_checksums(skb, src_ip, new_src_ip, src_port, new_src_port, proto);
    return 0;
}

/* ─────────────────────────────────────────
   DNAT
   rewrites destination IP and port
   on incoming packets
───────────────────────────────────────── */

static int do_dnat(struct sk_buff *skb, struct sealant_whisker *w,
                    uint32_t src_ip, uint32_t dst_ip,
                    uint16_t src_port, uint16_t dst_port,
                    uint8_t proto)
{
    struct iphdr     *iph = ip_hdr(skb);
    struct nat_entry *e;
    uint32_t          new_dst_ip;
    uint16_t          new_dst_port;
    unsigned long     flags;

    new_dst_ip   = w->nat_ip;
    new_dst_port = w->nat_port ? w->nat_port : dst_port;

    if (!new_dst_ip)
        return -EINVAL;

    spin_lock_irqsave(&nat_lock, flags);

    e = nat_lookup(src_ip, dst_ip, src_port, dst_port, proto);
    if (!e) {
        e = kmalloc(sizeof(*e), GFP_ATOMIC);
        if (!e) {
            spin_unlock_irqrestore(&nat_lock, flags);
            return -ENOMEM;
        }

        e->orig_src_ip   = src_ip;
        e->orig_dst_ip   = dst_ip;
        e->orig_src_port = src_port;
        e->orig_dst_port = dst_port;
        e->proto         = proto;
        e->nat_src_ip    = src_ip;
        e->nat_dst_ip    = new_dst_ip;
        e->nat_src_port  = src_port;
        e->nat_dst_port  = new_dst_port;
        e->nat_type      = NAT_DNAT;
        e->expires       = jiffies + 300 * HZ;

        uint32_t bucket  = nat_hash(src_ip, dst_ip,
                                     src_port, dst_port, proto);
        e->next          = nat_table[bucket];
        nat_table[bucket] = e;
        nat_count++;
    }

    new_dst_ip   = e->nat_dst_ip;
    new_dst_port = e->nat_dst_port;

    spin_unlock_irqrestore(&nat_lock, flags);

    /* rewrite packet */
    iph->daddr = htonl(new_dst_ip);
    if (proto == IPPROTO_TCP) {
        tcp_hdr(skb)->dest = htons(new_dst_port);
    } else if (proto == IPPROTO_UDP) {
        udp_hdr(skb)->dest = htons(new_dst_port);
    }

    fixup_checksums(skb, dst_ip, new_dst_ip, dst_port, new_dst_port, proto);

    return 0;
}

/* ─────────────────────────────────────────
   MASQUERADE
   SNAT where the source IP is the
   outgoing interface's address
   automatically determined at runtime
───────────────────────────────────────── */

static int do_masquerade(struct sk_buff *skb, struct sealant_whisker *w,
                          uint32_t src_ip, uint32_t dst_ip,
                          uint16_t src_port, uint16_t dst_port,
                          uint8_t proto)
{
    struct net_device   *dev;
    struct in_device    *in_dev;
    uint32_t            iface_ip = 0;

    dev = skb->dev;
    if (!dev)
        return -ENODEV;

    in_dev = __in_dev_get_rcu(dev);
    if (!in_dev)
        return -ENODEV;

    if (in_dev->ifa_list)
        iface_ip = ntohl(in_dev->ifa_list->ifa_local);

    if (!iface_ip)
        return -ENODEV;

    w->nat_ip   = iface_ip;
    w->nat_port = 0;

    return do_snat(skb, w, src_ip, dst_ip, src_port, dst_port, proto);
}

/* ─────────────────────────────────────────
   REPLY UNNAT
   undoes NAT translation on reply packets
───────────────────────────────────────── */

static int do_unnat(struct sk_buff *skb,
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint8_t proto)
{
    struct iphdr    *iph = ip_hdr(skb);
    struct nat_entry *e;
    unsigned long   flags;

    spin_lock_irqsave(&nat_lock, flags);
    e = nat_lookup_reply(src_ip, dst_ip, src_port, dst_port, proto);
    if (!e) {
        spin_unlock_irqrestore(&nat_lock, flags);
        return 0;
    }

    if (e->nat_type == NAT_SNAT) {
        uint32_t old_ip     = dst_ip;
        uint16_t old_port   = dst_port;
        uint32_t new_ip     = e->orig_src_ip;
        uint16_t new_port   = e->orig_src_port;

        spin_unlock_irqrestore(&nat_lock, flags);

        iph->daddr = htonl(new_ip);
        if (proto == IPPROTO_TCP)
            tcp_hdr(skb)->dest = htons(new_port);
        else if (proto == IPPROTO_UDP)
            udp_hdr(skb)->dest = htons(new_port);

        fixup_checksums(skb, old_ip, new_ip, old_port, new_port, proto);

    } else if (e->nat_type == NAT_DNAT) {
        uint32_t old_ip   = src_ip;
        uint16_t old_port = src_port;
        uint32_t new_ip   = e->orig_dst_ip;
        uint16_t new_port = e->orig_dst_port;

        spin_unlock_irqrestore(&nat_lock, flags);

        iph->saddr = htonl(new_ip);
        if (proto == IPPROTO_TCP)
            tcp_hdr(skb)->source = htons(new_port);
        else if (proto == IPPROTO_UDP)
            udp_hdr(skb)->source = htons(new_port);

        fixup_checksums(skb, old_ip, new_ip, old_port, new_port, proto);
    } else {
        spin_unlock_irqrestore(&nat_lock, flags);
    }
    return 0;
}

/* ─────────────────────────────────────────
   MAIN NAT ENTRY POINT
   called from evaluate_packet for NAT pod
───────────────────────────────────────── */

int sealant_nat_process(struct sk_buff *skb,
    const struct nf_hook_state *state,
    struct sealant_whisker *w,
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint8_t proto)
{
    switch (w->nat_type) {
    case NAT_SNAT:
        return do_snat(skb, w, src_ip, dst_ip,
            src_port, dst_port, proto);
    case NAT_DNAT:
        return do_dnat(skb, w, src_ip, dst_ip,
            src_port, dst_port, proto);
    case NAT_MASQUERADE:
        return do_masquerade(skb, w, src_ip, dst_ip,
            src_port, dst_port, proto);
    default:
        return 0;
    }
}

int sealant_nat_unprocess(struct sk_buff *skb,
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint8_t proto)
{
    return do_unnat(skb, src_ip, dst_ip, src_port, dst_port, proto);
}

/* ─────────────────────────────────────────
   GARBAGE COLLECTOR
───────────────────────────────────────── */

void sealant_nat_gc(void)
{
    struct nat_entry *e, *prev, *next;
    unsigned long   flags;
    uint32_t        i;

    spin_lock_irqsave(&nat_lock, flags);

    for (i = 0; i < NAT_TABLE_SIZE; i++) {
        prev = NULL;
        e    = nat_table[i];
        while (e) {
            next = e->next;
            if (time_after(jiffies, e->expires)) {
                if (prev)
                    prev->next = next;
                else
                    nat_table[i] = next;
                kfree(e);
                nat_count--;
            } else {
                prev = e;
            }
            e = next;
        }
    }
    spin_unlock_irqrestore(&nat_lock, flags);
}

/* ─────────────────────────────────────────
   FLUSH
───────────────────────────────────────── */

void sealant_nat_flush(void)
{
    struct nat_entry *e, *next;
    unsigned long   flags;
    uint32_t        i;

    spin_lock_irqsave(&nat_lock, flags);
    for (i = 0; i < NAT_TABLE_SIZE; i++) {
        e = nat_table[i];
        while (e) {
            next = e->next;
            kfree(e);
            e = next;
        }
        nat_table[i] = NULL;
    }
    nat_count = 0;
    spin_unlock_irqrestore(&nat_lock, flags);
}

/* ─────────────────────────────────────────
   INIT / EXIT
───────────────────────────────────────── */

int sealant_nat_init(void)
{
    memset(nat_table, 0, sizeof(nat_table));
    nat_count       = 0;
    nat_port_cursor = 1024;
    printk(KERN_INFO "sealant: NAT initialized (%u buckets)\n",
        NAT_TABLE_SIZE);
    return 0;
}

void sealant_nat_exit(void)
{
    sealant_nat_flush();
    printk(KERN_INFO "sealant: NAT shut down\n");
}
