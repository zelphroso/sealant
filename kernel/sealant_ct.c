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
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/hash.h>
#include <linux/netfilter.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
#define del_timer_sync timer_delete_sync
#endif

#include "../include/sealant.h"

/* ─────────────────────────────────────────
   TIMEOUTS (in seconds)
───────────────────────────────────────── */

#define PUP_TIMEOUT_TCP_ESTABLISHED	432000
#define PUP_TIMEOUT_TCP_NEW		120
#define PUP_TIMEOUT_UDP			30
#define PUP_TIMEOUT_ICMP		10
#define PUP_GC_INTERVAL			60

/* ─────────────────────────────────────────
   HASH TABLE
   pups stored in buckets via chaining
───────────────────────────────────────── */

#define PUP_HASH_BITS	16
#define PUP_HASH_SIZE	(1 << PUP_HASH_BITS)
#define PUP_HASH_MASK	(PUP_HASH_SIZE - 1)

struct pup_entry {
	struct sealant_pup	pup;
	struct pup_entry	*next;
	unsigned long		expires;
};

static struct pup_entry		*pup_table[PUP_HASH_SIZE];
static uint32_t			pup_count = 0;
static DEFINE_SPINLOCK(ct_lock);

/* garb */
static struct timer_list	gc_timer;

/* ─────────────────────────────────────────
   CAPACITY WARNING THRESHOLDS
───────────────────────────────────────── */

#define PUP_WARN_80   ((SEALANT_MAX_PUPS * 80) / 100)
#define PUP_WARN_95   ((SEALANT_MAX_PUPS * 95) / 100)

static uint8_t ct_warned_95 = 0;
static uint8_t ct_warned_80 = 0;

/* ─────────────────────────────────────────
   HASH FUNCTION
   hashes a 5-tuple -> bucket index
───────────────────────────────────────── */

static uint32_t pup_hash(uint32_t src_ip, uint32_t dst_ip,
			uint16_t src_port, uint16_t dst_port,
			uint8_t proto)
{
	uint32_t h = src_ip ^ dst_ip;
	h ^= ((uint32_t)src_port << 16) | dst_port;
	h ^= proto;
	return hash_32(h, PUP_HASH_BITS);
}

/* ─────────────────────────────────────────
   LOOKUP
───────────────────────────────────────── */

static struct pup_entry *pup_lookup(uint32_t src_ip, uint32_t dst_ip,
					uint16_t src_port, uint16_t dst_port,
					uint8_t proto)
{
	uint32_t	bucket	= pup_hash(src_ip, dst_ip,
						src_port, dst_port, proto);
	struct pup_entry *e	= pup_table[bucket];

	while (e) {
		if (e->pup.src_ip	== src_ip &&
		    e->pup.dst_ip	== dst_ip &&
		    e->pup.src_port	== src_port &&
		    e->pup.dst_port	== dst_port &&
		    e->pup.protocol	== proto)
		    return e;
		e = e->next;
	}
	return NULL;
}

/* ─────────────────────────────────────────
   REVERSE LOOKUP
   finds a pup by the reply direction
───────────────────────────────────────── */

static struct pup_entry *pup_lookup_reply(uint32_t src_ip, uint32_t dst_ip,
						uint16_t src_port, uint16_t dst_port,
						uint8_t proto)
{
	return pup_lookup(dst_ip, src_ip, dst_port, src_port, proto);
}

/* ─────────────────────────────────────────
   GET TIMEOUT
   returns the correct timeout for a pup
   based on protocol and state
───────────────────────────────────────── */

static unsigned long pup_get_timeout(uint8_t proto, uint8_t molt)
{
	if (proto == PROTO_TCP) {
		if (molt == MOLT_ESTABLISHED)
			return PUP_TIMEOUT_TCP_ESTABLISHED * HZ;
		return PUP_TIMEOUT_TCP_NEW * HZ;
	}
	if (proto == PROTO_UDP)
		return PUP_TIMEOUT_UDP * HZ;
	return PUP_TIMEOUT_ICMP * HZ;
}

/* ─────────────────────────────────────────
   CREATE PUP
   allocates and inserts a new conntrack
   entry for a new connection
───────────────────────────────────────── */

static struct pup_entry *pup_create(uint32_t src_ip, uint32_t dst_ip,
					uint16_t src_port, uint16_t dst_port,
					uint8_t proto)
{
	struct pup_entry *e;
	uint32_t	bucket;

	if (pup_count >= SEALANT_MAX_PUPS) {
		sealant_intern_write(INTERN_ERROR, SUBSYS_CT,
		    "conntrack table full (%u/%u), dropping new flow",
		    pup_count, SEALANT_MAX_PUPS);
		return NULL;
	}

	if (!ct_warned_95 && pup_count >= PUP_WARN_95) {
		sealant_intern_write(INTERN_WARN, SUBSYS_CT,
		    "conntrack table at 95%% capacity (%u/%u)",
		    pup_count, SEALANT_MAX_PUPS);
		ct_warned_95 = 1;
	} else if (!ct_warned_80 && pup_count >= PUP_WARN_80) {
		sealant_intern_write(INTERN_WARN, SUBSYS_CT,
		    "conntrack table at 80%% capacity (%u/%u)",
		    pup_count, SEALANT_MAX_PUPS);
		ct_warned_80 = 1;
	}

	e = kmalloc(sizeof(*e), GFP_ATOMIC);
	if (!e) {
		sealant_intern_write(INTERN_ERROR, SUBSYS_CT,
		    "pup kmalloc failed for new flow");
		return NULL;
	}

	memset(e, 0, sizeof(*e));

	e->pup.src_ip   = src_ip;
	e->pup.dst_ip   = dst_ip;
	e->pup.src_port = src_port;
	e->pup.dst_port = dst_port;
	e->pup.protocol = proto;
	e->pup.molt     = MOLT_NEW;
	e->pup.timestamp_start = (uint64_t)jiffies_to_msecs(jiffies);
	e->pup.timestamp_last  = e->pup.timestamp_start;
	e->expires = jiffies + pup_get_timeout(proto, MOLT_NEW);

	bucket = pup_hash(src_ip, dst_ip, src_port, dst_port, proto);

	e->next			= pup_table[bucket];
	pup_table[bucket]	= e;
	pup_count++;

	return e;
}

/* ─────────────────────────────────────────
   UPDATE PUP
   refreshes a pup's state and timeout
   based on what the packet looks like
───────────────────────────────────────── */

static void pup_update(struct pup_entry *e, struct sk_buff *skb,
			uint8_t proto, int reply_dir)
{
	struct tcphdr *tcph;

	if (reply_dir) {
		e->pup.bytes_in += skb->len;
		e->pup.packets_in++;
	} else {
		e->pup.bytes_out += skb->len;
		e->pup.packets_out++;
	}

	e->pup.timestamp_last = (uint64_t)jiffies_to_msecs(jiffies);

	if (proto == PROTO_TCP) {
		tcph = tcp_hdr(skb);
		if (tcph) {
			if (tcph->syn && !tcph->ack) {
				e->pup.molt = MOLT_NEW;
			} else if (tcph->syn && tcph->ack) {
				e->pup.molt = MOLT_ESTABLISHED;
			} else if (tcph->ack && !tcph->syn) {
				e->pup.molt = MOLT_ESTABLISHED;
			} else if (tcph->fin || tcph->rst) {
				e->pup.molt = MOLT_INVALID;
				e->expires  = jiffies + 5 * HZ;
				return;
			}
		}
	} else {
		if (reply_dir)
			e->pup.molt = MOLT_ESTABLISHED;
	}

	e->expires = jiffies + pup_get_timeout(proto, e->pup.molt);
}

/* ─────────────────────────────────────────
   GARBAGE COLLECTOR
   runs on a timer, evicts expired pups
───────────────────────────────────────── */

static void pup_gc(struct timer_list *t)
{
	struct pup_entry *e, *prev, *next;
	unsigned long	flags;
	uint32_t	i;
	uint32_t	evicted = 0;

	spin_lock_irqsave(&ct_lock, flags);

	for (i = 0; i < PUP_HASH_SIZE; i++) {
		prev = NULL;
		e    = pup_table[i];

		while (e) {
			next = e->next;
			if (time_after(jiffies, e->expires)) {
				if (prev)
					prev->next = next;
				else
					pup_table[i] = next;
				kfree(e);
				pup_count--;
				evicted++;
			} else {
				prev = e;
			}
			e = next;
		}
	}

	if (ct_warned_95 && pup_count < PUP_WARN_95)
		ct_warned_95 = 0;
	if (ct_warned_80 && pup_count < PUP_WARN_80)
		ct_warned_80 = 0;

	spin_unlock_irqrestore(&ct_lock, flags);

	if (evicted > 0)
		sealant_intern_write(INTERN_INFO, SUBSYS_CT,
		    "gc evicted %u expired pups, %u remaining",
		    evicted, pup_count);

	/* piggyback NAT GC */
	sealant_nat_gc();

	mod_timer(&gc_timer, jiffies + PUP_GC_INTERVAL * HZ);
}

/* ─────────────────────────────────────────
   MAIN CONNTRACK FUNCTION
   called from evaluate_packet in
   sealant_main.c for every packet
   returns the molt state of the packet
───────────────────────────────────────── */

uint8_t sealant_ct_track(struct sk_buff *skb, uint8_t proto,
			uint32_t src_ip, uint32_t dst_ip,
			uint16_t src_port, uint16_t dst_port)
{
	struct pup_entry *e;
	unsigned long	flags;
	uint8_t		molt;
	int		reply = 0;

	spin_lock_irqsave(&ct_lock, flags);

	e = pup_lookup(src_ip, dst_ip, src_port, dst_port, proto);

	if (!e) {
		e = pup_lookup_reply(src_ip, dst_ip, src_port, dst_port, proto);
		if (e)
			reply = 1;
	}

	if (e) {
		pup_update(e, skb, proto, reply);
		molt = e->pup.molt;
		spin_unlock_irqrestore(&ct_lock, flags);
		return molt;
	}

	e = pup_create(src_ip, dst_ip, src_port, dst_port, proto);
	if (!e) {
		spin_unlock_irqrestore(&ct_lock, flags);
		return MOLT_INVALID;
	}

	spin_unlock_irqrestore(&ct_lock, flags);
	return MOLT_NEW;
}

/* ─────────────────────────────────────────
   FLUSH ALL PUPS
   called on module unload
───────────────────────────────────────── */

void sealant_ct_flush(void)
{
	struct pup_entry *e, *next;
	unsigned long	flags;
	uint32_t	i;

	spin_lock_irqsave(&ct_lock, flags);

	for (i = 0; i < PUP_HASH_SIZE; i++) {
		e = pup_table[i];
		while (e) {
			next = e->next;
			kfree(e);
			e = next;
		}
		pup_table[i] = NULL;
	}

	pup_count    = 0;
	ct_warned_80 = 0;
	ct_warned_95 = 0;

	spin_unlock_irqrestore(&ct_lock, flags);
}

/* ─────────────────────────────────────────
   GET PUP COUNT
───────────────────────────────────────── */

uint32_t sealant_ct_count(void)
{
	return pup_count;
}

/* ─────────────────────────────────────────
   INIT / EXIT
───────────────────────────────────────── */

int sealant_ct_init(void)
{
	memset(pup_table, 0, sizeof(pup_table));
	pup_count    = 0;
	ct_warned_80 = 0;
	ct_warned_95 = 0;

	timer_setup(&gc_timer, pup_gc, 0);
	mod_timer(&gc_timer, jiffies + PUP_GC_INTERVAL * HZ);

	sealant_intern_write(INTERN_INFO, SUBSYS_CT,
	    "conntrack initialized (%u buckets, max %u pups)",
	    PUP_HASH_SIZE, SEALANT_MAX_PUPS);
	return 0;
}

void sealant_ct_exit(void)
{
	del_timer_sync(&gc_timer);
	sealant_ct_flush();
	sealant_intern_write(INTERN_INFO, SUBSYS_CT,
	    "conntrack shut down");
}
