// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Sealant — iptables replacement firewall
 * Copyright (C) 2026 Ven Robinson <zelphroso>
 * https://github.com/zelphroso/sealant
 *
 * This file is dual licensed under GPL-2.0 (for kernel use)
 * and MIT (for userspace use). Use whichever license applies
 * to your context.
 */

#ifndef SEALANT_H
#define SEALANT_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/netfilter.h>
#else
#include <stdint.h>
#include <string.h>
#endif

/* ─────────────────────────────────────────
   VERSION
───────────────────────────────────────── */
#define SEALANT_VERSION      "1.0.1.26"
#define SEALANT_IOCTL_MAGIC  0x5E

/* ─────────────────────────────────────────
   LIMITS
───────────────────────────────────────── */
#define SEALANT_MAX_WHISKERS    10000
#define SEALANT_MAX_PUPS        65536
#define SEALANT_IFACE_LEN       16
#define SEALANT_NAME_LEN        32
#define SEALANT_LOG_PREFIX_LEN  64

/* ─────────────────────────────────────────
   PODS (tables)
───────────────────────────────────────── */
typedef enum {
    POD_FILTER = 0,
    POD_NAT,
    POD_MANGLE,
    POD_RAW,
    POD_MAX
} sealant_pod;

/* ─────────────────────────────────────────
   FLOES (chains)
───────────────────────────────────────── */
typedef enum {
    FLOE_INPUT = 0,
    FLOE_OUTPUT,
    FLOE_FORWARD,
    FLOE_PREROUTING,
    FLOE_POSTROUTING,
    FLOE_MAX
} sealant_floe;

/* ─────────────────────────────────────────
   ACTIONS (targets)
───────────────────────────────────────── */
typedef enum {
    ACTION_HAUL  = 0,  /* ACCEPT */
    ACTION_DIVE,       /* DROP   */
    ACTION_BARK,       /* REJECT */
    ACTION_BLEAT,      /* LOG    */
    ACTION_MAX
} sealant_action;

/* ─────────────────────────────────────────
   MOLTS (connection states)
───────────────────────────────────────── */
typedef enum {
    MOLT_NEW         = (1 << 0),
    MOLT_ESTABLISHED = (1 << 1),
    MOLT_RELATED     = (1 << 2),
    MOLT_INVALID     = (1 << 3)
} sealant_molt;

/* ─────────────────────────────────────────
   PROTOCOLS
───────────────────────────────────────── */
typedef enum {
    PROTO_ANY    = 0,
    PROTO_TCP    = 6,
    PROTO_UDP    = 17,
    PROTO_ICMP   = 1,
    PROTO_ICMPv6 = 58
} sealant_proto;

/* ─────────────────────────────────────────
   NAT TYPE
───────────────────────────────────────── */
typedef enum {
    NAT_NONE = 0,
    NAT_SNAT,
    NAT_DNAT,
    NAT_MASQUERADE
} sealant_nat_type;

/* ─────────────────────────────────────────
   RATE LIMIT STATE
   one per whisker, tracks token bucket
───────────────────────────────────────── */
struct sealant_rate_state {
    uint64_t    tokens;
    uint64_t    last_refill;
};

/* ─────────────────────────────────────────
   WHISKER (rule)
───────────────────────────────────────── */
struct sealant_whisker {
    /* identity */
    uint32_t    id;
    char        name[SEALANT_NAME_LEN];

    /* pod + floe */
    uint8_t     pod;
    uint8_t     floe;

    /* action */
    uint8_t     action;

    /* protocol */
    uint8_t     protocol;

    /* IPv4 */
    uint32_t    src_ip;
    uint32_t    src_mask;
    uint32_t    dst_ip;
    uint32_t    dst_mask;

    /* IPv6 */
    uint8_t     src_ip6[16];
    uint8_t     src_mask6[16];
    uint8_t     dst_ip6[16];
    uint8_t     dst_mask6[16];

    /* ports */
    uint16_t    src_port_min;
    uint16_t    src_port_max;
    uint16_t    dst_port_min;
    uint16_t    dst_port_max;

    /* interfaces */
    char        iface_in[SEALANT_IFACE_LEN];
    char        iface_out[SEALANT_IFACE_LEN];
    uint8_t     negate_iface_in;
    uint8_t     negate_iface_out;
    uint8_t     ipv4_only;

    /* connection state bitmask */
    uint8_t     molt_mask;

    /* rate limiting */
    uint32_t    rate_limit;
    uint32_t    rate_burst;

    /* NAT */
    uint8_t     nat_type;
    uint32_t    nat_ip;
    uint8_t     nat_ip6[16];
    uint16_t    nat_port;

    /* logging */
    char        log_prefix[SEALANT_LOG_PREFIX_LEN];

    /* meta */
    uint8_t     enabled;
    uint8_t     ipv6;
    uint64_t    hit_count;
    uint64_t    byte_count;
};

/* ─────────────────────────────────────────
   PUP (conntrack entry)
───────────────────────────────────────── */
struct sealant_pup {
    /* IPv4 */
    uint32_t    src_ip;
    uint32_t    dst_ip;

    /* IPv6 */
    uint8_t     src_ip6[16];
    uint8_t     dst_ip6[16];

    /* ports */
    uint16_t    src_port;
    uint16_t    dst_port;

    /* protocol */
    uint8_t     protocol;

    /* state */
    uint8_t     molt;

    /* traffic */
    uint64_t    bytes_in;
    uint64_t    bytes_out;
    uint64_t    packets_in;
    uint64_t    packets_out;

    /* timing */
    uint64_t    timestamp_start;
    uint64_t    timestamp_last;

    /* flags */
    uint8_t     ipv6;
};

/* ─────────────────────────────────────────
   STATS
───────────────────────────────────────── */
struct sealant_stats {
    uint32_t    whisker_count;
    uint32_t    pup_count;
    uint32_t    log_entries;
    uint32_t    log_dropped;
    uint64_t    packets_total;
    uint64_t    bytes_total;
    char        version[16];
};

/* ─────────────────────────────────────────
   IOCTL COMMANDS
───────────────────────────────────────── */
#define SEALANT_IOC_ADD_WHISKER   _IOW(SEALANT_IOCTL_MAGIC, 1,  struct sealant_whisker)
#define SEALANT_IOC_DEL_WHISKER   _IOW(SEALANT_IOCTL_MAGIC, 2,  uint32_t)
#define SEALANT_IOC_LIST_WHISKERS _IOR(SEALANT_IOCTL_MAGIC, 3,  struct sealant_whisker)
#define SEALANT_IOC_FLUSH_FLOE    _IOW(SEALANT_IOCTL_MAGIC, 4,  uint8_t)
#define SEALANT_IOC_GET_PUPS      _IOR(SEALANT_IOCTL_MAGIC, 5,  struct sealant_pup)
#define SEALANT_IOC_HOT_RELOAD    _IO (SEALANT_IOCTL_MAGIC, 6)
#define SEALANT_IOC_SET_POLICY    _IOW(SEALANT_IOCTL_MAGIC, 7,  uint8_t)
#define SEALANT_IOC_SAVE_RULES    _IO (SEALANT_IOCTL_MAGIC, 9)
#define SEALANT_IOC_LOAD_RULES    _IO (SEALANT_IOCTL_MAGIC, 10)
#define SEALANT_IOC_FLUSH_LOG     _IO (SEALANT_IOCTL_MAGIC, 11)
#define SEALANT_IOC_GET_STATS     _IOR(SEALANT_IOCTL_MAGIC, 12, struct sealant_stats)

/* ─────────────────────────────────────────
   KERNEL-ONLY APIs
───────────────────────────────────────── */
#ifdef __KERNEL__

/* conntrack */
int      sealant_ct_init(void);
void     sealant_ct_exit(void);
uint8_t  sealant_ct_track(struct sk_buff *skb, uint8_t proto,
                           uint32_t src_ip, uint32_t dst_ip,
                           uint16_t src_port, uint16_t dst_port);
void     sealant_ct_flush(void);
uint32_t sealant_ct_count(void);

/* log */
int  sealant_log_init(void);
void sealant_log_exit(void);
void sealant_log_packet(struct sk_buff *skb,
                         const struct nf_hook_state *state,
                         struct sealant_whisker *w,
                         uint8_t action, uint8_t floe,
                         uint32_t src_ip, uint32_t dst_ip,
                         uint16_t src_port, uint16_t dst_port,
                         uint8_t proto);
void sealant_log_flush(void);

/* rules */
int  sealant_rules_init(void);
void sealant_rules_exit(void);
int  sealant_rules_save(void);
int  sealant_rules_load(void);
int  sealant_rules_hot_reload(void);

/* NAT */
int  sealant_nat_init(void);
void sealant_nat_exit(void);
int  sealant_nat_process(struct sk_buff *skb,
                          const struct nf_hook_state *state,
                          struct sealant_whisker *w,
                          uint32_t src_ip, uint32_t dst_ip,
                          uint16_t src_port, uint16_t dst_port,
                          uint8_t proto);
int  sealant_nat_unprocess(struct sk_buff *skb,
                            uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port,
                            uint8_t proto);
void sealant_nat_gc(void);
void sealant_nat_flush(void);

#endif /* __KERNEL__ */

/* ─────────────────────────────────────────
   USERSPACE COMM API
───────────────────────────────────────── */
#ifndef __KERNEL__

int  sealant_comm_open(void);
void sealant_comm_close(int fd);
int  sealant_comm_add(struct sealant_whisker *w);
int  sealant_comm_del(uint32_t id);
int  sealant_comm_flush(uint8_t floe);
int  sealant_comm_set_policy(uint8_t floe, uint8_t action);
int  sealant_comm_reload(void);
int  sealant_comm_save(void);
int  sealant_comm_load(void);
int  sealant_comm_get_stats(struct sealant_stats *stats);
int  sealant_comm_flush_log(void);

#endif /* !__KERNEL__ */

#endif /* SEALANT_H */
