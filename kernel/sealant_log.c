#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/time.h>
#include <linux/jiffies.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/circ_buf.h>

#include "../include/sealant.h"

/* ─────────────────────────────────────────
   LOG RING BUFFER
───────────────────────────────────────── */

#define SEALANT_LOG_MAX     1024
#define SEALANT_LOG_MASK    (SEALANT_LOG_MAX - 1)

struct sealant_log_entry {
    uint64_t    timestamp;
    uint32_t    src_ip;
    uint32_t    dst_ip;
    uint16_t    src_port;
    uint16_t    dst_port;
    uint8_t     protocol;
    uint8_t     action;
    uint8_t     floe;
    uint8_t     ipv6;
    uint8_t     valid;
    uint8_t     src_ip6[16];
    uint8_t     dst_ip6[16];
    char        rule_name[SEALANT_NAME_LEN];
    char        iface[SEALANT_IFACE_LEN];
    uint32_t    pkt_len;
};

static struct sealant_log_entry log_ring[SEALANT_LOG_MAX];
static uint32_t     log_head = 0;
static uint32_t     log_tail = 0;
static uint64_t     log_dropped = 0;
static DEFINE_SPINLOCK(log_lock);

/* ─────────────────────────────────────────
   ACTION / PROTO STRING HELPERS
───────────────────────────────────────── */

static const char *action_to_str(uint8_t action)
{
    switch (action) {
        case ACTION_HAUL:   return "HAUL";
        case ACTION_DIVE:   return "DIVE";
        case ACTION_BARK:   return "BARK";
        case ACTION_BLEAT:  return "BLEAT";
        default:            return "?";
    }
}

static const char *proto_to_str(uint8_t proto)
{
    switch (proto) {
        case PROTO_TCP:     return "TCP";
        case PROTO_UDP:     return "UDP";
        case PROTO_ICMP:    return "ICMP";
        default:            return "?";
    }
}

static const char *floe_to_str(uint8_t floe)
{
    switch (floe) {
        case FLOE_INPUT:        return "INPUT";
        case FLOE_OUTPUT:       return "OUTPUT";
        case FLOE_FORWARD:      return "FORWARD";
        case FLOE_PREROUTING:   return "PREROUTING";
        case FLOE_POSTROUTING:  return "POSTROUTING";
        default:                return "?";
    }
}

/* ─────────────────────────────────────────
   WRITE LOG ENTRY
   called from evaluate_packet on BLEAT
   also called on DIVE/BARK if audit mode
───────────────────────────────────────── */

void sealant_log_packet(struct sk_buff *skb,
                         const struct nf_hook_state *state,
                         struct sealant_whisker *w,
                         uint8_t action, uint8_t floe,
                         uint32_t src_ip, uint32_t dst_ip,
                         uint16_t src_port, uint16_t dst_port,
                         uint8_t proto)
{
    struct sealant_log_entry *e;
    unsigned long             flags;
    uint32_t                  next_head;

    spin_lock_irqsave(&log_lock, flags);

    next_head = (log_head + 1) & SEALANT_LOG_MASK;

    if (next_head == log_tail) {
        /* ring full — evict oldest */
        log_tail = (log_tail + 1) & SEALANT_LOG_MASK;
        log_dropped++;
    }

    e = &log_ring[log_head];
    memset(e, 0, sizeof(*e));

    e->timestamp = (uint64_t)jiffies_to_msecs(jiffies);
    e->src_ip    = htonl(src_ip);
    e->dst_ip    = htonl(dst_ip);
    e->src_port  = src_port;
    e->dst_port  = dst_port;
    e->protocol  = proto;
    e->action    = action;
    e->floe      = floe;
    e->pkt_len   = skb->len;
    e->ipv6      = 0;
    e->valid     = 1;

    if (w)
        strncpy(e->rule_name, w->name[0] ? w->name : "(unnamed)",
                SEALANT_NAME_LEN - 1);
    else
        strncpy(e->rule_name, "(default)", SEALANT_NAME_LEN - 1);

    if (state->in)
        strncpy(e->iface, state->in->name, SEALANT_IFACE_LEN - 1);
    else if (state->out)
        strncpy(e->iface, state->out->name, SEALANT_IFACE_LEN - 1);

    log_head = next_head;

    spin_unlock_irqrestore(&log_lock, flags);

    printk(KERN_INFO "sealant: [%s] rule='%s' floe=%s proto=%s "
           "src=%pI4:%u dst=%pI4:%u len=%u\n",
           action_to_str(action),
           e->rule_name,
           floe_to_str(floe),
           proto_to_str(proto),
           &e->src_ip, src_port,
           &e->dst_ip, dst_port,
           skb->len);
}

/* ─────────────────────────────────────────
   PROC READ (/proc/sealant/log)
   userspace reads the ring buffer here
───────────────────────────────────────── */

static int sealant_log_show(struct seq_file *m, void *v)
{
    unsigned long flags;
    uint32_t      i;

    seq_printf(m, "%-14s %-32s %-12s %-6s %-8s %-21s %-21s %-6s %-6s\n",
               "TIMESTAMP", "RULE", "FLOE", "ACTION",
               "PROTO", "SRC", "DST", "LEN", "IFACE");

    spin_lock_irqsave(&log_lock, flags);

    i = log_tail;
    while (i != log_head) {
        struct sealant_log_entry *e = &log_ring[i];
        char src_buf[22], dst_buf[22];

        if (!e->valid) {
            i = (i + 1) & SEALANT_LOG_MASK;
            continue;
        }

        snprintf(src_buf, sizeof(src_buf), "%pI4:%u",
                 &e->src_ip, e->src_port);
        snprintf(dst_buf, sizeof(dst_buf), "%pI4:%u",
                 &e->dst_ip, e->dst_port);

        seq_printf(m, "%-14llu %-32s %-12s %-6s %-8s %-21s %-21s %-6u %-6s\n",
                   e->timestamp,
                   e->rule_name,
                   floe_to_str(e->floe),
                   action_to_str(e->action),
                   proto_to_str(e->protocol),
                   src_buf,
                   dst_buf,
                   e->pkt_len,
                   e->iface[0] ? e->iface : "-");

        i = (i + 1) & SEALANT_LOG_MASK;
    }

    if (log_dropped > 0)
        seq_printf(m, "\n# %llu entries dropped (ring overflow)\n",
                   log_dropped);

    spin_unlock_irqrestore(&log_lock, flags);

    return 0;
}

static int sealant_log_open(struct inode *inode, struct file *file)
{
    return single_open(file, sealant_log_show, NULL);
}

static const struct proc_ops sealant_log_ops = {
    .proc_open      = sealant_log_open,
    .proc_read      = seq_read,
    .proc_lseek     = seq_lseek,
    .proc_release   = single_release,
};

/* ─────────────────────────────────────────
   FLUSH LOG
───────────────────────────────────────── */

void sealant_log_flush(void)
{
    unsigned long flags;
    spin_lock_irqsave(&log_lock, flags);
    log_head    = 0;
    log_tail    = 0;
    log_dropped = 0;
    memset(log_ring, 0, sizeof(log_ring));
    spin_unlock_irqrestore(&log_lock, flags);
}

/* ─────────────────────────────────────────
   INIT / EXIT
───────────────────────────────────────── */

int sealant_log_init(void)
{
    memset(log_ring, 0, sizeof(log_ring));
    log_head    = 0;
    log_tail    = 0;
    log_dropped = 0;

    proc_create("sealant/log", 0444, NULL, &sealant_log_ops);

    printk(KERN_INFO "sealant: log initialized (%u entry ring)\n",
        SEALANT_LOG_MAX);
    return 0;
}

void sealant_log_exit(void)
{
    remove_proc_entry("sealant/log", NULL);
    sealant_log_flush();
    printk(KERN_INFO "sealant: log shut down\n");
}
