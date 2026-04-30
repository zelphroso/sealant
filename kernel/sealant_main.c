#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/spinlock.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <net/icmp.h>
#include <net/addrconf.h>
#include <linux/workqueue.h>

#include "../include/sealant.h"

/* ─────────────────────────────────────────
   MODULE METADATA
───────────────────────────────────────── */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("zelphroso");
MODULE_DESCRIPTION("Sealant, Strong security with a softer side.");
MODULE_VERSION(SEALANT_VERSION);

/* ─────────────────────────────────────────
   GLOBAL RULE TABLE
───────────────────────────────────────── */

struct sealant_whisker	whisker_table[SEALANT_MAX_WHISKERS];
uint32_t			    whisker_count = 0;
DEFINE_SPINLOCK(whisker_lock);
static struct sealant_rate_state rate_state[SEALANT_MAX_WHISKERS];

static struct delayed_work rules_load_work;

static void rules_load_worker(struct work_struct *work)
{
	sealant_rules_load();
	printk(KERN_INFO "sealant: rules loaded from delayed worker\n");
}

/* ─────────────────────────────────────────
   DEFAULT POLICIES
───────────────────────────────────────── */

uint8_t default_policy[FLOE_MAX] = {
	[FLOE_INPUT]       = ACTION_HAUL,
	[FLOE_OUTPUT]      = ACTION_HAUL,
	[FLOE_FORWARD]     = ACTION_HAUL,
	[FLOE_PREROUTING]  = ACTION_HAUL,
	[FLOE_POSTROUTING] = ACTION_HAUL,
};

/* ─────────────────────────────────────────
   FORWARD DECLARATIONS
───────────────────────────────────────── */

static unsigned int sealant_hook_ipv4_in(void *priv, struct sk_buff *skb,
					  const struct nf_hook_state *state);
static unsigned int sealant_hook_ipv4_out(void *priv, struct sk_buff *skb,
					   const struct nf_hook_state *state);
static unsigned int sealant_hook_ipv4_fwd(void *priv, struct sk_buff *skb,
					   const struct nf_hook_state *state);
static unsigned int sealant_hook_ipv6_in(void *priv, struct sk_buff *skb,
					  const struct nf_hook_state *state);
static unsigned int sealant_hook_ipv6_out(void *priv, struct sk_buff *skb,
					   const struct nf_hook_state *state);
static unsigned int sealant_hook_ipv6_fwd(void *priv, struct sk_buff *skb,
					   const struct nf_hook_state *state);

/* ─────────────────────────────────────────
   TOKEN BUCKET RATE LIMITER
   returns 1 if packet is allowed
   returns 0 if packet exceeds rate limit
───────────────────────────────────────── */

static int rate_limit_check(uint32_t whisker_id,
                             uint32_t rate_limit,
                             uint32_t burst)
{
    struct sealant_rate_state *rs = &rate_state[whisker_id];
    uint64_t now    = (uint64_t)jiffies_to_msecs(jiffies);
    uint64_t delta  = now - rs->last_refill;
    uint64_t refill;

    refill = (delta * rate_limit) / 60000;

    if (refill > 0) {
        rs->tokens     += refill;
        rs->last_refill = now;
        if (rs->tokens > burst)
            rs->tokens = burst;
    }

    /* initialize on first use */
    if (rs->last_refill == 0) {
        rs->tokens      = burst;
        rs->last_refill = now;
    }

    if (rs->tokens == 0)
        return 0;

    rs->tokens--;
    return 1;
}

/* ─────────────────────────────────────────
   CORE PACKET EVALUATOR
───────────────────────────────────────── */

static unsigned int evaluate_packet(struct sk_buff *skb,
				     const struct nf_hook_state *state,
				     uint8_t floe)
{
	struct sealant_whisker	*w;
	struct iphdr		*iph;
	struct tcphdr		*tcph;
	struct udphdr		*udph;
	uint32_t		src_ip, dst_ip;
	uint16_t		src_port = 0, dst_port = 0;
	uint8_t			proto;
	uint8_t			pkt_molt;
	uint32_t		i;
	unsigned long		flags;

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (!iph)
		return NF_ACCEPT;

	src_ip = ntohl(iph->saddr);
	dst_ip = ntohl(iph->daddr);
	proto  = iph->protocol;

	if (proto == IPPROTO_TCP) {
		if (!pskb_may_pull(skb, ip_hdrlen(skb) + sizeof(struct tcphdr)))
			return NF_ACCEPT;
		tcph = tcp_hdr(skb);
		if (tcph) {
			src_port = ntohs(tcph->source);
			dst_port = ntohs(tcph->dest);
		}
	} else if (proto == IPPROTO_UDP) {
		if (!pskb_may_pull(skb, ip_hdrlen(skb) + sizeof(struct udphdr)))
			return NF_ACCEPT;
		udph = udp_hdr(skb);
		if (udph) {
			src_port = ntohs(udph->source);
			dst_port = ntohs(udph->dest);
		}
	}

	pkt_molt = sealant_ct_track(skb, proto, src_ip, dst_ip,
				     src_port, dst_port);

	spin_lock_irqsave(&whisker_lock, flags);

	for (i = 0; i < whisker_count; i++) {
		w = &whisker_table[i];

		if (!w->enabled)
			continue;
		if (w->floe != floe)
			continue;
		if (w->ipv6)
			continue;
		if (w->protocol != PROTO_ANY && w->protocol != proto)
			continue;
		if (w->molt_mask != 0) {
			if (!(w->molt_mask & pkt_molt))
				continue;
		}
		if (w->src_ip != 0) {
			if ((src_ip & w->src_mask) != (w->src_ip & w->src_mask))
				continue;
		}
		if (w->dst_ip != 0) {
			if ((dst_ip & w->dst_mask) != (w->dst_ip & w->dst_mask))
				continue;
		}
		if (w->dst_port_min != 0 || w->dst_port_max != 0) {
			if (dst_port < w->dst_port_min || dst_port > w->dst_port_max)
				continue;
		}
		if (w->src_port_min != 0 || w->src_port_max != 0) {
			if (src_port < w->src_port_min || src_port > w->src_port_max)
				continue;
		}
		if (w->iface_in[0] != '\0' && state->in) {
			if (strncmp(w->iface_in, state->in->name, SEALANT_IFACE_LEN) != 0)
				continue;
		}
		if (w->iface_out[0] != '\0' && state->out) {
			if (strncmp(w->iface_out, state->out->name, SEALANT_IFACE_LEN) != 0)
				continue;
		}

		w->hit_count++;
		w->byte_count += skb->len;

		if (w->rate_limit > 0) {
			if (!rate_limit_check(i, w->rate_limit,
					      w->rate_burst ? w->rate_burst : w->rate_limit)) {
				spin_unlock_irqrestore(&whisker_lock, flags);
				return NF_DROP;
			}
		}

		if (w->pod == POD_NAT && w->nat_type != NAT_NONE) {
			spin_unlock_irqrestore(&whisker_lock, flags);
			sealant_nat_process(skb, state, w,
					    src_ip, dst_ip,
					    src_port, dst_port, proto);
			return NF_ACCEPT;
		}

		switch (w->action) {
		case ACTION_HAUL:
			spin_unlock_irqrestore(&whisker_lock, flags);
			return NF_ACCEPT;
		case ACTION_DIVE:
			spin_unlock_irqrestore(&whisker_lock, flags);
			return NF_DROP;
		case ACTION_BARK:
			spin_unlock_irqrestore(&whisker_lock, flags);
			icmp_send(skb, ICMP_DEST_UNREACH,
				  ICMP_PORT_UNREACH, 0);
			return NF_DROP;
		case ACTION_BLEAT:
			sealant_log_packet(skb, state, w, w->action, floe,
					   src_ip, dst_ip,
					   src_port, dst_port, proto);
			continue;
		}
	}

	spin_unlock_irqrestore(&whisker_lock, flags);

	switch (default_policy[floe]) {
	case ACTION_DIVE: return NF_DROP;
	default:          return NF_ACCEPT;
	}
}

/* ─────────────────────────────────────────
   NETFILTER HOOKS - IPv4
───────────────────────────────────────── */

static unsigned int sealant_hook_ipv4_in(void *priv, struct sk_buff *skb,
					  const struct nf_hook_state *state)
{
	return evaluate_packet(skb, state, FLOE_INPUT);
}

static unsigned int sealant_hook_ipv4_out(void *priv, struct sk_buff *skb,
					   const struct nf_hook_state *state)
{
	return evaluate_packet(skb, state, FLOE_OUTPUT);
}

static unsigned int sealant_hook_ipv4_fwd(void *priv, struct sk_buff *skb,
					   const struct nf_hook_state *state)
{
	return evaluate_packet(skb, state, FLOE_FORWARD);
}

/* ─────────────────────────────────────────
   IPV6 PACKET EVALUATOR
───────────────────────────────────────── */

static unsigned int evaluate_packet_ipv6(struct sk_buff *skb,
					  const struct nf_hook_state *state,
					  uint8_t floe)
{
	struct sealant_whisker	*w;
	struct ipv6hdr		*ip6h;
	struct tcphdr		*tcph;
	struct udphdr		*udph;
	uint16_t		src_port = 0, dst_port = 0;
	uint8_t			proto;
	uint32_t		i;
	unsigned long	flags;

	ip6h = ipv6_hdr(skb);
	if (!ip6h)
		return NF_ACCEPT;

	proto = ip6h->nexthdr;

	if (proto == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
		if (tcph) {
			src_port = ntohs(tcph->source);
			dst_port = ntohs(tcph->dest);
		}
	} else if (proto == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		if (udph) {
			src_port = ntohs(udph->source);
			dst_port = ntohs(udph->dest);
		}
	}

	spin_lock_irqsave(&whisker_lock, flags);

	for (i = 0; i < whisker_count; i++) {
		w = &whisker_table[i];

		if (!w->enabled)
			continue;

		if (w->floe != floe)
			continue;

		if (!w->ipv6)
			continue;

		if (w->protocol != PROTO_ANY && w->protocol != proto)
			continue;

		if (!ipv6_addr_any((struct in6_addr *)w->src_ip6)) {
			struct in6_addr masked_src, masked_rule;
			int j;
			for (j = 0; j < 16; j++) {
				masked_src.s6_addr[j]  = ip6h->saddr.s6_addr[j] &
							  w->src_mask6[j];
				masked_rule.s6_addr[j] = w->src_ip6[j] &
							  w->src_mask6[j];
			}
			if (!ipv6_addr_equal(&masked_src, &masked_rule))
				continue;
		}

		if (!ipv6_addr_any((struct in6_addr *)w->dst_ip6)) {
			struct in6_addr masked_dst, masked_rule;
			int j;
			for (j = 0; j < 16; j++) {
				masked_dst.s6_addr[j]  = ip6h->daddr.s6_addr[j] &
							  w->dst_mask6[j];
				masked_rule.s6_addr[j] = w->dst_ip6[j] &
							  w->dst_mask6[j];
			}
			if (!ipv6_addr_equal(&masked_dst, &masked_rule))
				continue;
		}

		if (w->dst_port_min != 0 || w->dst_port_max != 0) {
			if (dst_port < w->dst_port_min || dst_port > w->dst_port_max)
				continue;
		}

		/* source port match */
		if (w->src_port_min != 0 || w->src_port_max != 0) {
			if (src_port < w->src_port_min || src_port > w->src_port_max)
				continue;
		}

		/* interface match */
		if (w->iface_in[0] != '\0' && state->in) {
			if (strncmp(w->iface_in, state->in->name, SEALANT_IFACE_LEN) != 0)
				continue;
		}

		if (w->iface_out[0] != '\0' && state->out) {
			if (strncmp(w->iface_out, state->out->name, SEALANT_IFACE_LEN) != 0)
				continue;
		}

		w->hit_count++;
		w->byte_count += skb->len;

		if (w->rate_limit > 0) {
			if (!rate_limit_check(i, w->rate_limit,
					      w->rate_burst ? w->rate_burst : w->rate_limit)) {
				spin_unlock_irqrestore(&whisker_lock, flags);
				return NF_DROP;
			}
		}

		/* filter actions */
		switch (w->action) {
		case ACTION_HAUL:
			spin_unlock_irqrestore(&whisker_lock, flags);
			return NF_ACCEPT;
		case ACTION_DIVE:
			spin_unlock_irqrestore(&whisker_lock, flags);
			return NF_DROP;
		case ACTION_BARK:
			spin_unlock_irqrestore(&whisker_lock, flags);
			icmp6_send(skb, ICMPV6_DEST_UNREACH,
				   ICMPV6_PORT_UNREACH, 0, NULL, NULL);
			return NF_DROP;
		case ACTION_BLEAT:
			sealant_log_packet(skb, state, w, w->action, floe,
					   0, 0, src_port, dst_port, proto);
			continue;
		}
	}

	spin_unlock_irqrestore(&whisker_lock, flags);

	switch (default_policy[floe]) {
	case ACTION_DIVE: return NF_DROP;
	default:          return NF_ACCEPT;
	}
}

/* ─────────────────────────────────────────
   NETFILTER HOOKS - IPv6
   stubs — full impl in dual-stack pass
───────────────────────────────────────── */

static unsigned int sealant_hook_ipv6_in(void *priv, struct sk_buff *skb,
					  const struct nf_hook_state *state)
{
	return evaluate_packet_ipv6(skb, state, FLOE_INPUT);
}

static unsigned int sealant_hook_ipv6_out(void *priv, struct sk_buff *skb,
					   const struct nf_hook_state *state)
{
	return evaluate_packet_ipv6(skb, state, FLOE_OUTPUT);
}

static unsigned int sealant_hook_ipv6_fwd(void *priv, struct sk_buff *skb,
					   const struct nf_hook_state *state)
{
	return evaluate_packet_ipv6(skb, state, FLOE_FORWARD);
}

/* ─────────────────────────────────────────
   HOOK REGISTRATIONS
───────────────────────────────────────── */

static struct nf_hook_ops sealant_hooks[] = {
	/* IPv4 */
	{
		.hook    = sealant_hook_ipv4_in,
		.pf      = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_FILTER,
	},
	{
		.hook    = sealant_hook_ipv4_out,
		.pf      = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_FILTER,
	},
	{
		.hook    = sealant_hook_ipv4_fwd,
		.pf      = NFPROTO_IPV4,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FILTER,
	},
	/* IPv6 */
	{
		.hook    = sealant_hook_ipv6_in,
		.pf      = NFPROTO_IPV6,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP6_PRI_FILTER,
	},
	{
		.hook    = sealant_hook_ipv6_out,
		.pf      = NFPROTO_IPV6,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP6_PRI_FILTER,
	},
	{
		.hook    = sealant_hook_ipv6_fwd,
		.pf      = NFPROTO_IPV6,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP6_PRI_FILTER,
	},
};

/* ─────────────────────────────────────────
   IOCTL HANDLER
───────────────────────────────────────── */

static long sealant_ioctl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	struct sealant_whisker	w;
	uint32_t		id;
	uint8_t			payload;
	uint8_t			floe;
	uint8_t			action;
	unsigned long		flags;
	int			ret = 0;

	switch (cmd) {

	case SEALANT_IOC_ADD_WHISKER:
		if (copy_from_user(&w, (void __user *)arg, sizeof(w)))
			return -EFAULT;
		spin_lock_irqsave(&whisker_lock, flags);
		if (whisker_count >= SEALANT_MAX_WHISKERS) {
			spin_unlock_irqrestore(&whisker_lock, flags);
			return -ENOMEM;
		}
		/* shadow check */
		{
			uint32_t k;
			for (k = 0; k < whisker_count; k++) {
				struct sealant_whisker *existing = &whisker_table[k];
				if (!existing->enabled) continue;
				if (existing->floe != w.floe) continue;
				if (existing->src_ip == 0 &&
				    existing->dst_ip == 0 &&
				    existing->dst_port_min == 0 &&
				    existing->dst_port_max == 0 &&
				    existing->iface_in[0] == '\0' &&
				    existing->iface_out[0] == '\0' &&
				    existing->molt_mask == 0 &&
				    existing->protocol == PROTO_ANY) {
					printk(KERN_WARNING "sealant: whisker may be "
					       "shadowed by rule %u\n", existing->id);
					break;
				}
			}
		}
		w.id         = whisker_count;
		w.hit_count  = 0;
		w.byte_count = 0;
		whisker_table[whisker_count++] = w;
		if (!w.ipv6 && whisker_count < SEALANT_MAX_WHISKERS) {
			struct sealant_whisker w6 = w;
			w6.ipv6       = 1;
			w6.id         = whisker_count;
			w6.hit_count  = 0;
			w6.byte_count = 0;
			whisker_table[whisker_count++] = w6;
		}
		spin_unlock_irqrestore(&whisker_lock, flags);
		break;

	case SEALANT_IOC_DEL_WHISKER:
		if (copy_from_user(&id, (void __user *)arg, sizeof(id)))
			return -EFAULT;
		spin_lock_irqsave(&whisker_lock, flags);
		if (id >= whisker_count) {
			spin_unlock_irqrestore(&whisker_lock, flags);
			return -EINVAL;
		}
		if (id + 1 < whisker_count &&
		    whisker_table[id + 1].ipv6 == 1 &&
		    whisker_table[id + 1].floe == whisker_table[id].floe &&
		    whisker_table[id + 1].action == whisker_table[id].action &&
		    whisker_table[id + 1].protocol == whisker_table[id].protocol &&
		    whisker_table[id + 1].dst_port_min == whisker_table[id].dst_port_min &&
		    whisker_table[id + 1].dst_port_max == whisker_table[id].dst_port_max) {
			memmove(&whisker_table[id], &whisker_table[id + 2],
				(whisker_count - id - 2) * sizeof(struct sealant_whisker));
			whisker_count -= 2;
		} else {
			memmove(&whisker_table[id], &whisker_table[id + 1],
				(whisker_count - id - 1) * sizeof(struct sealant_whisker));
			whisker_count--;
		}
		{
			uint32_t k;
			for (k = id; k < whisker_count; k++)
				whisker_table[k].id = k;
		}
		spin_unlock_irqrestore(&whisker_lock, flags);
		break;

	case SEALANT_IOC_FLUSH_FLOE:
		if (copy_from_user(&payload, (void __user *)arg, sizeof(payload)))
			return -EFAULT;
		spin_lock_irqsave(&whisker_lock, flags);
		{
			uint32_t i = 0, j = 0;
			for (i = 0; i < whisker_count; i++) {
				if (whisker_table[i].floe != payload)
					whisker_table[j++] = whisker_table[i];
			}
			whisker_count = j;
			for (j = 0; j < whisker_count; j++)
				whisker_table[j].id = j;
		}
		spin_unlock_irqrestore(&whisker_lock, flags);
		break;

	case SEALANT_IOC_SET_POLICY:
		if (copy_from_user(&payload, (void __user *)arg, sizeof(payload)))
			return -EFAULT;
		floe   = (payload >> 4) & 0x0F;
		action = payload & 0x0F;
		if (floe >= FLOE_MAX || action >= ACTION_MAX)
			return -EINVAL;
		default_policy[floe] = action;
		break;

	case SEALANT_IOC_HOT_RELOAD:
		ret = sealant_rules_hot_reload();
		break;

	case SEALANT_IOC_SAVE_RULES:
		ret = sealant_rules_save();
		break;

	case SEALANT_IOC_LOAD_RULES:
		ret = sealant_rules_load();
		break;

	case SEALANT_IOC_FLUSH_LOG:
		sealant_log_flush();
		break;

	case SEALANT_IOC_GET_STATS:
	{
		struct sealant_stats s;
		memset(&s, 0, sizeof(s));
		spin_lock_irqsave(&whisker_lock, flags);
		s.whisker_count = whisker_count;
		spin_unlock_irqrestore(&whisker_lock, flags);
		s.pup_count     = sealant_ct_count();
		strncpy(s.version, SEALANT_VERSION, sizeof(s.version) - 1);
		if (copy_to_user((void __user *)arg, &s, sizeof(s)))
			return -EFAULT;
		break;
	}

	default:
		ret = -ENOTTY;
	}

	return ret;
}

/* ─────────────────────────────────────────
   MISC DEVICE
───────────────────────────────────────── */

static const struct file_operations sealant_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = sealant_ioctl,
};

static struct miscdevice sealant_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "sealant",
	.fops  = &sealant_fops,
};

/* ─────────────────────────────────────────
   PROC ENTRY (/proc/sealant/observe)
───────────────────────────────────────── */

static int sealant_proc_show(struct seq_file *m, void *v)
{
	uint32_t      i;
	unsigned long flags;

	seq_printf(m, "%-4s %-32s %-6s %-8s %-6s %-16s %-16s %-6s %-6s %-10s %-10s %-4s\n",
		   "ID", "NAME", "FLOE", "ACTION", "PROTO",
		   "IFACE_IN", "IFACE_OUT", "DPORT_MIN", "DPORT_MAX",
		   "HITS", "BYTES", "IP6");

	spin_lock_irqsave(&whisker_lock, flags);
	for (i = 0; i < whisker_count; i++) {
		struct sealant_whisker *w = &whisker_table[i];
		seq_printf(m, "%-4u %-32s %-6u %-8u %-6u %-16s %-16s %-6u %-6u %-10llu %-10llu %-4u\n",
			   w->id,
			   w->name[0] ? w->name : "(unnamed)",
			   w->floe,
			   w->action,
			   w->protocol,
			   w->iface_in[0]  ? w->iface_in  : "-",
			   w->iface_out[0] ? w->iface_out : "-",
			   w->dst_port_min,
			   w->dst_port_max,
			   w->hit_count,
			   w->byte_count,
			   w->ipv6);
	}
	spin_unlock_irqrestore(&whisker_lock, flags);

	return 0;
}

static int sealant_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, sealant_proc_show, NULL);
}

static const struct proc_ops sealant_proc_ops = {
	.proc_open    = sealant_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

/* ─────────────────────────────────────────
   MODULE INIT
───────────────────────────────────────── */

static int __init sealant_init(void)
{
	int ret;

	printk(KERN_INFO "sealant: loading v%s\n", SEALANT_VERSION);

	memset(whisker_table, 0, sizeof(whisker_table));
	memset(rate_state, 0, sizeof(rate_state));
	whisker_count = 0;

	ret = sealant_ct_init();
	if (ret) {
		printk(KERN_ERR "sealant: conntrack init failed (%d)\n", ret);
		return ret;
	}

	proc_mkdir("sealant", NULL);
	proc_create("sealant/observe", 0444, NULL, &sealant_proc_ops);

	ret = sealant_log_init();
	if (ret) {
		printk(KERN_ERR "sealant: log init failed (%d)\n", ret);
		sealant_log_exit();
		misc_deregister(&sealant_dev);
		sealant_ct_exit();
		return ret;
	}

	ret = sealant_rules_init();
	if (ret) {
		printk(KERN_ERR "sealant: rules init failed (%d)\n", ret);
		sealant_log_exit();
		misc_deregister(&sealant_dev);
		sealant_ct_exit();
		return ret;
	}

	ret = sealant_nat_init();
	if (ret) {
		printk(KERN_ERR "sealant: NAT init failed (%d)\n", ret);
		sealant_rules_exit();
		sealant_log_exit();
		misc_deregister(&sealant_dev);
		sealant_ct_exit();
		return ret;
	}

	ret = misc_register(&sealant_dev);
	if (ret) {
		printk(KERN_ERR "sealant: failed to register device (%d)\n", ret);
		sealant_ct_exit();
		return ret;
	}

	ret = nf_register_net_hooks(&init_net, sealant_hooks,
				     ARRAY_SIZE(sealant_hooks));
	if (ret) {
		printk(KERN_ERR "sealant: failed to register hooks (%d)\n", ret);
		misc_deregister(&sealant_dev);
		sealant_ct_exit();
		return ret;
	}

	/* defer rule loading by 5s to allow filesystem and SELinux to settle */
	INIT_DELAYED_WORK(&rules_load_work, rules_load_worker);
	schedule_delayed_work(&rules_load_work, 5 * HZ);

	printk(KERN_INFO "sealant: loaded - %d hooks registered\n",
	       (int)ARRAY_SIZE(sealant_hooks));

	return 0;
}

/* ─────────────────────────────────────────
   MODULE EXIT
───────────────────────────────────────── */

static void __exit sealant_exit(void)
{
	printk(KERN_INFO "sealant: unloading\n");

	cancel_delayed_work_sync(&rules_load_work);

	remove_proc_entry("sealant/observe", NULL);
	remove_proc_entry("sealant", NULL);

	nf_unregister_net_hooks(&init_net, sealant_hooks,
				  ARRAY_SIZE(sealant_hooks));

	misc_deregister(&sealant_dev);

	sealant_ct_exit();
	sealant_log_exit();
	sealant_rules_exit();
	sealant_nat_exit();

	printk(KERN_INFO "sealant: unloaded cleanly\n");
}

module_init(sealant_init);
module_exit(sealant_exit);
