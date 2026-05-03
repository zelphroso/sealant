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
#include <ctype.h>
#include <arpa/inet.h>

#include "../include/sealant.h"

/* ─────────────────────────────────────────
   ACTION PARSING
   accepts both Sealant and iptables terms
───────────────────────────────────────── */
uint8_t parse_action(const char *s)
{
    if (!s) return ACTION_HAUL;
    /* sealant terms */
    if (strcasecmp(s, "HAUL")  == 0) return ACTION_HAUL;
    if (strcasecmp(s, "DIVE")  == 0) return ACTION_DIVE;
    if (strcasecmp(s, "BARK")  == 0) return ACTION_BARK;
    if (strcasecmp(s, "BLEAT") == 0) return ACTION_BLEAT;
    /* iptables terms */
    if (strcasecmp(s, "ACCEPT") == 0) return ACTION_HAUL;
    if (strcasecmp(s, "DROP")   == 0) return ACTION_DIVE;
    if (strcasecmp(s, "REJECT") == 0) return ACTION_BARK;
    if (strcasecmp(s, "LOG")    == 0) return ACTION_BLEAT;
    fprintf(stderr, "sealant: unknown action '%s'\n", s);
    fprintf(stderr, "sealant: valid actions: HAUL, DIVE, BARK, BLEAT\n");
    fprintf(stderr, "sealant: iptables aliases: ACCEPT, DROP, REJECT, LOG\n");
    exit(1);
}

const char *action_to_str(uint8_t action)
{
    switch (action) {
    case ACTION_HAUL:  return "HAUL";
    case ACTION_DIVE:  return "DIVE";
    case ACTION_BARK:  return "BARK";
    case ACTION_BLEAT: return "BLEAT";
    default:           return "?";
    }
}

const char *action_to_iptables_str(uint8_t action)
{
    switch (action) {
    case ACTION_HAUL:  return "ACCEPT";
    case ACTION_DIVE:  return "DROP";
    case ACTION_BARK:  return "REJECT";
    case ACTION_BLEAT: return "LOG";
    default:           return "?";
    }
}

/* ─────────────────────────────────────────
   FLOE PARSING
───────────────────────────────────────── */
uint8_t parse_floe(const char *s)
{
    if (!s) return FLOE_INPUT;
    if (strcasecmp(s, "INPUT")       == 0) return FLOE_INPUT;
    if (strcasecmp(s, "OUTPUT")      == 0) return FLOE_OUTPUT;
    if (strcasecmp(s, "FORWARD")     == 0) return FLOE_FORWARD;
    if (strcasecmp(s, "PREROUTING")  == 0) return FLOE_PREROUTING;
    if (strcasecmp(s, "POSTROUTING") == 0) return FLOE_POSTROUTING;
    fprintf(stderr, "sealant: unknown floe '%s'\n", s);
    fprintf(stderr, "sealant: valid floes: INPUT, OUTPUT, FORWARD, "
            "PREROUTING, POSTROUTING\n");
    exit(1);
}

const char *floe_to_str(uint8_t floe)
{
    switch (floe) {
    case FLOE_INPUT:       return "INPUT";
    case FLOE_OUTPUT:      return "OUTPUT";
    case FLOE_FORWARD:     return "FORWARD";
    case FLOE_PREROUTING:  return "PREROUTING";
    case FLOE_POSTROUTING: return "POSTROUTING";
    default:               return "?";
    }
}

/* ─────────────────────────────────────────
   PROTOCOL PARSING
───────────────────────────────────────── */
uint8_t parse_proto(const char *s)
{
    if (!s) return PROTO_ANY;
    if (strcasecmp(s, "tcp")    == 0) return PROTO_TCP;
    if (strcasecmp(s, "udp")    == 0) return PROTO_UDP;
    if (strcasecmp(s, "icmp")   == 0) return PROTO_ICMP;
    if (strcasecmp(s, "icmpv6") == 0) return PROTO_ICMPv6;
    if (strcasecmp(s, "any")    == 0) return PROTO_ANY;
    if (strcasecmp(s, "all")    == 0) return PROTO_ANY;
    fprintf(stderr, "sealant: unknown protocol '%s'\n", s);
    fprintf(stderr, "sealant: valid protocols: tcp, udp, icmp, icmpv6, any\n");
    exit(1);
}

const char *proto_to_str(uint8_t proto)
{
    switch (proto) {
    case PROTO_TCP:    return "tcp";
    case PROTO_UDP:    return "udp";
    case PROTO_ICMP:   return "icmp";
    case PROTO_ICMPv6: return "icmpv6";
    case PROTO_ANY:    return "any";
    default:           return "?";
    }
}

/* ─────────────────────────────────────────
   POD PARSING
───────────────────────────────────────── */
uint8_t parse_pod(const char *s)
{
    if (!s) return POD_FILTER;
    if (strcasecmp(s, "filter") == 0) return POD_FILTER;
    if (strcasecmp(s, "nat")    == 0) return POD_NAT;
    if (strcasecmp(s, "mangle") == 0) return POD_MANGLE;
    if (strcasecmp(s, "raw")    == 0) return POD_RAW;
    fprintf(stderr, "sealant: unknown pod '%s'\n", s);
    fprintf(stderr, "sealant: valid pods: filter, nat, mangle, raw\n");
    exit(1);
}

const char *pod_to_str(uint8_t pod)
{
    switch (pod) {
    case POD_FILTER: return "filter";
    case POD_NAT:    return "nat";
    case POD_MANGLE: return "mangle";
    case POD_RAW:    return "raw";
    default:         return "?";
    }
}

/* ─────────────────────────────────────────
   IP PARSING
───────────────────────────────────────── */
uint32_t parse_ip(const char *s)
{
    struct in_addr addr;
    if (!s) return 0;
    if (inet_aton(s, &addr) == 0) {
        fprintf(stderr, "sealant: invalid IP address '%s'\n", s);
        exit(1);
    }
    return ntohl(addr.s_addr);
}

uint32_t parse_mask(const char *s)
{
    int bits = atoi(s);
    if (bits == 0)  return 0x00000000;
    if (bits >= 32) return 0xFFFFFFFF;
    return ~((1u << (32 - bits)) - 1);
}

void parse_cidr(const char *cidr, uint32_t *ip, uint32_t *mask)
{
    char   buf[64];
    char  *slash;

    if (!cidr) { *ip = 0; *mask = 0; return; }

    strncpy(buf, cidr, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    slash = strchr(buf, '/');

    if (slash) {
        *slash = '\0';
        *ip    = parse_ip(buf);
        *mask  = parse_mask(slash + 1);
    } else {
        *ip   = parse_ip(buf);
        *mask = 0xFFFFFFFF;
    }
}

/* ─────────────────────────────────────────
   PORT PARSING
───────────────────────────────────────── */
void parse_port_range(const char *s, uint16_t *min, uint16_t *max)
{
    char  buf[32];
    char *colon;

    if (!s) { *min = 0; *max = 0; return; }

    strncpy(buf, s, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    colon = strchr(buf, ':');

    if (colon) {
        *colon = '\0';
        *min   = (uint16_t)atoi(buf);
        *max   = (uint16_t)atoi(colon + 1);
    } else {
        *min = (uint16_t)atoi(s);
        *max = *min;
    }
}

/* ─────────────────────────────────────────
   IPTABLES COMPATIBILITY ALIASES
   maps iptables flags to sealant flags
───────────────────────────────────────── */
const char *normalize_flag(const char *flag)
{
    /* iptables subcommand aliases */
    if (strcmp(flag, "-A") == 0) return "add";
    if (strcmp(flag, "-D") == 0) return "del";
    if (strcmp(flag, "-L") == 0) return "list";
    if (strcmp(flag, "-F") == 0) return "flush";
    if (strcmp(flag, "-P") == 0) return "policy";
    if (strcmp(flag, "-I") == 0) return "add";
    if (strcmp(flag, "-R") == 0) return "add";
    if (strcmp(flag, "-n") == 0) return "-n";
    /* already a sealant flag */
    return flag;
}

/* ─────────────────────────────────────────
   WHISKER BUILDER
   parses argc/argv into a whisker struct
   shared between cmd_add and iptables compat
───────────────────────────────────────── */

int parse_whisker(int argc, char **argv, struct sealant_whisker *w)
{
    int   i;
    char *val;

    memset(w, 0, sizeof(*w));
    w->enabled  = 1;
    w->action   = ACTION_HAUL;
    w->floe     = FLOE_INPUT;
    w->protocol = PROTO_ANY;
    w->pod      = POD_FILTER;

    for (i = 0; i < argc; i++) {

        /* floe / chain */
        if ((strcmp(argv[i], "-f") == 0 ||
             strcmp(argv[i], "--floe") == 0 ||
             strcmp(argv[i], "--chain") == 0) && i+1 < argc)
            w->floe = parse_floe(argv[++i]);

        /* protocol */
        else if ((strcmp(argv[i], "-p") == 0 ||
                  strcmp(argv[i], "--protocol") == 0) && i+1 < argc)
            w->protocol = parse_proto(argv[++i]);

        /* action / target */
        else if ((strcmp(argv[i], "-j") == 0 ||
                  strcmp(argv[i], "--jump") == 0 ||
                  strcmp(argv[i], "--action") == 0) && i+1 < argc)
            w->action = parse_action(argv[++i]);

        /* source IP */
        else if ((strcmp(argv[i], "-s") == 0 ||
                  strcmp(argv[i], "--source") == 0 ||
                  strcmp(argv[i], "--src") == 0) && i+1 < argc)
            parse_cidr(argv[++i], &w->src_ip, &w->src_mask);

        /* destination IP */
        else if ((strcmp(argv[i], "-d") == 0 ||
                  strcmp(argv[i], "--destination") == 0 ||
                  strcmp(argv[i], "--dst") == 0) && i+1 < argc)
            parse_cidr(argv[++i], &w->dst_ip, &w->dst_mask);

        /* destination port */
        else if ((strcmp(argv[i], "--dport") == 0 ||
                  strcmp(argv[i], "--destination-port") == 0) && i+1 < argc) {
            val = argv[++i];
            parse_port_range(val, &w->dst_port_min, &w->dst_port_max);
        }

        /* source port */
        else if ((strcmp(argv[i], "--sport") == 0 ||
                  strcmp(argv[i], "--source-port") == 0) && i+1 < argc) {
            val = argv[++i];
            parse_port_range(val, &w->src_port_min, &w->src_port_max);
        }

        /* input interface */
        else if ((strcmp(argv[i], "-i") == 0 ||
                strcmp(argv[i], "--in-interface") == 0) && i+1 < argc) {
            val = argv[++i];
            if (val[0] == '!') {
                w->negate_iface_in = 1;
                val++;
                if (val[0] == '\0' && i+1 < argc)
                    val = argv[++i];
            }
            strncpy(w->iface_in, val, SEALANT_IFACE_LEN - 1);
        }

        /* output interface */
        else if ((strcmp(argv[i], "-o") == 0 ||
                strcmp(argv[i], "--out-interface") == 0) && i+1 < argc) {
            val = argv[++i];
            if (val[0] == '!') {
                w->negate_iface_out = 1;
                val++;
                if (val[0] == '\0' && i+1 < argc)
                    val = argv[++i];
            }
            strncpy(w->iface_out, val, SEALANT_IFACE_LEN - 1);
        }

        /* rule name */
        else if ((strcmp(argv[i], "-n") == 0 ||
                  strcmp(argv[i], "--name") == 0) && i+1 < argc)
            strncpy(w->name, argv[++i], SEALANT_NAME_LEN - 1);

        /* pod / table */
        else if ((strcmp(argv[i], "-t") == 0 ||
                  strcmp(argv[i], "--table") == 0 ||
                  strcmp(argv[i], "--pod") == 0) && i+1 < argc)
            w->pod = parse_pod(argv[++i]);

        /* rate limiting */
        else if (strcmp(argv[i], "--rate") == 0 && i+1 < argc)
            w->rate_limit = (uint32_t)atoi(argv[++i]);

        else if (strcmp(argv[i], "--burst") == 0 && i+1 < argc)
            w->rate_burst = (uint32_t)atoi(argv[++i]);

        /* connection state */
        else if (strcmp(argv[i], "--state") == 0 && i+1 < argc) {
            char  tmp[64];
            char *tok;
            strncpy(tmp, argv[++i], sizeof(tmp) - 1);
            tok = strtok(tmp, ",");
            while (tok) {
                if (strcasecmp(tok, "NEW") == 0)
                    w->molt_mask |= MOLT_NEW;
                else if (strcasecmp(tok, "ESTABLISHED") == 0)
                    w->molt_mask |= MOLT_ESTABLISHED;
                else if (strcasecmp(tok, "RELATED") == 0)
                    w->molt_mask |= MOLT_RELATED;
                else if (strcasecmp(tok, "INVALID") == 0)
                    w->molt_mask |= MOLT_INVALID;
                tok = strtok(NULL, ",");
            }
        }

        /* IPv6 flag */
        else if (strcmp(argv[i], "--ipv6") == 0 ||
                 strcmp(argv[i], "-6") == 0)
            w->ipv6 = 1;

        /* IPv4 only */
        else if (strcmp(argv[i], "--ipv4") == 0 ||
                 strcmp(argv[i], "-4") == 0)
            w->ipv4_only = 1;

        /* log prefix */
        else if (strcmp(argv[i], "--log-prefix") == 0 && i+1 < argc)
            strncpy(w->log_prefix, argv[++i], SEALANT_LOG_PREFIX_LEN - 1);

        /* NAT type */
        else if (strcmp(argv[i], "--snat") == 0)
            w->nat_type = NAT_SNAT;
        else if (strcmp(argv[i], "--dnat") == 0)
            w->nat_type = NAT_DNAT;
        else if (strcmp(argv[i], "--masquerade") == 0)
            w->nat_type = NAT_MASQUERADE;

        /* NAT target IP */
        else if (strcmp(argv[i], "--to-destination") == 0 && i+1 < argc) {
            char      tmp[64];
            char     *colon;
            struct in_addr addr;
            strncpy(tmp, argv[++i], sizeof(tmp) - 1);
            colon = strchr(tmp, ':');
            if (colon) {
                *colon      = '\0';
                w->nat_port = (uint16_t)atoi(colon + 1);
            }
            if (inet_aton(tmp, &addr))
                w->nat_ip = ntohl(addr.s_addr);
        }

        else if (strcmp(argv[i], "--to-source") == 0 && i+1 < argc) {
            char      tmp[64];
            char     *colon;
            struct in_addr addr;
            strncpy(tmp, argv[++i], sizeof(tmp) - 1);
            colon = strchr(tmp, ':');
            if (colon) {
                *colon      = '\0';
                w->nat_port = (uint16_t)atoi(colon + 1);
            }
            if (inet_aton(tmp, &addr))
                w->nat_ip = ntohl(addr.s_addr);
        }
    }

    /* warn on overly broad HAUL rules */
    if (w->action == ACTION_HAUL &&
        w->src_ip == 0 &&
        w->dst_ip == 0 &&
        w->dst_port_min == 0 &&
        w->dst_port_max == 0 &&
        w->iface_in[0] == '\0' &&
        w->iface_out[0] == '\0' &&
        w->protocol == PROTO_ANY &&
        w->molt_mask == 0) {
        fprintf(stderr, "sealant: warning — broad HAUL rule will "
                "match all traffic on %s\n",
                floe_to_str(w->floe));
    }

    return 0;
}

/* ─────────────────────────────────────────
   WHISKER DISPLAY
   prints a whisker as a formatted row
   with both Sealant and iptables terms
───────────────────────────────────────── */
void print_whisker_row(struct sealant_whisker *w)
{
    char action_buf[32];
    char src_buf[32]  = "-";
    char dst_buf[32]  = "-";
    char port_buf[32] = "-";
    char iface_buf[34] = "-";

    if (w->iface_in[0] && w->iface_out[0])
        snprintf(iface_buf, sizeof(iface_buf), "%s%s/%s%s",
                 w->negate_iface_in  ? "!" : "", w->iface_in,
                 w->negate_iface_out ? "!" : "", w->iface_out);
    else if (w->iface_in[0])
        snprintf(iface_buf, sizeof(iface_buf), "in:%s%s",
                 w->negate_iface_in ? "!" : "", w->iface_in);
    else if (w->iface_out[0])
        snprintf(iface_buf, sizeof(iface_buf), "out:%s%s",
                 w->negate_iface_out ? "!" : "", w->iface_out);

    /* build action string with iptables alias */
    snprintf(action_buf, sizeof(action_buf), "%s (%s)",
             action_to_str(w->action),
             action_to_iptables_str(w->action));

    /* format src IP */
    if (w->src_ip) {
        struct in_addr a = { .s_addr = htonl(w->src_ip) };
        snprintf(src_buf, sizeof(src_buf), "%s", inet_ntoa(a));
    }

    /* format dst IP */
    if (w->dst_ip) {
        struct in_addr a = { .s_addr = htonl(w->dst_ip) };
        snprintf(dst_buf, sizeof(dst_buf), "%s", inet_ntoa(a));
    }

    /* format port */
    if (w->dst_port_min) {
        if (w->dst_port_min == w->dst_port_max)
            snprintf(port_buf, sizeof(port_buf), "%u", w->dst_port_min);
        else
            snprintf(port_buf, sizeof(port_buf), "%u:%u",
                     w->dst_port_min, w->dst_port_max);
    }

    printf("%-4u %-24s %-12s %-20s %-8s %-16s %-16s %-16s %-8s %-10lu %-10lu\n",
           w->id,
           w->name[0] ? w->name : "(unnamed)",
           floe_to_str(w->floe),
           action_buf,
           proto_to_str(w->protocol),
           src_buf,
           dst_buf,
           iface_buf,
           port_buf,
           w->hit_count,
           w->byte_count);
}

void print_whisker_header(void)
{
    printf("%-4s %-24s %-12s %-20s %-8s %-16s %-16s %-16s %-8s %-10s %-10s\n",
           "ID", "NAME", "FLOE", "ACTION", "PROTO",
           "SRC", "DST", "IFACE", "PORT", "HITS", "BYTES");
    printf("%-4s %-24s %-12s %-20s %-8s %-16s %-16s %-16s %-8s %-10s %-10s\n",
           "──", "────────────────────────", "────────────",
           "────────────────────", "────────",
           "────────────────", "────────────────",
           "────────────────", "────────",
           "──────────", "──────────");
}
