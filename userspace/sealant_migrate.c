#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <errno.h>

#include "../include/sealant.h"

/* ─────────────────────────────────────────
   MIGRATION CONTEXT
───────────────────────────────────────── */

#define MIGRATE_MAX_RULES   4096
#define MIGRATE_LINE_MAX    1024

struct migrate_rule {
    struct sealant_whisker  w;
    int                     valid;
};

static struct migrate_rule  migrated[MIGRATE_MAX_RULES];
static uint32_t             migrated_count  = 0;
static int                  dry_run         = 1;
static int                  verbose         = 0;
static int                  ipv6_mode       = 0;

static uint8_t              current_pod     = POD_FILTER;

/* ─────────────────────────────────────────
   TRANSLATION HELPERS
───────────────────────────────────────── */

static uint8_t translate_target(const char *t)
{
    if (!t) return ACTION_HAUL;
    if (strcasecmp(t, "ACCEPT") == 0) return ACTION_HAUL;
    if (strcasecmp(t, "DROP")   == 0) return ACTION_DIVE;
    if (strcasecmp(t, "REJECT") == 0) return ACTION_BARK;
    if (strcasecmp(t, "LOG")    == 0) return ACTION_BLEAT;
    if (strcasecmp(t, "MASQUERADE") == 0) return ACTION_HAUL;
    fprintf(stderr, "sealant-migrate: unknown target '%s', defaulting to HAUL\n", t);
    return ACTION_HAUL;
}

static uint8_t translate_chain(const char *c)
{
    if (!c) return FLOE_INPUT;
    if (strcasecmp(c, "INPUT")       == 0) return FLOE_INPUT;
    if (strcasecmp(c, "OUTPUT")      == 0) return FLOE_OUTPUT;
    if (strcasecmp(c, "FORWARD")     == 0) return FLOE_FORWARD;
    if (strcasecmp(c, "PREROUTING")  == 0) return FLOE_PREROUTING;
    if (strcasecmp(c, "POSTROUTING") == 0) return FLOE_POSTROUTING;
    return FLOE_INPUT;
}

static uint8_t translate_proto(const char *p)
{
    if (!p) return PROTO_ANY;
    if (strcasecmp(p, "tcp")  == 0) return PROTO_TCP;
    if (strcasecmp(p, "udp")  == 0) return PROTO_UDP;
    if (strcasecmp(p, "icmp") == 0) return PROTO_ICMP;
    if (strcasecmp(p, "icmpv6") == 0) return PROTO_ICMPv6;
    if (strcasecmp(p, "all")  == 0) return PROTO_ANY;
    return PROTO_ANY;
}

static uint8_t translate_table(const char *t)
{
    if (!t) return POD_FILTER;
    if (strcasecmp(t, "filter") == 0) return POD_FILTER;
    if (strcasecmp(t, "nat")    == 0) return POD_NAT;
    if (strcasecmp(t, "mangle") == 0) return POD_MANGLE;
    if (strcasecmp(t, "raw")    == 0) return POD_RAW;
    return POD_FILTER;
}

static void parse_cidr(const char *cidr, uint32_t *ip, uint32_t *mask)
{
    char    buf[64];
    char    *slash;
    struct in_addr addr;
    int     bits;

    strncpy(buf, cidr, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    slash = strchr(buf, '/');

    if (slash) {
        *slash  = '\0';
        bits    = atoi(slash + 1);
    } else {
        bits = 32;
    }

    if (inet_aton(buf, &addr) == 0) {
        *ip = 0;
        *mask = 0;
        return;
    }

    *ip     = ntohl(addr.s_addr);
    *mask   = bits == 0 ? 0 : (bits == 32 ? 0xFFFFFFFF : ~((1u << (32 - bits)) - 1));
}

static void parse_port_range(const char *s, uint16_t *min, uint16_t *max)
{
    char    buf[32];
    char    *colon;

    strncpy(buf, s, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    colon = strchr(buf, ':');

    if (colon) {
        *colon  = '\0';
        *min    = (uint16_t)atoi(buf);
        *max    = (uint16_t)atoi(colon + 1);
    } else {
        *min = (uint16_t)atoi(buf);
        *max = *min;
    }
}

/* ─────────────────────────────────────────
   RULE PARSER
   parses one iptables-save rule line
   into a sealant_whisker
───────────────────────────────────────── */

static int parse_rule(const char *line, struct sealant_whisker *w)
{
    char   buf[MIGRATE_LINE_MAX];
    char  *tokens[128];
    int    ntok = 0;
    char  *p;
    int    i;
    int    negate = 0;

    strncpy(buf, line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    /* tokenize */
    p = strtok(buf, " \t\n");
    while (p && ntok < 127) {
        tokens[ntok++] = p;
        p = strtok(NULL, " \t\n");
    }
    tokens[ntok] = NULL;

    if (ntok < 2) return 0;

    /* must start with -A */
    if (strcmp(tokens[0], "-A") != 0) return 0;

    memset(w, 0, sizeof(*w));
    w->enabled  = 1;
    w->pod      = current_pod;
    w->floe     = translate_chain(tokens[1]);
    w->action   = ACTION_HAUL;
    w->protocol = PROTO_ANY;
    w->ipv6     = ipv6_mode;

    for (i = 2; i < ntok; i++) {

        /* negation flag */
        if (strcmp(tokens[i], "!") == 0) {
            negate = 1;
            continue;
        }

        /* protocol */
        if ((strcmp(tokens[i], "-p") == 0 ||
             strcmp(tokens[i], "--protocol") == 0) && i+1 < ntok) {
            w->protocol = translate_proto(tokens[++i]);
            negate = 0;
            continue;
        }

        /* source IP */
        if ((strcmp(tokens[i], "-s") == 0 ||
             strcmp(tokens[i], "--source") == 0) && i+1 < ntok) {
            if (!negate)
                parse_cidr(tokens[++i], &w->src_ip, &w->src_mask);
            else
                i++; /* skip negated — not supported in V1 */
            negate = 0;
            continue;
        }

        /* destination IP */
        if ((strcmp(tokens[i], "-d") == 0 ||
             strcmp(tokens[i], "--destination") == 0) && i+1 < ntok) {
            if (!negate)
                parse_cidr(tokens[++i], &w->dst_ip, &w->dst_mask);
            else
                i++;
            negate = 0;
            continue;
        }

        /* destination port */
        if ((strcmp(tokens[i], "--dport") == 0 ||
             strcmp(tokens[i], "--destination-port") == 0) && i+1 < ntok) {
            parse_port_range(tokens[++i],
                             &w->dst_port_min, &w->dst_port_max);
            negate = 0;
            continue;
        }

        /* source port */
        if ((strcmp(tokens[i], "--sport") == 0 ||
             strcmp(tokens[i], "--source-port") == 0) && i+1 < ntok) {
            parse_port_range(tokens[++i],
                             &w->src_port_min, &w->src_port_max);
            negate = 0;
            continue;
        }

        /* multiport --dports */
        if (strcmp(tokens[i], "--dports") == 0 && i+1 < ntok) {
            /* take first port of multiport for V1 */
            char  tmp[64];
            char *comma;
            strncpy(tmp, tokens[++i], sizeof(tmp) - 1);
            comma = strchr(tmp, ',');
            if (comma) *comma = '\0';
            parse_port_range(tmp, &w->dst_port_min, &w->dst_port_max);
            if (verbose)
                fprintf(stderr, "sealant-migrate: multiport partially "
                        "supported, took first port\n");
            negate = 0;
            continue;
        }

        /* input interface */
        if ((strcmp(tokens[i], "-i") == 0 ||
             strcmp(tokens[i], "--in-interface") == 0) && i+1 < ntok) {
            strncpy(w->iface_in, tokens[++i], SEALANT_IFACE_LEN - 1);
            negate = 0;
            continue;
        }

        /* output interface */
        if ((strcmp(tokens[i], "-o") == 0 ||
             strcmp(tokens[i], "--out-interface") == 0) && i+1 < ntok) {
            strncpy(w->iface_out, tokens[++i], SEALANT_IFACE_LEN - 1);
            negate = 0;
            continue;
        }

        /* connection state */
        if (strcmp(tokens[i], "--state") == 0 ||
            strcmp(tokens[i], "--ctstate") == 0) {
            if (i+1 < ntok) {
                char  tmp[64];
                char *state_tok;
                strncpy(tmp, tokens[++i], sizeof(tmp) - 1);
                state_tok = strtok(tmp, ",");
                while (state_tok) {
                    if (strcasecmp(state_tok, "NEW") == 0)
                        w->molt_mask |= MOLT_NEW;
                    else if (strcasecmp(state_tok, "ESTABLISHED") == 0)
                        w->molt_mask |= MOLT_ESTABLISHED;
                    else if (strcasecmp(state_tok, "RELATED") == 0)
                        w->molt_mask |= MOLT_RELATED;
                    else if (strcasecmp(state_tok, "INVALID") == 0)
                        w->molt_mask |= MOLT_INVALID;
                    state_tok = strtok(NULL, ",");
                }
            }
            negate = 0;
            continue;
        }

        /* target / action */
        if (strcmp(tokens[i], "-j") == 0 && i+1 < ntok) {
            char *target = tokens[++i];
            w->action = translate_target(target);

            /* NAT targets */
            if (strcasecmp(target, "MASQUERADE") == 0) {
                w->nat_type = NAT_MASQUERADE;
                w->action   = ACTION_HAUL;
            } else if (strcasecmp(target, "SNAT") == 0) {
                w->nat_type = NAT_SNAT;
                w->action   = ACTION_HAUL;
            } else if (strcasecmp(target, "DNAT") == 0) {
                w->nat_type = NAT_DNAT;
                w->action   = ACTION_HAUL;
            }
            negate = 0;
            continue;
        }

        /* DNAT --to-destination */
        if (strcmp(tokens[i], "--to-destination") == 0 && i+1 < ntok) {
            char      tmp[64];
            char     *colon;
            struct in_addr addr;
            strncpy(tmp, tokens[++i], sizeof(tmp) - 1);
            colon = strchr(tmp, ':');
            if (colon) {
                *colon     = '\0';
                w->nat_port = (uint16_t)atoi(colon + 1);
            }
            if (inet_aton(tmp, &addr))
                w->nat_ip = ntohl(addr.s_addr);
            negate = 0;
            continue;
        }

        /* SNAT --to-source */
        if (strcmp(tokens[i], "--to-source") == 0 && i+1 < ntok) {
            char      tmp[64];
            char     *colon;
            struct in_addr addr;
            strncpy(tmp, tokens[++i], sizeof(tmp) - 1);
            colon = strchr(tmp, ':');
            if (colon) {
                *colon     = '\0';
                w->nat_port = (uint16_t)atoi(colon + 1);
            }
            if (inet_aton(tmp, &addr))
                w->nat_ip = ntohl(addr.s_addr);
            negate = 0;
            continue;
        }

        /* rate limiting */
        if (strcmp(tokens[i], "--limit") == 0 && i+1 < ntok) {
            char  tmp[32];
            char *slash;
            strncpy(tmp, tokens[++i], sizeof(tmp) - 1);
            slash = strchr(tmp, '/');
            if (slash) *slash = '\0';
            w->rate_limit = (uint32_t)atoi(tmp);
            negate = 0;
            continue;
        }

        if (strcmp(tokens[i], "--limit-burst") == 0 && i+1 < ntok) {
            w->rate_burst = (uint32_t)atoi(tokens[++i]);
            negate = 0;
            continue;
        }

        /* log prefix */
        if (strcmp(tokens[i], "--log-prefix") == 0 && i+1 < ntok) {
            char *prefix = tokens[++i];
            /* strip surrounding quotes if present */
            if (prefix[0] == '"') {
                prefix++;
                char *end = strchr(prefix, '"');
                if (end) *end = '\0';
            }
            strncpy(w->log_prefix, prefix, SEALANT_LOG_PREFIX_LEN - 1);
            negate = 0;
            continue;
        }

        /* skip unknown flags silently */
        if (tokens[i][0] == '-') {
            if (verbose)
                fprintf(stderr, "sealant-migrate: skipping unknown flag '%s'\n",
                        tokens[i]);
        }

        negate = 0;
    }

    return 1;
}

/* ─────────────────────────────────────────
   PRINT AS SEALANT COMMAND
   shows what would be run
───────────────────────────────────────── */

static int mask_to_prefix(uint32_t mask)
{
    int bits = 0;
    while (mask & 0x80000000) { bits++; mask <<= 1; }
    return bits;
}

static void print_as_command(struct sealant_whisker *w, uint32_t idx)
{
    char src_buf[32] = {0};
    char dst_buf[32] = {0};

    const char *floe_str[] = {
        "INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"
    };
    const char *action_str[] = {
        "HAUL", "DIVE", "BARK", "BLEAT"
    };

    if (w->src_ip) {
            struct in_addr a = { .s_addr = htonl(w->src_ip) };
            snprintf(src_buf, sizeof(src_buf), " -s %s/%d",
                     inet_ntoa(a),
                     mask_to_prefix(w->src_mask));
    }
    if (w->dst_ip) {
            struct in_addr a = { .s_addr = htonl(w->dst_ip) };
            snprintf(dst_buf, sizeof(dst_buf), " -d %s/%d",
                     inet_ntoa(a),
                     mask_to_prefix(w->dst_mask));
    }

    printf("sealant add -f %s",
        w->floe < FLOE_MAX ? floe_str[w->floe] : "INPUT");

    if (w->protocol != PROTO_ANY) {
        uint8_t p = w->protocol;
        if (p == PROTO_TCP)     printf(" -p tcp");
        else if (p == PROTO_UDP) printf(" -p udp");
        else if (p == PROTO_ICMP) printf(" -p icmp");
        else                    printf(" -p %u", p);
    }

    if (src_buf[0]) printf("%s", src_buf);
    if (dst_buf[0]) printf("%s", dst_buf);

    if (w->dst_port_min) {
        if (w->dst_port_min == w->dst_port_max)
            printf(" --dport %u", w->dst_port_min);
        else
            printf(" --dport %u:%u", w->dst_port_min, w->dst_port_max);
    }

    if (w->src_port_min) {
        if (w->src_port_min == w->src_port_max)
            printf(" --sport %u", w->src_port_min);
        else
            printf(" --sport %u:%u", w->src_port_min, w->src_port_max);
    }

    if (w->iface_in[0])
        printf(" -i %s", w->iface_in);
    if (w->iface_out[0])
        printf(" -o %s", w->iface_out);

    if (w->molt_mask) {
        printf(" --state ");
        int first = 1;
        if (w->molt_mask & MOLT_NEW)         { printf("NEW");         first = 0; }
        if (w->molt_mask & MOLT_ESTABLISHED) { printf("%sESTABLISHED", first ? "" : ","); first = 0; }
        if (w->molt_mask & MOLT_RELATED)     { printf("%sRELATED",     first ? "" : ","); first = 0; }
        if (w->molt_mask & MOLT_INVALID)     { printf("%sINVALID",     first ? "" : ","); }
    }

    if (w->rate_limit)
        printf(" --rate %u --burst %u",
               w->rate_limit,
               w->rate_burst ? w->rate_burst : w->rate_limit);

    printf(" -j %s", w->action < ACTION_MAX ? action_str[w->action] : "HAUL");

    printf(" -n \"migrated_%u\"", idx);
    printf("\n");
}

/* ─────────────────────────────────────────
   APPLY VIA IOCTL
───────────────────────────────────────── */
static int apply_rules(void)
{
    int      fd;
    uint32_t i;
    uint32_t applied = 0;
    uint32_t failed  = 0;

    fd = open("/dev/sealant", O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "sealant-migrate: cannot open /dev/sealant: %s\n",
                strerror(errno));
        fprintf(stderr, "sealant-migrate: is the kernel module loaded?\n");
        return 1;
    }

    for (i = 0; i < migrated_count; i++) {
        if (!migrated[i].valid) continue;
        if (ioctl(fd, SEALANT_IOC_ADD_WHISKER, &migrated[i].w) < 0) {
            fprintf(stderr, "sealant-migrate: failed to apply rule %u: %s\n",
                    i, strerror(errno));
            failed++;
        } else {
            applied++;
        }
    }

    close(fd);
    printf("sealant-migrate: applied %u rules (%u failed)\n",
           applied, failed);
    return failed > 0 ? 1 : 0;
}

/* ─────────────────────────────────────────
   PROCESS IPTABLES-SAVE OUTPUT
───────────────────────────────────────── */
static void process_stream(FILE *f)
{
    char line[MIGRATE_LINE_MAX];

    while (fgets(line, sizeof(line), f)) {
        /* strip newline */
        line[strcspn(line, "\n")] = '\0';

        /* skip empty lines and comments */
        if (line[0] == '\0' || line[0] == '#')
            continue;

        /* table header — *filter, *nat, *mangle, *raw */
        if (line[0] == '*') {
            current_pod = translate_table(line + 1);
            if (verbose)
                printf("# table: %s\n", line + 1);
            continue;
        }

        /* chain policy — :INPUT ACCEPT [0:0] */
        if (line[0] == ':') {
            if (verbose)
                printf("# policy: %s\n", line + 1);
            continue;
        }

        /* COMMIT line */
        if (strncmp(line, "COMMIT", 6) == 0)
            continue;

        /* rule line */
        if (line[0] == '-' && line[1] == 'A') {
            if (migrated_count >= MIGRATE_MAX_RULES) {
                fprintf(stderr, "sealant-migrate: max rules reached\n");
                break;
            }

            struct sealant_whisker w;
            if (parse_rule(line, &w)) {
                snprintf(w.name, SEALANT_NAME_LEN, "migrated_%u", migrated_count);
                migrated[migrated_count].w     = w;
                migrated[migrated_count].valid = 1;
                migrated_count++;
            }
        }
    }
}

/* ─────────────────────────────────────────
   MAIN
───────────────────────────────────────── */
int cmd_migrate(int argc, char **argv)
{
    int     do_ipv6  = 0;
    int     from_file = 0;
    char   *input_file = NULL;
    int     i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--apply") == 0)
            dry_run = 0;
        else if (strcmp(argv[i], "--ipv6") == 0)
            do_ipv6 = 1;
        else if (strcmp(argv[i], "--verbose") == 0)
            verbose = 1;
        else if (strcmp(argv[i], "--file") == 0 && i+1 < argc) {
            input_file = argv[++i];
            from_file  = 1;
        }
    }

    printf("sealant-migrate v%s\n", SEALANT_VERSION);
    if (dry_run)
        printf("# DRY RUN — pass --apply to load rules into Sealant\n\n");

    /* ── IPv4 ── */
    ipv6_mode   = 0;
    current_pod = POD_FILTER;

    if (from_file && input_file) {
        FILE *f = fopen(input_file, "r");
        if (!f) {
            fprintf(stderr, "sealant-migrate: cannot open '%s': %s\n",
                    input_file, strerror(errno));
            return 1;
        }
        process_stream(f);
        fclose(f);
    } else {
        FILE *f = popen("iptables-save 2>/dev/null", "r");
        if (f) {
            process_stream(f);
            pclose(f);
        } else {
            fprintf(stderr, "sealant-migrate: iptables-save failed\n");
        }
    }

    /* ── IPv6 ── */
    if (do_ipv6) {
        ipv6_mode   = 1;
        current_pod = POD_FILTER;
        FILE *f = popen("ip6tables-save 2>/dev/null", "r");
        if (f) {
            process_stream(f);
            pclose(f);
        }
    }

    /* output or apply */
    if (dry_run) {
        uint32_t j;
        printf("# %u rules found\n\n", migrated_count);
        for (j = 0; j < migrated_count; j++) {
            if (migrated[j].valid)
                print_as_command(&migrated[j].w, j);
        }
        printf("\n# run with --apply to load these rules into Sealant\n");
        return 0;
    }

    return apply_rules();
}
