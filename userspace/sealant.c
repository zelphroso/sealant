#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include "../include/sealant.h"

int cmd_migrate(int argc, char **argv);

uint8_t     parse_action(const char *s);
uint8_t     parse_floe(const char *s);
uint8_t     parse_proto(const char *s);
uint8_t     parse_pod(const char *s);
uint32_t    parse_ip(const char *s);
void        parse_cidr(const char *cidr, uint32_t *ip, uint32_t *mask);
void        parse_port_range(const char *s, uint16_t *min, uint16_t *max);
int         parse_whisker(int argc, char **argv, struct sealant_whisker *w);
void        print_whisker_row(struct sealant_whisker *w);
void        print_whisker_header(void);

/* ─────────────────────────────────────────
   DEVICE PATH
───────────────────────────────────────── */

#define SEALANT_DEV "/dev/sealant"

/* ─────────────────────────────────────────
   USAGE
───────────────────────────────────────── */

static void usage(void)
{
    printf("sealant v%s\n\n", SEALANT_VERSION);
    printf("usage:\n");
    printf("  sealant add     -f <floe> -p <proto> --dport <port> -j <action>\n");
    printf("  sealant del     -i <id>\n");
    printf("  sealant list\n");
    printf("  sealant flush   -f <floe>\n");
    printf("  sealant policy  -f <floe> -j <action>\n");
    printf("  sealant reload\n");
    printf("  sealant save\n");
    printf("  sealant load\n");
    printf("  sealant status\n");
    printf("  sealant log\n");
    printf("  sealant flush-log\n");
    printf("  sealant migrate [--apply] [--ipv6] [--file <path>]\n");
    printf("  sealant watch   (v1.1)\n");
    printf("\nfloes:   INPUT, OUTPUT, FORWARD, PREROUTING, POSTROUTING\n");
    printf("actions: HAUL (ACCEPT), DIVE (DROP), BARK (REJECT), BLEAT (LOG)\n");
    printf("protos:  tcp, udp, icmp, icmpv6, any\n");
}

/* ─────────────────────────────────────────
   SUBCOMMANDS
───────────────────────────────────────── */

/* sealant add */
static int cmd_add(int argc, char **argv)
{
    struct sealant_whisker w;

    if (parse_whisker(argc, argv, &w) != 0)
        return 1;

    if (sealant_comm_add(&w) < 0)
        return 1;

    printf("sealant: whisker added\n");
    return 0;
}

/* sealant del */
static int cmd_del(int argc, char **argv)
{
    uint32_t id = 0;
    int      i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i+1 < argc)
            id = (uint32_t)atoi(argv[++i]);
    }

    if (sealant_comm_del(id) < 0)
        return 1;

    printf("sealant: whisker %u deleted\n", id);
    return 0;
}

static int cmd_list(int show_all)
{
    FILE *f;
    char  line[512];

    f = fopen("/proc/sealant/observe", "r");
    if (!f) {
        fprintf(stderr, "sealant: cannot read /proc/sealant/observe\n");
        fprintf(stderr, "sealant: is the kernel module loaded?\n");
        return 1;
    }

    print_whisker_header();

    /* skip kernel proc header */
    fgets(line, sizeof(line), f);

    while (fgets(line, sizeof(line), f)) {
        if (strlen(line) < 10) continue;

        char id_s[8], name_s[33], floe_s[8], action_s[8],
             proto_s[8], iface_in_s[17], iface_out_s[17],
             hits_s[12], bytes_s[12], ipv6_s[4];
        uint32_t dport_min, dport_max;

        if (sscanf(line, "%7s %32s %7s %7s %7s %16s %16s %6u %6u %11s %11s %3s",
                id_s, name_s, floe_s, action_s, proto_s,
                iface_in_s, iface_out_s,
                &dport_min, &dport_max,
                hits_s, bytes_s, ipv6_s) < 11)
            continue;

        if (atoi(id_s) == 0 && id_s[0] != '0') continue;

        uint8_t ipv6 = (uint8_t)atoi(ipv6_s);

        /* skip IPv6 mirrors unless --all */
        if (ipv6 && !show_all) continue;

        struct sealant_whisker w;
        memset(&w, 0, sizeof(w));
        w.id       = (uint32_t)atoi(id_s);
        w.floe     = (uint8_t)atoi(floe_s);
        w.action   = (uint8_t)atoi(action_s);
        w.protocol = (uint8_t)atoi(proto_s);
        w.hit_count  = (uint64_t)atol(hits_s);
        w.byte_count = (uint64_t)atol(bytes_s);
        w.ipv6       = ipv6;

        strncpy(w.name,
                strcmp(name_s, "(unnamed)") == 0 ? "" : name_s,
                SEALANT_NAME_LEN - 1);
        strncpy(w.iface_in,
                strcmp(iface_in_s, "-") == 0 ? "" : iface_in_s,
                SEALANT_IFACE_LEN - 1);
        strncpy(w.iface_out,
                strcmp(iface_out_s, "-") == 0 ? "" : iface_out_s,
                SEALANT_IFACE_LEN - 1);

        w.dst_port_min = (uint16_t)dport_min;
        w.dst_port_max = (uint16_t)dport_max;

        print_whisker_row(&w);
    }

    fclose(f);
    return 0;
}

static int cmd_flush(int argc, char **argv)
{
    int i;
    int got_floe = 0;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0 && i+1 < argc) {
            i++;
            got_floe = 1;

            /* flush ALL floes */
            if (strcasecmp(argv[i], "ALL") == 0) {
                sealant_comm_flush(FLOE_INPUT);
                sealant_comm_flush(FLOE_OUTPUT);
                sealant_comm_flush(FLOE_FORWARD);
                sealant_comm_flush(FLOE_PREROUTING);
                sealant_comm_flush(FLOE_POSTROUTING);
                printf("sealant: all floes flushed\n");
                return 0;
            }

            uint8_t floe = parse_floe(argv[i]);
            if (sealant_comm_flush(floe) < 0)
                return 1;
            printf("sealant: floe flushed\n");
            return 0;
        }
    }

    if (!got_floe) {
        fprintf(stderr, "sealant: flush requires -f <floe>\n");
        fprintf(stderr, "sealant: example: sealant flush -f INPUT\n");
        fprintf(stderr, "sealant: use -f ALL to flush everything\n");
        return 1;
    }

    return 0;
}

/* sealant policy */
static int cmd_policy(int argc, char **argv)
{
    uint8_t floe   = FLOE_INPUT;
    uint8_t action = ACTION_HAUL;
    int     i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0 && i+1 < argc)
            floe = parse_floe(argv[++i]);
        else if (strcmp(argv[i], "-j") == 0 && i+1 < argc)
            action = parse_action(argv[++i]);
    }

    if (sealant_comm_set_policy(floe, action) < 0)
        return 1;

    printf("sealant: policy set\n");
    return 0;
}

/* sealant reload */
static int cmd_reload(void)
{
    if (sealant_comm_reload() < 0)
        return 1;

    printf("sealant: hot reload triggered\n");
    return 0;
}

static int cmd_save(void)
{
    return sealant_comm_save();
}

static int cmd_load(void)
{
    return sealant_comm_load();
}

static int cmd_flush_log(void)
{
    return sealant_comm_flush_log();
}

static int cmd_status(void)
{
    struct sealant_stats s;

    if (sealant_comm_get_stats(&s) < 0)
        return 1;

    printf("sealant v%s\n\n", s.version);
    printf("  whiskers  : %u\n", s.whisker_count);
    printf("  pups      : %u\n", s.pup_count);
    printf("  log       : %u entries\n", s.log_entries);
    if (s.log_dropped > 0)
        printf("  dropped   : %u log entries\n", s.log_dropped);
    return 0;
}

static int cmd_log(void)
{
    FILE *f;
    char  line[512];

    f = fopen("/proc/sealant/log", "r");
    if (!f) {
        fprintf(stderr, "sealant: cannot read /proc/sealant/log\n");
        fprintf(stderr, "sealant: is the kernel module loaded?\n");
        return 1;
    }

    while (fgets(line, sizeof(line), f))
        printf("%s", line);

    fclose(f);
    return 0;
}

/* ─────────────────────────────────────────
   MAIN — subcommand dispatch
───────────────────────────────────────── */
int main(int argc, char **argv)
{
    if (argc < 2) {
        usage();
        return 0;
    }
    /* iptables compat aliases */
    if (strcmp(argv[1], "-A") == 0)      argv[1] = "add";
    else if (strcmp(argv[1], "-D") == 0) argv[1] = "del";
    else if (strcmp(argv[1], "-L") == 0) argv[1] = "list";
    else if (strcmp(argv[1], "-F") == 0) argv[1] = "flush";
    else if (strcmp(argv[1], "-P") == 0) argv[1] = "policy";
    else if (strcmp(argv[1], "-I") == 0) argv[1] = "add";

    if (strcmp(argv[1], "add") == 0)
        return cmd_add(argc - 2, argv + 2);
    else if (strcmp(argv[1], "del") == 0)
        return cmd_del(argc - 2, argv + 2);
    else if (strcmp(argv[1], "list") == 0) {
        int show_all = (argc > 2 && strcmp(argv[2], "--all") == 0);
        return cmd_list(show_all);
    }
    else if (strcmp(argv[1], "flush") == 0)
        return cmd_flush(argc - 2, argv + 2);
    else if (strcmp(argv[1], "policy") == 0)
        return cmd_policy(argc - 2, argv + 2);
    else if (strcmp(argv[1], "reload") == 0)
        return cmd_reload();
    else if (strcmp(argv[1], "save") == 0)
        return cmd_save();
    else if (strcmp(argv[1], "load") == 0)
        return cmd_load();
    else if (strcmp(argv[1], "status") == 0)
        return cmd_status();
    else if (strcmp(argv[1], "log") == 0)
        return cmd_log();
    else if (strcmp(argv[1], "flush-log") == 0)
        return cmd_flush_log();
    else if (strcmp(argv[1], "watch") == 0) {
        execl("/usr/bin/python3", "python3",
                "/usr/local/share/sealant/watch.py", NULL);
            /* fallback path */
        execl("/usr/bin/python3", "python3",
                "/mnt/projects/sealant-1.0.0.25/userspace/watch.py", NULL);
        fprintf(stderr, "sealant: python3 not found\n");
        return 1;
    }
    else if (strcmp(argv[1], "migrate") == 0)
        return cmd_migrate(argc - 2, argv + 2);
    else {
        fprintf(stderr, "sealant: unknown command '%s'\n", argv[1]);
        usage();
        return 1;
    }
}
