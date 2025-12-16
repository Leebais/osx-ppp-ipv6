#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

struct pppoe_hdr {
    u_char ver_type;
    u_char code;
    u_short session_id;
    u_short length;
};

struct ppp_hdr {
    u_short protocol;
};

static pcap_t *global_handle = NULL;

void run_command(const char *cmd) {
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "Command failed: %s\n", cmd);
    }
}

void configure_ipv6_and_route(const char *iface, const char *prefix, int prefix_len, const char *gateway) {
    char addr_cmd[256];
    char route_cmd[256];

    // 构造地址：prefix::1
    char full_addr[INET6_ADDRSTRLEN + 10];
    snprintf(full_addr, sizeof(full_addr), "%s1", prefix);

    // 配置地址到接口
    snprintf(addr_cmd, sizeof(addr_cmd),
             "/sbin/ifconfig %s inet6 %s prefixlen %d",
             iface, full_addr, prefix_len);
    run_command(addr_cmd);

    // 添加默认路由（fe80 地址必须加 %iface）
    snprintf(route_cmd, sizeof(route_cmd),
             "/sbin/route -n add -inet6 default %s%%%s",
             gateway, iface);
    run_command(route_cmd);
}

void parse_ra_options(const u_char *opt_ptr, int len, const char *iface, const char *gateway) {
    while (len > 0) {
        const struct nd_opt_hdr *opt = (const struct nd_opt_hdr *)opt_ptr;
        if (opt->nd_opt_len == 0) break;

        if (opt->nd_opt_type == ND_OPT_PREFIX_INFORMATION) {
            const struct nd_opt_prefix_info *pio = (const struct nd_opt_prefix_info *)opt;
            char prefix[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &pio->nd_opt_pi_prefix, prefix, sizeof(prefix));

            printf("--- Prefix Information Option ---\n");
            printf("Prefix Length: %d\n", pio->nd_opt_pi_prefix_len);
            printf("Valid Lifetime: %u\n", ntohl(pio->nd_opt_pi_valid_time));
            printf("Preferred Lifetime: %u\n", ntohl(pio->nd_opt_pi_preferred_time));
            printf("Prefix: %s\n", prefix);
            printf("---------------------------------\n");

            // 自动配置地址和路由
            configure_ipv6_and_route(iface, prefix, pio->nd_opt_pi_prefix_len, gateway);
        }

        int step = opt->nd_opt_len * 8;
        opt_ptr += step;
        len -= step;
    }
}

void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const u_char *pppoe = packet + 14;
    const u_char *ppp = pppoe + sizeof(struct pppoe_hdr);
    struct ppp_hdr *ppph = (struct ppp_hdr *)ppp;

    u_short proto = ntohs(ppph->protocol);
    if (proto == 0x0057) {
        const struct ip6_hdr *ip6 = (struct ip6_hdr *)(ppp + sizeof(struct ppp_hdr));

        char src[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6->ip6_src, src, sizeof(src));

        const struct icmp6_hdr *icmp6 = (const struct icmp6_hdr *)((const u_char *)ip6 + sizeof(struct ip6_hdr));
        if (icmp6->icmp6_type == ND_ROUTER_ADVERT) {
            const struct nd_router_advert *ra = (const struct nd_router_advert *)icmp6;
            printf("=== Router Advertisement ===\n");
            printf("Source: %s\n", src);
            printf("Hop Limit: %d\n", ra->nd_ra_curhoplimit);
            printf("Router Lifetime: %d\n", ntohs(ra->nd_ra_router_lifetime));
            printf("Reachable Time: %u\n", ntohl(ra->nd_ra_reachable));
            printf("Retrans Timer: %u\n", ntohl(ra->nd_ra_retransmit));

            int ra_hdr_len = sizeof(struct nd_router_advert);
            int opt_len = ntohs(ip6->ip6_plen) - ra_hdr_len;
            const u_char *opt_ptr = (const u_char *)icmp6 + ra_hdr_len;
            parse_ra_options(opt_ptr, opt_len, "ppp0", src);

            printf("=====================================\n");
            pcap_breakloop(global_handle);
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("en0", BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Couldn't open device en0: %s\n", errbuf);
        return 2;
    }
    global_handle = handle;

    printf("Listening on en0, decoding RA and configuring ppp0...\n");
    pcap_loop(handle, -1, handle_packet, NULL);
    pcap_close(handle);
    return 0;
}
