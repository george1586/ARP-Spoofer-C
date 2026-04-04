#include "utils_iptables.h"
#include <stdlib.h>
#include <stdio.h>

static const char *common_dns_ips[] = {
    "8.8.8.8", "8.8.4.4",           // Google
    "1.1.1.1", "1.0.0.1",           // Cloudflare
    "9.9.9.9", "149.112.112.112",    // Quad9
    "208.67.222.222", "208.67.220.220" // OpenDNS
};

static const int dns_ip_count = 8;

int setup_dns_redirect(void) {
    printf("[IPTABLES] Redirecting UDP port 53 to local port 53 for Technitium...\n");
    system("iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53 2>/dev/null || "
           "/sbin/iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53 2>/dev/null || "
           "/usr/sbin/iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53");

    printf("[IPTABLES] Blocking DNS over TLS (Port 853) to force fallback...\n");
    system("iptables -A FORWARD -p tcp --dport 853 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || "
           "/sbin/iptables -A FORWARD -p tcp --dport 853 -j REJECT --reject-with icmp-port-unreachable");

    printf("[IPTABLES] Blackholing common DoH provider IPs on Port 443...\n");
    for (int i = 0; i < dns_ip_count; i++) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "iptables -A FORWARD -d %s -p tcp --dport 443 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || "
                                  "/sbin/iptables -A FORWARD -d %s -p tcp --dport 443 -j REJECT --reject-with icmp-port-unreachable",
                 common_dns_ips[i], common_dns_ips[i]);
        system(cmd);
    }

    return 0;
}

int cleanup_dns_redirect(void) {
    printf("[IPTABLES] Removing DNS redirection and DoH/DoT blocks...\n");
    system("iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53 2>/dev/null");
    system("iptables -D FORWARD -p tcp --dport 853 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null");

    for (int i = 0; i < dns_ip_count; i++) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "iptables -D FORWARD -d %s -p tcp --dport 443 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null",
                 common_dns_ips[i]);
        system(cmd);
    }

    return 0;
}
