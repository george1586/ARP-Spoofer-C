#include "utils_iptables.h"
#include <stdlib.h>
#include <stdio.h>

int setup_dns_redirect(void) {
    printf("[IPTABLES] Redirecting UDP port 53 to local port 53 for Technitium...\n");
    return system("iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53");
}

int cleanup_dns_redirect(void) {
    printf("[IPTABLES] Removing UDP port 53 redirection...\n");
    return system("iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53");
}
