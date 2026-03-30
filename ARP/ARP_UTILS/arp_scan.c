#include "arp_scan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

struct arp_header {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_len;
    uint8_t proto_len;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};

extern unsigned char *get_own_mac(void);
extern unsigned char *get_own_ip(void);

unsigned char* get_mac_from_ip(unsigned char* target_ip) {
    int sockfd = -1;
    struct ifreq if_idx;
    struct sockaddr_ll socket_address;
    char ifName[IFNAMSIZ] = "eth0";

    unsigned char* dest_mac = malloc(6);
    if (!dest_mac) return NULL;

    unsigned char* my_mac = get_own_mac();
    unsigned char* my_ip = get_own_ip();
    if (!my_mac || !my_ip) {
        free(dest_mac);
        if (my_mac) free(my_mac);
        if (my_ip) free(my_ip);
        return NULL;
    }

    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1) {
        perror("socket");
        goto cleanup_error;
    }

    // Prepare socket address
    memset(&socket_address, 0, sizeof(struct sockaddr_ll));
    strcpy(if_idx.ifr_name, ifName);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
        perror("SIOCGIFINDEX");
        goto cleanup_error;
    }

    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    socket_address.sll_halen = ETH_ALEN;
    memset(socket_address.sll_addr, 0xFF, 6);

    // Buffer for packet
    int frame_length = sizeof(struct ethhdr) + sizeof(struct arp_header);
    char *buffer = malloc(frame_length);
    if (!buffer) goto cleanup_error;
    memset(buffer, 0, frame_length);

    // Build Ethernet header
    struct ethhdr *eth = (struct ethhdr *)buffer;
    memcpy(eth->h_source, my_mac, 6);
    memset(eth->h_dest, 0xFF, 6);
    eth->h_proto = htons(ETH_P_ARP);

    // Build ARP header
    struct arp_header *arp = (struct arp_header *)(buffer + sizeof(struct ethhdr));
    arp->hw_type = htons(1); // Ethernet
    arp->proto_type = htons(ETH_P_IP);
    arp->hw_len = 6;
    arp->proto_len = 4;
    arp->opcode = htons(1); // ARP Request
    memcpy(arp->sender_mac, my_mac, 6);
    memcpy(arp->sender_ip, my_ip, 4);
    memset(arp->target_mac, 0x00, 6);
    memcpy(arp->target_ip, target_ip, 4);

    // Send packet
    if (sendto(sockfd, buffer, frame_length, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0) {
        perror("sendto");
        free(buffer);
        goto cleanup_error;
    }
    
    // Receive loop with timeout
    struct timeval tv;
    tv.tv_sec = 2; // 2 seconds timeout
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("Error setting timeout");
    }

    char recv_buffer[ETH_FRAME_LEN];
    while (1) {
        int bytes = recv(sockfd, recv_buffer, ETH_FRAME_LEN, 0);
        if (bytes <= 0) {
            fprintf(stderr, "ARP Reply timeout or error\n");
            free(buffer);
            goto cleanup_error;
        }

        struct ethhdr *recv_eth = (struct ethhdr *)recv_buffer;
        if (ntohs(recv_eth->h_proto) == ETH_P_ARP) {
            struct arp_header *recv_arp = (struct arp_header *)(recv_buffer + sizeof(struct ethhdr));
            if (ntohs(recv_arp->opcode) == 2) { // ARP Reply
                // Check if it's the IP we want
                if (memcmp(recv_arp->sender_ip, target_ip, 4) == 0 && memcmp(recv_arp->target_mac, my_mac, 6) == 0) {
                    memcpy(dest_mac, recv_arp->sender_mac, 6);
                    break;
                }
            }
        }
    }

    free(buffer);
    close(sockfd);
    free(my_mac);
    free(my_ip);
    return dest_mac;

cleanup_error:
    if (sockfd != -1) close(sockfd);
    if (my_mac) free(my_mac);
    if (my_ip) free(my_ip);
    free(dest_mac);
    return NULL;
}
