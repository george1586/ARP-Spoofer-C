#include "arp_scan.h"
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

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

unsigned char *get_mac_from_ip(unsigned char *target_ip) {
  int sockfd = -1;
  struct ifreq if_idx;
  struct sockaddr_ll socket_address;
  char ifName[IFNAMSIZ] = "eth0";

  unsigned char *dest_mac = malloc(6);
  if (!dest_mac)
    return NULL;

  unsigned char *my_mac = get_own_mac();
  unsigned char *my_ip = get_own_ip();
  if (!my_mac || !my_ip) {
    free(dest_mac);
    if (my_mac)
      free(my_mac);
    if (my_ip)
      free(my_ip);
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
  if (!buffer)
    goto cleanup_error;
  memset(buffer, 0, frame_length);

  // Build Ethernet header
  struct ethhdr *eth = (struct ethhdr *)buffer;
  memcpy(eth->h_source, my_mac, 6);
  memset(eth->h_dest, 0xFF, 6);
  eth->h_proto = htons(ETH_P_ARP);

  // Build ARP header
  struct arp_header *arp =
      (struct arp_header *)(buffer + sizeof(struct ethhdr));
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
  if (sendto(sockfd, buffer, frame_length, 0,
             (struct sockaddr *)&socket_address,
             sizeof(struct sockaddr_ll)) < 0) {
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
      struct arp_header *recv_arp =
          (struct arp_header *)(recv_buffer + sizeof(struct ethhdr));
      if (ntohs(recv_arp->opcode) == 2) { // ARP Reply
        // Check if it's the IP we want
        if (memcmp(recv_arp->sender_ip, target_ip, 4) == 0 &&
            memcmp(recv_arp->target_mac, my_mac, 6) == 0) {
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
  if (sockfd != -1)
    close(sockfd);
  if (my_mac)
    free(my_mac);
  if (my_ip)
    free(my_ip);
  free(dest_mac);
  return NULL;
}

extern unsigned char *get_netmask(void);

struct Victim *scan_network(unsigned char *gateway_ip, int *out_count) {
  int sockfd = -1;
  struct ifreq if_idx;
  struct sockaddr_ll socket_address;
  char ifName[IFNAMSIZ] = "eth0";

  *out_count = 0;
  // Allocate space for up to 512 victims
  struct Victim *victims = malloc(sizeof(struct Victim) * 512);
  if (!victims)
    return NULL;

  unsigned char *my_mac = get_own_mac();
  unsigned char *my_ip = get_own_ip();
  unsigned char *netmask = get_netmask();

  if (!my_mac || !my_ip || !netmask) {
    if (my_mac)
      free(my_mac);
    if (my_ip)
      free(my_ip);
    if (netmask)
      free(netmask);
    free(victims);
    return NULL;
  }

  if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1) {
    perror("socket");
    goto cleanup_scan;
  }

  memset(&socket_address, 0, sizeof(struct sockaddr_ll));
  strcpy(if_idx.ifr_name, ifName);
  if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
    perror("SIOCGIFINDEX");
    goto cleanup_scan;
  }

  socket_address.sll_ifindex = if_idx.ifr_ifindex;
  socket_address.sll_halen = ETH_ALEN;
  memset(socket_address.sll_addr, 0xFF, 6);

  int frame_length = sizeof(struct ethhdr) + sizeof(struct arp_header);
  char *buffer = malloc(frame_length);
  if (!buffer)
    goto cleanup_scan;

  // Calculate start and end IP
  uint32_t ip_int = ntohl(*(uint32_t *)my_ip);
  uint32_t mask_int = ntohl(*(uint32_t *)netmask);
  uint32_t net_int = ip_int & mask_int;
  uint32_t bcast_int = net_int | ~mask_int;

  printf("[*] Scanning network from %d.%d.%d.%d to %d.%d.%d.%d\n",
         (net_int >> 24) & 0xFF, (net_int >> 16) & 0xFF, (net_int >> 8) & 0xFF,
         net_int & 0xFF, (bcast_int >> 24) & 0xFF, (bcast_int >> 16) & 0xFF,
         (bcast_int >> 8) & 0xFF, bcast_int & 0xFF);

  // Build base Ethernet header
  struct ethhdr *eth = (struct ethhdr *)buffer;
  memcpy(eth->h_source, my_mac, 6);
  memset(eth->h_dest, 0xFF, 6);
  eth->h_proto = htons(ETH_P_ARP);

  // Send broadcast ARP request for each IP
  for (uint32_t target = net_int + 1; target < bcast_int; target++) {
    uint32_t t_ip = htonl(target);
    if (memcmp(&t_ip, my_ip, 4) == 0)
      continue; // Skip own

    struct arp_header *arp =
        (struct arp_header *)(buffer + sizeof(struct ethhdr));
    arp->hw_type = htons(1);
    arp->proto_type = htons(ETH_P_IP);
    arp->hw_len = 6;
    arp->proto_len = 4;
    arp->opcode = htons(1);
    memcpy(arp->sender_mac, my_mac, 6);
    memcpy(arp->sender_ip, my_ip, 4);
    memset(arp->target_mac, 0x00, 6);
    memcpy(arp->target_ip, &t_ip, 4);

    sendto(sockfd, buffer, frame_length, 0, (struct sockaddr *)&socket_address,
           sizeof(struct sockaddr_ll));
  }

  // Set non-blocking/timeout for receive
  struct timeval tv;
  tv.tv_sec = 3; // 3 seconds timeout
  tv.tv_usec = 0;
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  printf("[*] Waiting for replies...\n");
  char recv_buffer[ETH_FRAME_LEN];
  while (1) {
    int bytes = recv(sockfd, recv_buffer, ETH_FRAME_LEN, 0);
    if (bytes <= 0) {
      break; // Timeout reached
    }

    struct ethhdr *recv_eth = (struct ethhdr *)recv_buffer;
    if (ntohs(recv_eth->h_proto) == ETH_P_ARP) {
      struct arp_header *recv_arp =
          (struct arp_header *)(recv_buffer + sizeof(struct ethhdr));
      if (ntohs(recv_arp->opcode) == 2) { // ARP Reply
        // Ignore replies from gateway or self
        if (gateway_ip && memcmp(recv_arp->sender_ip, gateway_ip, 4) == 0)
          continue;
        if (memcmp(recv_arp->sender_ip, my_ip, 4) == 0)
          continue;

        // Ensure it's addressed to us
        if (memcmp(recv_arp->target_mac, my_mac, 6) != 0)
          continue;

        // Check if already added
        int exists = 0;
        for (int i = 0; i < *out_count; i++) {
          if (memcmp(victims[i].ip, recv_arp->sender_ip, 4) == 0) {
            exists = 1;
            break;
          }
        }

        if (!exists && *out_count < 512) {
          memcpy(victims[*out_count].ip, recv_arp->sender_ip, 4);
          memcpy(victims[*out_count].mac, recv_arp->sender_mac, 6);
          (*out_count)++;
          printf("[+] Discovered Victim IP: %d.%d.%d.%d MAC: "
                 "%02x:%02x:%02x:%02x:%02x:%02x\n",
                 recv_arp->sender_ip[0], recv_arp->sender_ip[1],
                 recv_arp->sender_ip[2], recv_arp->sender_ip[3],
                 recv_arp->sender_mac[0], recv_arp->sender_mac[1],
                 recv_arp->sender_mac[2], recv_arp->sender_mac[3],
                 recv_arp->sender_mac[4], recv_arp->sender_mac[5]);
        }
      }
    }
  }

  free(buffer);
cleanup_scan:
  if (sockfd != -1)
    close(sockfd);
  free(my_mac);
  free(my_ip);
  free(netmask);

  if (*out_count == 0) {
    free(victims);
    return NULL;
  }

  return victims;
}
