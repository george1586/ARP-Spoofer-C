CC = gcc
CFLAGS = -Wall -Wextra -g
INCLUDES = -I ARP/ARP_UTILS

SRC = \
	main.c \
	ARP/ARP_UTILS/utils_discovery.c \
	ARP/ARP_UTILS/arp_scan.c \
	ARP/ARP_UTILS/arp_poison.c \
	ARP/ARP_UTILS/ndp_block.c \
	ARP/ARP_UTILS/utils_iptables.c \
	ARP/ARP_UTILS/utils_rate.c \
	ARP/ARP_UTILS/utils_firewall.c \
	ARP/ARP_UTILS/utils_log.c

program: $(SRC)
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC) -lpthread -o program

clean:
	rm -f program