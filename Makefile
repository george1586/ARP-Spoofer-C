CC = gcc
CFLAGS = -Wall -Wextra -g
INCLUDES = -I ARP/ARP_UTILS

SRC = \
	main.c \
	ARP/ARP_UTILS/utils_discovery.c \
	ARP/ARP_UTILS/arp_scan.c \
	ARP/ARP_UTILS/arp_poison.c \
	ARP/ARP_UTILS/utils_iptables.c

program: $(SRC)
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC) -o program

clean:
	rm -f program