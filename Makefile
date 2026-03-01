CC = gcc
CFLAGS = -Wall -Wextra -g
INCLUDES = -I ARP/ARP_UTILS -I ARP/ARP_TESTS

SRC = \
	ARP/ARP_TESTS/tests.c \
	ARP/ARP_UTILS/utils_discovery.c

program: $(SRC)
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC) -o program

clean:
	rm -f program