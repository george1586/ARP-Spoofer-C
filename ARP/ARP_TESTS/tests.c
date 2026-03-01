#include <stdio.h>
#include <stdlib.h>
#include "tests.h"
#include "utils_discovery.h"

unsigned char *get_own_mac();
unsigned char *get_own_ip();

void test_arp(void)
{
    unsigned char *own_mac = get_own_mac();
    unsigned char *own_ip = get_own_ip();
    unsigned char *netmask = get_netmask();

    if (!own_mac)
    {
        fprintf(stderr, "Failed to get own MAC\n");
    }
    else
    {
        printf("Owns MAC address: ");
        for (int i = 0; i < 6; ++i)
            printf("%02x%c", own_mac[i], i == 5 ? '\n' : ':');
    }

    if (!own_ip)
    {
        fprintf(stderr, "Failed to get own IP\n");
    }
    else
    {
        printf("Owns IP adress: ");
        for (int i = 0; i < 4; ++i)
        {
            printf("%u%c", own_ip[i], i == 3 ? '\n' : '.');
        }
    }
    if (!netmask)
    {
        fprintf(stderr, "Failed to get netmask IP\n");
    }
    else
    {
        printf("Netmask: ");
        for (int i = 0; i < 4; ++i)
        {
            printf("%u%c", netmask[i], i == 3 ? '\n' : '.');
        }
    }
    free(own_mac);
    free(own_ip);
    free(netmask);
}
