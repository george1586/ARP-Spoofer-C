#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "tests.h"

unsigned char *get_own_mac(void)
{
    struct ifreq s;
    unsigned char *own_mac = malloc(6);
    if (!own_mac)
        return NULL;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (fd < 0)
    {
        perror("socket");
        free(own_mac);
        return NULL;
    }
    strcpy(s.ifr_name, "eth0");
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s))
    {
        memcpy(own_mac, s.ifr_hwaddr.sa_data, 6);
        close(fd);
        return own_mac;
    }

    return NULL;
}

unsigned char *get_own_ip(void)
{
    struct ifreq s;
    unsigned char *own_ip = malloc(4);
    if (!own_ip)
        return NULL;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (fd < 0)
    {
        perror("ip");
        free(own_ip);
        return NULL;
    }
    strcpy(s.ifr_name, "wlan0"); // change to eth0 for pi
    if (0 == ioctl(fd, SIOCGIFADDR, &s))
    {
        struct sockaddr_in *addr = (struct sockaddr_in *)&s.ifr_addr;
        memcpy(own_ip, &addr->sin_addr, 4);
        close(fd);
        return own_ip;
    }
    return NULL;
}

unsigned char *get_netmask()
{
    struct ifreq s;
    unsigned char *netmask = malloc(4);
    if (!netmask)
        return NULL;
    int fd = socket(PF_INET, SOCK_DGRAM, AF_UNSPEC);
    if (fd < 0)
    {
        perror("netmask");
        free(netmask);
        return NULL;
    };
    memset(&s, 0, sizeof(s));
    strcpy(s.ifr_name, "wlan0");
    if (0 == ioctl(fd, SIOCGIFNETMASK, &s))
    {
        struct sockaddr_in *addr = (struct sockaddr_in *)&s.ifr_netmask;
        memcpy(netmask, &addr->sin_addr, 4);
        close(fd);
        return netmask;
    }
    return NULL;
}

int main()
{
    unsigned char *own_mac = get_own_mac();
    unsigned char *own_ip = get_own_ip();
    unsigned char *netmask = get_netmask();
    test_arp();
}