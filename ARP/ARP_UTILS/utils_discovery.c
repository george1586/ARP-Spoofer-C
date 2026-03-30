#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

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
    strcpy(s.ifr_name, "eth0"); // changed to eth0 for pi
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
    strcpy(s.ifr_name, "eth0");
    if (0 == ioctl(fd, SIOCGIFNETMASK, &s))
    {
        struct sockaddr_in *addr = (struct sockaddr_in *)&s.ifr_netmask;
        memcpy(netmask, &addr->sin_addr, 4);
        close(fd);
        return netmask;
    }
    return NULL;
}

int enable_ip_forwarding() {
    FILE *f = fopen("/proc/sys/net/ipv4/ip_forward", "w");
    if (f == NULL) {
        perror("Failed to open /proc/sys/net/ipv4/ip_forward");
        return -1;
    }
    fprintf(f, "1");
    fclose(f);
    return 0;
}