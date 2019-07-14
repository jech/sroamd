#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <ifaddrs.h>

#include "interface.h"

struct interface *interfaces = NULL;
int numinterfaces = 0;

struct interface *
find_interface(int ifindex)
{
    for(int i = 0; i < numinterfaces; i++) {
        if(interfaces[i].ifindex == ifindex)
            return &interfaces[i];
    }
    return NULL;
}

int
interface_v4(struct interface *interface, unsigned char *v4_return)
{
    struct ifreq req;
    int s, rc;

    s = socket(PF_INET, SOCK_DGRAM, 0);
    if(s < 0)
        return -1;

    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, interface->ifname, sizeof(req.ifr_name));
    req.ifr_addr.sa_family = AF_INET;
    rc = ioctl(s, SIOCGIFADDR, &req);
    if(rc < 0) {
        close(s);
        return -1;
    }
    close(s);

    memcpy(v4_return, &((struct sockaddr_in*)&req.ifr_addr)->sin_addr, 4);
    return 1;
}

int
interface_v6(struct interface *interface, unsigned char *v6_return)
{
    struct ifaddrs *ifaddr;
    int rc, found = 0;

    rc = getifaddrs(&ifaddr);
    if(rc < 0)
        return rc;

    for(struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        struct sockaddr_in6 *sin6;
        if(ifa->ifa_addr == NULL ||
           strcmp(ifa->ifa_name, interface->ifname) != 0 ||
           ifa->ifa_addr->sa_family != AF_INET6)
            continue;
        sin6 = (struct sockaddr_in6*)ifa->ifa_addr;
        if(!IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
            continue;
        memcpy(v6_return, &sin6->sin6_addr, 16);
        found = 1;
        break;
    }

    freeifaddrs(ifaddr);

    if(!found) {
        errno = ESRCH;
        return -1;
    }

    return 1;
}

int
sock_bindtodevice(int s, struct interface *interface)
{
    struct ifreq ifr;

    if(interface != NULL) {
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, interface->ifname, IFNAMSIZ);
        return setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));
    } else {
        return setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, NULL, 0);
    }
}
