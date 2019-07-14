#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

#include "interface.h"
#include "client.h"
#include "lease.h"
#include "flood.h"
#include "util.h"
#include "ra.h"

unsigned char dnsv6[16][16];
int numdnsv6 = 0;

int ra_socket = -1;

int
setup_ra_socket()
{
    int s, i, rc, one = 1, ff = 255;
    struct icmp6_filter filter;

    if(ra_socket >= 0) {
        close(ra_socket);
        ra_socket = -1;
    }

    s = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if(s < 0)
        return -1;

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ff, sizeof(ff));
    if(rc < 0)
        goto fail;

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ff, sizeof(ff));
    if(rc < 0)
        goto fail;

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &one, sizeof(one));
    if(rc < 0)
        goto fail;

    for(i = 0; i < numinterfaces; i++) {
        struct ipv6_mreq mreq;
        const unsigned char all_routers[16] =
            {0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
        if(interfaces[i].ifindex <= 0)
            continue;
        memset(&mreq, 0, sizeof(mreq));
        memcpy(&mreq.ipv6mr_multiaddr, &all_routers, 16);
        mreq.ipv6mr_interface = interfaces[i].ifindex;
        rc = setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                        (char*)&mreq, sizeof(mreq));
        if(rc < 0)
            goto fail;
    }

    ICMP6_FILTER_SETBLOCKALL(&filter);
    ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &filter);

    rc = setsockopt(s, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter));
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_GETFD, 0);
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_SETFD, rc | FD_CLOEXEC);
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_GETFL, 0);
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_SETFL, (rc | O_NONBLOCK));
    if(rc < 0)
        goto fail;

    ra_socket = s;
    return s;

fail:
    return -1;
}

#define CHECK(_n) if(buflen < i + (_n)) goto sendit
#define BYTE(_v) buf[i] = (_v); i++
#define BYTES(_v, _len) memcpy(buf + i, (_v), (_len)); i += (_len)
#define SHORT(_v) DO_HTONS(buf + i, (_v)); i += 2
#define LONG(_v) DO_HTONL(buf + i, (_v)); i += 4

static const unsigned char zeroes[8] = {0};

int
send_ra(const unsigned char *prefix, int tm,
        const struct sockaddr_in6 *to, struct interface *interface)
{
    int buflen = 1024;
    unsigned char buf[buflen];
    int i = 0;

    if(tm > 0xffff)
        tm = 0xffff;

    CHECK(16);
    BYTE(134);
    BYTE(0);
    SHORT(0);
    BYTE(0);
    BYTE(0);
    SHORT(prefix != NULL ? tm : 0);
    LONG(0);
    LONG(0);

    if(prefix != NULL) {
        CHECK(32);
        BYTE(3);
        BYTE(4);
        BYTE(64);
        BYTE(0x80 | 0x40);
        LONG(tm);
        LONG(2 * tm / 3);
        LONG(0);
        BYTES(prefix, 8);
        BYTES(zeroes, 8);

        if(numdnsv6 > 0) {
            CHECK(8 + numdnsv6 * 16);
            BYTE(25);
            BYTE(1 + numdnsv6 * 2);
            SHORT(0);
            LONG(MAX_RTR_ADV_INTERVAL * 3 / 2);
            for(int j = 0; j < numdnsv6; j++) {
                BYTES(&dnsv6[j], 16);
            }
        }
    }

    if(memcmp(interface->mac, zeroes, 6) != 0) {
        CHECK(8);
        BYTE(1);
        BYTE(1);
        BYTES(interface->mac, 6);
    }

 sendit:
    debugf("-> RA\n");
    return sendto(ra_socket, buf, i, 0, (struct sockaddr*)to, sizeof(*to));
}

int
receive_rs()
{
    int buflen = 1500, rc;
    unsigned char buf[buflen];
    unsigned char *mac;
    struct sockaddr_in6 from;
    struct interface *interface;
    struct iovec iov[1];
    struct msghdr msg;
    int cmsglen = 100;
    char cmsgbuf[100];
    struct cmsghdr *cmsg = (struct cmsghdr*)cmsgbuf;
    int hoplimit = -1;
    int i, doit;
    struct datum *lease;
    const unsigned char *addr;
    struct client *client;

    iov[0].iov_base = buf;
    iov[0].iov_len = buflen;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &from;
    msg.msg_namelen = sizeof(from);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg;
    msg.msg_controllen = cmsglen;

    rc = recvmsg(ra_socket, &msg, 0);
    if(rc < 0)
        return rc;

    if(msg.msg_namelen < sizeof(struct sockaddr_in6) ||
       from.sin6_family != AF_INET6)
        return 0;

    cmsg = CMSG_FIRSTHDR(&msg);
    while(cmsg != NULL) {
        if ((cmsg->cmsg_level == IPPROTO_IPV6) &&
            (cmsg->cmsg_type == IPV6_HOPLIMIT)) {
            hoplimit = *(unsigned char*)CMSG_DATA(cmsg);
            break;
        }
    }

    if(hoplimit != 255)
        return 0;

    if(rc < 8)
        return 0;

    if(buf[0] != 133 || buf[1] != 0)
        return 0;

    if(from.sin6_scope_id == 0)
        return 0;

    interface = find_interface(from.sin6_scope_id);
    if(interface == NULL)
        return 0;

    mac = NULL;
    i = 8;
    while(i <= rc - 8) {
        if(buf[i] == 1 && buf[i + 1] == 1) {
            mac = buf + i + 2;
            break;
        }
        i += buf[i + 1] * 8;
    }
    if(mac == NULL) {
        debugf("No source address option in router solicitation.\n");
        return -1;
    }

    debugf("<- RS %s\n", interface->ifname);

    client = update_association(interface, mac, ASSOCIATION_TIME);
    if(client == NULL) {
        fprintf(stderr, "Failed to create client.\n");
        return -1;
    }

    lease = update_lease(mac, 1, NULL, 3600, &doit);
    if(lease == NULL)
        return -1;

    addr = lease_address(lease, 1);
    if(addr == NULL)
        return -1;

    update_client_route(client, addr, 1);

    send_ra(addr, datum_remaining(lease), &from, interface);

    return 1;
}


static const unsigned char all_nodes[16] =
    {0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

int
send_gratuitious_na(struct interface *interface)
{
    int buflen = 1024;
    unsigned char buf[buflen], myipv6[16];
    struct sockaddr_in6 to;
    int rc, i = 0;

    memset(&to, 0, sizeof(to));
    to.sin6_family = AF_INET6;
    memcpy(&to.sin6_addr, all_nodes, 16);
    to.sin6_scope_id = interface->ifindex;

    rc = interface_v6(interface, myipv6);
    if(rc < 0)
        return rc;

    CHECK(24);
    BYTE(136);
    BYTE(0);
    SHORT(0);
    BYTE(0x80 | 0x20);
    BYTE(0);
    SHORT(0);
    BYTES(myipv6, 16);

    if(memcmp(interface->mac, zeroes, 6) != 0) {
        CHECK(8);
        BYTE(2);
        BYTE(1);
        BYTES(interface->mac, 6);
    }

 sendit:
    debugf("-> Neigbour Advertisement\n");
    return sendto(ra_socket, buf, i, 0, (struct sockaddr*)&to, sizeof(to));
}


int
ra_setup()
{
    return setup_ra_socket();
}

void
ra_cleanup()
{
    if(ra_socket < 0)
        return;

    for(int i = 0; i < numinterfaces; i++) {
        struct sockaddr_in6 to;
        memset(&to, 0, sizeof(to));
        to.sin6_family = AF_INET6;
        memcpy(&to.sin6_addr, all_nodes, 16);
        to.sin6_scope_id = interfaces[i].ifindex;
        send_ra(NULL, 0, &to, &interfaces[i]);
    }
    close(ra_socket);
    ra_socket = -1;
}
