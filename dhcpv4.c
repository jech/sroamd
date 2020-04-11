#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>

#include "interface.h"
#include "client.h"
#include "lease.h"
#include "flood.h"
#include "util.h"
#include "dhcpv4.h"

#define RENEW_TIME 1600
#define REBIND_TIME 1700
#define LEASE_TIME 1800

int dhcpv4_socket = -1;

static const unsigned char cookie[4] = {99, 130, 83, 99};
static const unsigned char zeroes[6] = {0, 0, 0, 0, 0, 0};

unsigned char dnsv4[16][4];
int numdnsv4 = 0;

static int
setup_dhcpv4_socket()
{
    int s, rc, one = 1;
    struct sockaddr_in sin;

    if(dhcpv4_socket >= 0) {
        close(dhcpv4_socket);
        dhcpv4_socket = -1;
    }

    s = socket(PF_INET, SOCK_DGRAM, 0);
    if(s < 0)
        return -1;

    rc = setsockopt(s, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
    if(rc < 0)
        goto fail;

    rc = setsockopt(s, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));
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

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(67);

    rc = bind(s, (struct sockaddr*)&sin, sizeof(sin));
    if(rc < 0)
        goto fail;

    dhcpv4_socket = s;
    return s;

fail:
    return -1;
}

int
dhcpv4_setup()
{
    return setup_dhcpv4_socket();
}

void
dhcpv4_cleanup()
{
    if(dhcpv4_socket >= 0) {
        close(dhcpv4_socket);
        dhcpv4_socket = -1;
    }
}

struct
dhcpv4_request
{
    int type;
    int broadcast;
    unsigned char xid[4];
    unsigned char ciaddr[4];
    unsigned char yiaddr[4];
    unsigned char siaddr[4];
    unsigned char giaddr[4];
    unsigned char chaddr[16];
    unsigned char ip[4];
    unsigned char sid[4];
    unsigned char *cid;
    int cidlen;
    unsigned char *uc;
    int uclen;
};

static int
dhcpv4_parse(unsigned char *buf, int buflen,
             struct dhcpv4_request *ret)
{
    int i = 0;
    unsigned char
        xid[4] = {0},
        ciaddr[4] = {0}, yiaddr[4] = {0}, siaddr[4] = {0}, giaddr[4] = {0},
        chaddr[16] = {0}, ip[4] = {0}, sid[4] = {0};
    unsigned char *cid = NULL, *uc = NULL;
    int dhcp_type = -1, broadcast = 0, cidlen = 0, uclen = 0;

    if(buflen < 236)
        goto fail;

    if(buf[0] != 1 || buf[1] != 1 || buf[2] != 6)
        goto fail;
    i += 4;

    memcpy(xid, buf + i, 4);
    i += 4;

    /* secs */
    i += 2;

    /* flags */
    broadcast = (buf[i] & 0x80) != 0;
    i += 2;

    /* ciaddr */
    memcpy(ciaddr, buf + i, 4);
    i += 4;

    /* yiaddr */
    memcpy(yiaddr, buf + i, 4);
    i += 4;

    /* siaddr */
    memcpy(siaddr, buf + i, 4);
    i += 4;

    /* giaddr */
    memcpy(giaddr, buf + i, 4);
    i += 4;

    /* chaddr */
    memcpy(chaddr, buf + i, 16);
    i += 16;

    /* sname */
    i += 64;

    /* file */
    i += 128;

    if(buflen - i < 4)
        goto fail;

    if(memcmp(buf + i, cookie, 4) != 0)
        goto fail;
    i += 4;

    while(i < buflen) {
        unsigned const char *tlv = buf + i;
        int type, bodylen;

        if(buflen - i < 1) {
            fprintf(stderr, "Received truncated DHCPv4 TLV.\n");
            goto fail;
        }

        type = tlv[0];
        if(type == 0) {
            i++;
            continue;
        }

        if(type == 255) {
            i++;
            goto done;
        }

        if(buflen - i < 2) {
            fprintf(stderr, "Received truncated DHCPv4 TLV.\n");
            goto fail;
        }

        bodylen = tlv[1];
        if(buflen - i < 2 + bodylen) {
            fprintf(stderr, "Received truncated DHCPv4 TLV.\n");
            goto fail;
        }

        switch(type) {
        case 50:
            if(bodylen != 4)
                goto fail;
            memcpy(ip, tlv + 2, 4);
            break;
        case 53:
            if(bodylen != 1)
                goto fail;
            dhcp_type = tlv[2];
            break;
        case 54:
            if(bodylen != 4)
                goto fail;
            memcpy(sid, tlv + 2, 4);
            break;
        case 61:
            if(cid != NULL)
                goto fail;
            cid = malloc(bodylen);
            if(cid == NULL)
                goto fail;
            memcpy(cid, tlv + 2, bodylen);
            cidlen = bodylen;
            break;
        case 77:
            if(uc != NULL)
                goto fail;
            uc = malloc(bodylen);
            if(uc == NULL)
                goto fail;
            memcpy(uc, tlv + 2, bodylen);
            uclen = bodylen;
            break;
        }
        i += 2 + bodylen;
    }
    /* Fall through */
 fail:
    fprintf(stderr, "Failed to parse DHCPv4 packet.\n");
    free(cid);
    free(uc);
    return -1;

 done:
    ret->type = dhcp_type;
    ret->broadcast = broadcast;
    memcpy(ret->chaddr, chaddr, 16);
    memcpy(ret->xid, xid, 4);
    memcpy(ret->ciaddr, ciaddr, 4);
    memcpy(ret->yiaddr, yiaddr, 4);
    memcpy(ret->siaddr, siaddr, 4);
    memcpy(ret->giaddr, giaddr, 4);
    memcpy(ret->ip, ip, 4);
    memcpy(ret->sid, sid, 4);
    ret->cid = cid;
    ret->cidlen = cidlen;
    ret->uc = uc;
    ret->uclen = uclen;
    return 1;
}

#define CHECK(_n) if(buflen < i + (_n)) goto fail
#define BYTE(_v) buf[i] = (_v); i++
#define BYTES(_v, _len) memcpy(buf + i, (_v), (_len)); i += (_len)
#define ZEROS(_len) memset(buf + i, 0, (_len)); i += (_len)
#define SHORT(_v) DO_HTONS(buf + i, (_v)); i += 2
#define LONG(_v) DO_HTONL(buf + i, (_v)); i += 4

static int
dhcpv4_send(int s, struct sockaddr_in *to, int dontroute,
            int type, const unsigned char *xid,
            const unsigned char *chaddr, const unsigned char *myaddr,
            const unsigned char *ip, struct interface *interface,
            const unsigned char *netmask,
            int lease_time)
{
    int buflen = 1024;
    unsigned char buf[buflen];
    int i = 0;
    int rc;

    debugf("-> DHCPv4 (type %d) %s\n", type, interface->ifname);

    MEM_UNDEFINED(buf, buflen);

    CHECK(236);
    BYTE(2);
    BYTE(1);
    BYTE(6);
    BYTE(0);
    BYTES(xid, 4);
    SHORT(0);
    SHORT(0);

    ZEROS(4);                   /* ciaddr */
    if(ip && lease_time >= 20) {
        BYTES(ip, 4);           /* yiaddr */
    } else {
        ZEROS(4);
    }
    BYTES(myaddr, 4);           /* siaddr */
    ZEROS(4);                   /* giaddr */
    BYTES(chaddr, 16);          /* chaddr */
    ZEROS(64);                  /* sname */
    ZEROS(128);                 /* file */

    CHECK(4);
    BYTES(cookie, 4);

    CHECK(3);
    BYTE(53);                   /* DHCP Message Type */
    BYTE(1);
    BYTE(type);

    CHECK(6);
    BYTE(54);                   /* Server Identifier */
    BYTE(4);
    BYTES(myaddr, 4);

    if(lease_time >= 20) {
        CHECK(6);
        BYTE(51);               /* IP Address Lease Time */
        BYTE(4);
        LONG(lease_time);

        CHECK(6);
        BYTE(58);               /* T1 */
        BYTE(4);
        LONG(min(RENEW_TIME, lease_time - 10));

        CHECK(6);
        BYTE(59);               /* T2 */
        BYTE(4);
        LONG(min(REBIND_TIME, lease_time - 15));
    }

    if(netmask) {
        CHECK(6);
        BYTE(1);
        BYTE(4);
        BYTES(netmask, 4);
    }

    CHECK(6);
    BYTE(3);
    BYTE(4);
    BYTES(myaddr, 4);

    if(numdnsv4 > 0) {
        CHECK(2 + 4 * numdnsv4);
        BYTE(6);
        BYTE(4 * numdnsv4);
        for(int j = 0; j < numdnsv4; j++) {
            BYTES((char*)&dnsv4[j], 4);
        }
    }

    CHECK(1);
    BYTE(255);

    sock_bindtodevice(dhcpv4_socket, interface);
    rc = sendto(dhcpv4_socket, buf, i, dontroute ? MSG_DONTROUTE : 0,
                (struct sockaddr*)to, sizeof(*to));
    sock_bindtodevice(dhcpv4_socket, NULL);
    return rc;

 fail:
    return -1;
}

int
dhcpv4_receive()
{
    int rc, buflen, doit;
    const unsigned char broadcast_addr[4] = {255, 255, 255, 255};
    struct sockaddr_in from, to;
    int dontroute = 1;
    int bufsiz = 1500;
    unsigned char buf[bufsiz];
    unsigned char myaddr[4];
    unsigned char netmask[4] = {255, 255, 255, 255};
    struct dhcpv4_request req;
    struct client *client;
    struct interface *interface;
    int ifindex = -1;
    struct iovec iov[1];
    struct msghdr msg;
    int cmsglen = 100;
    char cmsgbuf[cmsglen];
    struct cmsghdr *cmsg = (struct cmsghdr*)cmsgbuf;

    iov[0].iov_base = buf;
    iov[0].iov_len = bufsiz;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &from;
    msg.msg_namelen = sizeof(from);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg;
    msg.msg_controllen = cmsglen;

    rc = recvmsg(dhcpv4_socket, &msg, 0);

    if(rc < 0)
        return -1;

    if(from.sin_family != AF_INET || msg.msg_namelen < sizeof(from))
        return -1;

    buflen = rc;

    cmsg = CMSG_FIRSTHDR(&msg);
    while(cmsg != NULL) {
        if ((cmsg->cmsg_level == IPPROTO_IP) &&
            (cmsg->cmsg_type == IP_PKTINFO)) {
            struct in_pktinfo *info = (struct in_pktinfo*)CMSG_DATA(cmsg);
            ifindex = info->ipi_ifindex;
            break;
        }
        cmsg = CMSG_NXTHDR(&msg, cmsg);
    }

    if(ifindex < 0)
        return -1;
    interface = find_interface(ifindex);
    if(interface == NULL)
        return -1;

    rc = interface_v4(interface, myaddr);
    if(rc <= 0) {
        return -1;
    }

    memset(&req, 0, sizeof(req));
    rc = dhcpv4_parse(buf, buflen, &req);
    if(rc < 0)
        return -1;

    if(memcmp(req.sid, zeroes, 4) != 0 && memcmp(req.sid, myaddr, 4) != 0)
        return 0;

    debugf("<- DHCPv4 (type %d) %s\n", req.type, interface->ifname);

    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    if(memcmp(req.giaddr, zeroes, 4) != 0) {
        memcpy(&to.sin_addr, req.giaddr, 4);
        dontroute = 0;
    } else if(!req.broadcast && memcmp(req.ciaddr, zeroes, 4) != 0) {
        memcpy(&to.sin_addr, req.ciaddr, 4);
    } else {
        memcpy(&to.sin_addr, broadcast_addr, 4);
    }
    to.sin_port = htons(68);

    switch(req.type) {
    case 1:                     /* DHCPDISCOVER */
    case 3: {                   /* DHCPREQUEST */
        struct datum *lease = NULL;
        const unsigned char *addr;
        unsigned char cip[4];
        int have_cip;
        int remain;

        if(req.type == 1)
            memcpy(cip, req.ip, 4);
        else if(memcmp(req.ciaddr, zeroes, 4) != 0)
            memcpy(cip, req.ciaddr, 4);
        else
            memcpy(cip, req.ip, 4);

        have_cip = memcmp(cip, zeroes, 4) != 0;

        if(req.type == 3 && !have_cip)
            goto nak;

        client = update_association(interface, req.chaddr, ASSOCIATION_TIME);
        if(client == NULL) {
            fprintf(stderr, "Failed to create client.\n");
            goto nak;
        }

        lease = update_lease(req.chaddr, 0,
                             have_cip ? cip : NULL,
                             req.type == 1 ? 10 : LEASE_TIME,
                             &doit);
        if(lease == NULL)
            goto nak;

        addr = lease_address(lease, 0);
        if(addr == NULL)
            goto nak;

        if(req.type == 3 && memcmp(cip, addr, 4) != 0)
            goto nak;

        update_client_route(client, addr, 0);

        remain = req.type == 1 ? LEASE_TIME : datum_remaining(lease);
        if(remain < 60)
            goto nak;

        rc = dhcpv4_send(dhcpv4_socket, &to, dontroute,
                         req.type == 1 ? 2 : 5, req.xid, req.chaddr, myaddr,
                         addr, interface, netmask, remain);
        if(rc < 0)
            perror("dhcpv4_send");
        break;
    }
    case 4:                     /* DHCPDECLINE */
        fprintf(stderr, "Received DHCPDECLINE");
        break;
    case 7:                     /* DHCPRELEASE */
        fprintf(stderr, "Received DHCPRELEASE");
        break;
    case 8:                     /* DHCPINFORM */
        rc = dhcpv4_send(dhcpv4_socket, &to, dontroute,
                         5, req.xid, req.chaddr, myaddr,
                         NULL, interface, NULL, 0);
        if(rc < 0)
            perror("dhcpv4_send");
        break;
    }

    goto done;

 nak:
    /* NAK is always sent to broadcast address, except in relay case. */
    if(memcmp(req.giaddr, zeroes, 4) == 0)
        memcpy(&to.sin_addr, broadcast_addr, 4);
    if(req.type == 3)
        dhcpv4_send(dhcpv4_socket, &to, dontroute, 6, req.xid, req.chaddr,
                    myaddr, req.ip, interface, NULL, 0);
 done:
    free(req.cid);
    free(req.uc);
    return 1;
}

int
send_gratuitous_arp(const unsigned char *myaddr, struct interface *interface,
                     const unsigned char *mac)
{
    int buflen = 28;
    unsigned char buf[buflen];
    struct sockaddr_ll sll;
    int rc, s, i = 0;

    s = socket(PF_PACKET, SOCK_DGRAM, htons(ETHERTYPE_ARP));
    if(s < 0)
        return -1;

    CHECK(28);
    SHORT(ARPHRD_ETHER);
    SHORT(ETHERTYPE_IP);
    BYTE(6);
    BYTE(4);
    SHORT(2);
    BYTES(interface->mac, 6);
    BYTES(myaddr, 4);
    BYTES(zeroes, 6);
    BYTES(myaddr, 4);

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETHERTYPE_ARP);
    sll.sll_ifindex = interface->ifindex;
    sll.sll_hatype = htons(ARPHRD_ETHER);
    memcpy(&sll.sll_addr, mac, 6);
    sll.sll_halen = 6;

    debugf("-> ARP Reply.\n");
    rc = sendto(s, buf, i, 0, (struct sockaddr*)&sll, sizeof(sll));

    close(s);
    return rc;

 fail:
    close(s);
    return -1;

}
