#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <netlink/errno.h>

#include "interface.h"
#include "client.h"
#include "lease.h"
#include "ra.h"
#include "dhcpv4.h"
#include "flood.h"
#include "netlink.h"
#include "util.h"

static const unsigned char v4mapped[16] =
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0 };

static void
callback(int add, int ifindex, const unsigned char *mac)
{
    struct interface *interface;
    struct client *client;
    struct datum *lease;

    interface = find_interface(ifindex);
    if(interface == NULL)
        return;
    debugf("%s: %s station %s\n",
           interface->ifname, add ? "add" : "del", format_48(mac));
    if(add) {
        unsigned char myv4[4];
        int rc;
        struct timespec tv;

        client = update_association(interface, mac, ASSOCIATION_TIME);
        if(client == NULL) {
            fprintf(stderr, "Failed to add client.\n");
            flush_association(mac, ASSOCIATION_TIME);
            return;
        }
        lease = find_lease(mac, 0);
        if(lease) {
            const unsigned char *addr;
            addr = lease_address(lease, 0);
            if(addr == NULL) {
                fprintf(stderr, "Bad lease.\n");
                return;
            }
            update_client_route(client, addr, 0);
        }

        lease = find_lease(mac, 1);
        if(lease) {
            const unsigned char *addr;
            addr = lease_address(lease, 1);
            if(addr == NULL) {
                fprintf(stderr, "Bad lease.\n");
                return;
            }
            update_client_route(client, addr, 1);
        }

        tv.tv_sec = 0;
        tv.tv_nsec = 100 * 1000 * 1000;
        nanosleep(&tv, NULL);

        rc = interface_v4(interface, myv4);
        if(rc >= 0) {
            rc = send_gratuitous_arp(myv4, interface, mac);
            if(rc < 0)
                perror("send_gratuitous_arp");
        }
        rc = send_gratuitous_na(interface);
        if(rc < 0)
            perror("send_gratuitous_na");
    } else {
        flush_association(mac, ASSOCIATION_TIME);
    }
}

void
datum_callback(struct datum *datum, int conflict)
{
    if(datum->keylen < 1)
        return;

    switch(datum_key(datum)[0]) {
    case DATUM_ASSOCIATED: {
        struct client *client;
        if(datum->keylen != 7 || (datum->vallen != 0 && datum->vallen != 8)) {
            fprintf(stderr, "Corrupt association.\n");
            return;
        }

        if(datum->vallen == 0)
            return;

        client = find_client(datum_key(datum) + 1);
        if(client != NULL && memcmp(datum_val(datum), myid, 8) != 0) {
            debugf("Disassociating %s.\n", format_48(client->mac));
            netlink_disassociate(client->interface->ifindex, client->mac,
                                 client->interface->mac);
            flush_client(client->mac);
            if(conflict)
                flush_association(client->mac, ASSOCIATION_TIME);
        }
        break;
    }
    case DATUM_IPv4_LEASE:
    case DATUM_IPv6_LEASE:
        update_lease_routes(datum);
        /* XXX discard any matching routes, send RA or FORERENEW. */
        break;
    }
}

static volatile sig_atomic_t exiting = 0, dumping = 0;

static void
sigexit(int signo)
{
    exiting = 1;
}

static void
sigdump(int signo)
{
    dumping = 1;
}

static void
init_signals(void)
{
    struct sigaction sa;
    sigset_t ss;

    sigemptyset(&ss);
    sa.sa_handler = sigexit;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);

    sigemptyset(&ss);
    sa.sa_handler = sigexit;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGHUP, &sa, NULL);

    sigemptyset(&ss);
    sa.sa_handler = sigexit;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    sigemptyset(&ss);
    sa.sa_handler = sigdump;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, NULL);

#ifdef SIGINFO
    sigemptyset(&ss);
    sa.sa_handler = sigdump;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGINFO, &sa, NULL);
#endif
}

static void
check_interface(struct interface *iif)
{
    int ifindex, rc;

    ifindex = if_nametoindex(iif->ifname);
    if(ifindex != iif->ifindex)
        iif->ifindex = ifindex;

    if(iif->ifindex > 0) {
        rc = if_macaddr(iif->ifname, iif->ifindex, iif->mac);
        if(rc < 0)
            memset(iif->mac, 0, 6);
    }
}

int
main(int argc, char **argv)
{
    int rc, opt;

    while(1) {
        opt = getopt(argc, argv, "f:P:d:N:F:");
        if(opt < 0)
            break;

        switch(opt) {
        case 'f': {
            int p;
            char *end;
            p = strtol(optarg, &end, 0);
            if(*end != '\0' || p <= 0 || p > 0xFFFF)
                goto usage;
            server_port = p;
        }
            break;
        case 'P': {
            unsigned char buf[16];
            int plen, af;
            af = parse_prefix(optarg, buf, &plen);
            if(af == 4) {
                memcpy(v4prefix, buf, 4);
                v4plen = plen;
            } else if(af == 6) {
                memcpy(v6prefix, buf, 16);
                v6plen = plen;
            } else {
                goto usage;
            }
        }
            break;
        case 'd': {
            char *end;
            debug_level = strtol(optarg, &end, 0);
            if(*end != '\0')
                goto usage;
            break;
        }
        case 'N': {
            unsigned char buf[16];
            int af;
            af = parse_address(optarg, buf);
            if(af == 4) {
                if(numdnsv4 >= 16)
                    goto usage;
                memcpy(dnsv4[numdnsv4++], buf, 4);
            } else if(af == 6) {
                if(numdnsv6 >= 16)
                    goto usage;
                memcpy(dnsv6[numdnsv6++], buf, 16);
            } else {
                goto usage;
            }
        }
            break;
        case 'F': {
            unsigned char buf[16];
            unsigned short port;
            int af;
            af = parse_addrport(optarg, buf, &port);
            if(af >= 0) {
                struct sockaddr_in6 sin6;
                memset(&sin6, 0, sizeof(sin6));
                sin6.sin6_family = AF_INET6;
                if(af == 4) {
                    memcpy(&sin6.sin6_addr, v4mapped, 12);
                    memcpy((unsigned char*)&sin6.sin6_addr + 12, buf, 4);
                } else if(af == 6) {
                    memcpy(&sin6.sin6_addr, buf, 16);
                } else
                    goto usage;
                sin6.sin6_port = htons(port);
                flood_connect(&sin6);
            } else {
                goto usage;
            }
        }
            break;
        default:
            goto usage;
        }
    }

    rc = read_random_bytes(myid, sizeof(myid));
    if(rc < 0) {
        perror("read_random_bytes");
        exit(1);
    }

    for(int i = optind; i < argc; i++) {
        struct interface *n =
            realloc(interfaces,
                    (numinterfaces + 1) * sizeof(struct interface));
        if(n == NULL) {
            perror("alloc(interfaces)");
            exit(1);
        }
        interfaces = n;
        memset(&interfaces[numinterfaces], 0, sizeof(struct interface));
        interfaces[numinterfaces].ifname = argv[i];
        numinterfaces++;
    }

    init_signals();

    rc = netlink_init(callback);
    if(rc < 0) {
        perror("netlink_init");
        exit(1);
    }

    for(int i = 0; i < numinterfaces; i++) {
        check_interface(&interfaces[i]);
        if(interfaces[i].ifindex > 0) {
            rc = netlink_dump(interfaces[i].ifindex);
            if(rc < 0)
                perror("netlink_dump");
        }
    }

    rc = flood_setup(datum_callback);
    if(rc < 0) {
        perror("flood_setup");
        exit(1);
    }

    if(numinterfaces > 0) {
        rc = ra_setup();
        if(rc < 0) {
            perror("ra_setup");
            exit(1);
        }

        rc = dhcpv4_setup();
        if(rc < 0) {
            perror("dhcpv4_setup");
            exit(1);
        }
    }

    while(1) {
        fd_set readfds, writefds;
        int nls = netlink_socket();
        int maxfd;
        struct timespec now, deadline;

        FD_ZERO(&readfds);
        FD_ZERO(&writefds);

        FD_SET(nls, &readfds);
        maxfd = nls;

        if(numinterfaces > 0) {
            FD_SET(ra_socket, &readfds);
            maxfd = max(maxfd, ra_socket);
            FD_SET(dhcpv4_socket, &readfds);
            maxfd = max(maxfd, dhcpv4_socket);
        }

        FD_SET(server_socket, &readfds);
        maxfd = max(maxfd, server_socket);

        for(int i = 0; i < numneighs; i++) {
            if(neighs[i].fd >= 0) {
                if(neighs[i].out.len > 0)
                    FD_SET(neighs[i].fd, &writefds);
                FD_SET(neighs[i].fd, &readfds);
                maxfd = max(maxfd, neighs[i].fd);
            }
        }

        clock_gettime(CLOCK_MONOTONIC, &now);
        ts_minus(&deadline, &expire_neighs_time, &now);
        rc = pselect(maxfd + 1, &readfds, &writefds, NULL, &deadline, NULL);
        if(rc < 0 && errno != EINTR) {
            perror("pselect");
            sleep(1);
        }
        clock_gettime(CLOCK_MONOTONIC, &now);

        if(exiting)
            break;

        if(dumping) {
            static const char zeroes[8] = {0};
            printf("Interfaces");
            for(int i = 0; i < numinterfaces; i++)
                printf(" %s", interfaces[i].ifname);
            printf(".\n");
            for(int i = 0; i < numdata; i++) {
                if(data[i]->keylen < 1) {
                    printf("Datum %d %d", data[i]->keylen, data[i]->vallen);
                    continue;
                }
                switch(datum_key(data[i])[0]) {
                case DATUM_IPv4_LEASE:
                case DATUM_IPv6_LEASE: {
                    char addr[INET6_ADDRSTRLEN];
                    if(datum_key(data[i])[0] == DATUM_IPv4_LEASE &&
                       data[i]->keylen == 5) {
                        inet_ntop(AF_INET, datum_key(data[i]) + 1,
                                  addr, sizeof(addr));
                    } else if(datum_key(data[i])[0] == DATUM_IPv6_LEASE &&
                              data[i]->keylen == 9) {
                        unsigned char ipv6[16];
                        memcpy(ipv6, datum_key(data[i]) + 1, 8);
                        memset(ipv6 + 8, 0, 8);
                        inet_ntop(AF_INET6, ipv6, addr, sizeof(addr));
                        strncat(addr, "/64", sizeof(addr) - 1);
                       } else {
                        strncpy(addr, "(corrupt)", sizeof(addr));
                    }
                    printf("Lease %s %s %d %ds.\n",
                           addr,
                           data[i]->vallen == 6 ?
                           format_48(datum_val(data[i])) :
                           "(corrupt)",
                           data[i]->seqno,
                           (int)(data[i]->time - now.tv_sec));
                    break;
                }
                case DATUM_ASSOCIATED: {
                    char mac[24], id[28];
                    if(data[i]->keylen == 7)
                        strncpy(mac, format_48(datum_key(data[i]) + 1), 20);
                    else
                        strncpy(mac, "(truncated)", 20);
                    if(data[i]->vallen == 8)
                        strncpy(id, format_64(datum_val(data[i])), 20);
                    else
                        strncpy(id, "(truncated)", 20);
                    printf("Assoc %s %s %d %ds.\n",
                           data[i]->keylen == 7 ?
                           format_48(datum_key(data[i]) + 1) : "(corrupt)",
                           data[i]->vallen == 0 ? "(gone)" :
                           data[i]->vallen == 8 ?
                           format_64(datum_val(data[i])) : "(corrupt)",
                           data[i]->seqno,
                           (int)(data[i]->time - now.tv_sec));
                    break;
                }
                default:
                    printf("Datum %d %d %d %d %ds.\n",
                           data[i]->keylen, data[i]->vallen,
                           datum_key(data[i])[0],
                           data[i]->seqno,
                           (int)(data[i]->time - now.tv_sec));
                }
            }
            for(int i = 0; i < numclients; i++) {
                char buf[INET6_ADDRSTRLEN];
                printf("Client %s if %s",
                       format_48(clients[i].mac), clients[i].interface->ifname);
                if(memcmp(clients[i].ipv4, zeroes, 8) != 0) {
                   inet_ntop(AF_INET, clients[i].ipv4, buf, sizeof(buf));
                   printf(" ipv4 %s", buf);
                }
                if(memcmp(clients[i].ipv6, zeroes, 8) != 0) {
                    unsigned char ipv6[16];
                    memcpy(ipv6, clients[i].ipv6, 8);
                    memset(ipv6 + 8, 0, 8);
                    inet_ntop(AF_INET6, ipv6, buf, sizeof(buf));
                    printf(" ipv6 %s/64", buf);
                }
                printf(".\n");
            }
            printf("\n");
            for(int i = 0; i < numneighs; i++) {
                printf("Neighbour %d.\n", neighs[i].fd);
            }

            fflush(stdout);

            dumping = 0;
        }

        if(rc >= 0) {
            if(FD_ISSET(nls, &readfds)) {
                rc = netlink_listen();
                if(rc < 0)
                    nl_perror(rc, "netlink_listen");
            }

            if(FD_ISSET(server_socket, &readfds))
                flood_accept();

            for(int i = 0; i < numneighs; i++) {
                if(neighs[i].fd >= 0) {
                    if(FD_ISSET(neighs[i].fd, &readfds))
                        flood_read(&neighs[i]);
                    if(FD_ISSET(neighs[i].fd, &writefds))
                        flood_write(&neighs[i]);
                }
            }
            if(numinterfaces > 0) {
                if(FD_ISSET(ra_socket, &readfds))
                    receive_rs();

                if(FD_ISSET(dhcpv4_socket, &readfds))
                    dhcpv4_receive();
            }
        }

        if(ts_compare(&now, &expire_neighs_time) >= 0)
            expire_neighs();
    }

    client_cleanup();
    if(numinterfaces > 0) {
        ra_cleanup();
        dhcpv4_cleanup();
    }
    flood_cleanup();

    return 0;

 usage:
    fprintf(stderr,
            "Usage: sroamd [-d level] [-P prefix]... [-N nameserver]...\n"
            "              [-f port] [-F addr:port]... [interface]...\n");
    exit(1);
}
