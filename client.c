#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include <arpa/inet.h>

#include <netlink/errno.h>

#include "interface.h"
#include "client.h"
#include "netlink.h"

struct client *clients;
int numclients = 0, maxclients = 0;

struct client *
find_client(const unsigned char *mac)
{
    for(int i = 0; i < numclients; i++) {
        if(memcmp(clients[i].mac, mac, 6) == 0)
            return &clients[i];
    }
    return NULL;
}

struct client *
add_client(struct interface *interface, const unsigned char *mac)
{
    struct client *client;

    client = find_client(mac);
    if(client != NULL)
        return client;

    if(maxclients <= numclients) {
        int n = maxclients == 0 ? 8 : 2 * maxclients;
        struct client *newclients =
            realloc(clients, n * sizeof(struct client));
        if(newclients != NULL) {
            clients = newclients;
            maxclients = n;
        }
    }
    if(maxclients <= numclients)
        return NULL;

    memset(&clients[numclients], 0, sizeof(struct client));
    clients[numclients].interface = interface;
    memcpy(clients[numclients].mac, mac, 6);
    numclients++;
    return &clients[numclients - 1];
}

int
flush_client(const unsigned char *mac)
{
    int i;
    struct client *client;

    client = find_client(mac);
    if(client == NULL)
        return 0;
    i = client - clients;
    assert(i >= 0 && i < numclients);

    update_client_route(client, NULL, 0);
    update_client_route(client, NULL, 1);
    if(i < numclients - 1)
        memmove(clients + i, clients + i + 1, numclients - i - 1);
    numclients--;
    return 1;
}

static const char zeroes[8] = {0};

void
update_client_routes(const unsigned char *mac,
                     const unsigned char *addr, int ipv6)
{
    for(int i = 0; i < numclients; i++) {
        if(memcmp(clients[i].mac, mac, 6) == 0)
            update_client_route(&clients[i], addr, ipv6);
    }
}

void
client_cleanup()
{
    for(int i = 0; i < numclients; i++) {
        update_client_route(&clients[i], NULL, 0);
        update_client_route(&clients[i], NULL, 1);
    }
}

static const char zeroes[8];

int
update_client_route(struct client *client, const unsigned char *addr, int ipv6)
{
    int rc;

    if(ipv6) {
        unsigned char buf[16];
        if((addr == NULL && memcmp(client->ipv6, zeroes, 8) == 0) ||
           (addr != NULL && memcmp(client->ipv6, addr, 8) == 0))
            return 0;
        if(memcmp(client->ipv6, zeroes, 8) != 0) {
            memcpy(buf, client->ipv6, 8);
            memset(buf + 8, 0, 8);
            netlink_route(client->interface->ifindex, 0, 1, buf, 64);
            memset(client->ipv6, 0, 8);
        }
        if(addr != NULL) {
            memcpy(buf, addr, 8);
            memset(buf + 8, 0, 8);
            rc = netlink_route(client->interface->ifindex, 1, 1, buf, 64);
            if(rc < 0 && rc != -NLE_EXIST) {
                nl_perror(rc, "netlink_route");
                return rc;
            }
            memcpy(client->ipv6, addr, 8);
        } else {
            memcpy(client->ipv6, zeroes, 8);
        }
    } else {
        if((addr == NULL && memcmp(client->ipv4, zeroes, 4) == 0) ||
           (addr != NULL && memcmp(client->ipv4, addr, 4) == 0))
            return 0;
        if(memcmp(client->ipv4, zeroes, 4) != 0) {
            netlink_route(client->interface->ifindex, 0, 0, client->ipv4, 32);
            memset(client->ipv4, 0, 4);
        }
        if(addr != NULL) {
            rc = netlink_route(client->interface->ifindex, 1, 0, addr, 32);
            if(rc < 0 && rc != -NLE_EXIST) {
                nl_perror(rc, "netlink_route");
                return rc;
            }
            memcpy(client->ipv4, addr, 4);
        } else {
            memcpy(client->ipv4, zeroes, 4);
        }
    }
    return 1;
}
