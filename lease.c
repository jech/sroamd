#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include "prefix.h"
#include "client.h"
#include "flood.h"
#include "lease.h"

unsigned char myid[8];

#define LEASE_FUDGE 10

unsigned char v4prefix[4], v6prefix[16];
int v4plen = -1, v6plen = -1;

const unsigned char zeroes[8] = {0};

struct datum *
find_lease(const unsigned char *mac, int ipv6)
{
    struct datum *datum = NULL;

    /* In general, multiple leases can point to the same MAC.  Pick the
       one that's lexicographically smallest.  Perhaps we should be
       routing all of the addresses instead?  */

    for(int i = 0; i < numdata; i++) {
        if(data[i]->keylen < 1)
            continue;
        if(datum_key(data[i])[0] !=
           (ipv6 ? DATUM_IPv6_LEASE : DATUM_IPv4_LEASE) ||
           data[i]->keylen != (ipv6 ? 9 : 5))
            continue;
        if(data[i]->vallen != 6 || memcmp(datum_val(data[i]), mac, 6) != 0)
            continue;
        if(datum == NULL || memcmp(datum_val(data[i]), datum_val(datum), 6) < 0)
            datum = data[i];
    }
    return datum;
}

struct datum *
find_lease_by_ip(const unsigned char *a, int ipv6)
{
    if(ipv6) {
        for(int i = 0; i < numdata; i++) {
            if(data[i]->keylen == 9 &&
               datum_key(data[i])[0] == DATUM_IPv6_LEASE &&
               memcmp(datum_key(data[i]) + 1, a, 8) == 0)
                return data[i];
        }
    } else {
        for(int i = 0; i < numdata; i++) {
            if(data[i]->keylen == 5 &&
               datum_key(data[i])[0] == DATUM_IPv4_LEASE &&
               memcmp(datum_key(data[i]) + 1, a, 4) == 0)
                return data[i];
        }
    }
    return NULL;
}

static struct datum *
make_lease(const unsigned char *suggested, const unsigned char *mac, int ipv6)
{
    struct datum *datum = NULL;
    unsigned char key[9];
    struct timespec now;
    int ok;
    unsigned char addr[8];

    clock_gettime(CLOCK_MONOTONIC, &now);

    if(suggested)
        datum = find_lease_by_ip(suggested, ipv6);
    if(datum != NULL && datum->time + LEASE_FUDGE < now.tv_sec &&
       datum->vallen == 6) {
        memcpy((char*)datum_val(datum), mac, 6);
        return datum;
    } else {
        datum = NULL;
    }

    ok = 0;
    for(int i = 0; i < 32; i++) {
        int rc;
        if(!ipv6)
            rc = random_prefix(v4prefix, v4plen, addr, 32);
        else
            rc = random_prefix(v6prefix, v6plen, addr, 64);
        if(rc >= 0 && find_lease(addr, ipv6) == NULL) {
            ok = 1;
            break;
        }
    }

    if(!ok)
        return NULL;

    key[0] = ipv6 ? DATUM_IPv6_LEASE : DATUM_IPv4_LEASE;
    memcpy(key + 1, addr, ipv6 ? 8 : 4);
    return update_datum(key, ipv6 ? 9 : 5, 0, mac, 6, 0, NULL, NULL);
}

struct datum *
update_lease(const unsigned char *mac, int ipv6,
             const unsigned char *suggested,
             int time, int *doit_return)
{
    struct datum *datum;
    int doit;

    datum = find_lease(mac, ipv6);

    if(datum != NULL) {
        doit = extend_datum(datum, time);
        if(doit_return)
            *doit_return = doit;
        flood(datum, NULL);
        return datum;
    }

    if ((!ipv6 && (v4plen < 0 || v4plen > 32)) ||
        (ipv6 && (v6plen < 0 || v6plen > 64))) {
        return NULL;
    }

    datum = make_lease(suggested, mac, ipv6);
    if(datum == NULL)
        return NULL;

    doit = extend_datum(datum, time);
    if(doit_return)
        *doit_return = doit;
    update_client_routes(mac, lease_address(datum, ipv6), ipv6);
    flood(datum, NULL);
    return datum;
}

const unsigned char *
lease_address(const struct datum *datum, int ipv6)
{
    if(datum_key(datum)[0] != (ipv6 ? DATUM_IPv6_LEASE : DATUM_IPv4_LEASE))
        return NULL;
    if(datum->keylen != (ipv6 ? 9 : 5))
        return NULL;

    return datum_key(datum) + 1;
}

void
update_lease_routes(const struct datum *datum)
{
    int ipv6;
    if(datum->keylen < 1)
        return;
    if(datum_key(datum)[0] == DATUM_IPv6_LEASE)
        ipv6 = 1;
    else if(datum_key(datum)[0] == DATUM_IPv4_LEASE)
        ipv6 = 0;
    else
        return;

    if(datum->keylen != (ipv6 ? 9 : 5) || datum->vallen != 6)
        return;

    for(int i = 0; i < numclients; i++) {
        int match;
        if(ipv6)
            match = memcmp(clients[i].ipv6, datum_key(datum) + 1, 8) == 0;
        else
            match = memcmp(clients[i].ipv4, datum_key(datum) + 1, 4) == 0;
        if(match && memcmp(clients[i].mac, datum_val(datum), 6) != 0) {
            update_client_route(&clients[i], NULL, ipv6);
        }
    }
}

struct client *
update_association(struct interface *interface, const unsigned char *mac,
                   int time)
{
    unsigned char key[1 + 6];
    struct datum *datum;
    int seqno = 0;
    struct client *client;

    client = add_client(interface, mac);
    if(client == NULL)
        return NULL;

    key[0] = DATUM_ASSOCIATED;
    memcpy(key + 1, mac, 6);
    datum = find_datum(key, 7);
    if(datum != NULL) {
        if(datum->vallen == 8 &&
           memcmp(datum_val(datum), myid, 8) == 0) {
            extend_datum(datum, time);
            flood(datum, NULL);
            return client;
        } else {
            seqno = datum->seqno + 1;
        }
    }

    datum = update_datum(key, 7, seqno, myid, 8, time, NULL, NULL);
    flood(datum, NULL);
    return client;
}

void
flush_association(const unsigned char *mac, int time)
{
    unsigned char key[1 + 6];
    struct datum *datum;
    int seqno;

    flush_client(mac);

    key[0] = DATUM_ASSOCIATED;
    memcpy(key + 1, mac, 6);
    datum = find_datum(key, 7);
    if(datum == NULL || datum->vallen != 8 ||
       memcmp(datum_val(datum), myid, 8) != 0)
        return;

    seqno = datum->seqno + 1;

    datum = update_datum(key, 7, seqno, NULL, 0, time, NULL, NULL);
    flood(datum, NULL);
}
