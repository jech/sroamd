#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include <fcntl.h>
#include <sys/socket.h>
#define __USE_GNU
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "interface.h"
#include "lease.h"
#include "flood.h"
#include "util.h"

int flood_socket = -1;
int flood_port = 4444;

struct datum **data = NULL;
int numdata = 0, maxdata = 0;

struct timespec flood_time = {0, 0};

static void
schedule_flood()
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    ts_add_msec(&flood_time, &now, 1);
}

static void (*datum_callback)(struct datum *, int) = NULL;

static int buffer_update(struct neighbour *neigh,
                         const unsigned char *key, int keylen, int acked);
static int record_unacked(struct neighbour *neigh,
                          const unsigned char *key, int keylen);
static int flush_unacked(struct neighbour *neigh,
                         const unsigned char *key, int keylen);

static int
seqno_compare(unsigned short s1, unsigned short s2)
{
    if(s1 == s2)
        return 0;
    else
        return ((s2 - s1) & 0x8000) ? 1 : -1;
}

struct datum *
find_datum(const unsigned char *key, int keylen)
{
    for(int i = 0; i < numdata; i++) {
        if(data[i]->keylen == keylen &&
           memcmp(data[i]->datum, key, keylen) == 0)
            return data[i];
    }
    return NULL;
}

struct datum *
update_datum(const unsigned char *key, int keylen,
             unsigned short seqno,
             const unsigned char *val, int vallen,
             int time, int *updated, int *conflict)
{
    struct datum *datum;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    for(int i = 0; i < numdata; i++) {
        if(data[i]->keylen == keylen &&
           memcmp(data[i]->datum, key, keylen) == 0) {
            int cmp = seqno_compare(data[i]->seqno, seqno);
            if(cmp > 0) {
                if(updated != NULL)
                    *updated = 0;
                if(conflict != NULL)
                    *conflict = 0;
                return data[i];
            } else if(cmp == 0) {
                if(data[i]->vallen == vallen &&
                   memcmp(datum_val(data[i]), val, vallen) == 0) {
                    int u = 0;
                    if(data[i]->time < now.tv_sec + time) {
                        data[i]->time = now.tv_sec + time;
                        u = 1;
                    }
                    if(updated != NULL)
                        *updated = u;
                    if(conflict != NULL)
                        *conflict = 0;
                    return data[i];
                } else {
                    /* conflict */
                    if(data[i]->time > now.tv_sec + time) {
                        /* we win */
                        if(updated != NULL)
                            *updated = 0;
                        if(conflict != NULL)
                            *conflict = 1;
                        return data[i];
                    }
                    /* they win */
                    if(data[i]->vallen != vallen) {
                        datum =
                            realloc(data[i], sizeof(struct datum) + keylen + vallen);
                        if(datum == NULL)
                            return NULL;
                        datum->vallen = vallen;
                        data[i] = datum;
                    }
                    data[i]->time = now.tv_sec + time;
                    if(updated != NULL)
                        *updated = 1;
                    if(conflict != NULL)
                        *conflict = 1;
                    return data[i];
                }
            } else {
                if(data[i]->vallen != vallen) {
                    datum =
                        realloc(data[i], sizeof(struct datum) + keylen + vallen);
                    if(datum == NULL)
                        return NULL;
                    datum->vallen = vallen;
                    data[i] = datum;
                }
                data[i]->seqno = seqno;
                memcpy(data[i]->datum + keylen, val, vallen);
                data[i]->time = now.tv_sec + time;
                if(updated != NULL)
                    *updated = 1;
                if(conflict != NULL)
                    *conflict = 0;
                return data[i];
            }
        }
    }

    if(maxdata <= numdata) {
        int n = maxdata == 0 ? 8 : 2 * maxdata;
        struct datum **newdata =
            realloc(data, n * sizeof(struct datum*));
        if(newdata != NULL) {
            data = newdata;
            maxdata = n;
        }
    }
    if(maxdata <= numdata)
        return NULL;

    datum = calloc(1, sizeof(struct datum) + keylen + vallen);
    if(datum == NULL) {
        if(updated != NULL)
            *updated = 0;
        if(conflict != NULL)
            *conflict = 0;
        return NULL;
    }

    datum->seqno = seqno;
    datum->keylen = keylen;
    memcpy(datum->datum, key, keylen);
    datum->vallen = vallen;
    memcpy(datum->datum + keylen, val, vallen);
    datum->time = now.tv_sec + time;
    data[numdata++] = datum;
    if(updated != NULL)
        *updated = 1;
    if(conflict != NULL)
        *conflict = 0;
    return datum;
}

void
flush_datum(struct datum *datum)
{
    for(int i = 0; i < numdata; i++) {
        if(data[i] == datum) {
            if(i < numdata - 1)
                memmove(data + i, data + i + 1,
                        (numdata - i - 1) * sizeof(struct datum));
            numdata--;
            return;
        }
    }
    abort();
}

time_t
datum_remaining(const struct datum *datum)
{
    struct timespec now;
    time_t t;
    clock_gettime(CLOCK_MONOTONIC, &now);
    t = datum->time - now.tv_sec;
    if(t < 0)
        return 0;
    return t;
}

int
extend_datum(struct datum *datum, time_t extend)
{
    if(extend >= 0) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if(datum->time < now.tv_sec)
            datum->seqno = (datum->seqno + 1) & 0xFFFF;
        if(datum->time < now.tv_sec + extend) {
            datum->time = now.tv_sec + extend;
            return 1;
        }
    }

    return 0;
}

struct neighbour *neighbours = NULL;
int numneighbours = 0, maxneighbours = 0;

static int send_dump_request(struct neighbour *neigh);
static int send_dump_reply(struct neighbour *neigh);

int
flood_setup(void (*callback)(struct datum *, int))
{
    struct sockaddr_in6 sin6;
    int s, rc, saved_errno;
    int zero = 0, one = 1;

    s = socket(PF_INET6, SOCK_DGRAM, 0);
    if(s < 0)
        return -1;

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_GETFL, 0);
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_SETFL, (rc | O_NONBLOCK));
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_GETFD, 0);
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_SETFD, rc | FD_CLOEXEC);
    if(rc < 0)
        goto fail;

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
    if(rc < 0)
        goto fail;

    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(flood_port);
    rc = bind(s, (struct sockaddr*)&sin6, sizeof(sin6));
    if(rc < 0)
        goto fail;

    flood_socket = s;

    datum_callback = callback;

    periodic_flood();

    return 1;

 fail:
    saved_errno = errno;
    close(s);
    errno = saved_errno;
    return -1;
}

void
flood_cleanup()
{
    close(flood_socket);
    flood_socket = -1;
}

static void
commit_neighbour(struct neighbour *neigh, int update, int permanent)
{
    if(update) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        neigh->time = now.tv_sec;
    }
    if(permanent)
        neigh->permanent = 1;
}

static int
match(const struct sockaddr_in6 *a, const struct sockaddr_in6 *b)
{
    return a->sin6_port == b->sin6_port &&
        memcmp(&a->sin6_addr, &b->sin6_addr, 16) == 0;
}

struct neighbour *
find_neighbour(struct sockaddr_in6 *sin6, int create, int update, int permanent)
{
    for(int i = 0; i < numneighbours; i++) {
        if(match(sin6, &neighbours[i].addr)) {
            commit_neighbour(&neighbours[i], update, permanent);
            return &neighbours[i];
        }
    }

    if(!create)
        return NULL;

    if(maxneighbours <= numneighbours) {
        int n = maxneighbours == 0 ? 8 : 2 * maxneighbours;
        struct neighbour *newneighbours =
            realloc(neighbours, n * sizeof(struct neighbour));
        if(newneighbours != NULL) {
            neighbours = newneighbours;
            maxneighbours = n;
        }
    }
    if(maxneighbours <= numneighbours)
        return NULL;

    memset(&neighbours[numneighbours], 0, sizeof(struct neighbour));
    memcpy(&neighbours[numneighbours].addr, sin6, sizeof(struct sockaddr_in6));
    neighbours[numneighbours].dump_done = 0;
    commit_neighbour(&neighbours[numneighbours], update, permanent);
    numneighbours++;
    return &neighbours[numneighbours-1];
}

void
flush_neighbour(struct neighbour *neigh)
{
    int i = neigh - neighbours;
    assert(i >= 0 && i < numneighbours);
    free(neighbours[i].unacked);
    neighbours[i].unacked = NULL;
    free(neighbours[i].pktinfo);
    neighbours[i].pktinfo = NULL;
    if(i < numneighbours - 1)
        memmove(neighbours + i, neighbours + i + 1,
                (numneighbours - i - 1) * sizeof(struct neighbour));
    numneighbours--;
}

static void
parse_packet(struct sockaddr_in6 *from, struct in6_pktinfo *info,
             const unsigned char *packet, int packetlen)
{
    struct neighbour *neigh;
    unsigned int bodylen;
    int i;

    if(packetlen < 4)
        return;

    if(packet[0] != 44 || packet[1] != 0)
        return;

    DO_NTOHS(bodylen, packet + 2);

    if(bodylen + 4 > packetlen) {
        fprintf(stderr, "Received truncated packet.\n");
        return;
    }

    neigh = find_neighbour(from, 1, 1, 0);
    if(neigh == NULL)
        return;

    if(info != NULL) {
        if(neigh->pktinfo != NULL) {
            if(memcmp(neigh->pktinfo, info, sizeof(struct in6_pktinfo)) != 0) {
                free(neigh->pktinfo);
                neigh->pktinfo = NULL;
            }
        }
        if(neigh->pktinfo == NULL)
            neigh->pktinfo = malloc(sizeof(struct in6_pktinfo));
        if(neigh->pktinfo != NULL)
            memcpy(neigh->pktinfo, info, sizeof(struct in6_pktinfo));
    }

    i = 0;
    while(i < bodylen) {
        const unsigned char *tlv = packet + 4 + i;
        int len;
        if(tlv[0] == 0) {
            i++;
            continue;
        }
        if(i + 1 > bodylen)
            return;
        len = tlv[1];
        if(i + len + 2 > bodylen)
            return;

        switch(tlv[0]) {
        case 1:
            debugf("<- PAD1\n");
            break;
        case 2: {
            struct datum *datum;
            unsigned char keylen;
            unsigned short seqno;
            unsigned int time;
            int ack, doit, conflict;
            if(len < 2) {
                debugf("Truncated DATUM.\n");
                goto skip;
            }
            ack = !!(tlv[2] & 0x80);
            DO_NTOHS(seqno, tlv + 3);
            DO_NTOHL(time, tlv + 5);
            keylen = tlv[9];
            if(len < keylen + 8) {
                debugf("Truncated DATUM.\n");
                goto skip;
            }
            debugf("<- DATUM %d (%d) %ld%s\n",
                   keylen <= 0 ? -1 : (int)tlv[10], keylen, (long)time,
                   ack ? " (ack)" : "");
            datum = find_datum(tlv+10, keylen);
            if(datum != NULL && seqno >= datum->seqno) {
                flush_unacked(neigh, tlv+10, keylen);
            }
            datum = update_datum(tlv + 10, keylen, seqno,
                                 tlv + 10 + keylen, len - keylen - 8,
                                 time, &doit, &conflict);
            if(doit && datum_callback != NULL)
                datum_callback(datum, conflict);
            if(doit || ack)
                flood(datum, neigh, ack, doit);
        }
            break;
        case 3:
            debugf("<- DUMP\n");
            send_dump_reply(neigh);
            for(int i = 0; i < numneighbours; i++) {
                for(int j = 0; j < numdata; j++)
                    record_unacked(&neighbours[i],
                                   datum_key(data[j]), data[j]->keylen);
            }
            schedule_flood();
            break;
        case 4:
            debugf("<- DUMP-ACK\n");
            neigh->dump_done = 1;
            break;
        default:
            debugf("Unknown TLV %d\n", tlv[0]);
        }

    skip:
        i += 2 + len;
    }
    flush_updates(neigh, 1);
}

int
flood_listen(void)
{
    struct sockaddr_in6 from;
    struct in6_pktinfo *info;
    unsigned char buf[4096];
    struct iovec iov[1];
    struct msghdr msg;
    int cmsglen = 100;
    char cmsgbuf[cmsglen];
    struct cmsghdr *cmsg = (struct cmsghdr*)cmsgbuf;
    int rc;

    iov[0].iov_base = buf;
    iov[0].iov_len = 4096;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &from;
    msg.msg_namelen = sizeof(from);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg;
    msg.msg_controllen = cmsglen;

    rc = recvmsg(flood_socket, &msg, 0);

    if(rc < 0)
        return rc;

    info = NULL;
    cmsg = CMSG_FIRSTHDR(&msg);
    while(cmsg != NULL) {
        if ((cmsg->cmsg_level == IPPROTO_IPV6) &&
            (cmsg->cmsg_type == IPV6_PKTINFO)) {
            info = (struct in6_pktinfo*)CMSG_DATA(cmsg);
            break;
        }
        cmsg = CMSG_NXTHDR(&msg, cmsg);
    }

    if(info == NULL) {
        errno = EINVAL;
        return -1;
    }

    parse_packet(&from, info, buf, rc);
    return 1;
}

static int
send_neighbour(struct neighbour *neigh, unsigned char *buf, int buflen)
{
    struct timespec now;
    struct msghdr msg;
    struct iovec iov[1];
    struct cmsghdr *cmsg;
    union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    } u;

    clock_gettime(CLOCK_MONOTONIC, &now);
    neigh->send_time = now.tv_sec;

    iov[0].iov_base = buf;
    iov[0].iov_len = buflen;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (struct sockaddr*)&neigh->addr;
    msg.msg_namelen = sizeof(neigh->addr);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    if(neigh->pktinfo != NULL) {
        memset(u.buf, 0, sizeof(u.buf));
        msg.msg_control = u.buf;
        msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
        memcpy(CMSG_DATA(cmsg), neigh->pktinfo, sizeof(struct in6_pktinfo));
    }

    return sendmsg(flood_socket, &msg, 0);

}

static int
send_dump_request(struct neighbour *neigh)
{
    unsigned char buf[6] = {44, 0, 0, 2, 3, 0};
    debugf("-> DUMP\n");
    return send_neighbour(neigh, buf, 6);
}

static int
send_dump_reply(struct neighbour *neigh)
{
    unsigned char buf[6] = {44, 0, 0, 2, 4, 0};
    debugf("-> DUMP-ACK\n");
    return send_neighbour(neigh, buf, 6);
}

int
flush_updates(struct neighbour *neigh, int all)
{
    unsigned char buf[1024] = {44, 0, 0, 0};
    struct timespec now;
    time_t time;
    int i, n, rc = 0;

    if(neigh->numbuffered == 0)
        return 0;

    clock_gettime(CLOCK_MONOTONIC, &now);

    i = 0;
    for(n = 0; n < neigh->numbuffered; n++) {
        struct datum *datum;

        if(i == 0) {
            buf[i] = 44; i++;
            buf[i] = 0; i++;
            buf[i] = 0; i++;
            buf[i] = 0; i++;
        }

        datum = find_datum(neigh->buffered[n].key, neigh->buffered[n].keylen);
        free(neigh->buffered[n].key);
        neigh->buffered[n].key = NULL;
        if(datum == NULL)
            continue;
        time = datum->time - now.tv_sec;
        if(time <= 0)
            continue;
        if(time > 0xFFFFFFFF)
            time = 0xFFFFFFFF;

        buf[i++] = 2;
        buf[i++] = 1 + 2 + 4 + 1 + datum->keylen + datum->vallen;
        buf[i++] = neigh->buffered[n].acked ? 0x80 : 0;
        DO_HTONS(buf + i, datum->seqno); i += 2;
        DO_HTONL(buf + i, time); i += 4;
        buf[i++] = datum->keylen;
        memcpy(buf + i, datum->datum, datum->keylen + datum->vallen);
        i += datum->keylen + datum->vallen;

        debugf("-> DATUM %d (%d) %ld%s\n",
               datum->keylen <= 0 ? -1 : datum->datum[0], datum->keylen,
               (long)time, neigh->buffered[n].acked ? " (ack)" : "");

        if(i >= 1024 - 32) {
            if(!all)
                break;
            DO_HTONS(buf + 2, i - 4);
            rc = send_neighbour(neigh, buf, i);
        }
    }

    if(i > 0) {
        DO_HTONS(buf + 2, i - 4);
        rc = send_neighbour(neigh, buf, i);
    }

    if(n < neigh->numbuffered) {
        memmove(neigh->buffered, neigh->buffered + n,
                (neigh->numbuffered - n) * sizeof(struct buffered));
        neigh->numbuffered -= n;
    } else {
        neigh->numbuffered = 0;
    }

    return rc;
}

static int
buffer_update(struct neighbour *neigh, const unsigned char *key, int keylen,
              int acked)
{
    unsigned char *newkey;

    if(neigh->buffered == NULL) {
        neigh->buffered = malloc(MAXBUFFERED * sizeof(struct buffered));
        if(neigh->buffered == NULL)
            return -1;
    }
    if(neigh->numbuffered >= MAXBUFFERED)
        flush_updates(neigh, 0);
    assert(neigh->numbuffered < MAXBUFFERED);

    newkey = malloc(keylen);
    if(newkey == NULL)
        return -1;
    memcpy(newkey, key, keylen);

    neigh->buffered[neigh->numbuffered].key = newkey;
    neigh->buffered[neigh->numbuffered].keylen = keylen;
    neigh->buffered[neigh->numbuffered].acked = acked;
    neigh->numbuffered++;

    return 1;
}

static int
send_keepalive(struct neighbour *neigh)
{
    unsigned char buf[4] = {44, 0, 0, 0};
    debugf("-> Keepalive\n");
    return send_neighbour(neigh, buf, 4);
}

static int
neighbour_alive(struct neighbour *neigh, time_t now)
{
    if(neigh->permanent)
        return 1;
    return neigh->time > now - 240;
}

void
flood(struct datum *datum, struct neighbour *neigh, int ack, int doit)
{
    struct timespec now;
    if(ack && neigh != NULL)
        buffer_update(neigh, datum_key(datum), datum->keylen, 0);

    clock_gettime(CLOCK_MONOTONIC, &now);
    if(doit) {
        for(int i = 0; i < numneighbours; i++) {
            if(neighbour_alive(&neighbours[i], now.tv_sec) &&
               &neighbours[i] != neigh)
                record_unacked(&neighbours[i], datum_key(datum), datum->keylen);
        }
    }
    schedule_flood();
}

static struct unacked *
find_unacked(struct neighbour *neigh, const unsigned char *key, int keylen)
{
    for(int i = 0; i < neigh->numunacked; i++) {
        if(neigh->unacked[i].keylen == keylen &&
           memcmp(neigh->unacked[i].key, key, keylen) == 0)
            return &neigh->unacked[i];
    }
    return NULL;
}

static int
record_unacked(struct neighbour *neigh, const unsigned char *key, int keylen)
{
    struct unacked *unacked;
    struct timespec now;
    unsigned char *newkey;

    clock_gettime(CLOCK_MONOTONIC, &now);

    unacked = find_unacked(neigh, key, keylen);
    if(unacked != NULL) {
        unacked->count = 0;
        unacked->time = now.tv_sec;
        return 0;
    }

    if(neigh->numunacked >= neigh->maxunacked) {
        struct unacked *n;
        int count = neigh->maxunacked * 3 / 2;
        if(count < 8)
            count = 8;
        n = realloc(neigh->unacked, count * sizeof(struct unacked));
        if(n == NULL)
            return -1;
        neigh->unacked = n;
        neigh->maxunacked = count;
    }

    newkey = malloc(keylen);
    if(newkey == NULL)
        return -1;
    memcpy(newkey, key, keylen);

    neigh->unacked[neigh->numunacked].count = 0;
    neigh->unacked[neigh->numunacked].key = newkey;
    neigh->unacked[neigh->numunacked].keylen = keylen;
    neigh->unacked[neigh->numunacked].time = now.tv_sec;
    neigh->numunacked++;

    schedule_flood();
    return 1;
}

static int
flush_unacked(struct neighbour *neigh, const unsigned char *key, int keylen)
{
    int i;
    struct unacked *unacked;

    unacked = find_unacked(neigh, key, keylen);
    if(unacked == NULL)
        return 0;
    i = unacked - neigh->unacked;
    assert(i >= 0 && i < neigh->numunacked);

    free(neigh->unacked[i].key);
    neigh->unacked[i].key = NULL;

    if(i < neigh->numunacked - 1)
        memmove(neigh->unacked + i, neigh->unacked + i + 1,
                (neigh->numunacked - i - 1) * sizeof(struct unacked));
    neigh->numunacked--;
    return 1;
}

static struct timespec expire_neighbours_time = {0, 0};

static void
expire_neighbours()
{
    struct timespec now;
    int i;
    clock_gettime(CLOCK_MONOTONIC, &now);

    i = 0;
    while(i < numneighbours) {
        if(neighbour_alive(&neighbours[i], now.tv_sec)) {
            if(neighbours[i].send_time < now.tv_sec - 60)
                send_keepalive(&neighbours[i]);
            i++;
        } else {
            flush_neighbour(&neighbours[i]);
        }
    }
}

void
periodic_flood()
{
    struct timespec now;
    int work = 0;

    clock_gettime(CLOCK_MONOTONIC, &now);

    if(ts_compare(&expire_neighbours_time, &now) <= 0) {
        expire_neighbours();
        expire_neighbours_time = now;
        expire_neighbours_time.tv_sec += 10;
    }
    for(int i = 0; i < numneighbours; i++) {
        if(!neighbours[i].dump_done && neighbours[i].dump_request_count < 4) {
            work = 1;
            send_dump_request(&neighbours[i]);
            neighbours[i].dump_request_count++;
        }
        if(neighbours[i].numunacked > 0)
            work = 1;
        for(int j = 0; j < neighbours[i].numunacked; j++) {
            struct unacked *unacked = &neighbours[i].unacked[j];
            struct timespec soon = {unacked->time, 0};
            if(unacked->count > 0)
                soon.tv_sec += 1 << (unacked->count - 1);
            if(ts_compare(&soon, &now) <= 0) {
                buffer_update(&neighbours[i], unacked->key, unacked->keylen, 1);
                unacked->count++;
            }
        }
        flush_updates(&neighbours[i], 1);
    }
    if(work) {
        flood_time = now;
        flood_time.tv_sec += 1;
    } else {
        flood_time.tv_sec = 0;
        flood_time.tv_nsec = 0;
    }
}
