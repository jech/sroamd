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

int server_socket = -1;
int server_port = -1;

struct datum **data = NULL;
int numdata = 0, maxdata = 0;

static void (*datum_callback)(struct datum *, int) = NULL;

static int parse_tlv(struct neighbour *neigh);
static int handshake(struct neighbour *neigh);
static int dump_data(struct neighbour *neigh);

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
    if(datum == NULL)
        return NULL;

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

struct neighbour *neighs = NULL;
int numneighs = 0, maxneighs = 0;

struct neighbour *
find_neighbour(int fd)
{
    for(int i = 0; i < numneighs; i++) {
        if(neighs[i].fd == fd)
            return &neighs[i];
    }
    return NULL;
}

struct neighbour *
create_neighbour()
{
    if(maxneighs <= numneighs) {
        int n = maxneighs == 0 ? 8 : 2 * maxneighs;
        struct neighbour *newneighs =
            realloc(neighs, n * sizeof(struct neighbour));
        if(newneighs != NULL) {
            neighs = newneighs;
            maxneighs = n;
        }
    }
    if(maxneighs <= numneighs)
        return NULL;

    memset(&neighs[numneighs], 0, sizeof(struct neighbour));
    neighs[numneighs].fd = -1;
    numneighs++;
    return &neighs[numneighs - 1];
}

void
flush_neighbour(struct neighbour *neigh)
{
    int i = neigh - neighs;
    assert(i >= 0 && i < numneighs);

    if(neigh->fd >= 0) {
        close(neigh->fd);
        neigh->fd = -1;
    }

    if(neigh->sin6 != NULL) {
        free(neigh->sin6);
        neigh->sin6 = NULL;
    }

    if(i < numneighs - 1)
        memmove(neighs + i, neighs + i + 1,
                (numneighs - i - 1) * sizeof(struct neighbour));
    numneighs--;
}

static int
setup_socket(int fd)
{
    int rc, saved_errno;
    int zero = 0;

    if(fd < 0) {
        fd = socket(PF_INET6, SOCK_STREAM, 0);
        if(fd < 0)
            return -1;

        rc = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
        if(rc < 0)
            goto fail;
    }

    rc = fcntl(fd, F_GETFL, 0);
    if(rc < 0)
        goto fail;

    rc = fcntl(fd, F_SETFL, (rc | O_NONBLOCK));
    if(rc < 0)
        goto fail;

    rc = fcntl(fd, F_GETFD, 0);
    if(rc < 0)
        goto fail;

    rc = fcntl(fd, F_SETFD, rc | FD_CLOEXEC);
    if(rc < 0)
        goto fail;

    return fd;

 fail:
    saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
}

int
flood_setup(void (*callback)(struct datum *, int))
{
    struct sockaddr_in6 sin6;
    int fd, rc, saved_errno;

    datum_callback = callback;

    if(server_port < 0)
        return 0;

    fd = setup_socket(-1);
    if(fd < 0)
        return -1;

    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(server_port);
    rc = bind(fd, (struct sockaddr*)&sin6, sizeof(sin6));
    if(rc < 0)
        goto fail;

    rc = listen(fd, 1024);
    if(rc < 0)
        goto fail;

    server_socket = fd;


    return 1;

 fail:
    saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
}

void
flood_cleanup()
{
    for(int i = 0; i < numneighs; i++) {
        if(neighs[i].fd >= 0) {
            close(neighs[i].fd);
            neighs[i].fd = -1;
        }
    }
    if(server_socket >= 0) {
        close(server_socket);
        server_socket = -1;
    }
}

int
flood_accept()
{
    int fd, rc;
    struct neighbour *neigh;

    fd = accept(server_socket, NULL, NULL);
    if(fd < 0) {
        if(errno != EAGAIN)
            perror("accept");
        return 0;
    }

    rc = setup_socket(fd);
    if(rc < 0) {
        perror("setup_socket(accept)");
        close(fd);
        return -1;
    }

    neigh = create_neighbour();
    if(neigh == NULL) {
        close(fd);
        return -1;
    }

    neigh->fd = fd;
    rc = handshake(neigh);
    if(rc < 0) {
        close(neigh->fd);
        neigh->fd = -1;
    }
    return 1;
}

static int
flood_reconnect(struct neighbour *neigh)
{
    int fd, rc;

    fd = setup_socket(-1);
    if(fd < 0) {
        return -1;
    }

    rc = connect(fd, (struct sockaddr*)neigh->sin6, sizeof(struct sockaddr_in6));
    if(rc < 0 && errno != EINPROGRESS) {
        perror("connect");
        close(fd);
        /* let the connect loop recover */
        return 0;
    }

    neigh->fd = fd;
    rc = handshake(neigh);
    if(rc < 0) {
        close(neigh->fd);
        neigh->fd = -1;
        return -1;
    }
    return 1;
}

int
flood_connect(const struct sockaddr_in6 *sin6)
{
    struct neighbour *neigh;
    neigh = create_neighbour();
    if(neigh == NULL)
        return -1;

    if(neigh->sin6 == NULL)
        neigh->sin6 = malloc(sizeof(struct sockaddr_in6));
    if(neigh->sin6 == NULL) {
        flush_neighbour(neigh);
        return -1;
    }
    memcpy(neigh->sin6, sin6, sizeof(struct sockaddr_in6));

    return flood_reconnect(neigh);
}

int
flood_read(struct neighbour *neigh)
{
    int rc;
    if(neigh->in.cap == 0) {
        neigh->in.buf = malloc(4096);
        if(neigh->in.buf == NULL) {
            close(neigh->fd);
            neigh->fd = -1;
            return -1;
        }
        neigh->in.cap = 4096;
    }

    if(neigh->in.len >= neigh->in.cap) {
        fprintf(stderr, "Read buffer overflow.\n");
        close(neigh->fd);
        neigh->fd = -1;
        return -1;
    }

    rc = read(neigh->fd,
              neigh->in.buf + neigh->in.len,
              neigh->in.cap - neigh->in.len);
    if(rc <= 0) {
        if(errno == EAGAIN)
            return 0;
        if(rc < 0)
            perror("read");
        close(neigh->fd);
        neigh->fd = -1;
    }
    neigh->in.len += rc;

    while(neigh->in.len > 0) {
        rc = parse_tlv(neigh);
        if(rc < 0) {
            close(neigh->fd);
            neigh->fd = -1;
            return -1;
        }
        if(rc == 0)
            return 1;

        memmove(neigh->in.buf, neigh->in.buf + rc,
                neigh->in.len - rc);
        neigh->in.len -= rc;
    }
    return 1;
}

int
flood_write(struct neighbour *neigh)
{
    int rc;

    if(neigh->fd < 0) {
        fprintf(stderr, "flood_write called for dead neighbour!\n");
        return -1;
    }

    if(neigh->out.len <= 0) {
        fprintf(stderr, "flood_write called but nothing to do!\n");
        return 0;
    }

    rc = write(neigh->fd, neigh->out.buf, neigh->out.len);
    if(rc < 0) {
        if(errno == EAGAIN)
            return 0;
        close(neigh->fd);
        neigh->fd = -1;
        return -1;
    }
    if(rc < neigh->out.len) {
        memmove(neigh->out.buf, neigh->out.buf + rc, neigh->out.len - rc);
        neigh->out.len -= rc;
    } else {
        neigh->out.len = 0;
    }
    return 1;
}

static int
parse_tlv(struct neighbour *neigh)
{
    int tpe, len;
    unsigned char *body;

    if(!neigh->handshake_received) {
        if(neigh->in.len < 4)
            return 0;
        if(neigh->in.buf[0] != 44 ||
           neigh->in.buf[1] != 1)
            return -1;
        debugf("<- Handshake\n");
        neigh->handshake_received = 1;
        if(!neigh->dump_sent) {
            int rc = dump_data(neigh);
            if(rc < 0)
                return rc;
        }
        return 4;
    }

    if(neigh->in.len < 1)
        return 0;

    if(neigh->in.buf[0] == 0) {
        debugf("<- PAD1\n");
        return 1;
    }

    if(neigh->in.len < 2)
        return 0;

    tpe = neigh->in.buf[0];
    len = neigh->in.buf[1];

    if(neigh->in.len < len + 2)
        return 0;

    body = neigh->in.buf + 2;

    switch(tpe) {
    case 1:
        debugf("<- PADN\n");
        break;
    case 2: {
        struct datum *datum;
        unsigned char keylen;
        unsigned short seqno;
        unsigned int time;
        int doit, conflict;
        if(len < 7) {
            debugf("Truncated Update.\n");
            return -1;
        }
        DO_NTOHS(seqno, body);
        DO_NTOHL(time, body + 2);
        keylen = body[6];
        if(len < keylen + 7) {
            debugf("Truncated Update.\n");
            return -1;
        }
        debugf("<- Update %d (%d) %ld\n",
               keylen <= 0 ? -1 : (int)body[7], keylen, (long)time);
        datum = update_datum(body + 7, keylen, seqno,
                             body + 7 + keylen, len - keylen - 7,
                             time, &doit, &conflict);
        if(datum != NULL && doit) {
            if(datum_callback != NULL)
                datum_callback(datum, conflict);
            flood(datum, neigh);
        }
    }
        break;
    default:
        debugf("Unknown TLV %d\n", tpe);
    }
    return 2 + len;
}

static int
expand_buffer(struct buffer *buf, int len)
{
    int cap;
    unsigned char *b;

    if(buf->cap - buf->len >= len)
        return 0;

    cap = buf->len + len;
    if(cap < buf->cap * 2)
        cap = buf->cap * 2;

    b = malloc(cap);
    if(b == NULL)
        return -1;
    memcpy(b, buf->buf, buf->len);
    free(buf->buf);
    buf->buf = b;
    buf->cap = cap;
    return 1;
}

static const unsigned char hs[4] = {44, 1, 0, 0};

static int
buffer_handshake(struct neighbour *neigh)
{
    int rc;
    rc = expand_buffer(&neigh->out, 4);
    if(rc < 0)
        return -1;
    memcpy(neigh->out.buf + neigh->out.len, hs, 4);
    neigh->out.len += 4;
    debugf("-> Handshake\n");
    return 1;
}

static int
buffer_tlv(struct neighbour *neigh, int tpe, int len, unsigned char *body)
{
    int rc;
    rc = expand_buffer(&neigh->out, 2 + len);
    if(rc < 0)
        return -1;

    neigh->out.buf[neigh->out.len++] = tpe;
    neigh->out.buf[neigh->out.len++] = len;
    memcpy(neigh->out.buf + neigh->out.len, body, len);
    neigh->out.len += len;
    return 1;
}

static int
buffer_update(struct neighbour *neigh, struct datum *datum)
{
    int len = 2 + 4 + 1 + datum->keylen + datum->vallen;
    unsigned char body[len];
    struct timespec now;
    time_t time;

    clock_gettime(CLOCK_MONOTONIC, &now);
    time = datum->time - now.tv_sec;
    if(time < 0)
        time = 0;
    if(time > 0xFFFFFFFF)
        time = 0xFFFFFFFF;
    DO_HTONS(body, datum->seqno);
    DO_HTONL(body + 2, (unsigned int)time);
    body[6] = datum->keylen;
    memcpy(body + 7, datum->datum, datum->keylen);
    memcpy(body + 7 + datum->keylen, datum->datum + datum->keylen,
           datum->vallen);
    debugf("-> Update\n");
    return buffer_tlv(neigh, 2, len, body);
}

static int
dump_data(struct neighbour *neigh)
{
    for(int i = 0; i < numdata; i++) {
        int rc = buffer_update(neigh, data[i]);
        if(rc < 0)
            return rc;
    }
    neigh->dump_sent = 1;
    return 1;
}

static int
handshake(struct neighbour *neigh)
{
    int rc;
    if(neigh->fd < 0)
        return -1;

    rc = buffer_handshake(neigh);
    if(rc < 0)
        return rc;

    if(neigh->handshake_received) {
        rc = dump_data(neigh);
        if(rc < 0)
            return rc;
    }

    return 1;
}

void
flood(struct datum *datum, struct neighbour *neigh)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    for(int i = 0; i < numneighs; i++) {
        if(neighs[i].fd >= 0 && &neighs[i] != neigh) {
            int rc;
            rc = buffer_update(&neighs[i], datum);
            if(rc < 0) {
                close(neighs[i].fd);
                neighs[i].fd = -1;
            }
        }
    }
}

struct timespec expire_neighs_time = {0, 0};

void
expire_neighs()
{
    int i = 0;
    while(i < numneighs) {
        if(neighs[i].fd >= 0) {
            i++;
        } else if(neighs[i].sin6 != NULL) {
            flood_reconnect(&neighs[i]);
            i++;
        } else {
            flush_neighbour(&neighs[i]);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &expire_neighs_time);
    expire_neighs_time.tv_sec += 30;
}

