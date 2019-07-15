#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#ifdef HAVE_GETRANDOM
#include <sys/random.h>
#endif
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include "util.h"

#ifndef NO_DEBUG
int debug_level = 0;
#endif

int
read_random_bytes(void *buf, int len)
{
    int rc;

#ifdef HAVE_GETRANDOM
    rc = getrandom(buf, len, 0);
#else
    rc = -1;
    errno = ENOSYS;
#endif
    if(rc < 0 && errno == ENOSYS) {
        int fd;
        fd = open("/dev/urandom", O_RDONLY);
        if(fd < 0)
            return -1;

        rc = read(fd, buf, len);
        close(fd);
    }

    if(rc < len)
        rc = -1;
    return rc;
}

int
ts_compare(const struct timespec *s1, const struct timespec *s2)
{
    if(s1->tv_sec < s2->tv_sec)
        return -1;
    else if(s1->tv_sec > s2->tv_sec)
        return 1;
    else if(s1->tv_nsec < s2->tv_nsec)
        return -1;
    else if(s1->tv_nsec > s2->tv_nsec)
        return 1;
    else
        return 0;
}

/* {0, 0} represents infinity */
void
ts_min(struct timespec *d, const struct timespec *s)
{
    if(s->tv_sec == 0)
        return;

    if(d->tv_sec == 0 || ts_compare(d, s) > 0) {
        *d = *s;
    }
}

void
ts_minus(struct timespec *d,
         const struct timespec *s1, const struct timespec *s2)
{
    if(s1->tv_nsec >= s2->tv_nsec) {
        d->tv_nsec = s1->tv_nsec - s2->tv_nsec;
        d->tv_sec = s1->tv_sec - s2->tv_sec;
    } else {
        d->tv_nsec = s1->tv_nsec + 1000000000 - s2->tv_nsec;
        d->tv_sec = s1->tv_sec - s2->tv_sec - 1;
    }
}

int
ts_minus_msec(const struct timespec *s1, const struct timespec *s2)
{
    return (s1->tv_sec - s2->tv_sec) * 1000 +
        (s1->tv_nsec - s2->tv_nsec) / 1000000;
}

static void
ts_add_nsec(struct timespec *d, const struct timespec *s, long long nsecs)
{
    *d = *s;

    while(nsecs + d->tv_nsec > 1000000000) {
        d->tv_sec += 1;
        nsecs -= 1000000000LL;
    }

    while(nsecs + d->tv_nsec < 0) {
        d->tv_sec -= 1;
        nsecs += 1000000000LL;
    }

    d->tv_nsec += nsecs;
}

static const long long million = 1000000LL;

void
ts_add_msec(struct timespec *d, const struct timespec *s, int msecs)
{
    ts_add_nsec(d, s, msecs * million);
}

void
ts_add_random(struct timespec *d, const struct timespec *s, int msecs)
{
    ts_add_nsec(d, s, (random() % msecs) * million + random() % million);
}

void
ts_zero(struct timespec *d)
{
    d->tv_sec = 0;
    d->tv_nsec = 0;
}

const char *
format_32(const unsigned char *data)
{
    static char buf[4][16];
    static int i = 0;
    i = (i + 1) % 4;
    snprintf(buf[i], 16, "%02x:%02x:%02x:%02x",
             data[0], data[1], data[2], data[3]);
    return buf[i];
}

const char *
format_48(const unsigned char *data)
{
    static char buf[4][22];
    static int i = 0;
    i = (i + 1) % 4;
    snprintf(buf[i], 22, "%02x:%02x:%02x:%02x:%02x:%02x",
             data[0], data[1], data[2], data[3], data[4], data[5]);
    return buf[i];
}

const char *
format_64(const unsigned char *data)
{
    static char buf[4][28];
    static int i = 0;
    i = (i + 1) % 4;
    snprintf(buf[i], 28, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
             data[0], data[1], data[2], data[3],
             data[4], data[5], data[6], data[7]);
    return buf[i];
}

void
do_debugf(int level, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if(debug_level >= level) {
        vfprintf(stderr, format, args);
        fflush(stderr);
    }
    va_end(args);
}

int
parse_address(const char *string, unsigned char *p_return)
{
    char buf[INET6_ADDRSTRLEN];
    int rc;
    struct in_addr ina;
    struct in6_addr ina6;

    strncpy(buf, string, INET6_ADDRSTRLEN);
    buf[INET6_ADDRSTRLEN - 1] = '\0';

    rc = inet_pton(AF_INET, buf, &ina);
    if(rc > 0) {
        memcpy(p_return, &ina, 4);
        return 4;
    }
    rc = inet_pton(AF_INET6, buf, &ina6);
    if(rc > 0) {
        memcpy(p_return, &ina6, 16);
        return 6;
    }
    return -1;
}

int
parse_prefix(const char *string, unsigned char *p_return, int *plen_return)
{
    char buf[INET6_ADDRSTRLEN];
    int rc, plen;
    char *slash;
    struct in_addr ina;
    struct in6_addr ina6;

    strncpy(buf, string, INET6_ADDRSTRLEN);
    buf[INET6_ADDRSTRLEN - 1] = '\0';

    slash = strchr(buf, '/');
    if(slash == NULL) {
        return -1;
    } else {
        char *end;
        plen = strtol(slash + 1, &end, 0);
        if(*end != '\0' || plen < 0 || plen > 128)
            return -1;
        *slash = '\0';
    }

    rc = inet_pton(AF_INET, buf, &ina);
    if(rc > 0) {
        memcpy(p_return, &ina, 4);
        *plen_return = plen;
        return 4;
    }
    rc = inet_pton(AF_INET6, buf, &ina6);
    if(rc > 0) {
        memcpy(p_return, &ina6, 16);
        *plen_return = plen;
        return 6;
    }
    return -1;
}

int parse_addrport(const char *string, unsigned char *a_return,
                   unsigned short *port_return)
{
    char buf[INET6_ADDRSTRLEN];
    int rc, ret, port;
    struct in_addr ina;
    struct in6_addr ina6;
    char *colon, *end;

    strncpy(buf, string, INET6_ADDRSTRLEN);
    buf[INET6_ADDRSTRLEN - 1] = '\0';

    if(buf[0] == '[') {
        char *bracket;
        bracket = strchr(buf, ']');
        if(bracket == NULL || *(bracket + 1) != ':')
            return -1;
        colon = bracket + 1;
        *bracket = '\0';
        rc = inet_pton(AF_INET6, buf + 1, &ina6);
        if(rc <= 0)
            return -1;
        memcpy(a_return, &ina6, 16);
        ret = 6;
    } else {
        colon = strchr(buf, ':');
        if(colon == NULL) {
            return -1;
        }
        *colon = '\0';
        rc = inet_pton(AF_INET, buf, &ina);
        if(rc <= 0)
            return -1;
        memcpy(a_return, &ina, 4);
        ret = 4;
    }

    port = strtol(colon + 1, &end, 0);
    if(*end != '\0' || port <= 0 || port > 0xFFFF)
        return -1;

    *port_return = port;
    return ret;
}

static const unsigned char zeroes[6];

int
if_macaddr(char *ifname, int ifindex, unsigned char *mac_return)
{
    int s, rc;
    struct ifreq ifr;
    unsigned char *mac;

    s = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(s < 0) return -1;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    rc = ioctl(s, SIOCGIFHWADDR, &ifr);
    if(rc < 0) {
        int saved_errno = errno;
        close(s);
        errno = saved_errno;
        return -1;
    }
    close(s);

    if(ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
        debugf("Unknown hardware type %d.\n", ifr.ifr_hwaddr.sa_family);
        errno = ENOENT;
        return -1;
    }

    mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    if(memcmp(mac, zeroes, 6) == 0) {
        errno = ENOENT;
        return -1;
    }
    memcpy(mac_return, mac, 6);
    return 1;
}
