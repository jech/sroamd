#include <stdlib.h>
#include <string.h>
#include "prefix.h"

int
in_prefix(const unsigned char *a, const unsigned char *p, int plen)
{
    if(memcmp(a, p, plen / 8) != 0)
        return 0;

    if(plen % 8 == 0) {
        return 1;
    } else {
        int i = plen / 8 + 1;
        unsigned char mask = (0xFF << (plen % 8)) & 0xFF;
        return (a[i] & mask) == (p[i] & mask);
    }
}

static void
random_bits(unsigned char *buf, int first, int len)
{
    int i;

    if(first % 8 != 0) {
        unsigned char mask = (0xFF >> (first % 8)) ^ 0xFF;
        buf[first / 8] &= mask;
        buf[first / 8] |= random() & (0xFF ^ mask);
    }

    for(i = (first + 7) / 8; i < (first + len) / 8; i++)
        buf[i] = random() % 0xFF;

    if((first + len) % 8 != 0) {
        unsigned char mask = 0xFF >> ((first + len) % 8);
        buf[(first + len) / 8] &= mask;
        buf[(first + len) / 8] |= random() & (0xFF ^ mask);
    }
}

int
random_prefix(const unsigned char *p, int plen, unsigned char *q, int qlen)
{
    if(plen < 0 || plen > qlen)
        return -1;

    memset(q, 0, (qlen + 7) / 8);
    memcpy(q, p, (plen + 7) / 8);
    random_bits(q, plen, qlen - plen);
    return 1;
}
