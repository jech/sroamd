/*
Copyright (c) 2015 by Juliusz Chroboczek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#define MAX_RA_DELAY_TIME 500
#define MIN_DELAY_BETWEEN_RAS 3000

#define MAX_RTR_ADV_INTERVAL 600000
#define MIN_RTR_ADV_INTERVAL (33 * MAX_RTR_ADV_INTERVAL / 100)

extern int ra_socket;
extern unsigned char dnsv6[16][16];
extern int numdnsv6;
int ra_setup(void);
void ra_cleanup(void);
int send_ra(const unsigned char *prefix, int tm,
            const struct sockaddr_in6 *to, struct interface *interface);
int receive_rs(void);
int send_gratuitious_na(struct interface *interface);


