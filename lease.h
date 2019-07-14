#define DATUM_IPv4_LEASE 0
#define DATUM_IPv6_LEASE 1
#define DATUM_ASSOCIATED 2

#define ASSOCIATION_TIME 5400

extern unsigned char myid[8];

extern unsigned char v4prefix[4], v6prefix[16];
extern int v4plen, v6plen;

struct datum *find_lease(const unsigned char *mac, int ipv6);
struct datum *find_lease_by_ip(const unsigned char *a, int ipv6);
struct datum *update_lease(const unsigned char *mac, int ipv6,
                           const unsigned char *suggested,
                           int time, int *doit_return);
const unsigned char *lease_address(const struct datum *datum, int ipv6);
void update_lease_routes(const struct datum *datum);
struct client *update_association(struct interface *interface,
                                 const unsigned char *mac, int time);
void flush_association(const unsigned char *mac, int time);
void datum_notify(struct datum *datum);
