typedef void (*netlink_callback)(int add, int ifindex, const unsigned char *mac);

int netlink_init(netlink_callback cb);
int netlink_dump(int ifindex);
int netlink_listen(void);
int netlink_socket(void);
int netlink_disassociate(int ifindex, const unsigned char *mac,
                         const unsigned char *mymac);
int netlink_route(int ifindex, int add, int ipv6,
                  const unsigned char *dst, int dlen);
