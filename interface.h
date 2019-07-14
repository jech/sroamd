struct interface {
    char *ifname;
    int ifindex;
    unsigned char mac[6];
};

extern struct interface *interfaces;
extern int numinterfaces, maxinterfaces;

struct interface *find_interface(int ifindex);
int interface_v4(struct interface *interface, unsigned char *v4_return);
int interface_v6(struct interface *interface, unsigned char *v6_return);
int sock_bindtodevice(int s, struct interface *interface);
