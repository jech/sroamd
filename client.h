struct client {
    struct interface *interface;
    unsigned char mac[6];
    unsigned char ipv4[4];
    unsigned char ipv6[8];
};

extern struct client *clients;
extern int numclients, maxclients;

struct client *find_client(const unsigned char *mac);
struct client *add_client(struct interface *interface, const unsigned char *mac);
int flush_client(const unsigned char *mac);
int update_client_route(struct client *client,
                        const unsigned char *addr, int ipv6);
void update_client_routes(const unsigned char *mac,
                          const unsigned char *addr, int ipv6);
void client_cleanup(void);
