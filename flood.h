struct datum {
    unsigned short seqno;
    unsigned char keylen;
    unsigned char vallen;
    time_t time;
    unsigned char datum[];
};

static inline const unsigned char *
datum_key(const struct datum *datum)
{
    return datum->datum;
}

static inline const unsigned char *
datum_val(const struct datum *datum)
{
    return datum->datum + datum->keylen;
}

extern int server_port;
extern int server_socket;
extern struct datum **data;
extern int numdata, maxdata;

struct unacked {
    int count;
    unsigned char *key;
    int keylen;
    time_t time;
};

struct buffered {
    unsigned char *key;
    int keylen;
    int acked;
};

struct buffer {
    unsigned char *buf;
    int len, cap;
};

struct neighbour {
    int fd;
    int handshake_received;
    int dump_sent;
    struct sockaddr_in6 *sin6;
    struct buffer in, out;
};

extern struct neighbour *neighs;
extern int numneighs, maxneighs;

extern struct timespec expire_neighs_time;

struct datum *find_datum(const unsigned char *key, int keylen);
struct datum *update_datum(const unsigned char *key, int keylen,
                           unsigned short seqno,
                           const unsigned char *val, int vallen,
                           int time, int *updated, int *conflict);
void flush_datum(struct datum *datum);
time_t datum_remaining(const struct datum *datum);
int extend_datum(struct datum *datum, time_t extend);
int flood_setup(void (*callback)(struct datum *, int));
void flood_cleanup(void);
int flood_accept(void);
int flood_connect(const struct sockaddr_in6* sin6);
int flood_read(struct neighbour *neigh);
int flood_write(struct neighbour *neigh);
void flood(struct datum *datum, struct neighbour *except);
void expire_neighs(void);
