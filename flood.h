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

extern int flood_port;
extern int flood_socket;
extern struct datum **data;
extern int numdata, maxdata;

extern struct timespec flood_time;

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

#define MAXBUFFERED 100

struct neighbour {
    struct sockaddr_in6 addr;
    struct in6_pktinfo *pktinfo;
    int permanent;
    time_t time;
    time_t send_time;
    struct unacked *unacked;
    int numunacked, maxunacked;
    struct buffered *buffered;
    int numbuffered;
    int dump_request_count;
    int dump_done;
};

extern struct neighbour *neighbours;
extern int numneighbours, maxneighbours;

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
int flood_listen(void);
struct neighbour *
find_neighbour(struct sockaddr_in6 *sin6, int create, int update, int permanent);
void flood(struct datum *datum, struct neighbour *neigh, int ack, int doit);
void periodic_flood(void);
int flush_updates(struct neighbour *neigh, int all);
