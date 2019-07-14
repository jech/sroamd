#include <stdlib.h>
#include <errno.h>
#include <net/if.h>

#include <linux/nl80211.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/route/addr.h>
#include <netlink/route/route.h>
#include <netlink/errno.h>

#include "netlink.h"

struct nl_sock *nl_sock;
int nl80211_id;
struct nl_cb *nl_cb;

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg)
{
    int *ret = arg;
    *ret = err->error;
    return NL_STOP;
}

static int ack_handler(struct nl_msg *msg, void *arg)
{
    int *ret = arg;
    *ret = 0;
    return NL_STOP;
}

struct handler_args {
    const char *group;
    int id;
};

static int family_handler(struct nl_msg *msg, void *arg)
{
    struct handler_args *grp = arg;
    struct nlattr *tb[CTRL_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *mcgrp;
    int rem_mcgrp;

    nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[CTRL_ATTR_MCAST_GROUPS])
        return NL_SKIP;

    nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], rem_mcgrp) {
        struct nlattr *tb_mcgrp[CTRL_ATTR_MCAST_GRP_MAX + 1];

        nla_parse(tb_mcgrp, CTRL_ATTR_MCAST_GRP_MAX,
                  nla_data(mcgrp), nla_len(mcgrp), NULL);

        if (!tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME] ||
            !tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID])
            continue;
        if (strncmp(nla_data(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME]),
                    grp->group, nla_len(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME])))
            continue;
        grp->id = nla_get_u32(tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID]);
        break;
    }

    return NL_SKIP;
}

int nl_get_multicast_id(struct nl_sock *sock,
                        const char *family, const char *group)
{
    struct nl_msg *msg;
    struct nl_cb *cb;
    int ret, ctrlid;
    struct handler_args grp = {
        .group = group,
        .id = -ENOENT,
    };

    msg = nlmsg_alloc();
    if (!msg)
        return -ENOMEM;

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        ret = -ENOMEM;
        goto out_fail_cb;
    }

    ctrlid = genl_ctrl_resolve(sock, "nlctrl");

    genlmsg_put(msg, 0, 0, ctrlid, 0,
                0, CTRL_CMD_GETFAMILY, 0);

    ret = -ENOBUFS;
    NLA_PUT_STRING(msg, CTRL_ATTR_FAMILY_NAME, family);

    ret = nl_send_auto(sock, msg);
    if (ret < 0)
        goto out;

    ret = 1;

    nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &ret);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &ret);
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, family_handler, &grp);

    while (ret > 0)
        nl_recvmsgs(sock, cb);

    if (ret == 0)
        ret = grp.id;
 nla_put_failure:
 out:
    nl_cb_put(cb);
 out_fail_cb:
    nlmsg_free(msg);
    return ret;
}

static int
ok_handler(struct nl_msg *msg, void *arg)
{
    return NL_OK;
}

static int
event_handler(struct nl_msg *msg, void *arg)
{
    netlink_callback cb = arg;
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    char ifname[100];

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0), NULL);

    if(tb[NL80211_ATTR_IFINDEX] == NULL)
        return NL_OK;

    if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), ifname);

    if(gnlh->cmd != NL80211_CMD_NEW_STATION &&
       gnlh->cmd != NL80211_CMD_DEL_STATION) {
        return NL_OK;
    }

    if(cb != NULL)
        cb(gnlh->cmd == NL80211_CMD_NEW_STATION,
           nla_get_u32(tb[NL80211_ATTR_IFINDEX]),
           nla_data(tb[NL80211_ATTR_MAC]));

    return NL_OK;
}

int
netlink_init(netlink_callback cb)
{
    int rc, mcid;

    nl_sock = nl_socket_alloc();
    if(nl_sock == NULL)
        return -1;

    rc = genl_connect(nl_sock);
    if(rc < 0)
        return -1;

    nl_socket_set_buffer_size(nl_sock, 8192, 8192);

    nl80211_id = genl_ctrl_resolve(nl_sock, "nl80211");
    if(nl80211_id < 0)
        return -1;

    mcid = nl_get_multicast_id(nl_sock, "nl80211", "mlme");
    if(mcid < 0)
        return -1;

    rc = nl_socket_add_membership(nl_sock, mcid);
    if(rc < 0)
        return -1;

    nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
    if(nl_cb == NULL)
        return -1;

    nl_cb_set(nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, ok_handler, NULL);
    nl_cb_set(nl_cb, NL_CB_VALID, NL_CB_CUSTOM, event_handler, cb);

    rc = nl_socket_set_nonblocking(nl_sock);
    if(rc < 0)
        return -1;

    return 1;
}

int
netlink_dump(int ifindex)
{
    struct nl_msg *msg;
    int rc;

    msg = nlmsg_alloc();
    if(msg == NULL)
        return -1;
    genlmsg_put(msg, 0, 0, nl80211_id, 0, NLM_F_DUMP,
                NL80211_CMD_GET_STATION, 0);
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifindex);
    rc = nl_send_auto(nl_sock, msg);
    nlmsg_free(msg);
    if(rc < 0)
        return rc;
    return 1;

 nla_put_failure:
    return -1;
}

int
netlink_listen()
{
    return nl_recvmsgs(nl_sock, nl_cb);
}

int
netlink_socket()
{
    return nl_socket_get_fd(nl_sock);
}

int
netlink_disassociate(int ifindex, const unsigned char *mac,
                     const unsigned char *mymac)
{
    struct nl_msg *msg;
    int rc;

#if 0
    unsigned char buf[26];
    msg = nlmsg_alloc();
    if(msg == NULL)
        return -1;
    genlmsg_put(msg, 0, 0, nl80211_id, 0, 0, NL80211_CMD_FRAME, 0);
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifindex);
    memset(buf, 0, 26);
    buf[0] = 10 << 4;           /* FC */
    memcpy(buf + 4, mac, 6);    /* da */
    memcpy(buf + 10, mymac, 6); /* sa */
    memcpy(buf + 16, mymac, 6); /* bssid */
    buf[24] = 1;                /* reason */
    buf[25] = 0;
    NLA_PUT(msg, NL80211_ATTR_FRAME, 26, buf);
    NLA_PUT_FLAG(msg, NL80211_ATTR_OFFCHANNEL_TX_OK);
    rc = nl_send_auto(nl_sock, msg);
    nlmsg_free(msg);
    if(rc < 0)
        return rc;
#endif

    msg = nlmsg_alloc();
    if(msg == NULL)
        return -1;
    genlmsg_put(msg, 0, 0, nl80211_id, 0, 0, NL80211_CMD_DEL_STATION, 0);
    NLA_PUT(msg, NL80211_ATTR_MAC, 6, mac);
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifindex);
    NLA_PUT_U8(msg, NL80211_ATTR_MGMT_SUBTYPE, 0x0a);
    NLA_PUT_U16(msg, NL80211_ATTR_REASON_CODE, 1);
    rc = nl_send_auto(nl_sock, msg);
    nlmsg_free(msg);
    if(rc < 0)
        return rc;

    return 1;

 nla_put_failure:
    return -1;
}

struct nl_sock *rtnl_sock = NULL;

int
netlink_route(int ifindex, int add, int ipv6, const unsigned char *dst, int dlen)
{
    struct rtnl_route *route = NULL;
    struct nl_addr *addr = NULL;
    struct rtnl_nexthop *nh = NULL;
    unsigned char dest[16];
    int rc;

    if(rtnl_sock == NULL) {
        rtnl_sock = nl_socket_alloc();
        if(rtnl_sock == NULL)
            return -NLE_NOMEM;

        rc = nl_connect(rtnl_sock, NETLINK_ROUTE);
        if(rc < 0) {
            nl_socket_free(rtnl_sock);
            rtnl_sock = NULL;
            return rc;
        }
    }

    memcpy(dest, dst, ipv6 ? 16 : 4);

    addr = nl_addr_alloc(ipv6 ? 16 : 4);
    if(addr == NULL) {
        rc = NLE_NOMEM;
        goto fail;
    }

    nl_addr_set_family(addr, ipv6 ? AF_INET6 : AF_INET);
    nl_addr_set_binary_addr(addr, dest, ipv6 ? 16 : 4);
    nl_addr_set_prefixlen(addr, dlen);

    route = rtnl_route_alloc();
    if(route == NULL) {
        rc = NLE_NOMEM;
        goto fail;
    }

    rc = rtnl_route_set_family(route, ipv6 ? AF_INET6 : AF_INET);
    if(rc < 0)
        goto fail;

    rc = rtnl_route_set_dst(route, addr);
    if(rc < 0)
        goto fail;

    nh = rtnl_route_nh_alloc();
    if(nh == NULL) {
        rc = NLE_NOMEM;
        goto fail;
    }

    rtnl_route_nh_set_ifindex(nh, ifindex);
#if 0
    rtnl_route_nh_set_gateway(nh, addr);
    rtnl_route_nh_set_flags(nh, RTNH_F_ONLINK);
#endif

    rtnl_route_add_nexthop(route, nh);
    nh = NULL;

    rtnl_route_set_protocol(route, 44);

    if(add)
        rc = rtnl_route_add(rtnl_sock, route, 0);
    else
        rc = rtnl_route_delete(rtnl_sock, route, 0);

    if(rc < 0) {
        goto fail;
    }

    rtnl_route_put(route);
    nl_addr_put(addr);
    return 1;

 fail:
    if(route != NULL)
        rtnl_route_put(route);
    if(nh != NULL)
        rtnl_route_nh_free(nh);
    if(addr != NULL)
        nl_addr_put(addr);
    return rc;
}


