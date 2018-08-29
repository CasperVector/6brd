/**
 * Copyright (C) 2017 Hans Dedecker <dedeckeh@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License v2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <errno.h>
#include <string.h>
#include <syslog.h>

#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <arpa/inet.h>

#include "odhcpd.h"

struct event_socket {
	struct odhcpd_event ev;
	struct nl_sock *sock;
	int sock_bufsize;
};

static void handle_rtnl_event(struct odhcpd_event *ev);
static int cb_rtnl_valid(struct nl_msg *msg, void *arg);
static void catch_rtnl_err(struct odhcpd_event *e, int error);
static struct nl_sock *create_socket(int protocol);
static void netlink_dump_addr_table (const bool v6);

static struct nl_sock *rtnl_socket = NULL;
static struct event_socket rtnl_event = {
	.ev = {
		.uloop = {.fd = - 1, },
		.handle_dgram = NULL,
		.handle_error = catch_rtnl_err,
		.recv_msgs = handle_rtnl_event,
	},
	.sock = NULL,
	.sock_bufsize = 133120,
};

int netlink_init(void)
{
	rtnl_socket = create_socket(NETLINK_ROUTE);
	if (!rtnl_socket) {
		syslog(LOG_ERR, "Unable to open nl socket: %m");
		goto err;
	}

	rtnl_event.sock = create_socket(NETLINK_ROUTE);
	if (!rtnl_event.sock) {
		syslog(LOG_ERR, "Unable to open nl event socket: %m");
		goto err;
	}

	rtnl_event.ev.uloop.fd = nl_socket_get_fd(rtnl_event.sock);

	if (nl_socket_set_buffer_size(rtnl_event.sock, rtnl_event.sock_bufsize, 0))
		goto err;

	nl_socket_disable_seq_check(rtnl_event.sock);

	nl_socket_modify_cb(rtnl_event.sock, NL_CB_VALID, NL_CB_CUSTOM,
			cb_rtnl_valid, NULL);

	if (nl_socket_add_memberships (rtnl_event.sock,
				RTNLGRP_NEIGH, RTNLGRP_LINK, 0))
		goto err;

	odhcpd_register(&rtnl_event.ev);

	return 0;

err:
	if (rtnl_socket) {
		nl_socket_free(rtnl_socket);
		rtnl_socket = NULL;
	}

	if (rtnl_event.sock) {
		nl_socket_free(rtnl_event.sock);
		rtnl_event.sock = NULL;
		rtnl_event.ev.uloop.fd = -1;
	}

	return -1;
}

static void handle_rtnl_event(struct odhcpd_event *e)
{
	struct event_socket *ev_sock = container_of(e, struct event_socket, ev);

	nl_recvmsgs_default(ev_sock->sock);
}

/* Handler for neighbor cache entries from the kernel. This is our source
 * to learn and unlearn hosts on interfaces. */
static int cb_rtnl_valid(struct nl_msg *msg, _unused void *arg)
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct netevent_handler_info event_info;
	bool add = false;
	char ipbuf[INET6_ADDRSTRLEN];

	memset(&event_info, 0, sizeof(event_info));
	switch (hdr->nlmsg_type) {
	case RTM_NEWLINK: {
		struct ifinfomsg *ifi = nlmsg_data(hdr);
		struct nlattr *nla[__IFLA_MAX];

		if (!nlmsg_valid_hdr(hdr, sizeof(*ifi)) ||
				ifi->ifi_family != AF_UNSPEC)
			return NL_SKIP;

		nlmsg_parse(hdr, sizeof(*ifi), nla, __IFLA_MAX - 1, NULL);
		if (!nla[IFLA_IFNAME])
			return NL_SKIP;

		event_info.iface = odhcpd_get_interface_by_name(nla_get_string(nla[IFLA_IFNAME]));
		if (!event_info.iface)
			return NL_SKIP;

		if (event_info.iface->ifindex != ifi->ifi_index) {
			event_info.iface->ifindex = ifi->ifi_index;
		}
		break;
	}

	case RTM_NEWNEIGH:
		add = true;
		/* fall through */
	case RTM_DELNEIGH: {
		struct ndmsg *ndm = nlmsg_data(hdr);
		struct nlattr *nla[__NDA_MAX];

		if (!nlmsg_valid_hdr(hdr, sizeof(*ndm)) ||
				ndm->ndm_family != AF_INET6)
			return NL_SKIP;

		event_info.iface = odhcpd_get_interface_by_index(ndm->ndm_ifindex);
		if (!event_info.iface)
			return NL_SKIP;

		nlmsg_parse(hdr, sizeof(*ndm), nla, __NDA_MAX - 1, NULL);
		if (!nla[NDA_DST])
			return NL_SKIP;

		nla_memcpy(&event_info.neigh.dst, nla[NDA_DST], sizeof(event_info.neigh.dst));

		if (IN6_IS_ADDR_LINKLOCAL(&event_info.neigh.dst) ||
		    IN6_IS_ADDR_MULTICAST(&event_info.neigh.dst))
			return NL_SKIP;

		inet_ntop(AF_INET6, &event_info.neigh.dst, ipbuf, sizeof(ipbuf));
		syslog (LOG_DEBUG, "Netlink %s %s%%%s", add ? "newneigh" : "delneigh",
			ipbuf, event_info.iface->ifname);

		event_info.neigh.state = ndm->ndm_state;
		event_info.neigh.flags = ndm->ndm_flags;
		ndp_netevent_cb (add ? NETEV_NEIGH6_ADD : NETEV_NEIGH6_DEL, &event_info);
		break;
	}

	default:
		return NL_SKIP;
	}

	return NL_OK;
}

static void catch_rtnl_err(struct odhcpd_event *e, int error)
{
	struct event_socket *ev_sock = container_of(e, struct event_socket, ev);

	if (error != ENOBUFS)
		goto err;

	/* Double netlink event buffer size */
	ev_sock->sock_bufsize *= 2;

	if (nl_socket_set_buffer_size(ev_sock->sock, ev_sock->sock_bufsize, 0))
		goto err;

	netlink_dump_addr_table(true);
	return;

err:
	odhcpd_deregister(e);
}

static struct nl_sock *create_socket(int protocol)
{
	struct nl_sock *nl_sock;

	nl_sock = nl_socket_alloc();
	if (!nl_sock)
		goto err;

	if (nl_connect(nl_sock, protocol) < 0)
		goto err;

	return nl_sock;

err:
	if (nl_sock)
		nl_socket_free(nl_sock);

	return NULL;
}


int netlink_setup_route(const struct in6_addr *addr, const int prefixlen,
		const int ifindex, const struct in6_addr *gw,
		const uint32_t metric, const bool add)
{
	struct nl_msg *msg;
	struct rtmsg rtm = {
		.rtm_family = AF_INET6,
		.rtm_dst_len = prefixlen,
		.rtm_src_len = 0,
		.rtm_table = RT_TABLE_MAIN,
		.rtm_protocol = (add ? RTPROT_STATIC : RTPROT_UNSPEC),
		.rtm_scope = (add ? (gw ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK) : RT_SCOPE_NOWHERE),
		.rtm_type = (add ? RTN_UNICAST : RTN_UNSPEC),
	};
	int ret = 0;

	msg = nlmsg_alloc_simple(add ? RTM_NEWROUTE : RTM_DELROUTE,
					add ? NLM_F_CREATE | NLM_F_REPLACE : 0);
	if (!msg)
		return -1;

	nlmsg_append(msg, &rtm, sizeof(rtm), 0);

	nla_put(msg, RTA_DST, sizeof(*addr), addr);
	nla_put_u32(msg, RTA_OIF, ifindex);
	nla_put_u32(msg, RTA_PRIORITY, metric);

	if (gw)
		nla_put(msg, RTA_GATEWAY, sizeof(*gw), gw);

	ret = nl_send_auto_complete(rtnl_socket, msg);
	nlmsg_free(msg);

	if (ret < 0)
		return ret;

	return nl_wait_for_ack(rtnl_socket);
}


int netlink_setup_proxy_neigh(const struct in6_addr *addr,
		const int ifindex, const bool add)
{
	struct nl_msg *msg;
	struct ndmsg ndm = {
		.ndm_family = AF_INET6,
		.ndm_flags = NTF_PROXY,
		.ndm_ifindex = ifindex,
	};
	int ret = 0, flags = NLM_F_REQUEST;

	if (add)
		flags |= NLM_F_REPLACE | NLM_F_CREATE;

	msg = nlmsg_alloc_simple(add ? RTM_NEWNEIGH : RTM_DELNEIGH, flags);
	if (!msg)
		return -1;

	nlmsg_append(msg, &ndm, sizeof(ndm), 0);

	nla_put(msg, NDA_DST, sizeof(*addr), addr);

	ret = nl_send_auto_complete(rtnl_socket, msg);
	nlmsg_free(msg);

	if (ret < 0)
		return ret;

	return nl_wait_for_ack(rtnl_socket);
}


void netlink_dump_neigh_table(const bool proxy)
{
	struct nl_msg *msg;
	struct ndmsg ndm = {
		.ndm_family = AF_INET6,
		.ndm_flags = proxy ? NTF_PROXY : 0,
	};

	msg = nlmsg_alloc_simple(RTM_GETNEIGH, NLM_F_REQUEST | NLM_F_DUMP);
	if (!msg)
		return;

	nlmsg_append(msg, &ndm, sizeof(ndm), 0);

	nl_send_auto_complete(rtnl_event.sock, msg);

	nlmsg_free(msg);
}

static void netlink_dump_addr_table (const bool v6)
{
	struct nl_msg *msg;
	struct ifaddrmsg ifa = {
		.ifa_family = v6 ? AF_INET6 : AF_INET,
	};

	msg = nlmsg_alloc_simple(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP);
	if (!msg)
		return;

	nlmsg_append(msg, &ifa, sizeof(ifa), 0);

	nl_send_auto_complete(rtnl_event.sock, msg);

	nlmsg_free(msg);
}
