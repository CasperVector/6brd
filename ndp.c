/**
 * Copyright (C) 2012-2013 Steven Barth <steven@midlink.org>
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

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netpacket/packet.h>

#include <linux/filter.h>
#include <linux/neighbour.h>

#include "nloop.h"
#include "6brd.h"

static void setup_route(struct in6_addr *addr, struct interface *iface, int add);
static void setup_addr_for_relaying(struct in6_addr *addr, struct interface *iface, int add);
static void handle_solicit(void *addr, void *data, size_t len, struct interface *iface);

static int ping_socket = -1;

/* Filter ICMPv6 messages of type neighbor soliciation */
static struct sock_filter bpf[] = {
	BPF_STMT(BPF_LD | BPF_B | BPF_ABS, offsetof(struct ip6_hdr, ip6_nxt)),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_ICMPV6, 0, 3),
	BPF_STMT(BPF_LD | BPF_B | BPF_ABS, sizeof(struct ip6_hdr) +
			offsetof(struct icmp6_hdr, icmp6_type)),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ND_NEIGHBOR_SOLICIT, 0, 1),
	BPF_STMT(BPF_RET | BPF_K, 0xffffffff),
	BPF_STMT(BPF_RET | BPF_K, 0),
};
static const struct sock_fprog bpf_prog = {sizeof(bpf) / sizeof(*bpf), bpf};

/* Initialize NDP-proxy */
int ndp_init(void)
{
	struct icmp6_filter filt;
	int val = 2, ret = 0;

	/* Open ICMPv6 socket */
	ping_socket = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6);
	if (ping_socket < 0) {
		do_log (LOG_ERR, "socket(AF_INET6): %s", strerror (errno));
		ret = -1;
		goto out;
	}

	if (setsockopt(ping_socket, IPPROTO_RAW, IPV6_CHECKSUM,
				&val, sizeof(val)) < 0) {
		do_log (LOG_ERR, "setsockopt(IPV6_CHECKSUM): %s", strerror (errno));
		ret = -1;
		goto out;
	}

	/* This is required by RFC 4861 */
	val = 255;
	if (setsockopt(ping_socket, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
				&val, sizeof(val)) < 0) {
		do_log (LOG_ERR, "setsockopt(IPV6_MULTICAST_HOPS): %s", strerror (errno));
		ret = -1;
		goto out;
	}

	if (setsockopt(ping_socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
				&val, sizeof(val)) < 0) {
		do_log (LOG_ERR, "setsockopt(IPV6_UNICAST_HOPS): %s", strerror (errno));
		ret = -1;
		goto out;
	}

	/* Filter all packages, we only want to send */
	ICMP6_FILTER_SETBLOCKALL(&filt);
	if (setsockopt(ping_socket, IPPROTO_ICMPV6, ICMP6_FILTER,
				&filt, sizeof(filt)) < 0) {
		do_log (LOG_ERR, "setsockopt(ICMP6_FILTER): %s", strerror (errno));
		ret = -1;
		goto out;
	}

out:
	if (ret < 0 && ping_socket > 0) {
		close(ping_socket);
		ping_socket = -1;
	}

	return ret;
}

int ndp_setup_interface(struct interface *iface, int enable)
{
	int ret = 0, procfd;
	int dump_neigh = 0;
	char procbuf[64];

	snprintf(procbuf, sizeof(procbuf), "/proc/sys/net/ipv6/conf/%s/proxy_ndp", iface->ifname);
	procfd = open(procbuf, O_WRONLY);

	if (procfd < 0) {
		ret = -1;
		goto out;
	}

	if (iface->ndp_event.uloop.fd > 0) {
		uloop_fd_delete(&iface->ndp_event.uloop);
		close(iface->ndp_event.uloop.fd);
		iface->ndp_event.uloop.fd = -1;
		if (!enable && write (procfd, "0\n", 2) < 0) {}
		dump_neigh = 1;
	}

	if (enable) {
		struct sockaddr_ll ll;
		struct packet_mreq mreq;

		if (write(procfd, "1\n", 2) < 0) {}

		iface->ndp_event.uloop.fd = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_IPV6));
		if (iface->ndp_event.uloop.fd < 0) {
			do_log (LOG_ERR, "socket(AF_PACKET): %s", strerror (errno));
			ret = -1;
			goto out;
		}

#ifdef PACKET_RECV_TYPE
		int pktt = 1 << PACKET_MULTICAST;
		if (setsockopt(iface->ndp_event.uloop.fd, SOL_PACKET, PACKET_RECV_TYPE,
				&pktt, sizeof(pktt)) < 0) {
			do_log (LOG_ERR, "setsockopt(PACKET_RECV_TYPE): %s", strerror (errno));
			ret = -1;
			goto out;
		}
#endif

		if (setsockopt(iface->ndp_event.uloop.fd, SOL_SOCKET, SO_ATTACH_FILTER,
				&bpf_prog, sizeof(bpf_prog))) {
			do_log (LOG_ERR, "setsockopt(SO_ATTACH_FILTER): %s", strerror (errno));
			ret = -1;
			goto out;
		}

		memset(&ll, 0, sizeof(ll));
		ll.sll_family = AF_PACKET;
		ll.sll_ifindex = iface->ifindex;
		ll.sll_protocol = htons(ETH_P_IPV6);

		if (bind(iface->ndp_event.uloop.fd, (struct sockaddr*)&ll, sizeof(ll)) < 0) {
			do_log (LOG_ERR, "bind(): %s", strerror (errno));
			ret = -1;
			goto out;
		}

		memset(&mreq, 0, sizeof(mreq));
		mreq.mr_ifindex = iface->ifindex;
		mreq.mr_type = PACKET_MR_ALLMULTI;
		mreq.mr_alen = ETH_ALEN;

		if (setsockopt(iface->ndp_event.uloop.fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
				&mreq, sizeof(mreq)) < 0) {
			do_log (LOG_ERR, "setsockopt(PACKET_ADD_MEMBERSHIP): %s", strerror (errno));
			ret = -1;
			goto out;
		}

		iface->ndp_event.handle_dgram = handle_solicit;
		odhcpd_register(&iface->ndp_event);

		/* If we already were enabled dump is unnecessary, if not do dump */
		if (!dump_neigh)
			netlink_dump_neigh_table(0);
		else
			dump_neigh = 0;
	}

	if (dump_neigh)
		netlink_dump_neigh_table(1);

 out:
	if (ret < 0 && iface->ndp_event.uloop.fd > 0) {
		close(iface->ndp_event.uloop.fd);
		iface->ndp_event.uloop.fd = -1;
	}

	if (procfd >= 0)
		close(procfd);

	return ret;
}

void ndp_netevent_cb (unsigned long event, struct netevent_handler_info *info)
{
	struct interface *iface = info->iface;
	int add = 1;

	if (!iface) return;

	switch (event) {
	case NETEV_NEIGH6_DEL:
		add = 0;
		/* fall through */
	case NETEV_NEIGH6_ADD:
		if (info->neigh.flags & NTF_PROXY) {
			if (add) {
				netlink_setup_proxy_neigh (&info->neigh.dst, iface->ifindex, 0);
				setup_route (&info->neigh.dst, iface, 0);
				netlink_dump_neigh_table(0);
			}
			break;
		}

		if (add &&
		    !(info->neigh.state &
		      (NUD_REACHABLE|NUD_STALE|NUD_DELAY|NUD_PROBE|NUD_PERMANENT|NUD_NOARP)))
			break;

		setup_addr_for_relaying (&info->neigh.dst, iface, add);
		setup_route (&info->neigh.dst, iface, add);

		if (!add)
			netlink_dump_neigh_table(0);
		break;
	default:
		break;
	}
}

/* Send an ICMP-ECHO. This is less for actually pinging but for the
 * neighbor cache to be kept up-to-date. */
static void ping6(struct in6_addr *addr,
		const struct interface *iface)
{
	struct sockaddr_in6 dest = { .sin6_family = AF_INET6, .sin6_addr = *addr, .sin6_scope_id = iface->ifindex, };
	struct icmp6_hdr echo = { .icmp6_type = ICMP6_ECHO_REQUEST };
	struct iovec iov = { .iov_base = &echo, .iov_len = sizeof(echo) };
	char ipbuf[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, addr, ipbuf, sizeof(ipbuf));
	do_log(LOG_NOTICE, "Pinging for %s%%%s", ipbuf, iface->ifname);

	netlink_setup_route(addr, 128, iface->ifindex, NULL, 128, 1);
	odhcpd_send(ping_socket, &dest, &iov, 1, iface);
	netlink_setup_route(addr, 128, iface->ifindex, NULL, 128, 0);
}

/* Handle solicitations */
static void handle_solicit(void *addr, void *data, size_t len, struct interface *iface)
{
	struct ip6_hdr *ip6 = data;
	struct nd_neighbor_solicit *req = (struct nd_neighbor_solicit*)&ip6[1];
	struct sockaddr_ll *ll = addr;
	char ipbuf[INET6_ADDRSTRLEN];
	uint8_t mac[6];

	/* Solicitation is for duplicate address detection */
	int ns_is_dad = IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src);

	/* Don't forward any non-DAD solicitation for external ifaces
	 * TODO: check if we should even forward DADs for them */
	if (iface->external && !ns_is_dad) return;

	if (len < sizeof(*ip6) + sizeof(*req))
		return; // Invalid reqicitation

	if (IN6_IS_ADDR_LINKLOCAL(&req->nd_ns_target) ||
			IN6_IS_ADDR_LOOPBACK(&req->nd_ns_target) ||
			IN6_IS_ADDR_MULTICAST(&req->nd_ns_target))
		return; /* Invalid target */

	inet_ntop(AF_INET6, &req->nd_ns_target, ipbuf, sizeof(ipbuf));
	do_log (LOG_DEBUG, "Got a NS for %s%%%s", ipbuf, iface->ifname);

	odhcpd_get_mac(iface, mac);
	if (!memcmp(ll->sll_addr, mac, sizeof(mac)))
		return; /* Looped back */

	for (int i = 0; i < config.cnt; ++i) {
		struct interface *c = interfaces + i;
		if (iface != c && (ns_is_dad || !c->external))
			ping6(&req->nd_ns_target, c);
	}
}

/* Use rtnetlink to modify kernel routes */
static void setup_route(struct in6_addr *addr, struct interface *iface, int add)
{
	char ipbuf[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, addr, ipbuf, sizeof(ipbuf));
	do_log (LOG_NOTICE, "%s about %s%s%%%s",
			(add) ? "Learning" : "Forgetting",
			iface->learn_routes ? "proxy routing for " : "",
			ipbuf, iface->ifname);

	if (iface->learn_routes)
		netlink_setup_route(addr, 128, iface->ifindex, NULL, 1024, add);
}

static void setup_addr_for_relaying(struct in6_addr *addr, struct interface *iface, int add)
{
	char ipbuf[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, addr, ipbuf, sizeof(ipbuf));
	for (int i = 0; i < config.cnt; ++i) {
		struct interface *c = interfaces + i;
		if (iface == c) continue;
		if (netlink_setup_proxy_neigh (addr, c->ifindex, add))
			do_log (LOG_DEBUG, "Failed to %s proxy neighbour entry %s%%%s",
				add ? "add" : "delete", ipbuf, c->ifname);
		else
			do_log (LOG_DEBUG, "%s proxy neighbour entry %s%%%s",
				add ? "Added" : "Deleted", ipbuf, c->ifname);
	}
}
