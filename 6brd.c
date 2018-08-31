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

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip6.h>
#include <netpacket/packet.h>
#include <linux/netlink.h>

#include <sys/socket.h>
#include <sys/ioctl.h>

#include "nloop.h"
#include "6brd.h"

struct config config = { .log_level = LOG_ERR };
static int ioctl_sock;

static int scan_args (int argc, char **argv) {
	int i, j, l;
	struct interface *tmp;
	for (i = 1; i < argc; ++i) {
		l = strlen (argv[i]);
		if (!l) goto argerr;
		else if (argv[i][0] == '-') {
			if (l == 1) goto argerr;
			for (j = 1; j < l; ++j) switch (argv[i][j]) {
			case 'f':
				config.foreground = true;
				break;
			case 'v':
				switch (config.log_level) {
					case LOG_ERR: config.log_level = LOG_NOTICE; break;
					case LOG_NOTICE: config.log_level = LOG_DEBUG; break;
				}
				break;
			default:
				goto argerr;
			}
		} else break;
	}

	for (; i < argc; ++i, ++config.cnt) {
		struct interface *iface;
		if ((tmp = realloc (
			interfaces, (config.cnt + 1) * sizeof (struct interface)
		)) == NULL) {
			free (interfaces);
			fprintf (stderr, "Failed to allocate memory for interfaces\n");
			return 2;
		} else {
			interfaces = tmp;
			iface = interfaces + config.cnt;
			*iface = (struct interface) { .learn_routes = 1 };
		}

		l = strlen (argv[i]);
		for (j = 0; j < l; ++j) {
			if (argv[i][j] == '~') iface->external = 1;
			else if (argv[i][j] == '!') iface->learn_routes = 0;
			else break;
		}
		if (j < l) {
			iface->ifname = argv[i] + j;
			if ((iface->ifindex = if_nametoindex (iface->ifname)) <= 0) {
				free (interfaces);
				fprintf (
					stderr, "Failed to get interface index for %s\n",
					iface->ifname
				);
				return 2;
			}
		} else {
			free (interfaces);
			goto argerr;
		}
	}

	if (config.cnt < 2) {
		if (interfaces) free (interfaces);
		goto argerr;
	}

	return 1;
argerr:
	fprintf (
		stderr,
		"%s [-f] [-v ...] [~][!]iface1 [~][!]iface2 [[~][!]iface3 ...]\n"
		"  -f:   foreground and send log messages to stderr\n"
		"  -v:   increase verbosity by 1, at most 2 increments\n"
		"   ~:   only proxy DAD messages for the specified interface\n"
		"   !:   do not learn routes for neighbours on the interface\n",
		argv[0]
	);
	return 0;
}

int main(int argc, char **argv)
{
	int i;
	if (!scan_args (argc, argv)) return 1;
	if (getuid () != 0) {
		fprintf (stderr, "Must be run as root!\n");
		return 2;
	}
	if (!config.foreground) {
		openlog ("odhcpd", LOG_PID, LOG_DAEMON);
		if (daemon (0, 0)) do_log
			(LOG_ERR, "Failed to daemonize: %s", strerror (errno));
	}
	uloop_init();

	ioctl_sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (ioctl_sock < 0)
		return 4;
	if (netlink_init())
		return 4;
	if (ndp_init())
		return 4;

	for (i = 0; i < config.cnt; ++i)
		ndp_setup_interface (interfaces + i, 1);
	uloop_run ();
	for (i = 0; i < config.cnt; ++i)
		ndp_setup_interface (interfaces + i, 0);
	return 0;
}

void do_log (int priority, const char *format, ...) {
	if (priority > config.log_level) return;
	va_list args;
	va_start (args, format);
	if (config.foreground) {
		vfprintf (stderr, format, args);
		fprintf (stderr, "\n");
	} else vsyslog (priority, format, args);
	va_end (args);
	return;
}

/* Read IPv6 MAC for interface */
int odhcpd_get_mac(const struct interface *iface, uint8_t mac[6])
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface->ifname, sizeof(ifr.ifr_name) - 1);
	if (ioctl(ioctl_sock, SIOCGIFHWADDR, &ifr) < 0)
		return -1;

	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
	return 0;
}


/* Forwards a packet on a specific interface */
ssize_t odhcpd_send(int socket, struct sockaddr_in6 *dest,
		struct iovec *iov, size_t iov_len,
		const struct interface *iface)
{
	/* Construct headers */
	uint8_t cmsg_buf[CMSG_SPACE(sizeof(struct in6_pktinfo))] = {0};
	struct msghdr msg = {
		.msg_name = (void *) dest,
		.msg_namelen = sizeof(*dest),
		.msg_iov = iov,
		.msg_iovlen = iov_len,
		.msg_control = cmsg_buf,
		.msg_controllen = sizeof(cmsg_buf),
		.msg_flags = 0
	};

	/* Set control data (define destination interface) */
	struct cmsghdr *chdr = CMSG_FIRSTHDR(&msg);
	chdr->cmsg_level = IPPROTO_IPV6;
	chdr->cmsg_type = IPV6_PKTINFO;
	chdr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	struct in6_pktinfo *pktinfo = (struct in6_pktinfo*)CMSG_DATA(chdr);
	pktinfo->ipi6_ifindex = iface->ifindex;

	/* Also set scope ID if link-local */
	if (IN6_IS_ADDR_LINKLOCAL(&dest->sin6_addr)
			|| IN6_IS_ADDR_MC_LINKLOCAL(&dest->sin6_addr))
		dest->sin6_scope_id = iface->ifindex;

	char ipbuf[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &dest->sin6_addr, ipbuf, sizeof(ipbuf));

	ssize_t sent = sendmsg(socket, &msg, MSG_DONTWAIT);
	if (sent < 0)
		do_log (LOG_NOTICE, "Failed to send to %s%%%s: %s",
				ipbuf, iface->ifname, strerror (errno));
	else
		do_log (LOG_DEBUG, "Sent %li bytes to %s%%%s",
				(long)sent, ipbuf, iface->ifname);
	return sent;
}


struct interface* odhcpd_get_interface_by_index(int ifindex)
{
	for (int i = 0; i < config.cnt; ++i) {
		if (interfaces[i].ifindex == ifindex) return interfaces + i;
	}
	return NULL;
}


struct interface* odhcpd_get_interface_by_name(const char *name)
{
	for (int i = 0; i < config.cnt; ++i) {
		if (!strcmp (interfaces[i].ifname, name)) return interfaces + i;
	}
	return NULL;
}


/* Convenience function to receive and do basic validation of packets */
static void odhcpd_receive_packets(struct uloop_fd *u, unsigned int events)
{
	struct odhcpd_event *e = container_of(u, struct odhcpd_event, uloop);

	uint8_t data_buf[8192], cmsg_buf[128];
	union {
		struct sockaddr_in6 in6;
		struct sockaddr_in in;
		struct sockaddr_ll ll;
		struct sockaddr_nl nl;
	} addr;

	if (u->error) {
		int ret = -1;
		socklen_t ret_len = sizeof(ret);

		u->error = 0;
		if (e->handle_error && getsockopt(u->fd, SOL_SOCKET, SO_ERROR, &ret, &ret_len) == 0)
			e->handle_error(e, ret);
	}

	if (e->recv_msgs) {
		e->recv_msgs(e);
		return;
	}

	while (1) {
		struct iovec iov = {data_buf, sizeof(data_buf)};
		struct msghdr msg = {
			.msg_name = (void *) &addr,
			.msg_namelen = sizeof(addr),
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = cmsg_buf,
			.msg_controllen = sizeof(cmsg_buf),
			.msg_flags = 0
		};

		ssize_t len = recvmsg(u->fd, &msg, MSG_DONTWAIT);
		if (len < 0) {
			if (errno == EAGAIN)
				break;
			else
				continue;
		}


		/* Extract destination interface */
		int destiface = 0;
		int *hlim = NULL;
		struct in6_pktinfo *pktinfo;
		struct in_pktinfo *pkt4info;
		for (struct cmsghdr *ch = CMSG_FIRSTHDR(&msg); ch != NULL; ch = CMSG_NXTHDR(&msg, ch)) {
			if (ch->cmsg_level == IPPROTO_IPV6 &&
					ch->cmsg_type == IPV6_PKTINFO) {
				pktinfo = (struct in6_pktinfo*)CMSG_DATA(ch);
				destiface = pktinfo->ipi6_ifindex;
			} else if (ch->cmsg_level == IPPROTO_IP &&
					ch->cmsg_type == IP_PKTINFO) {
				pkt4info = (struct in_pktinfo*)CMSG_DATA(ch);
				destiface = pkt4info->ipi_ifindex;
			} else if (ch->cmsg_level == IPPROTO_IPV6 &&
					ch->cmsg_type == IPV6_HOPLIMIT) {
				hlim = (int*)CMSG_DATA(ch);
			}
		}

		/* Check hoplimit if received */
		if (hlim && *hlim != 255)
			continue;

		/* Detect interface for packet sockets */
		if (addr.ll.sll_family == AF_PACKET)
			destiface = addr.ll.sll_ifindex;

		char ipbuf[INET6_ADDRSTRLEN] = "kernel";
		if (addr.ll.sll_family == AF_PACKET &&
				len >= (ssize_t)sizeof(struct ip6_hdr))
			inet_ntop(AF_INET6, &data_buf[8], ipbuf, sizeof(ipbuf));
		else if (addr.in6.sin6_family == AF_INET6)
			inet_ntop(AF_INET6, &addr.in6.sin6_addr, ipbuf, sizeof(ipbuf));
		else if (addr.in.sin_family == AF_INET)
			inet_ntop(AF_INET, &addr.in.sin_addr, ipbuf, sizeof(ipbuf));

		/* From netlink */
		if (addr.nl.nl_family == AF_NETLINK) {
			do_log (LOG_DEBUG, "Received %li Bytes from %s%%%s", (long)len,
					ipbuf, "netlink");
			e->handle_dgram(&addr, data_buf, len, NULL);
			return;
		} else if (destiface != 0) {
			for (int i = 0; i < config.cnt; ++i) {
				struct interface *iface = interfaces + i;
				if (iface->ifindex != destiface) continue;
				do_log (LOG_DEBUG, "Received %li Bytes from %s%%%s", (long)len,
						ipbuf, iface->ifname);
				e->handle_dgram(&addr, data_buf, len, iface);
			}
		}
	}
}

/* Register events for the multiplexer */
int odhcpd_register(struct odhcpd_event *event)
{
	event->uloop.cb = odhcpd_receive_packets;
	return uloop_fd_add(&event->uloop, ULOOP_READ |
			((event->handle_error) ? ULOOP_ERROR_CB : 0));
}

int odhcpd_deregister(struct odhcpd_event *event)
{
	event->uloop.cb = NULL;
	return uloop_fd_delete(&event->uloop);
}
