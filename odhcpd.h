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

#pragma once
#include <stddef.h>
#include <netinet/in.h>

#ifndef container_of
#define container_of(ptr, type, member) (           \
    (type *)( (char *)ptr - offsetof(type,member) ))
#endif

#include <libubox/uloop.h>

struct interface;

struct odhcpd_event {
	struct uloop_fd uloop;
	void (*handle_dgram)(void *addr, void *data, size_t len,
			struct interface *iface);
	void (*handle_error)(struct odhcpd_event *e, int error);
	void (*recv_msgs)(struct odhcpd_event *e);
};

struct netevent_handler_info {
	struct interface *iface;
	struct {
		struct in6_addr dst;
		uint16_t state;
		uint8_t flags;
	} neigh;
};

void ndp_netevent_cb
	(unsigned long event, struct netevent_handler_info *info);

enum netevents {
	NETEV_NEIGH6_ADD,
	NETEV_NEIGH6_DEL,
};

struct config {
	int log_level;
	int cnt;
} config;

struct interface {
	int ifindex;
	char *ifname;
	int learn_routes;
	int external;
	struct odhcpd_event ndp_event;
} *interfaces;

// Exported main functions
int odhcpd_register(struct odhcpd_event *event);
int odhcpd_deregister(struct odhcpd_event *event);

ssize_t odhcpd_send(int socket, struct sockaddr_in6 *dest,
		struct iovec *iov, size_t iov_len,
		const struct interface *iface);
struct interface* odhcpd_get_interface_by_name(const char *name);
int odhcpd_get_mac(const struct interface *iface, uint8_t mac[6]);
struct interface* odhcpd_get_interface_by_index(int ifindex);

int netlink_setup_route(const struct in6_addr *addr, const int prefixlen,
		const int ifindex, const struct in6_addr *gw,
		const uint32_t metric, const int add);
int netlink_setup_proxy_neigh(const struct in6_addr *addr,
		const int ifindex, const int add);
void netlink_dump_neigh_table(const int proxy);

// Exported module initializers
int netlink_init(void);
int ndp_init(void);
int ndp_setup_interface(struct interface *iface, int enable);
