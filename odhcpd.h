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
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet/ether.h>
#include <stdbool.h>
#include <syslog.h>

#include <libubox/blobmsg.h>

#ifndef container_of
#define container_of(ptr, type, member) (           \
    (type *)( (char *)ptr - offsetof(type,member) ))
#endif

#include <libubox/list.h>
#include <libubox/uloop.h>

#define _unused __attribute__((unused))

struct interface;

struct odhcpd_event {
	struct uloop_fd uloop;
	void (*handle_dgram)(void *addr, void *data, size_t len,
			struct interface *iface, void *dest_addr);
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

enum netevents {
	NETEV_NEIGH6_ADD,
	NETEV_NEIGH6_DEL,
};

struct netevent_handler {
	struct list_head head;
	void (*cb) (unsigned long event, struct netevent_handler_info *info);
};

enum odhcpd_mode {
	MODE_DISABLED,
	MODE_SERVER,
	MODE_RELAY,
	MODE_HYBRID
};

struct config {
	int log_level;
} config;

struct interface {
	struct list_head head;

	int ifindex;
	char *ifname;
	const char *name;

	// NDP runtime data
	struct odhcpd_event ndp_event;

	// Services
	enum odhcpd_mode ndp;

	// Config
	bool inuse;
	bool external;
	bool master;

	// RA
	int learn_routes;
};

extern struct list_head interfaces;

// Exported main functions
int odhcpd_register(struct odhcpd_event *event);
int odhcpd_deregister(struct odhcpd_event *event);

ssize_t odhcpd_send(int socket, struct sockaddr_in6 *dest,
		struct iovec *iov, size_t iov_len,
		const struct interface *iface);
struct interface* odhcpd_get_interface_by_name(const char *name);
int odhcpd_get_mac(const struct interface *iface, uint8_t mac[6]);
struct interface* odhcpd_get_interface_by_index(int ifindex);

void odhcpd_run(void);

int netlink_add_netevent_handler(struct netevent_handler *hdlr);
int netlink_setup_route(const struct in6_addr *addr, const int prefixlen,
		const int ifindex, const struct in6_addr *gw,
		const uint32_t metric, const bool add);
int netlink_setup_proxy_neigh(const struct in6_addr *addr,
		const int ifindex, const bool add);
void netlink_dump_neigh_table(const bool proxy);

// Exported module initializers
int netlink_init(void);
int ndp_init(void);
int ndp_setup_interface(struct interface *iface, bool enable);
