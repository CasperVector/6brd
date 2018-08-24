#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <libgen.h>
#include <net/if.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>

#include <uci.h>
#include <uci_blob.h>
#include <libubox/utils.h>

#include "odhcpd.h"

static struct blob_buf b;
static int reload_pipe[2];
struct list_head interfaces = LIST_HEAD_INIT(interfaces);
struct config config = {.log_level = LOG_INFO};

enum {
	IFACE_ATTR_IFNAME,
	IFACE_ATTR_MASTER,
	IFACE_ATTR_NDP,
	IFACE_ATTR_NDPROXY_ROUTING,
	IFACE_ATTR_NDPROXY_SLAVE,
	IFACE_ATTR_MAX
};

static const struct blobmsg_policy iface_attrs[IFACE_ATTR_MAX] = {
	[IFACE_ATTR_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_MASTER] = { .name = "master", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_NDP] = { .name = "ndp", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_NDPROXY_ROUTING] = { .name = "ndproxy_routing", .type = BLOBMSG_TYPE_BOOL },
	[IFACE_ATTR_NDPROXY_SLAVE] = { .name = "ndproxy_slave", .type = BLOBMSG_TYPE_BOOL },
};

const struct uci_blob_param_list interface_attr_list = {
	.n_params = IFACE_ATTR_MAX,
	.params = iface_attrs,
};

enum {
	ODHCPD_ATTR_LOGLEVEL,
	ODHCPD_ATTR_MAX
};

static const struct blobmsg_policy odhcpd_attrs[ODHCPD_ATTR_MAX] = {
	[ODHCPD_ATTR_LOGLEVEL] = { .name = "loglevel", .type = BLOBMSG_TYPE_INT32 },
};

const struct uci_blob_param_list odhcpd_attr_list = {
	.n_params = ODHCPD_ATTR_MAX,
	.params = odhcpd_attrs,
};

static struct interface* get_interface(const char *name)
{
	struct interface *c;
	list_for_each_entry(c, &interfaces, head)
		if (!strcmp(c->name, name))
			return c;
	return NULL;
}

static void set_interface_defaults(struct interface *iface)
{
	iface->learn_routes = 1;
}

static void clean_interface(struct interface *iface)
{
	set_interface_defaults(iface);
}

static void close_interface(struct interface *iface)
{
	if (iface->head.next)
		list_del(&iface->head);
	ndp_setup_interface(iface, false);

	clean_interface(iface);
	free(iface->ifname);
	free(iface);
}

static int parse_mode(const char *mode)
{
	if (!strcmp(mode, "disabled"))
		return MODE_DISABLED;
	else if (!strcmp(mode, "server"))
		return MODE_SERVER;
	else if (!strcmp(mode, "relay"))
		return MODE_RELAY;
	else if (!strcmp(mode, "hybrid"))
		return MODE_HYBRID;
	else
		return -1;
}

static void set_config(struct uci_section *s)
{
	struct blob_attr *tb[ODHCPD_ATTR_MAX], *c;

	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, &odhcpd_attr_list);
	blobmsg_parse(odhcpd_attrs, ODHCPD_ATTR_MAX, tb, blob_data(b.head), blob_len(b.head));

	if ((c = tb[ODHCPD_ATTR_LOGLEVEL])) {
		int log_level = (blobmsg_get_u32(c) & LOG_PRIMASK);

		if (config.log_level != log_level) {
			config.log_level = log_level;
			setlogmask(LOG_UPTO(config.log_level));
		}
	}
}

static int config_parse_interface(void *data, size_t len, const char *name, bool overwrite)
{
	struct blob_attr *tb[IFACE_ATTR_MAX], *c;

	blobmsg_parse(iface_attrs, IFACE_ATTR_MAX, tb, data, len);

	if (!name)
		return -1;

	struct interface *iface = get_interface(name);
	if (!iface) {
		char *iface_name;

		iface = calloc_a(sizeof(*iface), &iface_name, strlen(name) + 1);
		if (!iface)
			return -1;

		iface->name = strcpy(iface_name, name);

		set_interface_defaults(iface);

		list_add(&iface->head, &interfaces);
		overwrite = true;
	}

	const char *ifname = NULL;
	if (overwrite) {
		if ((c = tb[IFACE_ATTR_IFNAME]))
			ifname = blobmsg_get_string(c);
	}

	if (!iface->ifname && !ifname)
		goto err;

	if (ifname) {
		free(iface->ifname);
		iface->ifname = strdup(ifname);

		if (!iface->ifname)
			goto err;

		if (!iface->ifindex &&
		    (iface->ifindex = if_nametoindex(iface->ifname)) <= 0)
			goto err;
	}

	iface->inuse = true;

	if ((c = tb[IFACE_ATTR_MASTER]))
		iface->master = blobmsg_get_bool(c);

	int mode;

	if ((c = tb[IFACE_ATTR_NDP])) {
		if ((mode = parse_mode(blobmsg_get_string(c))) >= 0)
			iface->ndp = mode;
		else
			goto err;
	}

	if ((c = tb[IFACE_ATTR_NDPROXY_ROUTING]))
		iface->learn_routes = blobmsg_get_bool(c);

	if ((c = tb[IFACE_ATTR_NDPROXY_SLAVE]))
		iface->external = blobmsg_get_bool(c);

	return 0;

err:
	close_interface(iface);
	return -1;
}

static int set_interface(struct uci_section *s)
{
	blob_buf_init(&b, 0);
	uci_to_blob(&b, s, &interface_attr_list);

	return config_parse_interface(blob_data(b.head), blob_len(b.head), s->e.name, true);
}

static void odhcpd_reload(void)
{
	struct uci_context *uci = uci_alloc_context();

	struct interface *master = NULL, *i, *n;

	if (!uci)
		return;

	list_for_each_entry(i, &interfaces, head)
		clean_interface(i);

	struct uci_package *dhcp = NULL;
	if (!uci_load(uci, "dhcp", &dhcp)) {
		struct uci_element *e;
		uci_foreach_element(&dhcp->sections, e) {
			struct uci_section *s = uci_to_section(e);
			if (!strcmp(s->type, "odhcpd"))
				set_config(s);
		}

		uci_foreach_element(&dhcp->sections, e) {
			struct uci_section *s = uci_to_section(e);
			if (!strcmp(s->type, "dhcp"))
				set_interface(s);
		}
	}

	bool any_ndp_slave = false;

	/* Test for */
	list_for_each_entry(i, &interfaces, head) {
		if (i->master)
			continue;

		if (i->ndp == MODE_HYBRID || i->ndp == MODE_RELAY)
			any_ndp_slave = true;
	}

	/* Evaluate hybrid mode for master */
	list_for_each_entry(i, &interfaces, head) {
		if (!i->master)
			continue;

		enum odhcpd_mode hybrid_mode = MODE_DISABLED;

		if (i->ndp == MODE_HYBRID)
			i->ndp = hybrid_mode;

		if (i->ndp == MODE_RELAY && !any_ndp_slave)
			i->ndp = MODE_DISABLED;

		if (i->ndp == MODE_RELAY)
			master = i;
	}


	list_for_each_entry_safe(i, n, &interfaces, head) {
		if (i->inuse) {
			/* Resolve hybrid mode */
			if (i->ndp == MODE_HYBRID)
				i->ndp = (master && master->ndp == MODE_RELAY) ?
						MODE_RELAY : MODE_DISABLED;
			ndp_setup_interface(i, i->ndp != MODE_DISABLED);
		} else
			close_interface(i);
	}

	uci_unload(uci, dhcp);
	uci_free_context(uci);
}

static void handle_signal(int signal)
{
	char b[1] = {0};

	if (signal == SIGHUP) {
		if (write(reload_pipe[1], b, sizeof(b)) < 0) {}
	} else
		uloop_end();
}

static void reload_cb(struct uloop_fd *u, _unused unsigned int events)
{
	char b[512];
	if (read(u->fd, b, sizeof(b)) < 0) {}

	odhcpd_reload();
}

static struct uloop_fd reload_fd = { .cb = reload_cb };

void odhcpd_run(void)
{
	if (pipe2(reload_pipe, O_NONBLOCK | O_CLOEXEC) < 0) {}

	reload_fd.fd = reload_pipe[0];
	uloop_fd_add(&reload_fd, ULOOP_READ);

	signal(SIGTERM, handle_signal);
	signal(SIGINT, handle_signal);
	signal(SIGHUP, handle_signal);

	odhcpd_reload();
	uloop_run();

	while (!list_empty(&interfaces))
		close_interface(list_first_entry(&interfaces, struct interface, head));
}

