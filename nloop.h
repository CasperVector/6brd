/*
 * uloop - event loop implementation
 *
 * Copyright (C) 2010-2013 Felix Fietkau <nbd@openwrt.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef _ULOOP_H__
#define _ULOOP_H__

#include <stdbool.h>
#include <stdint.h>

struct uloop_fd;
typedef void (*uloop_fd_handler)(struct uloop_fd *u, unsigned int events);

#define ULOOP_READ		(1 << 0)
#define ULOOP_WRITE		(1 << 1)
#define ULOOP_EDGE_TRIGGER	(1 << 2)
#define ULOOP_BLOCKING		(1 << 3)

#define ULOOP_EVENT_MASK	(ULOOP_READ | ULOOP_WRITE)

/* internal flags */
#define ULOOP_EVENT_BUFFERED	(1 << 4)
#ifdef USE_KQUEUE
#define ULOOP_EDGE_DEFER	(1 << 5)
#endif

#define ULOOP_ERROR_CB		(1 << 6)

struct uloop_fd
{
	uloop_fd_handler cb;
	int fd;
	bool eof;
	bool error;
	bool registered;
	uint8_t flags;
};

extern bool uloop_cancelled;
extern bool uloop_handle_sigchld;

int uloop_fd_add(struct uloop_fd *sock, unsigned int flags);
int uloop_fd_delete(struct uloop_fd *sock);

static inline void uloop_end(void)
{
	uloop_cancelled = true;
}

int uloop_init(void);
int uloop_run(void);
void uloop_done(void);

#endif
