/*
 * Copyright (c) 2014 Matt Dainty <matt@bodgit-n-scarper.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
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

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/queue.h>
#include <sys/uio.h>

#include <unistd.h>
#include <err.h>
#include <string.h>

#include "igdpcpd.h"

void	 dns_handle_signal(int, short, void *);
void	 dns_shutdown(void);
void	 dns_dispatch_imsg(int, short, void *);

void
dns_handle_signal(int sig, short event, void *arg)
{
	switch (sig) {
	case SIGINT:
		/* FALLTHROUGH */
	case SIGTERM:
		dns_shutdown();
		break;
	default:
		fatalx("unexpected signal");
	}
}

void
dns_shutdown(void)
{
	log_info("dns engine exiting");
	_exit(0);
}

pid_t
igdpcpd_dns(int dns_pipe[2], struct passwd *pw)
{
	pid_t			 pid;
	struct event_base	*base;
	struct event		*ev_sigint;
	struct event		*ev_sigterm;
	struct event		*ev_sighup;
	struct imsgev		*iev;

	switch (pid = fork()) {
	case -1:
		fatal("cannot fork");
		break;
	case 0:
		break;
	default:
		return (pid);
	}

	setproctitle("dns engine");
	close(dns_pipe[0]);

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("can't drop privileges");

	if ((base = event_base_new()) == NULL)
		fatalx("event_base_new");

	ev_sigint = evsignal_new(base, SIGINT, dns_handle_signal, NULL);
	ev_sigterm = evsignal_new(base, SIGTERM, dns_handle_signal, NULL);
	ev_sighup = evsignal_new(base, SIGHUP, dns_handle_signal, NULL);
	evsignal_add(ev_sigint, NULL);
	evsignal_add(ev_sigterm, NULL);
	evsignal_add(ev_sighup, NULL);

	if ((iev = calloc(1, sizeof(struct imsgev))) == NULL)
		fatal(NULL);

	iev->events = EV_READ;
	iev->data = iev;
	imsg_init(&iev->ibuf, dns_pipe[1]);
	iev->handler = dns_dispatch_imsg;
	iev->ev = event_new(base, iev->ibuf.fd, iev->events, iev->handler,
	    iev->data);
	event_add(iev->ev, NULL);

	event_base_dispatch(base);
	dns_shutdown();

	return (0);
}

void
dns_dispatch_imsg(int fd, short events, void *arg)
{
	struct imsg		 imsg;
	int			 n, cnt;
	char			*name;
	struct ntp_addr		*h, *hn;
	struct ibuf		*buf;
	struct imsgev		*iev = (struct imsgev *)arg;
	struct imsgbuf		*ibuf = &iev->ibuf;
	int			 shut = 0;

	if ((events & (EV_READ | EV_WRITE)) == 0)
		fatalx("unknown event");

	if (events & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1)
			fatal("imsg_read error");
		if (n == 0)
			shut = 1;
	}
	if (events & EV_WRITE) {
		if ((n = msgbuf_write(&ibuf->w)) == -1 && errno != EAGAIN)
			fatal("msgbuf_write");
		if (n == 0)
			shut = 1;
		goto done;
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("dns_dispatch_imsg: imsg_get error");
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_HOST_DNS:
			name = imsg.data;
			if (imsg.hdr.len < 1 + IMSG_HEADER_SIZE)
				fatalx("invalid IMSG_HOST_DNS received");
			imsg.hdr.len -= 1 + IMSG_HEADER_SIZE;
			if (name[imsg.hdr.len] != '\0' ||
			    strlen(name) != imsg.hdr.len)
				fatalx("invalid IMSG_HOST_DNS received");
			if ((cnt = host_dns(name, &hn)) == -1)
				break;
			buf = imsg_create(ibuf, IMSG_HOST_DNS,
			    imsg.hdr.peerid, 0,
			    cnt * sizeof(struct sockaddr_storage));
			if (buf == NULL)
				break;
			if (cnt > 0) {
				h = hn;
				while (h != NULL) {
					imsg_add(buf, &h->ss, sizeof(h->ss));
					hn = h->next;
					free(h);
					h = hn;
				}
			}

			imsg_close(ibuf, buf);
			break;
		default:
			break;
		}
		imsg_free(&imsg);
	}

done:
	if (!shut)
		imsg_event_add(iev);
	else {
		event_del(iev->ev);
		event_base_loopexit(event_get_base(iev->ev), NULL);
	}
}
