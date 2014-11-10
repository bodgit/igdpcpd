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
#include <sys/uio.h>
#include <sys/utsname.h>

#include <netinet/in.h>

#include <net/if_dl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include "igdpcpd.h"

#define	UPNP_ROOT_DEVICE	 "upnp:rootdevice"

#if UPNP_VERSION_NUMBER >= 0x0101
#define	SSDP_MAXIMUM_MX		 5
#else
#define	SSDP_MAXIMUM_MX		 120
#endif

enum ssdp_callback_type {
	SSDP_CALLBACK_NOTIFY_ALIVE = 0,
	SSDP_CALLBACK_NOTIFY_BYEBYE,
	SSDP_CALLBACK_NOTIFY_UPDATE,
	SSDP_CALLBACK_SEARCH_RESPONSE,
	SSDP_CALLBACK_MAX,
};

struct ssdp_callback {
	enum ssdp_callback_type		 type;
	struct igdpcpd			*env;
	struct event			 ev;
	struct listen_addr		*la;
	struct sockaddr_storage		 ss;
	socklen_t			 slen;
	union {
		struct {
			char		*usn;
			char		*st;
		};
		struct {
			char		*usn;
			char		*nt;
		};
	};
};

struct ssdp_header {
	TAILQ_ENTRY(ssdp_header)	 entry;
	char				*key;
	char				*value;
};

TAILQ_HEAD(ssdp_headers, ssdp_header);

char			*ssdp_concat(char *, char *);
void			 ssdp_host_header(struct evbuffer *,
			     struct listen_addr *, struct sockaddr_storage *);
void			 ssdp_date_header(struct evbuffer *);
void			 ssdp_server_header(struct evbuffer *);
void			 ssdp_cache_control_header(struct evbuffer *);
void			 ssdp_location_header(struct evbuffer *,
			     struct listen_addr *);
void			 ssdp_bootid_header(struct evbuffer *,
			     struct igdpcpd *);
void			 ssdp_configid_header(struct evbuffer *,
			     struct igdpcpd *);
void			 ssdp_sendto(int, short, void *);
struct ssdp_callback	*ssdp_callback_new(struct igdpcpd *);
void			 ssdp_callback_free(struct ssdp_callback *);
void			 ssdp_multicast(struct igdpcpd *, char *, char *);
struct ssdp_header	*ssdp_find_header(struct ssdp_headers *, char *);
int			 ssdp_parse_packet(struct evbuffer *, char **,
			     char **, char **, struct ssdp_headers *, char **);
void			 ssdp_unicast(struct igdpcpd *, struct listen_addr *,
			     struct sockaddr_storage, socklen_t, char *,
			     char *, int);

extern struct sockaddr_in	 ssdp4;
extern struct sockaddr_in6	 ssdp6;
extern struct utsname		 name;
extern const char		*upnp_version;

/* Construct SSDP header value of the form "lhs::rhs" */
char *
ssdp_concat(char *lhs, char *rhs)
{
	size_t	 len;
	char	*str;

	len = snprintf(NULL, 0, "%s::%s", lhs, rhs);
	if ((str = calloc(len + 1, sizeof(char))) == NULL)
		return (NULL);
	snprintf(str, len + 1, "%s::%s", lhs, rhs);

	return (str);
}

/* Add Host header */
void
ssdp_host_header(struct evbuffer *buffer, struct listen_addr *la,
    struct sockaddr_storage *ss)
{
	if (la->sa.ss_family == AF_INET)
		evbuffer_add_printf(buffer, "Host: %s:%u\r\n",
		    log_sockaddr((struct sockaddr *)ss), SSDP_PORT);
	else
		evbuffer_add_printf(buffer, "Host: [%s]:%u\r\n",
		    log_sockaddr((struct sockaddr *)ss), SSDP_PORT);
}

/* Add Date header */
void
ssdp_date_header(struct evbuffer *buffer)
{
	time_t		 t;
	struct tm	*tmp;
	char		 date[30]; /* "Mon, 01 Jan 1970 00:00:00 GMT" + '\0' */

	t = time(NULL);
	if ((tmp = localtime(&t)) == NULL)
		fatal("localtime");

	if (strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S GMT", tmp) == 0)
		fatalx("strftime");

	evbuffer_add_printf(buffer, "Date: %s\r\n", date);
}

/* Add Server header */
void
ssdp_server_header(struct evbuffer *buffer)
{
	extern char	*__progname;

	evbuffer_add_printf(buffer, "Server: %s/%s UPnP/%s %s/1.0\r\n",
	    name.sysname, name.release, upnp_version, __progname);
}

/* Add Cache-Control header */
void
ssdp_cache_control_header(struct evbuffer *buffer)
{
	evbuffer_add_printf(buffer, "Cache-Control: max-age=%d\r\n", 1800);
}

/* Add Location header */
void
ssdp_location_header(struct evbuffer *buffer, struct listen_addr *la)
{
	if (la->sa.ss_family == AF_INET)
		evbuffer_add_printf(buffer,
		    "Location: http://%s:%u/describe/root.xml\r\n",
		    log_sockaddr((struct sockaddr *)&la->http_sa),
		    ntohs(((struct sockaddr_in *)&la->http_sa)->sin_port));
	else
		evbuffer_add_printf(buffer,
		    "Location: http://[%s]:%u/describe/root.xml\r\n",
		    log_sockaddr((struct sockaddr *)&la->http_sa),
		    ntohs(((struct sockaddr_in6 *)&la->http_sa)->sin6_port));
}

/* Add BOOTID.UPNP.ORG header */
void
ssdp_bootid_header(struct evbuffer *buffer, struct igdpcpd *env)
{
	evbuffer_add_printf(buffer, "BOOTID.UPNP.ORG: %ld\r\n",
	    env->sc_boottime.tv_sec);
}

/* Add CONFIGID.UPNP.ORG header */
void
ssdp_configid_header(struct evbuffer *buffer, struct igdpcpd *env)
{
	evbuffer_add_printf(buffer, "CONFIGID.UPNP.ORG: %d\r\n",
	    env->sc_version);
}

#if 0
/* Add SECURELOCATION.UPNP.ORG header */
void
ssdp_securelocation_header(struct evbuffer *buffer, struct listen_addr *la)
{
	if (la->sa.ss_family == AF_INET)
		evbuffer_add_printf(buffer,
		    "SECURELOCATION.UPNP.ORG: https://%s:%u/describe/root.xml\r\n",
		    log_sockaddr((struct sockaddr *)&la->https_sa),
		    ntohs(((struct sockaddr_in *)&la->https_sa)->sin_port));
	else
		evbuffer_add_printf(buffer,
		    "SECURELOCATION.UPNP.ORG: https://[%s]:%u/describe/root.xml\r\n",
		    log_sockaddr((struct sockaddr *)&la->https_sa),
		    ntohs(((struct sockaddr_in6 *)&la->https_sa)->sin6_port));
}
#endif

/* Callback for sending SSDP responses immediately or after MX delay */
void
ssdp_sendto(int fd, short event, void *arg)
{
	struct ssdp_callback	*cb = (struct ssdp_callback *)arg;
	struct evbuffer		*output;

	if ((output = evbuffer_new()) == NULL)
		return;

	switch (cb->type) {
	case SSDP_CALLBACK_NOTIFY_ALIVE:
		evbuffer_add_printf(output, "NOTIFY * HTTP/1.1\r\n");

		ssdp_host_header(output, cb->la, &cb->ss);
		ssdp_cache_control_header(output);
		ssdp_location_header(output, cb->la);

		evbuffer_add_printf(output, "NT: %s\r\n", cb->nt);
		evbuffer_add_printf(output, "NTS: ssdp:alive\r\n");

		ssdp_server_header(output);

		evbuffer_add_printf(output, "USN: %s\r\n", cb->usn);

#if UPNP_VERSION_NUMBER >= 0x0101
		ssdp_bootid_header(output, cb->env);
		ssdp_configid_header(output, cb->env);
#endif

		evbuffer_add_printf(output, "\r\n");
		break;
	case SSDP_CALLBACK_NOTIFY_BYEBYE:
		evbuffer_add_printf(output, "NOTIFY * HTTP/1.1\r\n");

		ssdp_host_header(output, cb->la, &cb->ss);

		evbuffer_add_printf(output, "NT: %s\r\n", cb->nt);
		evbuffer_add_printf(output, "NTS: ssdp:byebye\r\n");
		evbuffer_add_printf(output, "USN: %s\r\n", cb->usn);

#if UPNP_VERSION_NUMBER >= 0x0101
		ssdp_bootid_header(output, cb->env);
		ssdp_configid_header(output, cb->env);
#endif

		evbuffer_add_printf(output, "\r\n");
		break;
#if UPNP_VERSION_NUMBER >= 0x0101
	case SSDP_CALLBACK_NOTIFY_UPDATE:
		evbuffer_add_printf(output, "NOTIFY * HTTP/1.1\r\n");

		ssdp_host_header(output, cb->la, &cb->ss);
		ssdp_location_header(output, cb->la);

		evbuffer_add_printf(output, "NT: %s\r\n", cb->nt);
		evbuffer_add_printf(output, "NTS: ssdp:update\r\n");
		evbuffer_add_printf(output, "USN: %s\r\n", cb->usn);

		ssdp_bootid_header(output, cb->env);
		ssdp_configid_header(output, cb->env);

		evbuffer_add_printf(output, "NEXTBOOTID.UPNP.ORG: %ld\r\n",
		    cb->env->sc_nexttime.tv_sec);
		evbuffer_add_printf(output, "\r\n");
		break;
#endif
	case SSDP_CALLBACK_SEARCH_RESPONSE:
		evbuffer_add_printf(output, "HTTP/1.1 200 OK\r\n");

		ssdp_cache_control_header(output);
		ssdp_date_header(output);

		evbuffer_add_printf(output, "Ext:\r\n");

		ssdp_location_header(output, cb->la);
		ssdp_server_header(output);

		evbuffer_add_printf(output, "ST: %s\r\n", cb->st);
		evbuffer_add_printf(output, "USN: %s\r\n", cb->usn);

#if UPNP_VERSION_NUMBER >= 0x0101
		ssdp_bootid_header(output, cb->env);
		ssdp_configid_header(output, cb->env);
#endif

		evbuffer_add_printf(output, "\r\n");
		break;
	default:
		log_warnx("invalid callback type");
		goto cleanup;
	}

	log_debug("Sending to %s\n%.*s",
	    log_sockaddr((struct sockaddr *)&cb->ss), EVBUFFER_LENGTH(output),
	    EVBUFFER_DATA(output));

	if (sendto(cb->la->fd, EVBUFFER_DATA(output), EVBUFFER_LENGTH(output),
	    0, (struct sockaddr *)&cb->ss, cb->slen) < 0)
		log_warn("sendto");

	/* Required before free? */
	evbuffer_drain(output, EVBUFFER_LENGTH(output));

cleanup:
	evbuffer_free(output);

	ssdp_callback_free(cb);
}

/* Create a context struct for using with an SSDP response callback */
struct ssdp_callback *
ssdp_callback_new(struct igdpcpd *env)
{
	struct ssdp_callback	*cb;

	if ((cb = calloc(1, sizeof(struct ssdp_callback))) == NULL)
		return (NULL);

	cb->env = env;
	evtimer_set(&cb->ev, ssdp_sendto, cb);

	return (cb);
}

/* Free a context struct after a callback has used it */
void
ssdp_callback_free(struct ssdp_callback *cb)
{
	if (cb == NULL)
		return;

	switch (cb->type) {
	case SSDP_CALLBACK_NOTIFY_ALIVE:
		/* FALLTHROUGH */
	case SSDP_CALLBACK_NOTIFY_BYEBYE:
		free(cb->nt);
		free(cb->usn);
		break;
	case SSDP_CALLBACK_SEARCH_RESPONSE:
		free(cb->st);
		free(cb->usn);
		break;
	default:
		log_warnx("unknown callback type");
		break;
	}

	free(cb);
}

/* Schedule multicast SSDP announcements from all listening addresses for
 * given NT and USN values
 */
void
ssdp_multicast(struct igdpcpd *env, char *nt, char *usn)
{
	struct listen_addr	*la;
	struct ssdp_callback	*cb;
	struct timeval		 tv = { 0, 0 };

	for (la = TAILQ_FIRST(&env->listen_addrs); la;
	    la = TAILQ_NEXT(la, entry)) {

		if ((cb = ssdp_callback_new(env)) == NULL)
			fatal("ssdp_callback_new");

		cb->type = SSDP_CALLBACK_NOTIFY_ALIVE;
		cb->la = la;

		switch (la->sa.ss_family) {
		case AF_INET:
			memcpy(&cb->ss, &ssdp4, sizeof(ssdp4));
			cb->slen = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			memcpy(&cb->ss, &ssdp6, sizeof(ssdp6));
			cb->slen = sizeof(struct sockaddr_in6);
			break;
		default:
			/* NOTREACHED */
			break;
		}

		if ((cb->nt = strdup(nt)) == NULL)
			fatal("strdup");
		if ((cb->usn = strdup(usn)) == NULL)
			fatal("strdup");

		/* Schedule immediately */
		evtimer_add(&cb->ev, &tv);
	}
}

void
ssdp_announce(int fd, short event, void *arg)
{
	struct igdpcpd		*env = (struct igdpcpd *)arg;
	struct ssdp_root	*root = env->sc_root;
	struct ssdp_device	*device;
	struct ssdp_service	*service;
	char			*usn, *type;
	struct timeval		 tv = { 900, 0 };

	for (device = TAILQ_FIRST(&root->devices); device;
	    device = TAILQ_NEXT(device, entry)) {
		if (device == TAILQ_FIRST(&root->devices)) {
			/* root device */
			if ((usn = ssdp_concat(device->uuid,
			    UPNP_ROOT_DEVICE)) == NULL)
				fatalx("ssdp_concat");

			ssdp_multicast(env, UPNP_ROOT_DEVICE, usn);

			free(usn);
		}

		ssdp_multicast(env, device->uuid, device->uuid);

		if ((type = urn_to_string(device->urn)) == NULL)
			fatalx("urn_to_string");
		if ((usn = ssdp_concat(device->uuid, type)) == NULL)
			fatalx("ssdp_concat");

		ssdp_multicast(env, type, usn);

		free(type);
		free(usn);
	}

	/* FIXME Should 'uniq' the list of services here */
	for (service = TAILQ_FIRST(&root->services); service;
	    service = TAILQ_NEXT(service, entry)) {
		if ((type = urn_to_string(service->urn)) == NULL)
			fatalx("urn_to_string");
		if ((usn = ssdp_concat(service->parent->uuid, type)) == NULL)
			fatalx("ssdp_concat");

		ssdp_multicast(env, type, usn);

		free(type);
		free(usn);
	}

	evtimer_add(&env->sc_announce_ev, &tv);
}

struct ssdp_header *
ssdp_find_header(struct ssdp_headers *headers, char *key)
{
	struct ssdp_header	*header = NULL;

	for (header = TAILQ_FIRST(headers);
	    header && strcasecmp(key, header->key);
	    header = TAILQ_NEXT(header, entry));

	return (header);
}

int
ssdp_parse_packet(struct evbuffer *packet, char **verb, char **uri,
    char **version, struct ssdp_headers *headers, char **body)
{
	char			*line, *p;
	size_t			 llen, len;
	struct ssdp_header	*header;
	char			*key, *value;

	TAILQ_INIT(headers);

	if ((line = evbuffer_readln(packet, &llen, EVBUFFER_EOL_CRLF)) == NULL)
		return (1);

	p = line;

	if ((len = strcspn(p, " ")) == 0
	    || (*verb = calloc(len + 1, sizeof(char))) == NULL)
		goto cleanup;
	strncpy(*verb, p, len);
	p += len;
	p += strspn(p, " ");

	if ((len = strcspn(p, " ")) == 0
	    || (*uri = calloc(len + 1, sizeof(char))) == NULL)
		goto cleanup;
	strncpy(*uri, p, len);
	p += len;
	p += strspn(p, " ");

	if ((len = strcspn(p, " ")) == 0
	    || (*version = calloc(len + 1, sizeof(char))) == NULL)
		goto cleanup;
	strncpy(*version, p, len);
	p += len;
	p += strspn(p, " ");

	if (*p)
		goto cleanup;

	free(line);

	while ((line = evbuffer_readln(packet, &llen, EVBUFFER_EOL_CRLF))) {
		if (llen == 0)
			break;

		p = line;

		if ((len = strcspn(p, ":")) == 0
		    || (key = calloc(len + 1, sizeof(char))) == NULL)
			goto cleanup;
		strncpy(key, p, len);
		p += len + 1;
		p += strspn(p, " ");

		if (p == NULL || (value = strdup(p)) == NULL) {
			free(key);
			goto cleanup;
		}

		/* Remove any trailing whitespace */
		if ((p = strchr(value, '\0')) != NULL && p != value) {
			p--;

			while (isspace(*p)) {
				*p = '\0';
				if (p == value)
					break;
				p--;
			}
		}

		free(line);

		if ((header = calloc(1, sizeof(struct ssdp_header))) == NULL) {
			free(key);
			free(value);
			goto cleanup;
		}

		header->key = key;
		header->value = value;

		TAILQ_INSERT_TAIL(headers, header, entry);
	}

	if (EVBUFFER_LENGTH(packet)) {
		if ((header = ssdp_find_header(headers,
		    "content-length")) != NULL) {
			len = atoi(header->value);

			if (len > EVBUFFER_LENGTH(packet)) {
				log_warnx("Not enough data");
				goto cleanup;
			}
		} else
			len = EVBUFFER_LENGTH(packet);

		if ((*body = calloc(len, sizeof(char))) == NULL)
			goto cleanup;
		evbuffer_remove(packet, *body, len);

		if (EVBUFFER_LENGTH(packet))
			log_warnx("Ignoring %d bytes of trailing data",
			    EVBUFFER_LENGTH(packet));
	}

	return (0);

cleanup:
	free(line);

	free(*verb);
	free(*uri);
	free(*version);

	while ((header = TAILQ_FIRST(headers))) {
		TAILQ_REMOVE(headers, header, entry);
		free(header->key);
		free(header->value);
		free(header);
	}

	return (1);
}

/* Schedule unicast SSDP response for given ST and USN values */
void
ssdp_unicast(struct igdpcpd *env, struct listen_addr *la,
    struct sockaddr_storage ss, socklen_t slen, char *st, char *usn, int mx)
{
	struct ssdp_callback	*cb;
	struct timeval		 tv = { 0, 0 };

	if ((cb = ssdp_callback_new(env)) == NULL)
		fatal("ssdp_callback_new");

	cb->type = SSDP_CALLBACK_SEARCH_RESPONSE;
	cb->la = la;
	cb->ss = ss;
	cb->slen = slen;

	if ((cb->st = strdup(st)) == NULL)
		fatal("strdup");
	if ((cb->usn = strdup(usn)) == NULL)
		fatal("strdup");

	/* If MX is non-zero, create timeval between 0 <= x < MX */
	if (mx) {
		tv.tv_sec = arc4random_uniform(mx);
		tv.tv_usec = arc4random_uniform(1000000);

		log_debug("triggering reply after %ld.%06ld seconds",
		    tv.tv_sec, tv.tv_usec);
	}

	evtimer_add(&cb->ev, &tv);
}

void
ssdp_recvmsg(int fd, short event, void *arg)
{
	struct igdpcpd		*env = (struct igdpcpd *)arg;
	u_int8_t		 buf[2048];
	struct iovec		 iov[1];
	struct sockaddr_storage	 ss;
	union {
		struct cmsghdr	 hdr;
		unsigned char	 buf[MAX(CMSG_SPACE(sizeof(struct sockaddr_dl)) + CMSG_SPACE(sizeof(struct in_addr)), CMSG_SPACE(sizeof(struct in6_pktinfo)))];
	} cmsgbuf;
	struct msghdr		 msg;
	ssize_t			 len;
	struct cmsghdr		*cmsg;
	unsigned int		 ifindex = 0;
	int			 mcast = 0;
	struct listen_addr	*la;
	struct evbuffer		*input;
	char			*verb = NULL, *uri = NULL, *version = NULL;
	struct ssdp_headers	 headers;
	struct ssdp_header	*header;
	char			*body = NULL;
	int			 mx;
	const char		*errstr;
	struct urn		*urn;
	struct upnp_nss		*nss;
	struct ssdp_root	*root = env->sc_root;
	struct ssdp_device	*device;
	struct ssdp_service	*service;
	char			*usn, *type;

	iov[0].iov_base = buf;
	iov[0].iov_len = sizeof(buf);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (struct sockaddr *)&ss;
	msg.msg_namelen = sizeof(ss);
	msg.msg_iov = iov;
	msg.msg_iovlen = nitems(iov);
	msg.msg_control = &cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);

	if ((len = recvmsg(fd, &msg, 0)) == -1) {
		log_warn("recvmsg");
		return;
	}

	if ((msg.msg_flags & MSG_TRUNC) || (msg.msg_flags & MSG_CTRUNC)) {
		log_warnx("truncated");
		return;
	}

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if ((cmsg->cmsg_level == IPPROTO_IP)
		    && (cmsg->cmsg_type == IP_RECVIF)) {
			struct sockaddr_dl	*sdl;

			sdl = (struct sockaddr_dl *)CMSG_DATA(cmsg);
			ifindex = sdl->sdl_index;
		}
		if ((cmsg->cmsg_level == IPPROTO_IP)
		   && (cmsg->cmsg_type == IP_RECVDSTADDR)) {
			struct in_addr	*in_addr;

			in_addr = (struct in_addr *)CMSG_DATA(cmsg);
			if (memcmp(in_addr, &ssdp4.sin_addr,
			    sizeof(struct in_addr)) == 0)
				mcast = 1;
		}
		if ((cmsg->cmsg_level == IPPROTO_IPV6)
		    && (cmsg->cmsg_type == IPV6_PKTINFO)) {
			struct in6_pktinfo	*info;

			info = (struct in6_pktinfo *)CMSG_DATA(cmsg);
			if (memcmp(&info->ipi6_addr, &ssdp6.sin6_addr,
			    sizeof(struct in6_addr)) == 0)
				mcast = 1;
		}
	}

	for (la = TAILQ_FIRST(&env->listen_addrs); la;
	    la = TAILQ_NEXT(la, entry))
		if (la->sa.ss_family == ss.ss_family && la->index == ifindex)
			break;

	if (la == NULL) {
		log_warnx("unable to find interface");
		goto cleanup;
	}

	if ((input = evbuffer_new()) == NULL)
		return;

	if (evbuffer_add(input, buf, len) == -1) {
		evbuffer_free(input);
		return;
	}

	if (ssdp_parse_packet(input, &verb, &uri, &version, &headers,
	    &body)) {
		log_warnx("Unable to parse HTTP(M)U packet:\n%.*s", len, buf);
		goto cleanup;
	}

	evbuffer_free(input);

	/* M-SEARCH verb, URI of '*', MX header present if received via
	 * multicast, MAN header of "ssdp:discover" (including quotes) and an
	 * ST that I understand
	 */
	if (strcmp(verb, "M-SEARCH") || strcmp(uri, "*"))
		goto cleanup;

	/* This was a multicast request */
	if (mcast) {
		if ((header = ssdp_find_header(&headers, "mx")) == NULL)
			goto cleanup;

		/* Convert MX */
		mx = strtonum(header->value, 0, UINT_MAX, &errstr);
		if (errstr) {
			log_warnx("MX header value is %s: %s", errstr,
			    header->value);
			goto cleanup;
		}
		if (mx > SSDP_MAXIMUM_MX)
			mx = SSDP_MAXIMUM_MX;
	} else
		mx = 0;

#if UPNP_VERSION_NUMBER >= 0x0200
	/* FIXME Deal with {TCPPORT,CPFN,CPUUID}.UPNP.ORG headers */
#endif

	if ((header = ssdp_find_header(&headers, "man")) == NULL
	    || strcmp(header->value, "\"ssdp:discover\"")
	    || (header = ssdp_find_header(&headers, "st")) == NULL)
		goto cleanup;

	log_debug("Got packet from %s:\n%.*s",
	    log_sockaddr((struct sockaddr *)&ss), len, buf);

	if (strcmp(header->value, "ssdp:all") == 0) {
		/* Send all devices and services */
		for (device = TAILQ_FIRST(&root->devices); device;
		    device = TAILQ_NEXT(device, entry)) {
			if (device == TAILQ_FIRST(&root->devices)) {
				/* root device */
				if ((usn = ssdp_concat(device->uuid,
				    UPNP_ROOT_DEVICE)) == NULL)
					fatalx("ssdp_concat");

				ssdp_unicast(env, la, ss, msg.msg_namelen,
				    UPNP_ROOT_DEVICE, usn, mx);

				free(usn);
			}

			ssdp_unicast(env, la, ss, msg.msg_namelen,
			    device->uuid, device->uuid, mx);

			if ((type = urn_to_string(device->urn)) == NULL)
				fatalx("urn_to_string");
			if ((usn = ssdp_concat(device->uuid, type)) == NULL)
				fatalx("ssdp_concat");

			ssdp_unicast(env, la, ss, msg.msg_namelen, type, usn,
			    mx);

			free(type);
			free(usn);
		}

		/* FIXME Should 'uniq' the list of services here */
		for (service = TAILQ_FIRST(&root->services); service;
		    service = TAILQ_NEXT(service, entry)) {
			if ((type = urn_to_string(service->urn)) == NULL)
				fatalx("urn_to_string");
			if ((usn = ssdp_concat(service->parent->uuid,
			    type)) == NULL)
				fatalx("ssdp_concat");

			ssdp_unicast(env, la, ss, msg.msg_namelen, type, usn,
			    mx);

			free(type);
			free(usn);
		}
	} else if (strcmp(header->value, UPNP_ROOT_DEVICE) == 0) {
		/* Send root device */
		device = TAILQ_FIRST(&root->devices);

		if ((usn = ssdp_concat(device->uuid, UPNP_ROOT_DEVICE)) == NULL)
			fatalx("ssdp_concat");

		ssdp_unicast(env, la, ss, msg.msg_namelen, UPNP_ROOT_DEVICE,
		    usn, mx);

		free(usn);
	} else if (strncmp(header->value, "uuid:", 5) == 0) {
		/* Send matching device */
		for (device = TAILQ_FIRST(&root->devices);
		    device; device = TAILQ_NEXT(device, entry))
			if (strcmp(device->uuid, header->value) == 0)
				break;
		if (device == NULL)
			goto cleanup;

		ssdp_unicast(env, la, ss, msg.msg_namelen, header->value,
		    header->value, mx);
	} else if (strncasecmp(header->value, "urn:", 4) == 0) {
		/* Send matching device or service of type */
		if ((urn = urn_from_string(header->value)) == NULL)
			goto cleanup;
		if ((nss = upnp_nss_from_string(urn->nss)) == NULL) {
			urn_free(urn);
			goto cleanup;
		}

		switch (nss->type) {
		case UPNP_TYPE_DEVICE:
			for (device = TAILQ_FIRST(&root->devices);
			    device; device = TAILQ_NEXT(device, entry))
				if (strcmp(urn->nid, device->urn->nid) == 0 &&
				    nss->type == device->nss->type &&
				    strcmp(nss->name, device->nss->name) == 0 &&
				    nss->version <= device->nss->version) {
					if ((usn = ssdp_concat(device->uuid,
					    header->value)) == NULL)
						fatalx("ssdp_concat");

					ssdp_unicast(env, la, ss,
					    msg.msg_namelen, header->value,
					    usn, mx);

					free(usn);
				}
			break;
		case UPNP_TYPE_SERVICE:
			for (service = TAILQ_FIRST(&root->services);
			    service; service = TAILQ_NEXT(service, entry))
				if (strcmp(urn->nid, service->urn->nid) == 0 &&
				    nss->type == service->nss->type &&
				    strcmp(nss->name, service->nss->name) == 0 &&
				    nss->version <= service->nss->version) {
					if ((usn = ssdp_concat(
					    service->parent->uuid,
					    header->value)) == NULL)
						fatalx("ssdp_concat");

					ssdp_unicast(env, la, ss,
					    msg.msg_namelen, header->value,
					    usn, mx);

					free(usn);
				}
			break;
		default:
			break;
		}

		upnp_nss_free(nss);
		urn_free(urn);

	} else
		log_warnx("unknown ST header value: %s", header->value);

cleanup:
	free(verb);
	free(uri);
	free(version);

	while ((header = TAILQ_FIRST(&headers))) {
		TAILQ_REMOVE(&headers, header, entry);
		free(header->key);
		free(header->value);
		free(header);
	}

	free(body);
}
