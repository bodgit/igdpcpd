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
#include <sys/socket.h>
#include <sys/utsname.h>

#include <netinet/in.h>

#include <net/if_dl.h>

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <err.h>
#include <pwd.h>
#include <ifaddrs.h>
#include <unistd.h>

#include "igdpcpd.h"

#if UPNP_VERSION_NUMBER <= 0x0100
#define	UPNP_MULTICAST_TTL	 4
#else
#define	UPNP_MULTICAST_TTL	 2
#endif

__dead void		 usage(void);
void			 handle_signal(int, short, void *);

struct sockaddr_in	 ssdp4, pcp4;
struct sockaddr_in6	 ssdp6, pcp6;
struct utsname		 name;

/* __dead is for lint */
__dead void
usage(void)
{
	extern char	*__progname;

	fprintf(stderr, "usage: %s [-dnv] [-f file]\n", __progname);
	exit(1);
}

void
handle_signal(int sig, short event, void *arg)
{
	log_info("exiting on signal %d", sig);

	exit(0);
}

int
main(int argc, char *argv[])
{
	int			 c;
	int			 debug = 0;
	int			 noaction = 0;
	const char		*conffile = CONF_FILE;
	u_int			 flags = 0;
	struct passwd		*pw;
	struct igdpcpd		*env;
	struct in6_addr		 ssdp_link_nodes = IN6ADDR_LINKLOCAL_SSDP_INIT;
	struct in6_addr		 all_nodes = IN6ADDR_LINKLOCAL_ALLNODES_INIT;
	struct ifaddrs		*ifap, *ifa, *ifal;
	struct listen_addr	*la;
	int			 reuse = 1;
	unsigned char		 loop4 = 0;
	unsigned int		 loop6 = 0;
	unsigned char		 ttl4 = UPNP_MULTICAST_TTL;
	int			 ttl6 = UPNP_MULTICAST_TTL;
	struct ip_mreq		 mreq4;
	struct ipv6_mreq	 mreq6;
	struct event		*ev_sighup;
	struct event		*ev_sigint;
	struct event		*ev_sigterm;
	struct timeval		 tv = { 0, 0 };
	socklen_t		 slen;

	log_init(1);

	while ((c = getopt(argc, argv, "df:nv")) != -1) {
		switch (c) {
		case 'd':
			debug = 1;
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'n':
			noaction++;
			break;
		case 'v':
			flags |= IGDPCPD_F_VERBOSE;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;
	if (argc > 0)
		usage();

	if ((env = parse_config(conffile, flags)) == NULL)
		exit(1);

	if (noaction) {
		fprintf(stderr, "configuration ok\n");
		exit(0);
	}

	if (geteuid())
		errx(1, "need root privileges");

	if ((pw = getpwnam(IGDPCPD_USER)) == NULL)
		errx(1, "unknown user %s", IGDPCPD_USER);

	log_init(debug);

	if (!debug) {
		if (daemon(1, 0) == -1)
			err(1, "failed to daemonize");
	}

	gettimeofday(&env->sc_boottime, NULL);

	memset(&ssdp4, 0, sizeof(ssdp4));
	ssdp4.sin_family = AF_INET;
	ssdp4.sin_len = sizeof(ssdp4);
	ssdp4.sin_addr.s_addr = htonl(INADDR_SSDP_GROUP);
	ssdp4.sin_port = htons(SSDP_PORT);

	memset(&ssdp6, 0, sizeof(ssdp6));
	ssdp6.sin6_family = AF_INET6;
	ssdp6.sin6_len = sizeof(ssdp6);
	ssdp6.sin6_addr = ssdp_link_nodes;
	ssdp6.sin6_port = htons(SSDP_PORT);

	memset(&pcp4, 0, sizeof(pcp4));
	pcp4.sin_family = AF_INET;
	pcp4.sin_len = sizeof(pcp4);
	pcp4.sin_addr.s_addr = htonl(INADDR_ALLHOSTS_GROUP);
	pcp4.sin_port = htons(PCP_CLIENT_PORT);

	memset(&pcp6, 0, sizeof(pcp6));
	pcp6.sin6_family = AF_INET6;
	pcp6.sin6_len = sizeof(pcp6);
	pcp6.sin6_addr = all_nodes;
	pcp6.sin6_port = htons(PCP_CLIENT_PORT);

	if (uname(&name) == -1)
		fatal("uname");

	if (getifaddrs(&ifap) == -1)
		fatal("getifaddrs");

	for (la = TAILQ_FIRST(&env->listen_addrs); la; ) {
		switch (la->sa.ss_family) {
		case AF_INET:
			if (((struct sockaddr_in *)&la->sa)->sin_port == 0)
				((struct sockaddr_in *)&la->sa)->sin_port =
				    htons(SSDP_PORT);
			break;
		case AF_INET6:
			if (((struct sockaddr_in6 *)&la->sa)->sin6_port == 0)
				((struct sockaddr_in6 *)&la->sa)->sin6_port =
				    htons(SSDP_PORT);
			break;
		default:
			fatalx("king bula sez: af borked");
		}

		log_info("listening on %s:%u",
		    log_sockaddr((struct sockaddr *)&la->sa),
		    SSDP_PORT);

		if ((la->fd = socket(la->sa.ss_family, SOCK_DGRAM, 0)) == -1)
			fatal("socket");

		if (fcntl(la->fd, F_SETFL, O_NONBLOCK) == -1)
			fatal("fcntl");

		if (setsockopt(la->fd, SOL_SOCKET, SO_REUSEADDR, &reuse,
		    sizeof(reuse)) == -1)
			fatal("setsockopt");

		if (setsockopt(la->fd, SOL_SOCKET, SO_REUSEPORT, &reuse,
		    sizeof(reuse)) == -1)
			fatal("setsockopt");

		switch (la->sa.ss_family) {
		case AF_INET:
			if (setsockopt(la->fd, IPPROTO_IP, IP_MULTICAST_LOOP,
			    &loop4, sizeof(loop4)) == -1)
				fatal("setsockopt");

			if (setsockopt(la->fd, IPPROTO_IP, IP_MULTICAST_TTL,
			    &ttl4, sizeof(ttl4)) == -1)
				fatal("setsockopt");

			if (setsockopt(la->fd, IPPROTO_IP, IP_MULTICAST_IF,
			    &(((struct sockaddr_in *)&la->sa)->sin_addr),
			    sizeof(struct in_addr)) == -1)
				fatal("setsockopt");

			if (setsockopt(la->fd, IPPROTO_IP, IP_RECVDSTADDR,
			    &reuse, sizeof(reuse)) == -1)
				fatal("setsockopt");

			if (setsockopt(la->fd, IPPROTO_IP, IP_RECVIF, &reuse,
			    sizeof(reuse)) == -1)
				fatal("setsockopt");

			/* Assume AF_LINK always comes first */
			for (ifa = ifal = ifap; ifa; ifa = ifa->ifa_next) {
				if (ifa->ifa_addr == NULL)
					continue;
				switch (ifa->ifa_addr->sa_family) {
				case AF_LINK:
					ifal = ifa;
					break;
				case AF_INET:
					if (memcmp(&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr,
					    &((struct sockaddr_in *)&la->sa)->sin_addr,
					    sizeof(struct in_addr)) == 0)
						la->index = ((struct sockaddr_dl *)ifal->ifa_addr)->sdl_index;
					break;
				}
			}
			break;
		case AF_INET6:
			if (setsockopt(la->fd, IPPROTO_IPV6,
			    IPV6_MULTICAST_LOOP, &loop6, sizeof(loop6)) == -1)
				fatal("setsockopt");

			if (setsockopt(la->fd, IPPROTO_IPV6,
			    IPV6_MULTICAST_HOPS, &ttl6, sizeof(ttl6)) == -1)
				fatal("setsockopt");

			if (setsockopt(la->fd, IPPROTO_IPV6, IPV6_MULTICAST_IF,
			    &((struct sockaddr_in6 *)&la->sa)->sin6_scope_id,
			    sizeof(((struct sockaddr_in6 *)&la->sa)->sin6_scope_id)) == -1)
				fatal("setsockopt");

			if (setsockopt(la->fd, IPPROTO_IPV6, IPV6_RECVPKTINFO,
			    &reuse, sizeof(reuse)) == -1)
				fatal("setsockopt");

			la->index = ((struct sockaddr_in6 *)&la->sa)->sin6_scope_id;
			break;
		default:
			/* NOTREACHED */
			break;
		}

		if (bind(la->fd, (struct sockaddr *)&la->sa,
		    SA_LEN((struct sockaddr *)&la->sa)) == -1) {
			struct listen_addr	*nla;

			log_warn("bind on %d failed, skipping",
			    log_sockaddr((struct sockaddr *)&la->sa));
			close(la->fd);
			nla = TAILQ_NEXT(la, entry);
			TAILQ_REMOVE(&env->listen_addrs, la, entry);
			free(la);
			la = nla;
			continue;
		}

		switch (la->sa.ss_family) {
		case AF_INET:
			/* Create IPv4 multicast socket if needed */
			if (env->sc_mc4_fd == 0) {
				if ((env->sc_mc4_fd = socket(AF_INET,
				    SOCK_DGRAM, 0)) == -1)
					fatal("socket");

				if (fcntl(env->sc_mc4_fd, F_SETFL,
				    O_NONBLOCK) == -1)
					fatal("fcntl");

				if (setsockopt(env->sc_mc4_fd, SOL_SOCKET,
				    SO_REUSEADDR, &reuse, sizeof(reuse)) == -1)
					fatal("setsockopt");

				if (setsockopt(env->sc_mc4_fd, SOL_SOCKET,
				    SO_REUSEPORT, &reuse, sizeof(reuse)) == -1)
					fatal("setsockopt");

				if (bind(env->sc_mc4_fd,
				    (struct sockaddr *)&ssdp4,
				    sizeof(ssdp4)) == -1)
					fatal("bind");

				if (setsockopt(env->sc_mc4_fd, IPPROTO_IP,
				    IP_MULTICAST_LOOP, &loop4,
				    sizeof(loop4)) == -1)
					fatal("setsockopt");

				if (setsockopt(env->sc_mc4_fd, IPPROTO_IP,
				    IP_RECVDSTADDR, &reuse,
				    sizeof(reuse)) == -1)
					fatal("setsockopt");

				if (setsockopt(env->sc_mc4_fd, IPPROTO_IP,
				    IP_RECVIF, &reuse, sizeof(reuse)) == -1)
					fatal("setsockopt");

				log_info("listening on %s:%u",
				    log_sockaddr((struct sockaddr *)&ssdp4),
				    SSDP_PORT);
			}

			memset(&mreq4, 0, sizeof(mreq4));
			mreq4.imr_multiaddr = ssdp4.sin_addr;
			mreq4.imr_interface = ((struct sockaddr_in *)&la->sa)->sin_addr;

			if (setsockopt(env->sc_mc4_fd, IPPROTO_IP,
			    IP_ADD_MEMBERSHIP, &mreq4, sizeof(mreq4)) == -1)
				fatal("setsockopt");
			break;
		case AF_INET6:
			/* Create IPv6 multicast socket if needed */
			if (env->sc_mc6_fd == 0) {
				if ((env->sc_mc6_fd = socket(AF_INET6,
				    SOCK_DGRAM, 0)) == -1)
					fatal("socket");

				if (fcntl(env->sc_mc6_fd, F_SETFL,
				    O_NONBLOCK) == -1)
					fatal("fcntl");

				if (setsockopt(env->sc_mc6_fd, SOL_SOCKET,
				    SO_REUSEADDR, &reuse, sizeof(reuse)) == -1)
					fatal("setsockopt");

				if (setsockopt(env->sc_mc6_fd, SOL_SOCKET,
				    SO_REUSEPORT, &reuse, sizeof(reuse)) == -1)
					fatal("setsockopt");

				if (bind(env->sc_mc6_fd,
				    (struct sockaddr *)&ssdp6,
				    sizeof(ssdp6)) == -1)
					fatal("bind");

				if (setsockopt(env->sc_mc6_fd, IPPROTO_IPV6,
				    IPV6_MULTICAST_LOOP, &loop6,
				    sizeof(loop6)) == -1)
					fatal("setsockopt");

				if (setsockopt(env->sc_mc6_fd, IPPROTO_IPV6,
				    IPV6_RECVPKTINFO, &reuse,
				    sizeof(reuse)) == -1)
					fatal("setsockopt");

				log_info("listening on %s:%u",
				    log_sockaddr((struct sockaddr *)&ssdp6),
				    SSDP_PORT);
			}

			memset(&mreq6, 0, sizeof(mreq6));
			mreq6.ipv6mr_multiaddr = ssdp6.sin6_addr;
			mreq6.ipv6mr_interface = ((struct sockaddr_in6 *)&la->sa)->sin6_scope_id;

			if (setsockopt(env->sc_mc6_fd, IPPROTO_IPV6,
			    IPV6_JOIN_GROUP, &mreq6, sizeof(mreq6)) == -1)
				fatal("setsockopt");
			break;
		default:
			/* NOTREACHED */
			break;
		}

		/* HTTP */
		memcpy(&la->http_sa, &la->sa, sizeof(la->sa));

		switch (la->http_sa.ss_family) {
		case AF_INET:
			((struct sockaddr_in *)&la->http_sa)->sin_port =
			    htons(env->sc_port);
			break;
		case AF_INET6:
			((struct sockaddr_in6 *)&la->http_sa)->sin6_port =
			    htons(env->sc_port);
			break;
		default:
			/* NOTREACHED */
			break;
		}

		if ((la->http_fd = socket(la->http_sa.ss_family, SOCK_STREAM,
		    0)) == -1)
			fatal("socket");

		if (fcntl(la->http_fd, F_SETFL, O_NONBLOCK) == -1)
			fatal("fcntl");

		if (setsockopt(la->http_fd, SOL_SOCKET, SO_REUSEADDR, &reuse,
		    sizeof(reuse)) == -1)
			fatal("setsockopt");

		if (bind(la->http_fd, (struct sockaddr *)&la->http_sa,
		    SA_LEN((struct sockaddr *)&la->http_sa)) == -1)
			fatal("bind");

		/* If the HTTP port is not explicitly configured, read back
		 * what the kernel gives us so we can use it in SSDP messages
		 */
		if (env->sc_port == 0) {
			slen = sizeof(la->http_fd);

			if (getsockname(la->http_fd,
			    (struct sockaddr *)&la->http_sa, &slen) == -1)
				fatal("getsockname");

#if 0
			/* Store the port so subsequent HTTP listeners will
			 * attempt to get the same port?
			 */
			switch (la->http_sa.ss_family) {
			case AF_INET:
				env->sc_port = ntohs(((struct sockaddr_in *)&la->http_sa)->sin_port);
				break;
			case AF_INET6:
				env->sc_port = ntohs(((struct sockaddr_in6 *)&la->http_sa)->sin6_port);
				break;
			default:
				/* NOTREACHED */
				break;
			}
#endif
		}

		if (listen(la->http_fd, 16) == -1)
			fatal("listen");

		la = TAILQ_NEXT(la, entry);
	}

	freeifaddrs(ifap);

	log_info("startup");

	if (chroot(pw->pw_dir) == -1)
		fatal("chroot");
	if (chdir("/") == -1)
		fatal("chdir(\"/\")");

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("cannot drop privileges");

	if ((env->sc_base = event_base_new()) == NULL)
		fatalx("event_base_new");

	signal(SIGPIPE, SIG_IGN);
	ev_sighup = evsignal_new(env->sc_base, SIGHUP, handle_signal, env);
	ev_sigint = evsignal_new(env->sc_base, SIGINT, handle_signal, env);
	ev_sigterm = evsignal_new(env->sc_base, SIGTERM, handle_signal, env);
	evsignal_add(ev_sighup, NULL);
	evsignal_add(ev_sigint, NULL);
	evsignal_add(ev_sigterm, NULL);

	if (env->sc_mc4_fd) {
		env->sc_mc4_ev = event_new(env->sc_base, env->sc_mc4_fd,
		    EV_READ|EV_PERSIST, ssdp_recvmsg, env);
		event_add(env->sc_mc4_ev, NULL);
	}

	if (env->sc_mc6_fd) {
		env->sc_mc6_ev = event_new(env->sc_base, env->sc_mc6_fd,
		    EV_READ|EV_PERSIST, ssdp_recvmsg, env);
		event_add(env->sc_mc6_ev, NULL);
	}

	env->sc_httpd = evhttp_new(env->sc_base);

	for (la = TAILQ_FIRST(&env->listen_addrs); la; ) {
		la->ev = event_new(env->sc_base, la->fd, EV_READ|EV_PERSIST,
		    ssdp_recvmsg, env);
		event_add(la->ev, NULL);

		evhttp_accept_socket(env->sc_httpd, la->http_fd);

		la = TAILQ_NEXT(la, entry);
	}

	env->sc_root = upnp_root_device(env->sc_version,
	    UPNP_DEVICE_INTERNET_GATEWAY_DEVICE, env->sc_httpd);

	/* FIXME DEBUG */
	evhttp_set_gencb(env->sc_httpd, upnp_debug, env);

	env->sc_announce_ev = evtimer_new(env->sc_base, ssdp_announce, env);
	evtimer_add(env->sc_announce_ev, &tv);

	event_base_dispatch(env->sc_base);

	return (0);
}
