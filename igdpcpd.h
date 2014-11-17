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

#ifndef _IGDPCPD_H
#define _IGDPCPD_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>
#include <netdb.h>

#include <libxml/tree.h>
#include <libxml/parser.h>

#define	SALIGN				 (sizeof(long) - 1)
#define	SA_RLEN(sa) \
	((sa)->sa_len ? (((sa)->sa_len + SALIGN) & ~SALIGN) : (SALIGN + 1))

#define IN6ADDR_LINKLOCAL_SSDP_INIT \
	{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c }}}

#define	IN6ADDR_LINKLOCAL_EVENT_INIT \
	{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x30 }}}

#define	IN6ADDR_V4MAPPED_INIT \
	{{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }}}

#define	IN6_IS_ADDR_V4MAPPED_ANY(a) \
	((*(const u_int32_t *)(const void *)(&(a)->s6_addr[0]) == 0) && \
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[4]) == 0) && \
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[8]) == ntohl(0x0000ffff)) && \
	 (*(const u_int32_t *)(const void *)(&(a)->s6_addr[12]) == 0))

#define	IGDPCPD_USER			 "_igdpcpd"
#define	CONF_FILE			 "/etc/igdpcpd.conf"

#define	INADDR_SSDP_GROUP		 __IPADDR(0xeffffffa) /* 239.255.255.250 */
#define	INADDR_EVENT_GROUP		 __IPADDR(0xeffffff6) /* 239.255.255.246 */
#define	SSDP_PORT			 1900
#define	EVENT_PORT			 7900

#if 0
#define	NATPMPD_SERVER_PORT		 5351
#define	NATPMPD_CLIENT_PORT		 5350

#define	NATPMPD_ANCHOR			 "natpmpd"

#define	NATPMP_MIN_VERSION		 0
#define	NATPMP_MAX_VERSION		 0

#define	NATPMP_SUCCESS			 0
#define	NATPMP_UNSUPP_VERSION		 1
#define	NATPMP_NOT_AUTHORISED		 2
#define	NATPMP_NETWORK_FAILURE		 3
#define	NATPMP_NO_RESOURCES		 4
#define	NATPMP_UNSUPP_OPCODE		 5

#define	NATPMP_MAX_PACKET_SIZE		 16

#define	NATPMP_OPCODE_ANNOUNCE		 0
#define	NATPMP_OPCODE_MAP_UDP		 1
#define	NATPMP_OPCODE_MAP_TCP		 2

#define	PCP_MIN_VERSION			 2
#define	PCP_MAX_VERSION			 2

#define	PCP_SUCCESS			 0
#define	PCP_UNSUPP_VERSION		 1
#define	PCP_NOT_AUTHORISED		 2
#define	PCP_MALFORMED_REQUEST		 3
#define	PCP_UNSUPP_OPCODE		 4
#define	PCP_UNSUPP_OPTION		 5
#define	PCP_MALFORMED_OPTION		 6
#define	PCP_NETWORK_FAILURE		 7
#define	PCP_NO_RESOURCES		 8
#define	PCP_UNSUPP_PROTOCOL		 9
#define	PCP_USER_EX_QUOTA		 10
#define	PCP_CANNOT_PROVIDE_EXTERNAL	 11
#define	PCP_ADDRESS_MISMATCH		 12
#define	PCP_EXCESSIVE_REMOTE_PEERS	 13
#define	PCP_UNSUPP_FAMILY		 14

#define	PCP_SHORT_LIFETIME		 30
#define	PCP_LONG_LIFETIME		 1800

#define	PCP_NONCE_LENGTH		 12

#define	PCP_MAX_PACKET_SIZE		 1100

#define	PCP_MAX_REMOTE_PEERS		 10

#define	PCP_OPCODE_ANNOUNCE		 0
#define	PCP_OPCODE_MAP			 1
#define	PCP_OPCODE_PEER			 2

#define	PCP_OPTION_THIRD_PARTY		 1
#define	PCP_OPTION_PREFER_FAILURE	 2
#define	PCP_OPTION_FILTER		 3

#define	NATPMPD_MAX_DELAY		 10

#define	NATPMPD_MAX_VERSION \
	MAX(NATPMP_MAX_VERSION, PCP_MAX_VERSION)

#define	NATPMPD_MAX_PACKET_SIZE \
	MAX(NATPMP_MAX_PACKET_SIZE, PCP_MAX_PACKET_SIZE)
#endif

#define	UPNP_VERSION_MAJOR	 2
#define	UPNP_VERSION_MINOR	 0
#define	UPNP_VERSION_NUMBER \
	((UPNP_VERSION_MAJOR << 8) + UPNP_VERSION_MINOR)
#define	UPNP_VERSION_STRING \
	(UPNP_STRING(UPNP_VERSION_MAJOR) "." UPNP_STRING(UPNP_VERSION_MINOR))

struct urn {
	char	*nid;		/* Namespace Identifier */
	char	*nss;		/* Namespace Specific String */
};

enum upnp_types {
	UPNP_TYPE_DEVICE = 0,
	UPNP_TYPE_SERVICE,
	UPNP_TYPE_MAX,
};

enum upnp_devices {
	UPNP_DEVICE_EOL = -1,
	UPNP_DEVICE_INTERNET_GATEWAY_DEVICE = 0,
	UPNP_DEVICE_WAN_DEVICE,
	UPNP_DEVICE_WAN_CONNECTION_DEVICE,
	UPNP_DEVICE_MAX,
};

enum upnp_services {
	UPNP_SERVICE_EOL = -1,
	UPNP_SERVICE_WAN_COMMON_INTERFACE_CONFIG = 0,
	UPNP_SERVICE_WAN_IP_CONNECTION,
	UPNP_SERVICE_MAX,
};

struct upnp_nss {
	enum upnp_types	 type;
	char		*name;
	unsigned int	 version;
};

struct ssdp_device {
	TAILQ_ENTRY(ssdp_device)	 entry;
	char				*uuid;
	struct urn			*urn;
	struct upnp_nss			*nss;
};

TAILQ_HEAD(ssdp_devices, ssdp_device);

struct ssdp_service {
	TAILQ_ENTRY(ssdp_service)	 entry;
	struct ssdp_device		*parent;
	struct urn			*urn;
	struct upnp_nss			*nss;
	xmlDocPtr			 document;
};

TAILQ_HEAD(ssdp_services, ssdp_service);

struct ssdp_root {
	struct ssdp_devices	 devices;
	struct ssdp_services	 services;
	xmlDocPtr		 document;
};

#if 0
struct address {
	struct sockaddr_storage	 ss;
	in_port_t		 port;
};
#endif

struct listen_addr {
	TAILQ_ENTRY(listen_addr)	 entry;
	struct sockaddr_storage		 sa;
	struct sockaddr_storage		 http_sa;
	int				 fd;
	int				 http_fd;
	unsigned int			 index;
	struct event			*ev;
};

struct ntp_addr {
	struct ntp_addr		*next;
	struct sockaddr_storage	 ss;
};

struct ntp_addr_wrap {
	char			*name;
	struct ntp_addr		*a;
	u_int8_t		 pool;
};

struct igdpcpd {
	struct event_base	*sc_base;
	u_int8_t		 sc_flags;
#define IGDPCPD_F_VERBOSE	 0x01;

	const char		*sc_confpath;
	TAILQ_HEAD(listen_addrs, listen_addr)		 listen_addrs;
	u_int8_t					 listen_all;
	struct timeval		 sc_boottime;
	struct timeval		 sc_nexttime;
	u_int32_t		 sc_version;
	u_int16_t		 sc_port;
	int			 sc_mc4_fd;
	int			 sc_mc6_fd;
	struct event		*sc_mc4_ev;
	struct event		*sc_mc6_ev;
	struct event		*sc_announce_ev;
	struct evhttp		*sc_httpd;
	struct ssdp_root	*sc_root;
};

/* prototypes */
/* log.c */
void			 log_init(int);
void			 vlog(int, const char *, va_list);
void			 log_warn(const char *, ...);
void			 log_warnx(const char *, ...);
void			 log_info(const char *, ...);
void			 log_debug(const char *, ...);
void			 fatal(const char *);
void			 fatalx(const char *);
const char		*log_sockaddr(struct sockaddr *);

/* parse.y */
struct igdpcpd		*parse_config(const char *, u_int);
int			 host(const char *, struct ntp_addr **);
int			 host_dns(const char *, struct ntp_addr **);

/* urn.c */
char			*urn_to_string(struct urn *);
struct urn		*urn_from_string(char *);
void			 urn_free(struct urn *);

/* ssdp.c */
void			 ssdp_announce(int, short, void *);
void			 ssdp_recvmsg(int, short, void *);

/* upnp.c */
char			*upnp_nss_to_string(struct upnp_nss *);
struct upnp_nss		*upnp_nss_from_string(char *);
void			 upnp_nss_free(struct upnp_nss *);
struct ssdp_root	*upnp_root_device(u_int32_t, enum upnp_devices,
			     struct evhttp *);
void			 upnp_debug(struct evhttp_request *, void *);

#endif
