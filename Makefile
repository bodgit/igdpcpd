LOCALBASE?= /usr/local

PROG=	igdpcpd
SRCS=	igdpcpd.c log.c parse.y urn.c ssdp.c upnp.c
CFLAGS+= -Wall -I${.CURDIR} -I/usr/local/include `pkg-config --cflags libxml-2.0`
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
YFLAGS=
LDADD+= -levent -L/usr/local/lib -luuid -leventextra `pkg-config --libs libxml-2.0`
DPADD+= ${LIBEVENT}
MAN=	#igdpcpd.8 igdpcpd.conf.5

MANDIR=	${LOCALBASE}/man/cat
BINDIR=	${LOCALBASE}/sbin

.include <bsd.prog.mk>
