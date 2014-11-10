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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "igdpcpd.h"

int	 isother(int);
char	*urn_percent_encode(char *);
char	*urn_percent_decode(char *);

/* Allowed plain characters in NSS as well as those accepted by isalnum() */
int
isother(int c)
{
	if ((c >= '\'' && c <= '.') || c == '!' || c == '$' || c == ':' ||
	    c == ';' || c == '=' || c == '@' || c == '_')
		return (1);

	return (0);
}

/* Encode a string as per the rules in section 2.2 of RFC 2141 */
char *
urn_percent_encode(char *in)
{
	char	*out, *p = in, *q;

	/* The worst possible case is every character gets replaced with %xx
	 * so the string grows to be three times longer
	 */
	if ((q = out = calloc((strlen(in) * 3) + 1, sizeof(char))) == NULL)
		return (NULL);

	while (*p) {
		if (isalnum(*p) || isother(*p))
			*q++ = *p;
		else {
			snprintf(q, 4, "%%%02x", *p);
			q += 3;
		}
		p++;
	}

	return (out);
}

/* Decode a string as per the rules in section 2.2 of RFC 2141 */
char *
urn_percent_decode(char *in)
{
	char	*out, *p = in, *q;

	if ((q = out = calloc(strlen(in) + 1, sizeof(char))) == NULL)
		return (NULL);

	while (*p) {
		if (*p == '%') {
			if (strlen(p) < 3 || !isxdigit(p[1]) ||
			    !isxdigit(p[2]) ||
			    sscanf(p, "%%%2hhx", q++) != 1) {
				free(out);
				return (NULL);
			}
			p += 2;
		} else
			*q++ = *p;
		p++;
	}

	return (out);
}

/* Return the string representation of the URN structure */
char *
urn_to_string(struct urn *urn)
{
	size_t	 len;
	char	*str, *nss;

	/* Create %-encoded version of the NSS */
	if ((nss = urn_percent_encode(urn->nss)) == NULL)
		return (NULL);

	len = snprintf(NULL, 0, "urn:%s:%s", urn->nid, nss);
	if ((str = calloc(len + 1, sizeof(char))) == NULL) {
		free(nss);
		return (NULL);
	}
	snprintf(str, len + 1, "urn:%s:%s", urn->nid, nss);

	free(nss);

	return (str);
}

/* Return a URN structure for a given string representation */
struct urn *
urn_from_string(char *str)
{
	struct urn	*urn = NULL;
	char		*p;

	if (strncasecmp(str, "urn:", 4))
		return (NULL);
	str += 4;

	/* First character must be one of A-Z, a-z or 0-9 */
	if (!isalnum(*str))
		return (NULL);

	p = str;
	while (isalnum(*p) || *p == '-')
		p++;
	if (*p != ':')
		return (NULL);

	if ((urn = calloc(1, sizeof(struct urn))) == NULL)
		return (NULL);

	if ((urn->nid = calloc((p - str) + 1, sizeof(char))) == NULL) {
		free(urn);
		return (NULL);
	}
	strncpy(urn->nid, str, p - str);

	p++;

	/* As per the RFC %-decode the NSS portion */
	if (!strcasecmp(urn->nid, "urn") || strlen(p) == 0 ||
	    (urn->nss = urn_percent_decode(p)) == NULL) {
		free(urn->nid);
		free(urn);
		return (NULL);
	}

	return (urn);
}

/* Free a URN structure */
void
urn_free(struct urn *urn)
{
	free(urn->nss);
	free(urn->nid);
	free(urn);
}
