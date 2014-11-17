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

#include <sys/limits.h>
#include <sys/utsname.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <uuid.h>

#include "igdpcpd.h"

#define	UPNP_NID		 "upnp-org"
#define	UPNP_SCHEMA_NID		 "schemas-upnp-org"
#define	UPNP_DEVICE_TYPE	 "device"
#define	UPNP_SERVICE_TYPE	 "service"
#define	UPNP_CONTROL_TYPE	 "control"
#define	UPNP_EVENT_TYPE		 "event"

/* Macro expansion fun */
#define	UPNP_STRING(x)		 __STRING(x)

#define	UPNP_URN(nid, nss)	("urn:" nid ":" nss)

#define	UPNP_TYPE_URN(nid, type, name, version) \
	(UPNP_URN(nid, type ":" name ":" UPNP_STRING(version)))
#define	UPNP_SCHEMA_URN(nid, type, major, minor) \
	(UPNP_URN(nid, type "-" UPNP_STRING(major) "-" UPNP_STRING(minor)))
#define	UPNP_SERVICE_ID_URN(nid, type, instance) \
	(UPNP_URN(nid, "serviceId:" type UPNP_STRING(instance)))

#define	UPNP_DEVICE_SCHEMA_URN \
	(UPNP_SCHEMA_URN(UPNP_SCHEMA_NID, UPNP_DEVICE_TYPE, 1, 0))
#define	UPNP_SERVICE_SCHEMA_URN \
	(UPNP_SCHEMA_URN(UPNP_SCHEMA_NID, UPNP_SERVICE_TYPE, 1, 0))
#define	UPNP_CONTROL_SCHEMA_URN \
	(UPNP_SCHEMA_URN(UPNP_SCHEMA_NID, UPNP_CONTROL_TYPE, 1, 0))
#define	UPNP_EVENT_SCHEMA_URN \
	(UPNP_SCHEMA_URN(UPNP_SCHEMA_NID, UPNP_EVENT_TYPE, 1, 0))

#define	UPNP_VERSION_INTERNET_GATEWAY_DEVICE		 2
#define	UPNP_VERSION_WAN_COMMON_INTERFACE_CONFIG	 1

#if UPNP_VERSION_INTERNET_GATEWAY_DEVICE >= 2
#define UPNP_VERSION_WAN_DEVICE				 2
#define	UPNP_VERSION_WAN_CONNECTION_DEVICE		 2
#define	UPNP_VERSION_WAN_IP_CONNECTION			 2
#else
#define	UPNP_VERSION_WAN_DEVICE				 1
#define	UPNP_VERSION_WAN_CONNECTION_DEVICE		 1
#define	UPNP_VERSION_WAN_IP_CONNECTION			 1
#endif

#define	XML_INDENT_TREE					 1

#define	SOAP_ENVELOPE_URI \
	"http://schemas.xmlsoap.org/soap/envelope/"
#define	SOAP_ENCODING_URI \
	"http://schemas.xmlsoap.org/soap/encoding/"
#define	SOAP_NAMESPACE_PREFIX				 "s"
#define	UPNP_NAMESPACE_PREFIX				 "u"

enum upnp_variable_types {
	UPNP_VARIABLE_TYPE_UI1 = 0,
	UPNP_VARIABLE_TYPE_UI2,
	UPNP_VARIABLE_TYPE_UI4,
	UPNP_VARIABLE_TYPE_I1,
	UPNP_VARIABLE_TYPE_I2,
	UPNP_VARIABLE_TYPE_I4,
	UPNP_VARIABLE_TYPE_INT,
	UPNP_VARIABLE_TYPE_R4,
	UPNP_VARIABLE_TYPE_R8,
	UPNP_VARIABLE_TYPE_NUMBER,
	UPNP_VARIABLE_TYPE_FIXED_14_4,
	UPNP_VARIABLE_TYPE_FLOAT,
	UPNP_VARIABLE_TYPE_CHAR,
	UPNP_VARIABLE_TYPE_STRING,
	UPNP_VARIABLE_TYPE_DATE,
	UPNP_VARIABLE_TYPE_DATE_TIME,
	UPNP_VARIABLE_TYPE_DATE_TIME_TZ,
	UPNP_VARIABLE_TYPE_TIME,
	UPNP_VARIABLE_TYPE_TIME_TZ,
	UPNP_VARIABLE_TYPE_BOOLEAN,
	UPNP_VARIABLE_TYPE_BIN_BASE64,
	UPNP_VARIABLE_TYPE_BIN_HEX,
	UPNP_VARIABLE_TYPE_URI,
	UPNP_VARIABLE_TYPE_UUID,
	UPNP_VARIABLE_TYPE_MAX,
};

enum upnp_variables {
	UPNP_VARIABLE_EOL = -1,
	/* WANCommonInterfaceConfig */
	UPNP_VARIABLE_WAN_ACCESS_TYPE = 0,
	UPNP_VARIABLE_LAYER_1_UPSTREAM_MAX_BIT_RATE,
	UPNP_VARIABLE_LAYER_1_DOWNSTREAM_MAX_BIT_RATE,
	UPNP_VARIABLE_PHYSICAL_LINK_STATUS,
	/* WANIPConnection */
	UPNP_VARIABLE_CONNECTION_TYPE,
	UPNP_VARIABLE_POSSIBLE_CONNECTION_TYPES,
	UPNP_VARIABLE_CONNECTION_STATUS,
	UPNP_VARIABLE_UPTIME,
	UPNP_VARIABLE_LAST_CONNECTION_ERROR,
	UPNP_VARIABLE_RSIP_AVAILABLE,
	UPNP_VARIABLE_NAT_ENABLED,
	UPNP_VARIABLE_EXTERNAL_IP_ADDRESS,
	UPNP_VARIABLE_PORT_MAPPING_NUMBER_OF_ENTRIES,
	UPNP_VARIABLE_PORT_MAPPING_ENABLED,
	UPNP_VARIABLE_PORT_MAPPING_LEASE_DURATION,
	UPNP_VARIABLE_REMOTE_HOST,
	UPNP_VARIABLE_EXTERNAL_PORT,
	UPNP_VARIABLE_INTERNAL_PORT,
	UPNP_VARIABLE_PORT_MAPPING_PROTOCOL,
	UPNP_VARIABLE_INTERNAL_CLIENT,
	UPNP_VARIABLE_PORT_MAPPING_DESCRIPTION,
	UPNP_VARIABLE_SYSTEM_UPDATE_ID,
	UPNP_VARIABLE_A_ARG_TYPE_MANAGE,
	UPNP_VARIABLE_A_ARG_TYPE_PORT_LISTING,
	UPNP_VARIABLE_MAX,
};

#define	UPNP_VARIABLE_FLAG_EVENT	(1<<0)
#define	UPNP_VARIABLE_FLAG_MULTICAST	(1<<1)

struct upnp_variable {
	char				 *name;
	enum upnp_variable_types	  type;
	unsigned int			  flags;
	char				**values;
	/* Probably shouldn't be char */
	char				 *value;
	char				 *minimum;
	char				 *maximum;
	char				 *step;
};

#define	UPNP_ARGUMENT_FLAG_RETURN	(1<<0)

struct upnp_argument {
	char				*name;
	unsigned int			 flags;
	enum upnp_variables		 related;
};

enum upnp_actions {
	UPNP_ACTION_EOL = -1,
	/* WANCommonInterfaceConfig */
	UPNP_ACTION_GET_COMMON_LINK_PROPERTIES = 0,
	/* WANIPConnection */
	UPNP_ACTION_SET_CONNECTION_TYPE,
	UPNP_ACTION_GET_CONNECTION_TYPE_INFO,
	UPNP_ACTION_REQUEST_CONNECTION,
	UPNP_ACTION_FORCE_TERMINATION,
	UPNP_ACTION_GET_STATUS_INFO,
	UPNP_ACTION_GET_NAT_RSIP_STATUS,
	UPNP_ACTION_GET_GENERIC_PORT_MAPPING_ENTRY,
	UPNP_ACTION_GET_SPECIFIC_PORT_MAPPING_ENTRY,
	UPNP_ACTION_ADD_PORT_MAPPING,
	UPNP_ACTION_ADD_ANY_PORT_MAPPING,
	UPNP_ACTION_DELETE_PORT_MAPPING,
	UPNP_ACTION_DELETE_PORT_MAPPING_RANGE,
	UPNP_ACTION_GET_EXTERNAL_IP_ADDRESS,
	UPNP_ACTION_GET_LIST_OF_PORT_MAPPINGS,
	UPNP_ACTION_MAX,
};

struct upnp_action {
	char			*name;
	unsigned int		 version, cin, cout;
	struct upnp_argument 	*in;
	struct upnp_argument 	*out;
};

struct upnp_service {
	char			*nid;
	struct upnp_nss		 nss;
	char			*id;
	char			*scpd;
	char			*control;
	char			*event;
	enum upnp_actions	*actions;
	enum upnp_variables	*variables;
};

struct upnp_device {
	char			*nid;
	struct upnp_nss		 nss;
	enum upnp_services	*services;
	enum upnp_devices	*devices;
};

enum upnp_errors {
	UPNP_ERROR_INVALID_ACTION = 0,
	UPNP_ERROR_INVALID_ARGS,
	UPNP_ERROR_ACTION_FAILED,
	UPNP_ERROR_ARGUMENT_VALUE_INVALID,
	UPNP_ERROR_ARGUMENT_VALUE_OUT_OF_RANGE,
	UPNP_ERROR_OPTIONAL_ACTION_NOT_IMPLEMENTED,
	UPNP_ERROR_OUT_OF_MEMORY,
	UPNP_ERROR_HUMAN_INTERVENTION_REQUIRED,
	UPNP_ERROR_STRING_ARGUMENT_TOO_LONG,
	UPNP_ERROR_ACTION_NOT_AUTHORIZED,
	UPNP_ERROR_SIGNATURE_FAILURE,
	UPNP_ERROR_SIGNATURE_MISSING,
	UPNP_ERROR_NOT_ENCRYPTED,
	UPNP_ERROR_INVALID_SEQUENCE,
	UPNP_ERROR_INVALID_CONTROL_URL,
	UPNP_ERROR_NO_SUCH_SESSION,
	UPNP_ERROR_MAX,
};

struct upnp_error {
	unsigned int		 code;
	char			*string;
};

void		 upnp_add_configid(xmlNodePtr, u_int32_t);
void		 upnp_add_version(xmlNodePtr);
void		 upnp_add_action(xmlNodePtr, const struct upnp_action *);
void		 upnp_add_variable(xmlNodePtr, const struct upnp_variable *);
xmlDocPtr	 upnp_service_xml(u_int32_t, enum upnp_services);
void		 upnp_add_service(xmlNodePtr, u_int32_t, enum upnp_services,
		     struct evhttp *, struct ssdp_device *,
		     struct ssdp_services *);
void		 upnp_add_device(xmlNodePtr, u_int32_t, enum upnp_devices,
		     struct evhttp *, struct ssdp_devices *,
		     struct ssdp_services *);
void		 upnp_add_xml(struct evbuffer *, xmlDocPtr);
void		 upnp_content_length_header(struct evhttp_request *,
		     struct evbuffer *);
void		 upnp_content_type_header(struct evhttp_request *);
void		 upnp_date_header(struct evhttp_request *);
void		 upnp_server_header(struct evhttp_request *);
void		 upnp_describe(struct evhttp_request *, void *);
void		 upnp_soap_error(struct evhttp_request *, enum upnp_errors);
void		 upnp_control(struct evhttp_request *, void *);
void		 upnp_event(struct evhttp_request *, void *);

extern struct utsname	 name;
const char		*upnp_version = UPNP_VERSION_STRING;

/* Used for parsing and generating URN NSS */
const char	*upnp_type[UPNP_TYPE_MAX] = {
	UPNP_DEVICE_TYPE,
	UPNP_SERVICE_TYPE,
};

/* UPnP variable types */
const char	*upnp_variable_type[UPNP_VARIABLE_TYPE_MAX] = {
	"ui1",
	"ui2",
	"ui4",
	"i1",
	"i2",
	"i4",
	"int",
	"r4",
	"r8",
	"number",
	"fixed.14.4",
	"float",
	"char",
	"string",
	"date",
	"dateTime",
	"dateTime.tz",
	"time",
	"time.tz",
	"boolean",
	"bin.base64",
	"bin.hex",
	"uri",
	"uuid",
};

/* UPnP state variables */
const struct upnp_variable	 upnp_variable[UPNP_VARIABLE_MAX] = {
	/* WANCommonInterfaceConfig */
	{
		"WANAccessType",
		UPNP_VARIABLE_TYPE_STRING,
		0,
		(char *[]){
			"DSL",
			"POTS",
			"Cable",
			"Ethernet",
			NULL,
		},
		NULL,
		NULL,
		NULL,
		NULL,
	},
	{
		"Layer1UpstreamMaxBitRate",
		UPNP_VARIABLE_TYPE_UI4,
		0,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
	},
	{
		"Layer1DownstreamMaxBitRate",
		UPNP_VARIABLE_TYPE_UI4,
		0,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
	},
	{
		"PhysicalLinkStatus",
		UPNP_VARIABLE_TYPE_STRING,
		UPNP_VARIABLE_FLAG_EVENT,
		(char *[]){
			"Up",
			"Down",
			NULL,
		},
		NULL,
		NULL,
		NULL,
		NULL,
	},
	/* WANIPConnection */
	{
		"ConnectionType",
		UPNP_VARIABLE_TYPE_STRING,
		0,
		(char *[]){
			"Unconfigured",
			"IP_Routed",
			"IP_Bridged",
			NULL,
		},
		NULL,
		NULL,
		NULL,
		NULL,
	},
	{
		"PossibleConnectionTypes",
		UPNP_VARIABLE_TYPE_STRING,
		UPNP_VARIABLE_FLAG_EVENT,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
	},
	{
		"ConnectionStatus",
		UPNP_VARIABLE_TYPE_STRING,
		UPNP_VARIABLE_FLAG_EVENT,
		(char *[]){
			"Unconfigured",
			"Connected",
			"Disconnected",
			NULL,
		},
		NULL,
		NULL,
		NULL,
		NULL,
	},
	{
		"Uptime",
		UPNP_VARIABLE_TYPE_UI4,
		0,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
	},
	{
		"LastConnectionError",
		UPNP_VARIABLE_TYPE_STRING,
		0,
		(char *[]){
			"ERROR_NONE",
			NULL,
		},
		NULL,
		NULL,
		NULL,
		NULL,
	},
	{
		"RSIPAvailable",
		UPNP_VARIABLE_TYPE_BOOLEAN,
		0,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
	},
	{
		"NATEnabled",
		UPNP_VARIABLE_TYPE_BOOLEAN,
		0,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
	},
	{
		"ExternalIPAddress",
		UPNP_VARIABLE_TYPE_STRING,
		UPNP_VARIABLE_FLAG_EVENT,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
	},
	{
		"PortMappingNumberOfEntries",
		UPNP_VARIABLE_TYPE_UI2,
		UPNP_VARIABLE_FLAG_EVENT,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
	},
	{
		"PortMappingEnabled",
		UPNP_VARIABLE_TYPE_BOOLEAN,
		0,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
	},
	{
		"PortMappingLeaseDuration",
		UPNP_VARIABLE_TYPE_UI4,
		0,
		NULL,
		"3600", /* XXX */
		"0",
		"604800",
		NULL,
	},
	{
		"RemoteHost",
		UPNP_VARIABLE_TYPE_STRING,
		0,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
	},
	{
		"ExternalPort",
		UPNP_VARIABLE_TYPE_UI2,
		0,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
	},
	{
		"InternalPort",
		UPNP_VARIABLE_TYPE_UI2,
		0,
		NULL,
		NULL,
		"1",
		"65535",
		NULL,
	},
	{
		"PortMappingProtocol",
		UPNP_VARIABLE_TYPE_STRING,
		0,
		(char *[]){
			"TCP",
			"UDP",
			NULL,
		},
		NULL,
		NULL,
		NULL,
		NULL,
	},
	{
		"InternalClient",
		UPNP_VARIABLE_TYPE_STRING,
		0,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
	},
	{
		"PortMappingDescription",
		UPNP_VARIABLE_TYPE_STRING,
		0,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
	},
	{
		"SystemUpdateID",
		UPNP_VARIABLE_TYPE_UI4,
		UPNP_VARIABLE_FLAG_EVENT,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
	},
	{
		"A_ARG_TYPE_Manage",
		UPNP_VARIABLE_TYPE_BOOLEAN,
		0,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
	},
	{
		"A_ARG_TYPE_PortListing",
		UPNP_VARIABLE_TYPE_STRING,
		0,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
	},
};

/* UPnP actions */
const struct upnp_action	 upnp_action[UPNP_ACTION_MAX] = {
	/* WANCommonInterfaceConfig */
	{
		"GetCommonLinkProperties",
		1, 0, 4,
		NULL,
		(struct upnp_argument[]){
			{
				"NewWANAccessType",
				0,
				UPNP_VARIABLE_WAN_ACCESS_TYPE,
			},
			{
				"NewLayer1UpstreamMaxBitRate",
				0,
				UPNP_VARIABLE_LAYER_1_UPSTREAM_MAX_BIT_RATE,
			},
			{
				"NewLayer1DownstreamMaxBitRate",
				0,
				UPNP_VARIABLE_LAYER_1_DOWNSTREAM_MAX_BIT_RATE,
			},
			{
				"NewPhysicalLinkStatus",
				0,
				UPNP_VARIABLE_PHYSICAL_LINK_STATUS,
			},
		},
	},
	/* WANIPConnection */
	{
		"SetConnectionType",
		1, 1, 0,
		(struct upnp_argument[]){
			{
				"NewConnectionType",
				0,
				UPNP_VARIABLE_CONNECTION_TYPE,
			},
		},
		NULL,
	},
	{
		"GetConnectionTypeInfo",
		1, 0, 2,
		NULL,
		(struct upnp_argument[]){
			{
				"NewConnectionType",
				0,
				UPNP_VARIABLE_CONNECTION_TYPE,
			},
			{
				"NewPossibleConnectionTypes",
				0,
				UPNP_VARIABLE_POSSIBLE_CONNECTION_TYPES,
			},
		},
	},
	{
		"RequestConnection",
		1, 0, 0,
		NULL,
		NULL,
	},
	{
		"ForceTermination",
		1, 0, 0,
		NULL,
		NULL,
	},
	{
		"GetStatusInfo",
		1, 0, 3,
		NULL,
		(struct upnp_argument[]){
			{
				"NewConnectionStatus",
				0,
				UPNP_VARIABLE_CONNECTION_STATUS,
			},
			{
				"NewLastConnectionError",
				0,
				UPNP_VARIABLE_LAST_CONNECTION_ERROR,
			},
			{
				"NewUptime",
				0,
				UPNP_VARIABLE_UPTIME,
			},
		},
	},
	{
		"GetNATRSIPStatus",
		1, 0, 2,
		NULL,
		(struct upnp_argument[]){
			{
				"NewRSIPAvailable",
				0,
				UPNP_VARIABLE_RSIP_AVAILABLE,
			},
			{
				"NewNATEnabled",
				0,
				UPNP_VARIABLE_NAT_ENABLED,
			},
		},
	},
	{
		"GetGenericPortMappingEntry",
		1, 1, 8,
		(struct upnp_argument[]){
			{
				"NewPortMappingIndex",
				0,
				UPNP_VARIABLE_PORT_MAPPING_NUMBER_OF_ENTRIES,
			},
		},
		(struct upnp_argument[]){
			{
				"NewRemoteHost",
				0,
				UPNP_VARIABLE_REMOTE_HOST,
			},
			{
				"NewExternalPort",
				0,
				UPNP_VARIABLE_EXTERNAL_PORT,
			},
			{
				"NewProtocol",
				0,
				UPNP_VARIABLE_PORT_MAPPING_PROTOCOL,
			},
			{
				"NewInternalPort",
				0,
				UPNP_VARIABLE_INTERNAL_PORT,
			},
			{
				"NewInternalClient",
				0,
				UPNP_VARIABLE_INTERNAL_CLIENT,
			},
			{
				"NewEnabled",
				0,
				UPNP_VARIABLE_PORT_MAPPING_ENABLED,
			},
			{
				"NewPortMappingDescription",
				0,
				UPNP_VARIABLE_PORT_MAPPING_DESCRIPTION,
			},
			{
				"NewLeaseDuration",
				0,
				UPNP_VARIABLE_PORT_MAPPING_LEASE_DURATION,
			},
		},
	},
	{
		"GetSpecificPortMappingEntry",
		1, 3, 5,
		(struct upnp_argument[]){
			{
				"NewRemoteHost",
				0,
				UPNP_VARIABLE_REMOTE_HOST,
			},
			{
				"NewExternalPort",
				0,
				UPNP_VARIABLE_EXTERNAL_PORT,
			},
			{
				"NewProtocol",
				0,
				UPNP_VARIABLE_PORT_MAPPING_PROTOCOL,
			},
		},
		(struct upnp_argument[]){
			{
				"NewInternalPort",
				0,
				UPNP_VARIABLE_INTERNAL_PORT,
			},
			{
				"NewInternalClient",
				0,
				UPNP_VARIABLE_INTERNAL_CLIENT,
			},
			{
				"NewEnabled",
				0,
				UPNP_VARIABLE_PORT_MAPPING_ENABLED,
			},
			{
				"NewPortMappingDescription",
				0,
				UPNP_VARIABLE_PORT_MAPPING_DESCRIPTION,
			},
			{
				"NewLeaseDuration",
				0,
				UPNP_VARIABLE_PORT_MAPPING_LEASE_DURATION,
			},
		},
	},
	{
		"AddPortMapping",
		1, 8, 0,
		(struct upnp_argument[]){
			{
				"NewRemoteHost",
				0,
				UPNP_VARIABLE_REMOTE_HOST,
			},
			{
				"NewExternalPort",
				0,
				UPNP_VARIABLE_EXTERNAL_PORT,
			},
			{
				"NewProtocol",
				0,
				UPNP_VARIABLE_PORT_MAPPING_PROTOCOL,
			},
			{
				"NewInternalPort",
				0,
				UPNP_VARIABLE_INTERNAL_PORT,
			},
			{
				"NewInternalClient",
				0,
				UPNP_VARIABLE_INTERNAL_CLIENT,
			},
			{
				"NewEnabled",
				0,
				UPNP_VARIABLE_PORT_MAPPING_ENABLED,
			},
			{
				"NewPortMappingDescription",
				0,
				UPNP_VARIABLE_PORT_MAPPING_DESCRIPTION,
			},
			{
				"NewLeaseDuration",
				0,
				UPNP_VARIABLE_PORT_MAPPING_LEASE_DURATION,
			},
		},
		NULL,
	},
	{
		"AddAnyPortMapping",
		2, 8, 1,
		(struct upnp_argument[]){
			{
				"NewRemoteHost",
				0,
				UPNP_VARIABLE_REMOTE_HOST,
			},
			{
				"NewExternalPort",
				0,
				UPNP_VARIABLE_EXTERNAL_PORT,
			},
			{
				"NewProtocol",
				0,
				UPNP_VARIABLE_PORT_MAPPING_PROTOCOL,
			},
			{
				"NewInternalPort",
				0,
				UPNP_VARIABLE_INTERNAL_PORT,
			},
			{
				"NewInternalClient",
				0,
				UPNP_VARIABLE_INTERNAL_CLIENT,
			},
			{
				"NewEnabled",
				0,
				UPNP_VARIABLE_PORT_MAPPING_ENABLED,
			},
			{
				"NewPortMappingDescription",
				0,
				UPNP_VARIABLE_PORT_MAPPING_DESCRIPTION,
			},
			{
				"NewLeaseDuration",
				0,
				UPNP_VARIABLE_PORT_MAPPING_LEASE_DURATION,
			},
		},
		(struct upnp_argument[]){
			{
				"NewReservedPort",
				0,
				UPNP_VARIABLE_EXTERNAL_PORT,
			},
		},
	},
	{
		"DeletePortMapping",
		1, 3, 0,
		(struct upnp_argument[]){
			{
				"NewRemoteHost",
				0,
				UPNP_VARIABLE_REMOTE_HOST,
			},
			{
				"NewExternalPort",
				0,
				UPNP_VARIABLE_EXTERNAL_PORT,
			},
			{
				"NewProtocol",
				0,
				UPNP_VARIABLE_PORT_MAPPING_PROTOCOL,
			},
		},
		NULL,
	},
	{
		"DeletePortMappingRange",
		2, 4, 0,
		(struct upnp_argument[]){
			{
				"NewStartPort",
				0,
				UPNP_VARIABLE_EXTERNAL_PORT,
			},
			{
				"NewEndPort",
				0,
				UPNP_VARIABLE_EXTERNAL_PORT,
			},
			{
				"NewProtocol",
				0,
				UPNP_VARIABLE_PORT_MAPPING_PROTOCOL,
			},
			{
				"NewManage",
				0,
				UPNP_VARIABLE_A_ARG_TYPE_MANAGE,
			},
		},
		NULL,
	},
	{
		"GetExternalIPAddress",
		1, 0, 1,
		NULL,
		(struct upnp_argument[]){
			{
				"NewExternalIPAddress",
				0,
				UPNP_VARIABLE_EXTERNAL_IP_ADDRESS,
			},
		},
	},
	{
		"GetListOfPortMappings",
		2, 5, 1,
		(struct upnp_argument[]){
			{
				"NewStartPort",
				0,
				UPNP_VARIABLE_EXTERNAL_PORT,
			},
			{
				"NewEndPort",
				0,
				UPNP_VARIABLE_EXTERNAL_PORT,
			},
			{
				"NewProtocol",
				0,
				UPNP_VARIABLE_PORT_MAPPING_PROTOCOL,
			},
			{
				"NewManage",
				0,
				UPNP_VARIABLE_A_ARG_TYPE_MANAGE,
			},
			{
				"NewNumberOfPorts",
				0,
				UPNP_VARIABLE_PORT_MAPPING_NUMBER_OF_ENTRIES,
			},
		},
		(struct upnp_argument[]){
			{
				"NewPortListing",
				0,
				UPNP_VARIABLE_A_ARG_TYPE_PORT_LISTING,
			},
		},
	},
};

/* UPnP services */
const struct upnp_service	 upnp_service[UPNP_SERVICE_MAX] = {
	{
		UPNP_SCHEMA_NID,
		{
			UPNP_TYPE_SERVICE,
			"WANCommonInterfaceConfig",
			UPNP_VERSION_WAN_COMMON_INTERFACE_CONFIG,
		},
		UPNP_SERVICE_ID_URN(UPNP_NID, "WANCommonIFC", 1),
		"/describe/WANCommonInterfaceConfig.xml",
		"/control/WANCommonInterfaceConfig",
		"/event/WANCommonInterfaceConfig",
		(enum upnp_actions[]){
			UPNP_ACTION_GET_COMMON_LINK_PROPERTIES,
			UPNP_ACTION_EOL,
		},
		(enum upnp_variables[]){
			UPNP_VARIABLE_WAN_ACCESS_TYPE,
			UPNP_VARIABLE_LAYER_1_UPSTREAM_MAX_BIT_RATE,
			UPNP_VARIABLE_LAYER_1_DOWNSTREAM_MAX_BIT_RATE,
			UPNP_VARIABLE_PHYSICAL_LINK_STATUS,
			UPNP_VARIABLE_EOL,
		},
	},
	{
		UPNP_SCHEMA_NID,
		{
			UPNP_TYPE_SERVICE,
			"WANIPConnection",
			UPNP_VERSION_WAN_IP_CONNECTION,
		},
		UPNP_SERVICE_ID_URN(UPNP_NID, "WANIPConn", 1),
		"/describe/WANIPConnection.xml",
		"/control/WANIPConnection",
		"/event/WANIPConnection",
		(enum upnp_actions[]){
			UPNP_ACTION_SET_CONNECTION_TYPE,
			UPNP_ACTION_GET_CONNECTION_TYPE_INFO,
			UPNP_ACTION_REQUEST_CONNECTION,
			UPNP_ACTION_FORCE_TERMINATION,
			UPNP_ACTION_GET_STATUS_INFO,
			UPNP_ACTION_GET_NAT_RSIP_STATUS,
			UPNP_ACTION_GET_GENERIC_PORT_MAPPING_ENTRY,
			UPNP_ACTION_GET_SPECIFIC_PORT_MAPPING_ENTRY,
			UPNP_ACTION_ADD_PORT_MAPPING,
#if UPNP_VERSION_WAN_IP_CONNECTION >= 2
			UPNP_ACTION_ADD_ANY_PORT_MAPPING,
#endif
			UPNP_ACTION_DELETE_PORT_MAPPING,
#if UPNP_VERSION_WAN_IP_CONNECTION >= 2
			UPNP_ACTION_DELETE_PORT_MAPPING_RANGE,
#endif
			UPNP_ACTION_GET_EXTERNAL_IP_ADDRESS,
#if UPNP_VERSION_WAN_IP_CONNECTION >= 2
			UPNP_ACTION_GET_LIST_OF_PORT_MAPPINGS,
#endif
			UPNP_ACTION_EOL,
		},
		(enum upnp_variables[]){
			UPNP_VARIABLE_CONNECTION_TYPE,
			UPNP_VARIABLE_POSSIBLE_CONNECTION_TYPES,
			UPNP_VARIABLE_CONNECTION_STATUS,
			UPNP_VARIABLE_UPTIME,
			UPNP_VARIABLE_LAST_CONNECTION_ERROR,
			UPNP_VARIABLE_RSIP_AVAILABLE,
			UPNP_VARIABLE_NAT_ENABLED,
			UPNP_VARIABLE_EXTERNAL_IP_ADDRESS,
			UPNP_VARIABLE_PORT_MAPPING_NUMBER_OF_ENTRIES,
			UPNP_VARIABLE_PORT_MAPPING_ENABLED,
			UPNP_VARIABLE_PORT_MAPPING_LEASE_DURATION,
			UPNP_VARIABLE_REMOTE_HOST,
			UPNP_VARIABLE_EXTERNAL_PORT,
			UPNP_VARIABLE_INTERNAL_PORT,
			UPNP_VARIABLE_PORT_MAPPING_PROTOCOL,
			UPNP_VARIABLE_INTERNAL_CLIENT,
			UPNP_VARIABLE_PORT_MAPPING_DESCRIPTION,
#if UPNP_VERSION_WAN_IP_CONNECTION >= 2
			UPNP_VARIABLE_SYSTEM_UPDATE_ID,
			UPNP_VARIABLE_A_ARG_TYPE_MANAGE,
			UPNP_VARIABLE_A_ARG_TYPE_PORT_LISTING,
#endif
			UPNP_VARIABLE_EOL,
		},
	},
};

/* UPnP devices */
const struct upnp_device	upnp_device[UPNP_DEVICE_MAX] = {
	{
		UPNP_SCHEMA_NID,
		{
			UPNP_TYPE_DEVICE,
			"InternetGatewayDevice",
			UPNP_VERSION_INTERNET_GATEWAY_DEVICE,
		},
		NULL,
		(enum upnp_devices[]){
			UPNP_DEVICE_WAN_DEVICE,
			UPNP_DEVICE_EOL,
		},
	},
	{
		UPNP_SCHEMA_NID,
		{
			UPNP_TYPE_DEVICE,
			"WANDevice",
			UPNP_VERSION_WAN_DEVICE,
		},
		(enum upnp_services[]){
			UPNP_SERVICE_WAN_COMMON_INTERFACE_CONFIG,
			UPNP_SERVICE_EOL,
		},
		(enum upnp_devices[]){
			UPNP_DEVICE_WAN_CONNECTION_DEVICE,
			UPNP_DEVICE_EOL,
		},
	},
	{
		UPNP_SCHEMA_NID,
		{
			UPNP_TYPE_DEVICE,
			"WANConnectionDevice",
			UPNP_VERSION_WAN_CONNECTION_DEVICE,
		},
		(enum upnp_services[]){
			UPNP_SERVICE_WAN_IP_CONNECTION,
			UPNP_SERVICE_EOL,
		},
		NULL,
	},
};

/* UPnP errors */
const struct upnp_error		 upnp_error[UPNP_ERROR_MAX] = {
	{ 401, "Invalid Action" },
	{ 402, "Invalid Args" },
	{ 501, "Action Failed" },
	{ 600, "Argument Value Invalid" },
	{ 601, "Argument Value Out of Range" },
	{ 602, "Optional Action Not Implemented" },
	{ 603, "Out of Memory" },
	{ 604, "Human Intervention Required" },
	{ 605, "String Argument Too Long" },
	{ 606, "Action not authorized" },
	{ 607, "Signature failure" },
	{ 608, "Signature missing" },
	{ 609, "Not encrypted" },
	{ 610, "Invalid sequence" },
	{ 611, "Invalid control URL" },
	{ 612, "No such session" },
};

/* Return the string representation of the UPnP NSS structure */
char *
upnp_nss_to_string(struct upnp_nss *nss)
{
	size_t	 len;
	char	*str;

	len = snprintf(NULL, 0, "%s:%s:%d", upnp_type[nss->type], nss->name,
	    nss->version);
	if ((str = calloc(len + 1, sizeof(char))) == NULL)
		return (NULL);
	snprintf(str, len + 1, "%s:%s:%d", upnp_type[nss->type], nss->name,
	    nss->version);
	
	return (str);
}

/* Return a UPnP NSS structure for a given string representation */
struct upnp_nss *
upnp_nss_from_string(char *str)
{
	struct upnp_nss	*nss;
	char		*p;
	int		 i;
	const char	*errstr;

	for (i = 0; i < UPNP_TYPE_MAX; i++)
		if (!strncmp(str, upnp_type[i], strlen(upnp_type[i])))
			break;

	if (i == UPNP_TYPE_MAX)
		return (NULL);

	if ((nss = calloc(1, sizeof(struct upnp_nss))) == NULL)
		return (NULL);

	nss->type = i;
	str += strlen(upnp_type[i]);

	if (*str != ':') {
		free(nss);
		return (NULL);
	}

	p = ++str;
	while (isalnum(*p))
		p++;
	if (*p != ':' ||
	    (nss->name = calloc((p - str) + 1, sizeof(char))) == NULL) {
		free(nss);
		return (NULL);
	}
	strncpy(nss->name, str, p - str);

	str = ++p;
	while (isdigit(*p))
		p++;

	nss->version = strtonum(str, 1, UINT_MAX, &errstr);
	if (*p || errstr) {
		free(nss->name);
		free(nss);
		return (NULL);
	}

	return (nss);
}

/* Free a UPnP NSS structure */
void
upnp_nss_free(struct upnp_nss *nss)
{
	free(nss->name);
	free(nss);
}

void
upnp_add_configid(xmlNodePtr node, u_int32_t version)
{
	size_t	 len;
	char	*str;

	len = snprintf(NULL, 0, "%d", version);
	if ((str = calloc(len + 1, sizeof(char))) == NULL)
		fatal("calloc");
	snprintf(str, len + 1, "%d", version);

	xmlNewProp(node, "configId", "1");

	free(str);
}

void
upnp_add_version(xmlNodePtr node)
{
	xmlNodePtr	 version;

	version = xmlNewChild(node, NULL, "specVersion", NULL);

	xmlNewChild(version, NULL, "major", UPNP_STRING(UPNP_VERSION_MAJOR));
	xmlNewChild(version, NULL, "minor", UPNP_STRING(UPNP_VERSION_MINOR));
}

void
upnp_add_action(xmlNodePtr node, const struct upnp_action *parent)
{
	xmlNodePtr			 action, arguments, argument;
	const struct upnp_argument	*arg;
	unsigned int			 i;

	action = xmlNewChild(node, NULL, "action", NULL);

	xmlNewChild(action, NULL, "name", parent->name);

	if (parent->cin || parent->cout) {
		arguments = xmlNewChild(action, NULL, "argumentList", NULL);

		for (i = 0, arg = parent->in; i < parent->cin; i++, arg++) {
			argument = xmlNewChild(arguments, NULL, "argument",
			    NULL);
			xmlNewChild(argument, NULL, "name", arg->name);
			xmlNewChild(argument, NULL, "direction", "in");
			if (arg->flags & UPNP_ARGUMENT_FLAG_RETURN)
				xmlNewChild(argument, NULL, "retval", NULL);
			xmlNewChild(argument, NULL, "relatedStateVariable",
			    upnp_variable[arg->related].name);
		}

		for (i = 0, arg = parent->out; i < parent->cout; i++, arg++) {
			argument = xmlNewChild(arguments, NULL, "argument",
			    NULL);
			xmlNewChild(argument, NULL, "name", arg->name);
			xmlNewChild(argument, NULL, "direction", "out");
			if (arg->flags & UPNP_ARGUMENT_FLAG_RETURN)
				xmlNewChild(argument, NULL, "retval", NULL);
			xmlNewChild(argument, NULL, "relatedStateVariable",
			    upnp_variable[arg->related].name);
		}
	}
}

void
upnp_add_variable(xmlNodePtr node, const struct upnp_variable *parent)
{
	xmlNodePtr	 variable, type, values, range;
	int		 i;

	variable = xmlNewChild(node, NULL, "stateVariable", NULL);
	if (!(parent->flags & UPNP_VARIABLE_FLAG_EVENT))
		xmlNewProp(variable, "sendEvents", "no");

#if UPNP_VERSION_NUMBER >= 0x0101
	if (parent->flags & UPNP_VARIABLE_FLAG_MULTICAST)
		xmlNewProp(variable, "multicast", "yes");
#endif

	xmlNewChild(variable, NULL, "name", parent->name);
	type = xmlNewChild(variable, NULL, "dataType",
	    upnp_variable_type[parent->type]);

#if UPNP_VERSION_NUMBER >= 0x0101
	/* FIXME type= */
#endif

	if (parent->value)
		xmlNewChild(variable, NULL, "defaultValue", parent->value);

	if (parent->type == UPNP_VARIABLE_TYPE_STRING && parent->values) {
		values = xmlNewChild(variable, NULL, "allowedValueList", NULL);
		for (i = 0; parent->values[i]; i++)
			xmlNewChild(values, NULL, "allowedValue",
			    parent->values[i]);
	}

	if (parent->minimum && parent->maximum) {
		range = xmlNewChild(variable, NULL, "allowedValueRange", NULL);
		xmlNewChild(range, NULL, "minimum", parent->minimum);
		xmlNewChild(range, NULL, "maximum", parent->maximum);
		if (parent->step)
			xmlNewChild(range, NULL, "step", parent->step);
	}
}

xmlDocPtr
upnp_service_xml(u_int32_t version, enum upnp_services service)
{
	xmlDocPtr	 document;
	xmlNodePtr	 scpd, actions, variables;
	xmlNsPtr	 ns;
	int		 i;

	document = xmlNewDoc("1.0");
	scpd = xmlNewNode(NULL, "scpd");
	xmlDocSetRootElement(document, scpd);

	/* From this point, every child node inherits the namespace */
	ns = xmlNewNs(scpd, UPNP_SERVICE_SCHEMA_URN, NULL);
	xmlSetNs(scpd, ns);

#if UPNP_VERSION_NUMBER >= 0x0101
	upnp_add_configid(scpd, version);
#endif

	upnp_add_version(scpd);

	/* Actions are optional */
	if (upnp_service[service].actions) {
		actions = xmlNewChild(scpd, NULL, "actionList", NULL);
		for (i = 0;
		    upnp_service[service].actions[i] != UPNP_ACTION_EOL; i++)
			upnp_add_action(actions,
			    &upnp_action[upnp_service[service].actions[i]]);
	}

	/* Variables are mandatory */
	variables = xmlNewChild(scpd, NULL, "serviceStateTable", NULL);
	for (i = 0; upnp_service[service].variables[i] != UPNP_VARIABLE_EOL;
	    i++)
		upnp_add_variable(variables,
		    &upnp_variable[upnp_service[service].variables[i]]);

	xmlSaveFormatFileEnc("-", document, NULL, XML_INDENT_TREE);

	return (document);
}

void
upnp_add_service(xmlNodePtr node, u_int32_t version, enum upnp_services type,
    struct evhttp *http, struct ssdp_device *parent,
    struct ssdp_services *services)
{
	xmlNodePtr		 service;
	struct ssdp_service	*ssdp;
	char			*urn;

	/* Create SSDP service search struct */
	if ((ssdp = calloc(1, sizeof(struct ssdp_service))) == NULL)
		fatal("calloc");

	ssdp->parent = parent;
	ssdp->document = upnp_service_xml(version, type);
	if ((ssdp->nss = calloc(1, sizeof(struct upnp_nss))) == NULL)
		fatal("calloc");
	memcpy(ssdp->nss, &upnp_service[type].nss, sizeof(struct upnp_nss));
	if ((ssdp->urn = calloc(1, sizeof(struct urn))) == NULL)
		fatal("calloc");
	if ((ssdp->urn->nss = upnp_nss_to_string(ssdp->nss)) == NULL)
		fatalx("upnp_nss_to_string");
	if ((ssdp->urn->nid = strdup(upnp_service[type].nid)) == NULL)
		fatal("strdup");

	if ((urn = urn_to_string(ssdp->urn)) == NULL)
		fatalx("urn_to_string");

	service = xmlNewChild(node, NULL, "service", NULL);

	xmlNewChild(service, NULL, "serviceType", urn);
	xmlNewChild(service, NULL, "serviceId", upnp_service[type].id);
	xmlNewChild(service, NULL, "SCPDURL", upnp_service[type].scpd);
	xmlNewChild(service, NULL, "controlURL", upnp_service[type].control);
	xmlNewChild(service, NULL, "eventSubURL", upnp_service[type].event);

	free(urn);

	TAILQ_INSERT_TAIL(services, ssdp, entry);

	evhttp_set_cb(http, upnp_service[type].scpd, upnp_describe,
	    ssdp->document);
	evhttp_set_cb(http, upnp_service[type].control, upnp_control, NULL);
	evhttp_set_cb(http, upnp_service[type].event, upnp_event, NULL);
}

void
upnp_add_device(xmlNodePtr node, u_int32_t version, enum upnp_devices type,
    struct evhttp *http, struct ssdp_devices *devices,
    struct ssdp_services *services)
{
	xmlNodePtr		 device, icons, servicelist, devicelist;
	uuid_t			*uuid;
	char			*str, *ptr = NULL, *urn;
	struct ssdp_device	*ssdp;
	int			 i;

	/* Create SSDP device search struct */
	if ((ssdp = calloc(1, sizeof(struct ssdp_device))) == NULL)
		fatal("calloc");

	if ((ssdp->nss = calloc(1, sizeof(struct upnp_nss))) == NULL)
		fatal("calloc");
	memcpy(ssdp->nss, &upnp_device[type].nss, sizeof(struct upnp_nss));
	if ((ssdp->urn = calloc(1, sizeof(struct urn))) == NULL)
		fatal("calloc");
	if ((ssdp->urn->nss = upnp_nss_to_string(ssdp->nss)) == NULL)
		fatalx("upnp_nss_to_string");
	if ((ssdp->urn->nid = strdup(upnp_device[type].nid)) == NULL)
		fatal("strdup");

	if ((urn = urn_to_string(ssdp->urn)) == NULL)
		fatalx("urn_to_string");

	device = xmlNewChild(node, NULL, "device", NULL);

	xmlNewChild(device, NULL, "deviceType", urn);

	/* FIXME */
	xmlNewChild(device, NULL, "friendlyName", "test");
	xmlNewChild(device, NULL, "manufacturer", "test");
	xmlNewChild(device, NULL, "modelDescription", "test");
	xmlNewChild(device, NULL, "modelName", "test");
	xmlNewChild(device, NULL, "modelNumber", "test");
	xmlNewChild(device, NULL, "modelURL", "test");
	xmlNewChild(device, NULL, "serialNumber", "test");

	if (uuid_create(&uuid) != 0)
		fatalx("uuid_create");
	if (uuid_make(uuid, UUID_MAKE_V1) != 0)
		fatalx("uuid_make");

	/* "uuid:" + uuid + "\0" */
	if ((str = calloc(UUID_LEN_STR + 6, sizeof(char))) == NULL)
		fatal("calloc");
	strlcat(str, "uuid:", UUID_LEN_STR + 6);

	if (uuid_export(uuid, UUID_FMT_STR, &ptr, NULL) != 0)
		fatalx("uuid_export");
	strlcat(str, ptr, UUID_LEN_STR + 6);
	free(ptr);

	xmlNewChild(device, NULL, "UDN", str);

	if (uuid_destroy(uuid) != 0)
		fatalx("uuid_destroy");

	/* FIXME */
	xmlNewChild(device, NULL, "UPC", "test");
	icons = xmlNewChild(device, NULL, "iconList", NULL);

	ssdp->uuid = str;

	free(urn);

	TAILQ_INSERT_TAIL(devices, ssdp, entry);

	if (upnp_device[type].services) {
		servicelist = xmlNewChild(device, NULL, "serviceList", NULL);
		for (i = 0; upnp_device[type].services[i] != UPNP_SERVICE_EOL;
		    i++)
			upnp_add_service(servicelist, version,
			    upnp_device[type].services[i], http, ssdp,
			    services);
	}

	if (upnp_device[type].devices) {
		devicelist = xmlNewChild(device, NULL, "deviceList", NULL);
		for (i = 0; upnp_device[type].devices[i] != UPNP_DEVICE_EOL;
		    i++)
			upnp_add_device(devicelist, version,
			    upnp_device[type].devices[i], http, devices,
			    services);
	}

	xmlNewChild(device, NULL, "presentationURL", "/");
}

struct ssdp_root *
upnp_root_device(u_int32_t version, enum upnp_devices type,
    struct evhttp *http)
{
	struct ssdp_root	*root;
	xmlNodePtr		 node;
	xmlNsPtr		 ns;

	if ((root = calloc(1, sizeof(struct ssdp_root))) == NULL)
		return (NULL);

	TAILQ_INIT(&root->devices);
	TAILQ_INIT(&root->services);

	root->document = xmlNewDoc("1.0");
	node = xmlNewNode(NULL, "root");
	xmlDocSetRootElement(root->document, node);

	/* From this point, every child node inherits the namespace */
	ns = xmlNewNs(node, UPNP_DEVICE_SCHEMA_URN, NULL);
	xmlSetNs(node, ns);

#if UPNP_VERSION_NUMBER >= 0x0101
	upnp_add_configid(node, version);
#endif

	upnp_add_version(node);

	upnp_add_device(node, version, type, http, &root->devices,
	    &root->services);

	evhttp_set_cb(http, "/describe/root.xml", upnp_describe,
	    root->document);

	return (root);
}

/* Add an XML document to an evbuffer */
void
upnp_add_xml(struct evbuffer *buffer, xmlDocPtr document)
{
	xmlChar	*xml = NULL;
	int	 len = 0;

	xmlDocDumpFormatMemory(document, &xml, &len, XML_INDENT_TREE);
	evbuffer_add(buffer, xml, len);
	xmlFree(xml);
}

/* Add Content-Length header */
void
upnp_content_length_header(struct evhttp_request *req, struct evbuffer *buffer)
{
	size_t	 len;
	char	*header;

	len = snprintf(NULL, 0, "%ld", EVBUFFER_LENGTH(buffer));
	if ((header = calloc(len + 1, sizeof(char))) == NULL)
		fatal("calloc");
	snprintf(header, len + 1, "%ld", EVBUFFER_LENGTH(buffer));
	evhttp_add_header(req->output_headers, "Content-Length",
	    header);
	free(header);
}

/* Add Content-Type header */
void
upnp_content_type_header(struct evhttp_request *req)
{
	evhttp_add_header(req->output_headers, "Content-Type",
	    "text/xml; charset=\"utf-8\"");
}

/* Add Date header */
void
upnp_date_header(struct evhttp_request *req)
{
	time_t		 t;
	struct tm	*tmp;
	char		 date[30]; /* "Mon, 01 Jan 1970 00:00:00 GMT" + '\0' */

	t = time(NULL);
	if ((tmp = localtime(&t)) == NULL)
		fatal("localtime");

	if (strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S GMT", tmp) == 0)
		fatalx("strftime");

	evhttp_add_header(req->output_headers, "Date", date);
}

/* Add Server header */
void
upnp_server_header(struct evhttp_request *req)
{
	extern char	*__progname;
	size_t		 len;
	char		*str;

	len = snprintf(NULL, 0, "%s/%s UPnP/%s %s/1.0", name.sysname,
	    name.release, upnp_version, __progname);
	if ((str = calloc(len + 1, sizeof(char))) == NULL)
		fatal("calloc");
	snprintf(str, len + 1, "%s/%s UPnP/%s %s/1.0", name.sysname,
	    name.release, upnp_version, __progname);

	evhttp_add_header(req->output_headers, "Server", str);

	free(str);
}

/* Serve XML description */
void
upnp_describe(struct evhttp_request *req, void *arg)
{
	xmlDocPtr	 document = (xmlDocPtr)arg;
	struct evbuffer	*output;

	if (req->type != EVHTTP_REQ_GET) {
		evhttp_add_header(req->output_headers, "Allow", "GET");
		evhttp_send_reply(req, 405, "Bad Method", NULL);
		return;
	}

	/* Check Host and Accept-Language headers? */

	log_debug("GET %s", evhttp_request_uri(req));

	if ((output = evbuffer_new()) == NULL)
		return;

	upnp_add_xml(output, document);

	/* Add Content-Language header if Accept-Language is present */

	upnp_content_length_header(req, output);
	upnp_content_type_header(req);
	upnp_date_header(req);

	evhttp_send_reply(req, HTTP_OK, "OK", output);
	evbuffer_free(output);
}

/* Generate and return a UPnP SOAP error */
void
upnp_soap_error(struct evhttp_request *req, enum upnp_errors error)
{
	xmlDocPtr	 document;
	xmlNodePtr	 node;
	xmlNsPtr	 ns;
	size_t		 len;
	char		*str;
	struct evbuffer	*output;

	document = xmlNewDoc("1.0");
	node = xmlNewNode(NULL, "Envelope");
	xmlDocSetRootElement(document, node);

	ns = xmlNewNs(node, SOAP_ENVELOPE_URI, SOAP_NAMESPACE_PREFIX);
	xmlSetNs(node, ns);
	xmlNewNsProp(node, ns, "encodingStyle", SOAP_ENCODING_URI);

	node = xmlNewChild(node, NULL, "Body", NULL);

	node = xmlNewChild(node, NULL, "Fault", NULL);

	/* Make the namespace unqualified for these three children */
	xmlSetNs(xmlNewChild(node, NULL, "faultcode",
	    SOAP_NAMESPACE_PREFIX ":Client"), NULL);
	xmlSetNs(xmlNewChild(node, NULL, "faultstring", "UPnPError"), NULL);
	node = xmlNewChild(node, NULL, "detail", NULL);
	xmlSetNs(node, NULL);

	node = xmlNewChild(node, NULL, "UPnPError", NULL);
	ns = xmlNewNs(node, UPNP_CONTROL_SCHEMA_URN, NULL);
	xmlSetNs(node, ns);

	len = snprintf(NULL, 0, "%d", upnp_error[error].code);
	if ((str = calloc(len + 1, sizeof(char))) == NULL)
		fatal("calloc");
	snprintf(str, len + 1, "%d", upnp_error[error].code);

	xmlNewChild(node, NULL, "errorCode", str);
	xmlNewChild(node, NULL, "errorDescription", upnp_error[error].string);

	free(str);

	if ((output = evbuffer_new()) == NULL) {
		xmlFreeDoc(document);
		return;
	}

	upnp_add_xml(output, document);
	xmlFreeDoc(document);

	upnp_content_length_header(req, output);
	upnp_content_type_header(req);
	upnp_date_header(req);

	evhttp_send_reply(req, 500, "Internal Server Error", output);
	evbuffer_free(output);
}

/* UPnP control (SOAP) */
void
upnp_control(struct evhttp_request *req, void *arg)
{
	const char			*header;
	char				*copy, *p, *service, *action;
	struct urn			*urn;
	struct upnp_nss			*nss;
	unsigned int			 i, j;
	xmlDocPtr			 document;
	xmlNodePtr			 root, body, request, argument;
	xmlChar				*encoding;
	xmlNsPtr			 ns;
	const struct upnp_action	*a;


	if (req->type != EVHTTP_REQ_POST) {
		evhttp_add_header(req->output_headers, "Allow", "POST");
		evhttp_send_reply(req, 405, "Bad Method", NULL);
		return;
	}

	/* Content-Type should be present and set to "text/xml" */
	if ((header = evhttp_find_header(req->input_headers,
	    "content-type")) == NULL ||
	    strcmp(header, "text/xml; charset=\"utf-8\"")) {
		evhttp_send_reply(req, 415, "Unsupported Media Type", NULL);
		return;
	}

	if ((header = evhttp_find_header(req->input_headers,
	    "soapaction")) == NULL)
		goto bad;

	if ((copy = strdup(header)) == NULL)
		fatal("strdup");

	p = copy;

	if (*p != '"' || strlen(++p) == 0) {
		free(copy);
		goto bad;
	}

	service = p;

	if ((p = strchr(p, '#')) == NULL) {
		free(copy);
		goto bad;
	}

	/* service is now NULL-terminated */
	*p = '\0';

	action = ++p;

	if (strlen(service) == 0 || (p = strchr(p, '"')) == NULL ||
	    strlen(p) != 1) {
		free(copy);
		goto bad;
	}

	/* action is now NULL-terminated */
	*p = '\0';

	if (strlen(action) == 0 || (urn = urn_from_string(service)) == NULL) {
		free(copy);
		goto bad;
	}

	if ((nss = upnp_nss_from_string(urn->nss)) == NULL) {
		urn_free(urn);
		free(copy);
		goto bad;
	}

	/* At this point we have the service URN and intended action */
	if ((document = xmlReadMemory(EVBUFFER_DATA(req->input_buffer),
	    EVBUFFER_LENGTH(req->input_buffer), NULL, NULL, 0)) == NULL) {
		upnp_nss_free(nss);
		urn_free(urn);
		free(copy);
		goto bad;
	}

	xmlSaveFormatFileEnc("-", document, NULL, XML_INDENT_TREE);

	root = xmlDocGetRootElement(document);

	for (ns = root->nsDef; ns; ns = ns->next)
		if (!strcmp(ns->href, SOAP_ENVELOPE_URI))
			break;
	encoding = xmlGetNsProp(root, "encodingStyle", SOAP_ENVELOPE_URI);
	for (body = root->children; body; body = body->next)
		if (body->type == XML_ELEMENT_NODE &&
		    !strcmp(body->name, "Body"))
			break;

	/* Validate the main SOAP envelope */
	if (ns == NULL || strcmp(root->name, "Envelope") || root->ns != ns ||
	    strcmp(encoding, SOAP_ENCODING_URI) || body == NULL ||
	    body->ns != ns) {
		log_warnx("malformed envelope");
		xmlFreeDoc(document);
		xmlFree(encoding);
		upnp_nss_free(nss);
		urn_free(urn);
		free(copy);
		goto bad;
	}

	xmlFree(encoding);

	for (request = body->children; request; request = request->next)
		if (request->type == XML_ELEMENT_NODE)
			break;
	if (request)
		for (ns = request->nsDef; ns; ns = ns->next)
			if (!strcmp(ns->href, service))
				break;

	/* Validate the SOAP action */
	if (ns == NULL || request == NULL || strcmp(request->name, action) ||
	    request->ns != ns) {
		log_warnx("malformed request");
		xmlFreeDoc(document);
		upnp_nss_free(nss);
		urn_free(urn);
		free(copy);
		goto bad;
	}

	for (i = 0; i < nitems(upnp_service); i++)
		if (!strcmp(urn->nid, upnp_service[i].nid) &&
		    nss->type == upnp_service[i].nss.type &&
		    !strcmp(nss->name, upnp_service[i].nss.name) &&
		    nss->version <= upnp_service[i].nss.version)
			break;

	if (i != nitems(upnp_service))
		for (j = 0; upnp_service[i].actions[j] != UPNP_ACTION_EOL;
		    j++) {
			a = &upnp_action[upnp_service[i].actions[j]];

			if (!strcmp(action, a->name) &&
			    nss->version >= a->version)
				break;
		}


	/* Can't find the service or action */
	if (i == nitems(upnp_service) ||
	    upnp_service[i].actions[j] == UPNP_ACTION_EOL) {
		log_warnx("invalid action");
		upnp_soap_error(req, UPNP_ERROR_INVALID_ACTION);
		xmlFreeDoc(document);
		upnp_nss_free(nss);
		urn_free(urn);
		free(copy);
		return;
	}

	/* First argument in action definition */
	i = 0;

	/* Find first element node */
	for (argument = request->children; argument; argument = argument->next)
		if (argument->type == XML_ELEMENT_NODE)
			break;

	/* Check each given argument against the one in the definition */
	while (argument && i < a->cin) {

		/* Name doesn't match */
		if (strcmp(argument->name, a->in[i].name))
			break;

		/* Check there is a sole text child node under the argument */
		if (argument->children == NULL ||
		    argument->children->type != XML_TEXT_NODE ||
		    argument->children->next != NULL)
			break;

		/* Find next element node */
		for (argument = argument->next; argument;
		    argument = argument->next)
			if (argument->type == XML_ELEMENT_NODE)
				break;

		/* Advance to next argument in action definition */
		i++;
	}

	/* Should be NULL && a->cin respectively */
	if (argument || i < a->cin) {
		log_warnx("invalid arguments");
		upnp_soap_error(req, UPNP_ERROR_INVALID_ARGS);
		xmlFreeDoc(document);
		upnp_nss_free(nss);
		urn_free(urn);
		free(copy);
		return;
	}

	log_debug("found it!");

	xmlFreeDoc(document);

#if 0
	document = xmlNewDoc("1.0");
	envelope = xmlNewNode(NULL, "Envelope");
	xmlDocSetRootElement(document, envelope);

	ns = xmlNewNs(envelope, SOAP_ENVELOPE_URI, SOAP_NAMESPACE_PREFIX);
	xmlSetNs(envelope, ns);
	xmlNewProp(envelope, "encodingStyle", SOAP_ENCODING_URI);
	xmlNewChild(envelope, NULL, "Body", NULL);
#endif

	upnp_nss_free(nss);
	urn_free(urn);
	free(copy);

	return;

bad:
	evhttp_send_reply(req, 400, "Bad Request", NULL);
}

void
upnp_event(struct evhttp_request *req, void *arg)
{
	struct evkeyval	*header;

	switch (req->type) {
	default:
		log_debug("%d %s HTTP/%d.%d", req->type, evhttp_request_uri(req), req->major, req->minor);

		for (header = TAILQ_FIRST(req->input_headers); header;
		    header = TAILQ_NEXT(header, next))
			log_debug("%s: %s", header->key, header->value);
		
		log_debug("%.*s", EVBUFFER_LENGTH(req->input_buffer), EVBUFFER_DATA(req->input_buffer));
		evhttp_send_reply(req, 500, "Internal Server Error", NULL);
		break;
	}
}

void
upnp_debug(struct evhttp_request *req, void *arg)
{
	struct evkeyval	*header;

	switch (req->type) {
	default:
		log_debug("%d %s HTTP/%d.%d", req->type, evhttp_request_uri(req), req->major, req->minor);

		for (header = TAILQ_FIRST(req->input_headers); header;
		    header = TAILQ_NEXT(header, next))
			log_debug("%s: %s", header->key, header->value);
		
		log_debug("%.*s", EVBUFFER_LENGTH(req->input_buffer), EVBUFFER_DATA(req->input_buffer));
		evhttp_send_reply(req, 500, "Internal Server Error", NULL);
		break;
	}
}
