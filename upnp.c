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

enum upnp_argument_directions {
	UPNP_ARGUMENT_DIRECTION_IN = 0,
	UPNP_ARGUMENT_DIRECTION_OUT,
	UPNP_ARGUMENT_DIRECTION_MAX,
};

#define	UPNP_ARGUMENT_FLAG_RETURN	(1<<0)

struct upnp_argument {
	char				*name;
	enum upnp_argument_directions	 direction;
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
	struct upnp_argument 	*arguments;
};

struct upnp_service {
	char			*type;
	char			*id;
	char			*scpd;
	char			*control;
	char			*event;
	enum upnp_actions	*actions;
	enum upnp_variables	*variables;
};

struct upnp_device {
	char			*type;
	enum upnp_services	*services;
	enum upnp_devices	*devices;
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
void		 upnp_xml(struct evhttp_request *, void *);
void		 upnp_soap(struct evhttp_request *, void *);
void		 upnp_event(struct evhttp_request *, void *);

const char	*upnp_version = UPNP_VERSION_STRING;

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

/* UPnP action argument direction */
const char	*upnp_argument_direction[UPNP_ARGUMENT_DIRECTION_MAX] = {
	"in",
	"out",
};

/* UPnP actions */
const struct upnp_action	 upnp_action[UPNP_ACTION_MAX] = {
	/* WANCommonInterfaceConfig */
	{
		"GetCommonLinkProperties",
		(struct upnp_argument[]){
			{
				"NewWANAccessType",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_WAN_ACCESS_TYPE,
			},
			{
				"NewLayer1UpstreamMaxBitRate",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_LAYER_1_UPSTREAM_MAX_BIT_RATE,
			},
			{
				"NewLayer1DownstreamMaxBitRate",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_LAYER_1_DOWNSTREAM_MAX_BIT_RATE,
			},
			{
				"NewPhysicalLinkStatus",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_PHYSICAL_LINK_STATUS,
			},
			{
				NULL,
				0,
				0,
				0,
			},
		},
	},
	/* WANIPConnection */
	{
		"SetConnectionType",
		(struct upnp_argument[]){
			{
				"NewConnectionType",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_CONNECTION_TYPE,
			},
			{
				NULL,
				0,
				0,
				0,
			},
		},
	},
	{
		"GetConnectionTypeInfo",
		(struct upnp_argument[]){
			{
				"NewConnectionType",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_CONNECTION_TYPE,
			},
			{
				"NewPossibleConnectionTypes",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_POSSIBLE_CONNECTION_TYPES,
			},
			{
				NULL,
				0,
				0,
				0,
			},
		},
	},
	{
		"RequestConnection",
		NULL,
	},
	{
		"ForceTermination",
		NULL,
	},
	{
		"GetStatusInfo",
		(struct upnp_argument[]){
			{
				"NewConnectionStatus",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_CONNECTION_STATUS,
			},
			{
				"NewLastConnectionError",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_LAST_CONNECTION_ERROR,
			},
			{
				"NewUptime",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_UPTIME,
			},
			{
				NULL,
				0,
				0,
				0,
			},
		},
	},
	{
		"GetNATRSIPStatus",
		(struct upnp_argument[]){
			{
				"NewRSIPAvailable",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_RSIP_AVAILABLE,
			},
			{
				"NewNATEnabled",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_NAT_ENABLED,
			},
			{
				NULL,
				0,
				0,
				0,
			},
		},
	},
	{
		"GetGenericPortMappingEntry",
		(struct upnp_argument[]){
			{
				"NewPortMappingIndex",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_PORT_MAPPING_NUMBER_OF_ENTRIES,
			},
			{
				"NewRemoteHost",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_REMOTE_HOST,
			},
			{
				"NewExternalPort",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_EXTERNAL_PORT,
			},
			{
				"NewProtocol",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_PORT_MAPPING_PROTOCOL,
			},
			{
				"NewInternalPort",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_INTERNAL_PORT,
			},
			{
				"NewInternalClient",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_INTERNAL_CLIENT,
			},
			{
				"NewEnabled",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_PORT_MAPPING_ENABLED,
			},
			{
				"NewPortMappingDescription",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_PORT_MAPPING_DESCRIPTION,
			},
			{
				"NewLeaseDuration",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_PORT_MAPPING_LEASE_DURATION,
			},
			{
				NULL,
				0,
				0,
				0,
			},
		},
	},
	{
		"GetSpecificPortMappingEntry",
		(struct upnp_argument[]){
			{
				"NewRemoteHost",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_REMOTE_HOST,
			},
			{
				"NewExternalPort",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_EXTERNAL_PORT,
			},
			{
				"NewProtocol",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_PORT_MAPPING_PROTOCOL,
			},
			{
				"NewInternalPort",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_INTERNAL_PORT,
			},
			{
				"NewInternalClient",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_INTERNAL_CLIENT,
			},
			{
				"NewEnabled",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_PORT_MAPPING_ENABLED,
			},
			{
				"NewPortMappingDescription",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_PORT_MAPPING_DESCRIPTION,
			},
			{
				"NewLeaseDuration",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_PORT_MAPPING_LEASE_DURATION,
			},
			{
				NULL,
				0,
				0,
				0,
			},
		},
	},
	{
		"AddPortMapping",
		(struct upnp_argument[]){
			{
				"NewRemoteHost",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_REMOTE_HOST,
			},
			{
				"NewExternalPort",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_EXTERNAL_PORT,
			},
			{
				"NewProtocol",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_PORT_MAPPING_PROTOCOL,
			},
			{
				"NewInternalPort",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_INTERNAL_PORT,
			},
			{
				"NewInternalClient",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_INTERNAL_CLIENT,
			},
			{
				"NewEnabled",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_PORT_MAPPING_ENABLED,
			},
			{
				"NewPortMappingDescription",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_PORT_MAPPING_DESCRIPTION,
			},
			{
				"NewLeaseDuration",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_PORT_MAPPING_LEASE_DURATION,
			},
			{
				NULL,
				0,
				0,
				0,
			},
		},
	},
	{
		"AddAnyPortMapping",
		(struct upnp_argument[]){
			{
				"NewRemoteHost",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_REMOTE_HOST,
			},
			{
				"NewExternalPort",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_EXTERNAL_PORT,
			},
			{
				"NewProtocol",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_PORT_MAPPING_PROTOCOL,
			},
			{
				"NewInternalPort",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_INTERNAL_PORT,
			},
			{
				"NewInternalClient",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_INTERNAL_CLIENT,
			},
			{
				"NewEnabled",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_PORT_MAPPING_ENABLED,
			},
			{
				"NewPortMappingDescription",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_PORT_MAPPING_DESCRIPTION,
			},
			{
				"NewLeaseDuration",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_PORT_MAPPING_LEASE_DURATION,
			},
			{
				"NewReservedPort",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_EXTERNAL_PORT,
			},
			{
				NULL,
				0,
				0,
				0,
			},
		},
	},
	{
		"DeletePortMapping",
		(struct upnp_argument[]){
			{
				"NewRemoteHost",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_REMOTE_HOST,
			},
			{
				"NewExternalPort",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_EXTERNAL_PORT,
			},
			{
				"NewProtocol",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_PORT_MAPPING_PROTOCOL,
			},
			{
				NULL,
				0,
				0,
				0,
			},
		},
	},
	{
		"DeletePortMappingRange",
		(struct upnp_argument[]){
			{
				"NewStartPort",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_EXTERNAL_PORT,
			},
			{
				"NewEndPort",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_EXTERNAL_PORT,
			},
			{
				"NewProtocol",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_PORT_MAPPING_PROTOCOL,
			},
			{
				"NewManage",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_A_ARG_TYPE_MANAGE,
			},
			{
				NULL,
				0,
				0,
				0,
			},
		},
	},
	{
		"GetExternalIPAddress",
		(struct upnp_argument[]){
			{
				"NewExternalIPAddress",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_EXTERNAL_IP_ADDRESS,
			},
			{
				NULL,
				0,
				0,
				0,
			},
		},
	},
	{
		"GetListOfPortMappings",
		(struct upnp_argument[]){
			{
				"NewStartPort",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_EXTERNAL_PORT,
			},
			{
				"NewEndPort",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_EXTERNAL_PORT,
			},
			{
				"NewProtocol",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_PORT_MAPPING_PROTOCOL,
			},
			{
				"NewManage",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_A_ARG_TYPE_MANAGE,
			},
			{
				"NewNumberOfPorts",
				UPNP_ARGUMENT_DIRECTION_IN,
				0,
				UPNP_VARIABLE_PORT_MAPPING_NUMBER_OF_ENTRIES,
			},
			{
				"NewPortListing",
				UPNP_ARGUMENT_DIRECTION_OUT,
				0,
				UPNP_VARIABLE_A_ARG_TYPE_PORT_LISTING,
			},
			{
				NULL,
				0,
				0,
				0,
			},
		},
	},
};

/* UPnP services */
const struct upnp_service	 upnp_service[UPNP_SERVICE_MAX] = {
	{
		UPNP_TYPE_URN(UPNP_SCHEMA_NID, UPNP_SERVICE_TYPE,
		    "WANCommonInterfaceConfig",
		    UPNP_VERSION_WAN_COMMON_INTERFACE_CONFIG),
		UPNP_SERVICE_ID_URN(UPNP_NID, "WANCommonIFC", 1),
		NULL,
		NULL,
		NULL,
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
		UPNP_TYPE_URN(UPNP_SCHEMA_NID, UPNP_SERVICE_TYPE,
		    "WANIPConnection", UPNP_VERSION_WAN_IP_CONNECTION),
		UPNP_SERVICE_ID_URN(UPNP_NID, "WANIPConn", 1),
		NULL,
		NULL,
		NULL,
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
		UPNP_TYPE_URN(UPNP_SCHEMA_NID, UPNP_DEVICE_TYPE,
		    "InternetGatewayDevice",
		    UPNP_VERSION_INTERNET_GATEWAY_DEVICE),
		NULL,
		(enum upnp_devices[]){
			UPNP_DEVICE_WAN_DEVICE,
			UPNP_DEVICE_EOL,
		},
	},
	{
		UPNP_TYPE_URN(UPNP_SCHEMA_NID, UPNP_DEVICE_TYPE,
		    "WANDevice", UPNP_VERSION_WAN_DEVICE),
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
		UPNP_TYPE_URN(UPNP_SCHEMA_NID, UPNP_DEVICE_TYPE,
		    "WANConnectionDevice", UPNP_VERSION_WAN_CONNECTION_DEVICE),
		(enum upnp_services[]){
			UPNP_SERVICE_WAN_IP_CONNECTION,
			UPNP_SERVICE_EOL,
		},
		NULL,
	},
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

	action = xmlNewChild(node, NULL, "action", NULL);

	xmlNewChild(action, NULL, "name", parent->name);

	if (parent->arguments) {
		arguments = xmlNewChild(action, NULL, "argumentList", NULL);
		for (arg = parent->arguments; arg->name; arg++) {
			argument = xmlNewChild(arguments, NULL, "argument",
			    NULL);
			xmlNewChild(argument, NULL, "name", arg->name);
			xmlNewChild(argument, NULL, "direction",
			    upnp_argument_direction[arg->direction]);
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

	xmlSaveFormatFileEnc("-", document, NULL, 1);

	return (document);
}

void
upnp_add_service(xmlNodePtr node, u_int32_t version, enum upnp_services type,
    struct evhttp *http, struct ssdp_device *parent,
    struct ssdp_services *services)
{
	xmlNodePtr		 service;
	struct ssdp_service	*ssdp;

	service = xmlNewChild(node, NULL, "service", NULL);

	xmlNewChild(service, NULL, "serviceType", upnp_service[type].type);
	xmlNewChild(service, NULL, "serviceId", upnp_service[type].id);
	xmlNewChild(service, NULL, "SCPDURL", upnp_service[type].scpd);
	xmlNewChild(service, NULL, "controlURL", upnp_service[type].control);
	xmlNewChild(service, NULL, "eventSubURL", upnp_service[type].event);

	/* Create SSDP service search struct */
	if ((ssdp = calloc(1, sizeof(struct ssdp_service))) == NULL)
		fatal("calloc");

	ssdp->parent = parent;
	if ((ssdp->urn = urn_from_string(upnp_service[type].type)) == NULL)
		fatalx("urn_from_string");
	if ((ssdp->nss = upnp_nss_from_string(ssdp->urn->nss)) == NULL)
		fatalx("upnp_nss_from_string");
	ssdp->document = upnp_service_xml(version, type);

	TAILQ_INSERT_TAIL(services, ssdp, entry);

#if 0
	evhttp_set_cb(http, upnp_service[type].scpd, upnp_xml, ssdp->document);
	evhttp_set_cb(http, upnp_service[type].control, upnp_soap, NULL);
	evhttp_set_cb(http, upnp_service[type].event, upnp_event, NULL);
#endif
}

void
upnp_add_device(xmlNodePtr node, u_int32_t version, enum upnp_devices type,
    struct evhttp *http, struct ssdp_devices *devices,
    struct ssdp_services *services)
{
	xmlNodePtr		 device, icons, servicelist, devicelist;
	uuid_t			*uuid;
	char			*str, *ptr = NULL;
	struct ssdp_device	*ssdp;
	int			 i;

	device = xmlNewChild(node, NULL, "device", NULL);

	xmlNewChild(device, NULL, "deviceType", upnp_device[type].type);

	/* FIXME */
	xmlNewChild(device, NULL, "friendlyName", NULL);
	xmlNewChild(device, NULL, "manufacturer", NULL);
	xmlNewChild(device, NULL, "modelDescription", NULL);
	xmlNewChild(device, NULL, "modelName", NULL);
	xmlNewChild(device, NULL, "modelNumber", NULL);
	xmlNewChild(device, NULL, "modelURL", NULL);
	xmlNewChild(device, NULL, "serialNumber", NULL);

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
	xmlNewChild(device, NULL, "UPC", NULL);
	icons = xmlNewChild(device, NULL, "iconList", NULL);

	/* Create SSDP device search struct */
	if ((ssdp = calloc(1, sizeof(struct ssdp_device))) == NULL)
		fatal("calloc");

	ssdp->uuid = str;
	if ((ssdp->urn = urn_from_string(upnp_device[type].type)) == NULL)
		fatalx("urn_from_string");
	if ((ssdp->nss = upnp_nss_from_string(ssdp->urn->nss)) == NULL)
		fatalx("upnp_nss_from_string");

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

	evhttp_set_cb(http, "/describe/root.xml", upnp_xml, root->document);

	return (root);
}

/* Serve XML description */
void
upnp_xml(struct evhttp_request *req, void *arg)
{
	xmlDocPtr	 document = (xmlDocPtr)arg;
	struct evbuffer	*output;
	xmlChar		*xml = NULL;
	int		 len = 0;
	char		*header;
	int		 hlen;

	/* Check Host and Accept-Language headers? */

	switch (req->type) {
	case EVHTTP_REQ_GET:
		log_debug("GET %s", evhttp_request_uri(req));

		if ((output = evbuffer_new()) == NULL)
			return;

		xmlDocDumpFormatMemory(document, &xml, &len, 1);
		evbuffer_add(output, xml, len);
		xmlFree(xml);

		/* Add Content-Language header if Accept-Language is present */

		hlen = snprintf(NULL, 0, "%d", len);
		if ((header = calloc(hlen + 1, sizeof(char))) == NULL)
			fatal("calloc");
		snprintf(header, hlen + 1, "%d", len);
		evhttp_add_header(req->output_headers, "Content-Length",
		    header);
		free(header);

		evhttp_add_header(req->output_headers, "Content-Type",
		    "text/xml");

		evhttp_send_reply(req, HTTP_OK, "OK", output);
		evbuffer_free(output);
		break;
	default:
		evhttp_add_header(req->output_headers, "Allow", "GET");
		evhttp_send_reply(req, 405, "Bad Method", NULL);
		break;
	}
}

void
upnp_soap(struct evhttp_request *req, void *arg)
{
	xmlDocPtr	 document;
	xmlNodePtr	 envelope;
	xmlNsPtr	 ns;

	switch (req->type) {
	case EVHTTP_REQ_POST:
		document = xmlNewDoc("1.0");
		envelope = xmlNewNode(NULL, "Envelope");
		xmlDocSetRootElement(document, envelope);

		ns = xmlNewNs(envelope, "http://schemas.xmlsoap.org/soap/envelope/", "s");
		xmlSetNs(envelope, ns);
		xmlNewProp(envelope, "encodingStyle", "http://schemas.xmlsoap.org/soap/encoding/");
		xmlNewChild(envelope, NULL, "Body", NULL);

		/* FIXME */
		break;
	default:
		evhttp_add_header(req->output_headers, "Allow", "POST");
		evhttp_send_reply(req, 405, "Bad Method", NULL);
		break;
	}
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
