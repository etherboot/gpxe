#ifndef _GPXE_DHCP6_H
#define _GPXE_DHCP6_H

/** @file
 *
 * Dynamic Host Configuration Protocol for IPv6, as per RFC3315
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <stdint.h>

/** DHCPv6 server port */
#define DHCP6S_PORT 547

/** DHCPv6 client port */
#define DHCP6C_PORT 546

/** DHCPv6 Status Codes */
#define DHCP6_SUCCESS	0
#define DHCP6_UNSPEC	1
#define DHCP6_NOADDRS	2
#define DHCP6_NOBIND	3
#define DHCP6_NOTLINK	4
#define DHCP6_MCAST	5

/** DHCPv6 message types */
#define DHCP6_SOLICIT	1
#define DHCP6_ADVERTISE	2
#define DHCP6_REQUEST	3
#define DHCP6_CONFIRM	4
#define DHCP6_RENEW	5
#define DHCP6_REBIND	6
#define DHCP6_REPLY	7
#define DHCP6_RELEASE	8
#define DHCP6_DECLINE	9
#define DHCP6_RECONF	10
#define DHCP6_INFOREQ	11

/** DHCPv6 message type. DHCPv6 options follow this header. */
struct dhcp6_msg {
	uint32_t type_id;
};

/** DHCP option header type. */
struct dhcp6_opt_hdr {
	uint16_t code;
	uint16_t len;
	/** variable-length option data. */
};

/** DHCPv6 option types */
#define DHCP6_OPT_CLIENTID	1
#define DHCP6_OPT_SERVERID	2
#define DHCP6_OPT_IA_NA		3
#define DHCP6_OPT_IA_TA		4
#define DHCP6_OPT_IAADDR	5
#define DHCP6_OPT_ORO		6
#define DHCP6_OPT_PREFERENCE	7
#define DHCP6_OPT_ELAPSED	8
#define DHCP6_OPT_UNICAST	12
#define DHCP6_OPT_STATUS	13
#define DHCP6_OPT_RCOMMIT	14
#define DHCP6_OPT_USER_CLASS	15
#define DHCP6_OPT_VENDOR_CLASS	16
#define DHCP6_OPT_VENDOR_INFO	17
#define DHCP6_OPT_IFACE_ID	18
#define DHCP6_OPT_RECONF_MSG	19
#define DHCP6_OPT_RECONF_ACCEPT	20

#define DHCP6_OPT_DNS_SERVERS	23
#define DHCP6_OPT_DNS_DOMAINS	24

/** Identity association for non-temporary address option */
struct dhcp6_opt_ia_na {
	uint16_t code;
	uint16_t len;
	uint32_t iaid;
	uint32_t t1;
	uint32_t t2;
	/** IA-NA options follow. */
};

/** Identity association for temporary addresses option */
struct dhcp6_opt_ia_ta {
	uint16_t code;
	uint16_t len;
	uint32_t iaid;
	/** IA-TA options follow. */
};

/** Identity association, Address option. */
struct dhcp6_opt_iaaddr {
	uint16_t code;
	uint16_t len;
	struct in6_addr addr;
	uint32_t pref_lifetime;
	uint32_t valid_lifetime;
	/** IAddr options follow. */
};

/** Option request option. */
struct dhcp6_opt_oro {
	uint16_t code;
	uint16_t len;
	uint16_t optcodes[];
};

/** Preference option. */
struct dhcp6_opt_pref {
	uint16_t code;
	uint16_t len;
	uint8_t pref_value;
};

/** Elapsed Time option. */
struct dhcp6_opt_elapsed {
	uint16_t code;
	uint16_t len;
	uint16_t time;
};

/** Server Unicast option. */
struct dhcp6_opt_unicast {
	uint16_t code;
	uint16_t len;
	struct in6_addr addr;
};

/** Status Code option. */
struct dhcp6_opt_status_code {
	uint16_t code;
	uint16_t len;
	uint16_t status;
	uint8_t utf8_message[]; /** UTF-8, for display to the user. */
};

/** User Class option. */
struct dhcp6_opt_user_class {
	uint16_t code;
	uint16_t len;
	char user_class_data[];
};

/** Vendor Class option. */
struct dhcp6_opt_vendor_class {
	uint16_t code;
	uint16_t len;
	uint32_t enterprise_number;
	char vendor_class_data[];
};

/** Vendor-Specific Information option. */
struct dhcp6_opt_vendor_specific_info {
	uint16_t code;
	uint16_t len;
	uint32_t enterprise_number;
	char option_data[]; /** Interpreted by vendor-specific code. */
};

/** Interface-ID option. */
struct dhcp6_opt_interface_id {
	uint16_t code;
	uint16_t len;
	char interface_id[];
};

/** Reconfigure Message option. */
struct dhcp6_opt_reconfigure {
	uint16_t code;
	uint16_t len;
	uint8_t msg_type;
};

/** DHCPv6 DUID types */
#define DHCP6_DUID_LLT	1
#define DHCP6_DUID_EN	2
#define DHCP6_DUID_LL	3

/** Common header for the DHCPv6 DUID. */
struct dhcp6_duid {
	uint16_t code;
};

/** DUID based on link layer address plus time (DUID-LLT) */
struct dhcp6_duid_llt {
	uint16_t code; /** 1 for LLT */
	uint16_t hwtype;
	uint32_t time;
	/** variable length link-layer address follows */
};

/** DUID assigned by vendor based on enterprise number (DUID-EN) */
struct dhcp6_duid_en {
	uint16_t code; /** 2 for EN */
	uint32_t enterprise;
	/** variable length for identifier, defined by the vendor */
};

/** DUID based on link layer address */
struct dhcp6_duid_ll {
	uint16_t code; /** 3 for LL */
	uint16_t hwtype;
	/** variable length for link layer address */
};

/** Start a DHCP6 transaction. */
int start_dhcp6 ( struct job_interface *job, struct net_device *netdev,
		  int onlyinfo, struct rsolicit_info *router );

#endif

