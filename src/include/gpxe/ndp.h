#ifndef _GPXE_NDP_H
#define _GPXE_NDP_H

#include <stdint.h>
#include <byteswap.h>
#include <string.h>
#include <gpxe/ip6.h>
#include <gpxe/in.h>
#include <gpxe/netdevice.h>
#include <gpxe/iobuf.h>
#include <gpxe/tcpip.h>

struct icmp6_net_protocol;
struct job_interface;

#define NDP_STATE_INVALID 0
#define NDP_STATE_INCOMPLETE 1
#define NDP_STATE_REACHABLE 2
#define NDP_STATE_DELAY 3
#define NDP_STATE_PROBE 4
#define NDP_STATE_STALE 5

#define RSOLICIT_STATE_INVALID	0
#define RSOLICIT_STATE_PENDING	1
#define RSOLICIT_STATE_COMPLETE	2
#define RSOLICIT_STATE_ALMOST	3

#define RSOLICIT_CODE_NONE	0
#define RSOLICIT_CODE_MANAGED	1
#define RSOLICIT_CODE_OTHERCONF	2

#define NDP_OPTION_SOURCE_LL        1
#define NDP_OPTION_TARGET_LL        2
#define NDP_OPTION_PREFIX_INFO      3
#define NDP_OPTION_REDIRECT         4
#define NDP_OPTION_MTU              5

struct neighbour_solicit {
	uint8_t type;
	uint8_t code;
	uint16_t csum;
	uint32_t reserved;
	struct in6_addr target;
};

struct neighbour_advert {
	uint8_t type;
	uint8_t code;
	uint16_t csum;
	uint8_t flags;
	uint8_t reserved;
	struct in6_addr target;
};

struct router_solicit {
	uint8_t type;
	uint8_t code;
	uint16_t csum;
	uint32_t reserved;
};

struct router_advert {
	uint8_t type;
	uint8_t code;
	uint16_t csum;
	uint16_t lifetime;
	uint16_t hops_flags;
	uint32_t reachable_time;
	uint32_t retrans_time;
};

struct ndp_option
{
	uint8_t type;
	uint8_t length;
};

struct ll_option
{
	uint8_t type;
	uint8_t length;
	uint8_t address[6];
};

struct prefix_option
{
	uint8_t type;
	uint8_t length;
	uint8_t prefix_len;
	uint8_t flags_rsvd;
	uint32_t lifetime;
	uint32_t pref_lifetime;
	uint32_t rsvd2;
	uint8_t prefix[16];
};

#define RADVERT_MANAGED		0x100
#define RADVERT_OTHERCONF	0x101

int ndp_resolve ( struct net_device *netdev, struct in6_addr *src,
		  struct in6_addr *dest, void *dest_ll_addr );

int ndp_send_rsolicit ( struct net_device *netdev, struct job_interface *job );

int ndp_process_radvert ( struct io_buffer *iobuf, struct sockaddr_tcpip *st_src,
			  struct sockaddr_tcpip *st_dest, struct net_device *netdev,
			  struct icmp6_net_protocol *net_protocol );

int ndp_process_nadvert ( struct io_buffer *iobuf, struct sockaddr_tcpip *st_src,
			  struct sockaddr_tcpip *st_dest,
			  struct icmp6_net_protocol *net_protocol );

int ndp_process_nsolicit ( struct io_buffer *iobuf, struct sockaddr_tcpip *st_src,
			   struct sockaddr_tcpip *st_dest, struct net_device *netdev,
			   struct icmp6_net_protocol *net_protocol );

#endif

