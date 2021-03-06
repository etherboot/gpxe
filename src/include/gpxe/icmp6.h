#ifndef _GPXE_ICMP6_H
#define _GPXE_ICMP6_H

/** @file
 *
 * ICMP6 protocol
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <gpxe/ip6.h>
#include <gpxe/ndp.h>
#include <gpxe/tcpip.h>

#include <gpxe/tables.h>

struct net_device;
struct net_protocol;

/** A network-layer protocol that relies upon ICMPv6 */
struct icmp6_net_protocol {
	/** Network-layer protocol */
	struct net_protocol *net_protocol;
	/** Check existence of address
	 *
	 * @v netdev	Network device
	 * @v net_addr	Network-layer address
	 * @ret rc	Return status code
	 */
	int ( * check ) ( struct net_device *netdev,
			  const void *net_addr );
};

/** ICMPv6 protocol table */
#define ICMP6_NET_PROTOCOLS \
	__table ( struct icmp6_net_protocol, "icmp6_net_protocols" )

/** Declare an ICMPv6 protocol */
#define __icmp6_net_protocol __table_entry ( ICMP6_NET_PROTOCOLS, 01 )

#define ICMP6_ECHO_REQUEST	128
#define ICMP6_ECHO_RESPONSE	129
#define ICMP6_ROUTER_SOLICIT	133
#define ICMP6_ROUTER_ADVERT	134
#define ICMP6_NSOLICIT		135
#define ICMP6_NADVERT		136

extern struct tcpip_protocol icmp6_protocol;

struct icmp6_header {
	uint8_t type;
	uint8_t code;
	uint16_t csum;
	/* Message body */
};

#define ICMP6_FLAGS_ROUTER 0x80
#define ICMP6_FLAGS_SOLICITED 0x40
#define ICMP6_FLAGS_OVERRIDE 0x20

int icmp6_rx ( struct io_buffer *iobuf, struct sockaddr_tcpip *st_src,
	       struct sockaddr_tcpip *st_dest, struct net_device *netdev,
	       uint16_t pshdr_csum );

int icmp6_send_solicit ( struct net_device *netdev, struct in6_addr *src, struct in6_addr *dest );

int icmp6_send_advert ( struct net_device *netdev, struct in6_addr *src, struct in6_addr *dest );

#endif /* _GPXE_ICMP6_H */
