/*
 * Copyright (C) 2011 Matthew Iselin <matthew@theiselins.net>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

FILE_LICENCE ( GPL2_OR_LATER );

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <gpxe/netdevice.h>
#include <gpxe/in.h>
#include <gpxe/ip6.h>
#include <gpxe/icmp6.h>
#include <gpxe/monojob.h>
#include <gpxe/process.h>
#include <usr/ifmgmt.h>
#include <usr/ip6mgmt.h>
#include <gpxe/dhcp6.h>

#define LINK_WAIT_MS	15000

/* Maximum length of the link-layer address we'll insert as an EUI-64. */
#define AUTOCONF_LL_MAX	6

int ip6_autoconf ( struct net_device *netdev ) {
	struct in6_addr ip6addr, ip6zero;
	size_t ll_size;
	int rc;
	int use_dhcp = 0, onlyinfo = 0;

	/* Check we can open the interface first */
	if ( ( rc = ifopen ( netdev ) ) != 0 )
		return rc;

	/* Wait for link-up */
	if ( ( rc = iflinkwait ( netdev, LINK_WAIT_MS ) ) != 0 )
		return rc;
	
	/* Create the host ID part of the IPv6 address from the Link-Layer
	 * address on the netdevice. */
	memset ( &ip6addr, 0, sizeof (struct in6_addr) );
	memset ( &ip6zero, 0, sizeof (struct in6_addr) );
	
	ll_size = netdev->ll_protocol->ll_addr_len;
	if ( ll_size < 6 ) {
		memcpy ( ip6addr.s6_addr + (8 - ll_size), netdev->ll_addr, ll_size );
	} else {
		ipv6_generate_eui64 ( ip6addr.s6_addr + 8, netdev->ll_addr );
	}
	
	/* Fill in the link-local prefix. */
	ip6addr.s6_addr[0] = 0xFE;
	ip6addr.s6_addr[1] = 0x80;
	
	/* TODO: send a few neighbour solicits on this address before we take
	 * it (once NDP is implemented). */
	
	DBG( "ipv6 autoconfig address is %s\n", inet6_ntoa(ip6addr) );
	
	/* Add as a route. It turns out Linux actually uses /64 for these, even
	 * though they are technically a /10. It does make routing easier, as
	 * /10 straddles a byte boundary. */
	add_ipv6_address ( netdev, ip6addr, 64, ip6addr, ip6zero );
	
	/* Solicit routers on the network. */
	if ( ( rc = ndp_send_rsolicit ( netdev, &monojob, NULL ) ) == 0 ) {
		rc = monojob_wait ( "" );
	}
	
	if ( rc < 0 ) {
		DBG ( "ipv6: router solicitation failed\n" );
		use_dhcp = 1;
		onlyinfo = 0;
	} else {
		if ( rc & RSOLICIT_CODE_MANAGED ) {
			DBG ( "ipv6: should use dhcp6 server\n" );
			use_dhcp = 1;
		} else if ( rc & RSOLICIT_CODE_OTHERCONF ) {
			DBG ( "ipv6: use dhcp6 server for DNS settings\n" );
			use_dhcp = 1;
			onlyinfo = 1;
		} else {
			DBG ( "ipv6: autoconfiguration complete\n" );
		}
	}
	
	/* Attempt DHCPv6 now, for addresses (if we don't already have one) and
	 * DNS configuration. */
	if ( use_dhcp ) {
		start_dhcp6 ( &monojob, netdev, onlyinfo );
		rc = monojob_wait ( "" );
	}
	
	return rc;
}

