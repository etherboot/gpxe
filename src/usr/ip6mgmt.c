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
#include <gpxe/monojob.h>
#include <gpxe/process.h>
#include <usr/ifmgmt.h>
#include <usr/ip6mgmt.h>

#define LINK_WAIT_MS	15000

/* Maximum length of the link-layer address we'll insert as an EUI-64. */
#define AUTOCONF_LL_MAX	6

int ip6_autoconf ( struct net_device *netdev __unused ) {
	struct in6_addr ip6addr;
	size_t ll_size;
	int rc;

	/* Check we can open the interface first */
	if ( ( rc = ifopen ( netdev ) ) != 0 )
		return rc;

	/* Wait for link-up */
	if ( ( rc = iflinkwait ( netdev, LINK_WAIT_MS ) ) != 0 )
		return rc;
	
	/* Create the host ID part of the IPv6 address from the Link-Layer
	 * address on the netdevice. */
	memset ( &ip6addr, 0, sizeof (struct in6_addr) );
	
	ll_size = netdev->ll_protocol->ll_addr_len;
	if ( ll_size < 6 ) {
		memcpy ( ip6addr.s6_addr + (8 - ll_size), netdev->ll_addr, ll_size );
	} else {
		/* Create an EUI-64 identifier. */
		memcpy( ip6addr.s6_addr + 8, netdev->ll_addr, 3 );
		memcpy( ip6addr.s6_addr + 8 + 5, netdev->ll_addr + 3, 3 );
		ip6addr.s6_addr[11] = 0xFF;
		ip6addr.s6_addr[12] = 0xFE;
		
		/* Designate that this is in fact an EUI-64. */
		ip6addr.s6_addr[8] |= 0x2;
	}
	
	/* Fill in the link-local prefix. */
	ip6addr.s6_addr[0] = 0xFE;
	ip6addr.s6_addr[1] = 0x80;
	
	DBG( "ip6 autoconfig address is %s\n", inet6_ntoa(ip6addr) );
	
	return 0;
}

