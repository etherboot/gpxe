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

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <byteswap.h>
#include <gpxe/in.h>
#include <gpxe/ip6.h>
#include <gpxe/list.h>
#include <gpxe/udp.h>
#include <gpxe/socket.h>
#include <gpxe/iobuf.h>
#include <gpxe/dhcp6.h>

/* Address for all DHCP servers and relay agents - FF02::1:2 */
static struct in6_addr dhcp6_servers __unused = {
	.in6_u.u6_addr32 = { htonl(0xFF02), 0, 0, htonl(0x10002) }
};



