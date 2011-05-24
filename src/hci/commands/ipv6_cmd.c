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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include <gpxe/netdevice.h>
#include <gpxe/in.h>
#include <gpxe/command.h>
#include <usr/ip6mgmt.h>
#include <usr/ifmgmt.h>

/** @file
 *
 * IPv6 management commands
 *
 */

/**
 * "ipv6" command syntax message
 *
 * @v argv		Argument list
 */
static void ipv6_syntax ( char **argv ) {
	printf ( "Usage:\n"
		 "  %s <interface> [<interface> ...]\n"
		 "  %s any\n"
		 "\n"
		 "Prepare a network interface for use with IPv6\n",
		 argv[0], argv[0] );
}


/**
 * Attempt to configure a device with an IPv6 link-local address
 *
 * @v netdev		Device to configure
 * @ret rc		Exit code
 */
static int ipv6_one_device ( struct net_device *netdev ) {
	int rc;

	/* Perform autoconfiguration */
	if ( ( rc = ip6_autoconf ( netdev ) ) != 0 ) {
		/* Close the device on error to avoid out-of-memory */
		netdev_close ( netdev );

		printf ( "Could not configure %s: %s\n", netdev->name,
			 strerror ( rc ) );
		return 1;
	}

	return 0;
}

/**
 * Call ipv6_one_device() for each name in argv
 *
 * @v argc		Number of devices
 * @v argv		List of device names
 * @ret rc		Exit code
 */
static int ipv6_each_device_name ( int argc, char **argv ) {
	int i;
	char *netdev_name;
	struct net_device *netdev;

	for ( i = 0; i < argc; i++ ) {
		netdev_name = argv[i];
		netdev = find_netdev ( netdev_name );

		if ( ! netdev ) {
			printf ( "No such interface: %s\n", netdev_name );
			continue;
		}

		if ( ipv6_one_device ( netdev ) == 0 )
			return 0;
	}

	printf ( "Could not configure any interface.\n" );
	return 1;
}

/**
 * Call ipv6_one_device() for each device in net_devices
 *
 * @ret rc		Exit code
 */
static int ipv6_each_device ( void ) {
	struct net_device *netdev;

	for_each_netdev ( netdev ) {
		if ( ipv6_one_device ( netdev ) == 0 )
			return 0;
	}

	printf ( "Could not configure any interface.\n" );
	return 1;
}

/**
 * The "ipv6" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Exit code
 */
static int ipv6_exec ( int argc __unused, char **argv __unused ) {
	static struct option longopts[] = {
		{ "help", 0, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};
	int c;

	/* Parse options */
	while ( ( c = getopt_long ( argc, argv, "h", longopts, NULL ) ) >= 0 ){
		switch ( c ) {
		case 'h':
			/* Display help text */
		default:
			/* Unrecognised/invalid option */
			ipv6_syntax ( argv );
			return 1;
		}
	}

	/* Need one or more interface names remaining after the options */
	if ( ( argc - optind ) < 1 ) {
		ipv6_syntax ( argv );
		return 1;
	}

	if ( strcmp ( argv[optind], "any" ) == 0 )
		return ipv6_each_device();

	return ipv6_each_device_name ( argc - optind, argv + optind );
}

static int dhcp6_exec ( int argc __unused, char **argv __unused ) {
	printf ( "DHCPv6 is not yet implemented.\n" );
	return 0;
}

/** IPv6 management commands */
struct command ipv6_commands[] __command = {
	{
		.name = "ipv6",
		.exec = ipv6_exec,
	},
	{
		.name = "dhcp6",
		.exec = dhcp6_exec,
	}
};


