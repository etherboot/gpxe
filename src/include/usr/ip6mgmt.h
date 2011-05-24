#ifndef _USR_IPV6MGMT_H
#define _USR_IPV6MGMT_H

/** @file
 *
 * IPv6 management
 *
 */

FILE_LICENCE ( GPL2_OR_LATER );

struct net_device;

extern int ip6_autoconf ( struct net_device *netdev );

#endif /* _USR_IPV6MGMT_H */

