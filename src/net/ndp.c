#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <byteswap.h>
#include <errno.h>
#include <gpxe/if_ether.h>
#include <gpxe/iobuf.h>
#include <gpxe/ndp.h>
#include <gpxe/icmp6.h>
#include <gpxe/ip6.h>
#include <gpxe/netdevice.h>
#include <gpxe/job.h>

/** @file
 *
 * Neighbour Discovery Protocol
 *
 * This file implements address resolution as specified by the neighbour
 * discovery protocol in RFC2461. This protocol is part of the IPv6 protocol
 * family.
 */

/* A neighbour entry */
struct ndp_entry {
	/** Target IP6 address */
	struct in6_addr in6;
	/** Link layer protocol */
	struct ll_protocol *ll_protocol;
	/** Link-layer address */
	uint8_t ll_addr[MAX_LL_ADDR_LEN];
	/** State of the neighbour entry */
	int state;
};

/** A pending router solicitation. */
struct pending_rsolicit {
	/** Network device for the solicit. */
	struct net_device *netdev;
	/** State of the solicitation. */
	int state;
	/** Status code after handling the solicit. */
	int code;
	/** Job control interface */
	struct job_interface job;
	/** Reference counter */
	struct refcnt refcnt;
};

/** Number of entries in the neighbour cache table */
#define NUM_NDP_ENTRIES 4

/** The neighbour cache table */
static struct ndp_entry ndp_table[NUM_NDP_ENTRIES];
#define ndp_table_end &ndp_table[NUM_NDP_ENTRIES]

static unsigned int next_new_ndp_entry = 0;

/** The pending solicit table */
static struct pending_rsolicit solicit_table[NUM_NDP_ENTRIES];
#define solicit_table_end &solicit_table[NUM_NDP_ENTRIES]

static unsigned int next_new_solicit_entry = 0;

/**
 * Handle kill() event received via job control interface
 *
 * @v job		Router solicit job control interface
 */
static void rsolicit_job_kill ( struct job_interface *job ) {
	struct pending_rsolicit *entry =
		container_of ( job, struct pending_rsolicit, job );

	/* Terminate. */
	entry->code = 0;
	entry->state = RSOLICIT_STATE_INVALID;
	
	/* Clean up. */
	job_nullify ( &entry->job );
	job_done ( &entry->job, -ECANCELED );
}

/** Router solicit job control interface operations */
static struct job_interface_operations rsolicit_job_operations = {
	.done		= ignore_job_done,
	.kill		= rsolicit_job_kill,
	.progress	= ignore_job_progress,
};

/**
 * Find entry in the neighbour cache
 *
 * @v in6	IP6 address
 */
static struct ndp_entry *
ndp_find_entry ( struct in6_addr *in6 ) {
	struct ndp_entry *ndp;

	for ( ndp = ndp_table ; ndp < ndp_table_end ; ndp++ ) {
		if ( IP6_EQUAL ( ( *in6 ), ndp->in6 ) &&
		     ( ndp->state != NDP_STATE_INVALID ) ) {
			return ndp;
		}
	}
	return NULL;
}

/**
 * Find a pending router solicitation for an interface.
 *
 * @v netdev	Interface for the solicitation.
 */
static struct pending_rsolicit *
solicit_find_entry ( struct net_device *netdev ) {
	struct pending_rsolicit *entry;

	for ( entry = solicit_table ; entry < solicit_table_end ; entry++ ) {
		if ( ( entry->netdev == netdev ) &&
		     ( entry->state == RSOLICIT_STATE_PENDING ) ) {
			return entry;
		}
	}
	return NULL;
}

/**
 * Add NDP entry
 *
 * @v netdev	Network device
 * @v in6	IP6 address
 * @v ll_addr	Link-layer address
 * @v state	State of the entry - one of the NDP_STATE_XXX values
 */
static void
add_ndp_entry ( struct net_device *netdev, struct in6_addr *in6,
		void *ll_addr, int state ) {
	struct ndp_entry *ndp;
	ndp = &ndp_table[next_new_ndp_entry++ % NUM_NDP_ENTRIES];

	/* Fill up entry */
	ndp->ll_protocol = netdev->ll_protocol;
	memcpy ( &ndp->in6, &( *in6 ), sizeof ( *in6 ) );
	if ( ll_addr ) {
		memcpy ( ndp->ll_addr, ll_addr, netdev->ll_protocol->ll_addr_len );
	} else {
		memset ( ndp->ll_addr, 0, netdev->ll_protocol->ll_addr_len );
	}
	ndp->state = state;
	DBG ( "New neighbour cache entry: IP6 %s => %s %s\n",
	      inet6_ntoa ( ndp->in6 ), netdev->ll_protocol->name,
	      netdev->ll_protocol->ntoa ( ndp->ll_addr ) );
}

/**
 * Add pending solicit entry
 * 
 * @v netdev	Network device
 * @v state	State of the entry - one of the RSOLICIT_STATE_XXX values
 */
static struct pending_rsolicit *
add_solicit_entry ( struct net_device *netdev, int state ) {
	struct pending_rsolicit *entry;
	entry = &solicit_table[next_new_solicit_entry++ % NUM_NDP_ENTRIES];

	/* Fill up entry */
	entry->netdev = netdev;
	entry->state = state;
	entry->code = RSOLICIT_CODE_NONE;
	
	return entry;
}

/**
 * Resolve the link-layer address
 *
 * @v netdev		Network device
 * @v dest		Destination address
 * @v src		Source address
 * @ret dest_ll_addr	Destination link-layer address or NULL
 * @ret rc		Status
 *
 * This function looks up the neighbour cache for an entry corresponding to the
 * destination address. If it finds a valid entry, it fills up dest_ll_addr and
 * returns 0. Otherwise it sends a neighbour solicitation to the solicited
 * multicast address.
 */
int ndp_resolve ( struct net_device *netdev, struct in6_addr *dest,
		  struct in6_addr *src, void *dest_ll_addr ) {
	struct ll_protocol *ll_protocol = netdev->ll_protocol;
	struct ndp_entry *ndp;
	int rc;

	ndp = ndp_find_entry ( dest );
	/* Check if the entry is valid */
	if ( ndp && ndp->state == NDP_STATE_REACHABLE ) {
		DBG ( "Neighbour cache hit: IP6 %s => %s %s\n",
		      inet6_ntoa ( *dest ), ll_protocol->name,
		      ll_protocol->ntoa ( ndp->ll_addr ) );
		memcpy ( dest_ll_addr, ndp->ll_addr, ll_protocol->ll_addr_len );
		return 0;
	}

	/* Check if the entry was already created */
	if ( ndp ) {
		DBG ( "Awaiting neighbour advertisement\n" );
		/* For test */
//		ndp->state = NDP_STATE_REACHABLE;
//		memcpy ( ndp->ll_addr, netdev->ll_addr, 6 );
//		assert ( ndp->ll_protocol->ll_addr_len == 6 );
//		icmp6_test_nadvert ( netdev, dest, ndp->ll_addr );
//		assert ( ndp->state == NDP_STATE_REACHABLE );
		/* Take it out till here */
		return -ENOENT;
	}
	DBG ( "Neighbour cache miss: IP6 %s\n", inet6_ntoa ( *dest ) );

	/* Add entry in the neighbour cache */
	add_ndp_entry ( netdev, dest, NULL, NDP_STATE_INCOMPLETE );

	/* Send neighbour solicitation */
	if ( ( rc = icmp6_send_solicit ( netdev, src, dest ) ) != 0 ) {
		return rc;
	}
	return -ENOENT;
}

/**
 * Send router solicitation packet
 *
 * @v netdev	Network device
 * @v src	Source address
 * @v dest	Destination address
 *
 * This function prepares a neighbour solicitation packet and sends it to the
 * network layer.
 */
int ndp_send_rsolicit ( struct net_device *netdev, struct job_interface *job ) {
	union {
		struct sockaddr_in6 sin6;
		struct sockaddr_tcpip st;
	} st_dest;
	struct router_solicit *solicit;
	struct io_buffer *iobuf = alloc_iob ( sizeof ( *solicit ) + MIN_IOB_LEN );
	struct pending_rsolicit *entry;
	int rc = 0;
	
	iob_reserve ( iobuf, MAX_HDR_LEN );
	solicit = iob_put ( iobuf, sizeof ( *solicit ) );

	/* Fill up the headers */
	memset ( solicit, 0, sizeof ( *solicit ) );
	solicit->type = ICMP6_ROUTER_SOLICIT;
	solicit->code = 0;
	
	/* Partial checksum */
	solicit->csum = 0;
	solicit->csum = tcpip_chksum ( solicit, sizeof ( *solicit ) );

	/* Solicited multicast address - FF02::2 (all routers on local network) */
	memset(&st_dest.sin6, 0, sizeof(st_dest.sin6));
	st_dest.sin6.sin_family = AF_INET6;
	st_dest.sin6.sin6_addr.in6_u.u6_addr8[0] = 0xff;
	st_dest.sin6.sin6_addr.in6_u.u6_addr8[1] = 0x2;
	st_dest.sin6.sin6_addr.in6_u.u6_addr8[15] = 0x2;
	
	/* Add an entry for this solicitation. */
	entry = add_solicit_entry ( netdev, RSOLICIT_STATE_ALMOST );
	
	/* Set up a job for the solicit. */
	job_init ( &entry->job, &rsolicit_job_operations, &entry->refcnt );

	/* Send packet over IP6 */
	rc = ipv6_tx ( iobuf, &icmp6_protocol, NULL, &st_dest.st,
		       netdev, &solicit->csum );
	
	/* Return. */
	if ( rc == 0 ) {
		entry->state = RSOLICIT_STATE_PENDING;
		
		job_plug_plug ( &entry->job, job );
		ref_put ( &entry->refcnt );
		return 0;
	} else {
		entry->state = RSOLICIT_STATE_INVALID;
		
		rsolicit_job_kill ( &entry->job );
		ref_put ( &entry->refcnt );
		return rc;
	}
}

/**
 * Process Router Advertisement
 *
 * @v iobuf I/O buffer containing the data.
 * @v st_src Address of the source station.
 * @v st_dest Address of the destination station. Typically FF02::1.
 */
int ndp_process_radvert ( struct io_buffer *iobuf, struct sockaddr_tcpip *st_src,
			  struct sockaddr_tcpip *st_dest __unused, struct net_device *netdev,
			  struct icmp6_net_protocol *net_protocol __unused ) {
	struct router_advert *radvert = iobuf->data;
	struct ndp_option *options = iobuf->data + sizeof(struct router_advert);
	struct in6_addr router_addr = ( ( struct sockaddr_in6 * ) st_src )->sin6_addr;
	struct in6_addr host_addr;
	int rc = -ENOENT;
	uint8_t prefix_len = 0;
	size_t offset = sizeof ( struct router_advert ), ll_size;
	
	/* Verify that there's a pending solicit */
	struct pending_rsolicit *pending = solicit_find_entry ( netdev );
	if ( ! pending ) {
		DBG ( "ndp: unsolicited router advertisement, ignoring\n" );
		return rc;
	}

	memset ( &host_addr, 0, sizeof ( host_addr ) );

	/* Router advertisement flags */
	if ( ntohs ( radvert->hops_flags ) & RADVERT_MANAGED ) {
		DBG ( "ndp: router advertisement suggests DHCPv6\n" );
		pending->code |= RSOLICIT_CODE_MANAGED;
	}
	if ( ntohs ( radvert->hops_flags ) & RADVERT_OTHERCONF ) {
		DBG ( "ndp: router advertisement suggests DHCPv6 for additional information\n" );
		pending->code |= RSOLICIT_CODE_OTHERCONF;
	}

	/* Parse options. */
	while ( offset < iob_len( iobuf ) ) {

		switch ( options->type ) {
		case NDP_OPTION_PREFIX_INFO:
			{
			struct prefix_option *opt = (struct prefix_option *) options;

			prefix_len = opt->prefix_len;

			if ( prefix_len % 8 ) {
				/* Copy one extra prefix byte. */
				prefix_len += 8;
			}

			if ( prefix_len > 64 ) {
				/* > 64-bit prefix shouldn't happen. */
				DBG ( "ndp: prefix length is quite long, connectivity may suffer.\n" );
			}

			/* Copy the prefix first and then add the EUI-64 */
			memcpy( &host_addr.s6_addr, opt->prefix, prefix_len / 8 );

			/* Create an IPv6 address for this station based on the prefix. */
			ll_size = netdev->ll_protocol->ll_addr_len;
			if ( ll_size < 6 ) {
				memcpy ( host_addr.s6_addr + (8 - ll_size), netdev->ll_addr, ll_size );
			} else {
				ipv6_generate_eui64 ( host_addr.s6_addr + 8, netdev->ll_addr );
			}

			rc = 0;
			}
			break;

		case NDP_OPTION_SOURCE_LL:
			{
			struct ll_option *opt = (struct ll_option *) options;

			/* Add entry in the neighbour cache for the router */
			if ( ! ndp_find_entry ( &router_addr ) ) {
				add_ndp_entry ( netdev, &router_addr, opt->address, NDP_STATE_REACHABLE );
			}

			}
			break;
		}

		offset += options->length * 8;
		options = (struct ndp_option *) (iobuf->data + offset);
	}

	if ( rc ) {
		DBG ( "ndp: couldn't generate a prefix from a router advertisement\n" );
		pending->code = RSOLICIT_CODE_NONE; /* Clear flags. */
		
		job_done ( &pending->job, -ENOENT );
		
		return 0;
	}

	/* Configure a route based on this router if none exists. */
	if ( net_protocol->check ( netdev, &host_addr ) ) {
		DBG ( "ndp: autoconfigured %s/%d via a router advertisement\n", inet6_ntoa( host_addr ), prefix_len);

		add_ipv6_address ( netdev, host_addr, prefix_len, host_addr, router_addr );
		
		job_done ( &pending->job, pending->code );
		
		pending->state = RSOLICIT_STATE_INVALID;
	}

	return 0;
}

/**
 * Process neighbour advertisement
 *
 * @v iobuf	I/O buffer
 * @v st_src	Source address
 * @v st_dest	Destination address
 */
int ndp_process_nadvert ( struct io_buffer *iobuf, struct sockaddr_tcpip *st_src __unused,
			   struct sockaddr_tcpip *st_dest __unused,
			   struct icmp6_net_protocol *net_protocol __unused ) {
	struct neighbour_advert *nadvert = iobuf->data;
	struct ll_option *ll_opt = iobuf->data + sizeof ( *nadvert );
	struct ndp_entry *ndp;

	/* Sanity check */
	if ( iob_len ( iobuf ) < sizeof ( *nadvert ) ) {
		DBG ( "Packet too short (%zd bytes)\n", iob_len ( iobuf ) );
		return -EINVAL;
	}

	/* FIXME: assumes link-layer option is first. */

	assert ( nadvert->code == 0 );
	assert ( nadvert->flags & ICMP6_FLAGS_SOLICITED );
	assert ( ll_opt->type == 2 );

	/* Update the neighbour cache, if entry is present */
	ndp = ndp_find_entry ( &nadvert->target );
	if ( ndp ) {

	assert ( ll_opt->length ==
			( ( 2 + ndp->ll_protocol->ll_addr_len ) / 8 ) );

		if ( IP6_EQUAL ( ndp->in6, nadvert->target ) ) {
			memcpy ( ndp->ll_addr, ll_opt->address,
				 ndp->ll_protocol->ll_addr_len );
			ndp->state = NDP_STATE_REACHABLE;
			return 0;
		}
	}
	DBG ( "Unsolicited advertisement (dropping packet)\n" );
	return 0;
}

/**
 * Process neighbour solicitation
 *
 * @v iobuf	I/O buffer
 * @v st_src	Source address
 * @v st_dest	Destination address
 * @v netdev	Network device the packet was received on.
 */
int ndp_process_nsolicit ( struct io_buffer *iobuf __unused, struct sockaddr_tcpip *st_src,
			   struct sockaddr_tcpip *st_dest __unused, struct net_device *netdev,
			   struct icmp6_net_protocol *net_protocol ) {
	struct neighbour_solicit *nsolicit = iobuf->data;
	struct in6_addr *src =  &( ( struct sockaddr_in6 * ) st_src )->sin6_addr;

	/* Does this match any addresses on the interface? */
	if ( ! net_protocol->check ( netdev, &nsolicit->target ) ) {
		/* Send an advertisement to the host. */
		DBG ( "ndp: neighbour solicit received for us\n" );
		return icmp6_send_advert ( netdev, &nsolicit->target, src );
	} else {
		DBG ( "ndp: neighbour solicit received but it's not for us\n" );
	}

	return 0;
}

