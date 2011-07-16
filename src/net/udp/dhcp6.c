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
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <byteswap.h>
#include <gpxe/in.h>
#include <gpxe/ip6.h>
#include <gpxe/list.h>
#include <gpxe/udp.h>
#include <gpxe/socket.h>
#include <gpxe/iobuf.h>
#include <gpxe/xfer.h>
#include <gpxe/open.h>
#include <gpxe/job.h>
#include <gpxe/monojob.h>
#include <gpxe/netdevice.h>
#include <gpxe/features.h>
#include <gpxe/retry.h>
#include <gpxe/timer.h>
#include <gpxe/settings.h>
#include <gpxe/ndp.h>
#include <gpxe/dhcp6.h>

/* Get an option encapsulated inside another option. */
#define dhcp6_get_encapsulated_option( iobuf, parent_type ) \
	( ( iobuf )->data + \
	sizeof ( struct parent_type ) - \
	sizeof ( struct dhcp6_opt_hdr ) )

/* Get an option given it's header in an iobuf. */
#define dhcp6_get_option( iobuf ) \
	( ( iobuf )->data )

/** Prototype for the DHCP6 tx function */
struct dhcp6_session;
static int dhcp6_tx ( struct dhcp6_session *dhcp_session );

/** Address for all DHCP servers and relay agents - FF02::1:2 */
static struct sockaddr_in6 dhcp6_peer = {
	.sin_family = AF_INET6,
	.sin_port = htons ( DHCP6S_PORT ),
	.sin6_addr.in6_u.u6_addr32 = { htons ( 0xFF02 ), 0, 0, htonl ( 0x10002 ) }
};

struct dhcp6_session_state;

/** DHCP6 active session */
struct dhcp6_session {
	/** Reference counter */
	struct refcnt refcnt;
	/** Job control interface */
	struct job_interface job;
	/** Data transfer interface */
	struct xfer_interface xfer;

	/** Network device being configured */
	struct net_device *netdev;
	/** Local socket address */
	struct sockaddr_in6 local;
	
	/** Current state of the transaction. */
	struct dhcp6_session_state *state;

	/** Retransmission timer */
	struct retry_timer timer;
	/** Start time of the current state (in ticks) */
	unsigned long start;
	
	/** Our client ID, for response verification. */
	void *client_duid;
	/** Length of the client ID. */
	size_t client_duid_len;
	
	/** Server DUID - for direct copy. */
	void *server_duid;
	/** Length of the DUID. */
	size_t server_duid_len;
	/** IPv6 address we are looking at keeping. */
	struct in6_addr offer;
	
	/** Settings to apply as a result of a DHCPv6 session. */
	struct settings *settings;
	
	/** Information about the router to use for address assignment. */
	struct rsolicit_info router;
};

static struct dhcp6_session_state dhcp6_solicit;
static struct dhcp6_session_state dhcp6_request;
static struct dhcp6_session_state dhcp6_inforeq; // For Information-Request.

/** DHCP6 state, for the state machine. */
struct dhcp6_session_state {
	/** Name for debugging. */
	const char *name;
	/**
	 * Construct transmitted packet
	 *
	 * @v dhcp		DHCP6 session
	 * @v iobuf		I/O buffer for the DHCP6 options & data
	 * @v peer		Destination address
	 */
	int ( * tx ) ( struct dhcp6_session *dhcp,
		       struct io_buffer *iobuf,
		       struct sockaddr_in6 *peer );
	/** Handle received packet
	 *
	 * @v dhcp		DHCP6 session
	 * @v iobuf		I/O buffer for the DHCP6 packet
	 * @v peer		DHCP server address
	 * @v msgtype		DHCP message type
	 * @v server_id		DHCP server ID
	 */
	void ( * rx ) ( struct dhcp6_session *dhcp,
			struct io_buffer *iobuf,
			struct sockaddr_in6 *peer,
			uint8_t msgtype );
	/** Handle timer expiry
	 *
	 * @v dhcp		DHCP6 session
	 */
	void ( * expired ) ( struct dhcp6_session *dhcp );
	/** Transmitted message type */
	uint8_t tx_msgtype;
	/** Apply minimum timeout */
	uint8_t apply_min_timeout;
};

/****************************************************************************
 *
 * Utility Functions
 *
 */

/**
 * Calculate DHCP6 transaction ID for a network device
 *
 * @v netdev		Network device
 * @ret xid		DHCP6 XID
 *
 * Extract the least significant bits of the hardware address for use
 * as the transaction ID.
 */
static uint32_t dhcp6_xid ( struct net_device *netdev ) {
	uint32_t xid;

	memcpy ( &xid, ( netdev->ll_addr + netdev->ll_protocol->ll_addr_len
			 - sizeof ( xid ) ), sizeof ( xid ) );
	return xid;
}

/**
 * Free DHCP6 session
 *
 * @v refcnt		Reference counter
 */
static void dhcp6_free ( struct refcnt *refcnt ) {
	struct dhcp6_session *dhcp =
		container_of ( refcnt, struct dhcp6_session, refcnt );

	netdev_put ( dhcp->netdev );
	free ( dhcp );
}

/**
 * Mark DHCP6 session as complete
 *
 * @v dhcp		DHCP6 session
 * @v rc		Return status code
 */
static void dhcp6_finished ( struct dhcp6_session *dhcp, int rc ) {
	/* Clean up. */
	if ( dhcp->server_duid != NULL )
		free ( dhcp->server_duid );
	
	/* Block futher incoming messages */
	job_nullify ( &dhcp->job );
	xfer_nullify ( &dhcp->xfer );

	/* Stop retry timer */
	stop_timer ( &dhcp->timer );

	/* Free resources and close interfaces */
	xfer_close ( &dhcp->xfer, rc );
	job_done ( &dhcp->job, rc );
}

/**
 * Handle DHCP6 retry timer expiry
 *
 * @v timer		DHCP retry timer
 * @v fail		Failure indicator
 */
static void dhcp_timer_expired ( struct retry_timer *timer, int fail ) {
	struct dhcp6_session *dhcp =
		container_of ( timer, struct dhcp6_session, timer );

	/* If we have failed, terminate DHCP */
	if ( fail ) {
		dhcp6_finished ( dhcp, -ETIMEDOUT );
		return;
	}

	/* Handle timer expiry based on current state */
	dhcp->state->expired ( dhcp );
}

/**
 * Transition to new DHCP6 session state
 *
 * @v dhcp		DHCP6 session
 * @v state		New session state
 */
static void dhcp6_set_state ( struct dhcp6_session *dhcp,
			     struct dhcp6_session_state *state ) {

	DBGC ( dhcp, "DHCP6 %p entering %s state\n", dhcp, state->name );
	dhcp->state = state;
	dhcp->start = currticks();
	stop_timer ( &dhcp->timer );
	dhcp->timer.min_timeout =
		( state->apply_min_timeout ? DHCP_MIN_TIMEOUT : 0 );
	dhcp->timer.max_timeout = DHCP_MAX_TIMEOUT;
	start_timer_nodelay ( &dhcp->timer );
}

/**
 * Receive new data
 *
 * @v xfer 		Data transfer interface
 * @v iobuf		I/O buffer
 * @v meta		Transfer metadata
 * @ret rc		Return status code
 */
static int dhcp6_deliver_iob ( struct xfer_interface *xfer,
			       struct io_buffer *iobuf,
			       struct xfer_metadata *meta ) {
	struct dhcp6_session *dhcp =
		container_of ( xfer, struct dhcp6_session, xfer );
	struct dhcp6_msg *dhcp_hdr = iobuf->data;
	struct sockaddr_in6 *peer;
	uint8_t msgtype = ntohl ( dhcp_hdr->type_id ) >> 24;
	uint32_t xid = ntohl ( dhcp_hdr->type_id ) & 0xFFFFFF;
	int rc = 0;

	/* Sanity checks */
	if ( ! meta->src ) {
		DBGC ( dhcp, "DHCP %p received packet without source port\n",
		       dhcp );
		rc = -EINVAL;
		goto err_no_src;
	}
	peer = ( struct sockaddr_in6 * ) meta->src;
	
	DBG ( "type: %d, xid: %x\n", msgtype, xid );
	
	/* Check the transaction ID. */
	if ( xid == ( dhcp6_xid ( dhcp->netdev ) & 0xFFFFFF ) ) {
		DBG ( "ipv6: dhcp6 iob arrived in state %s\n", dhcp->state->name );
		
		/* Remove the DHCP6 header from the packet. */
		iob_pull ( iobuf, sizeof ( struct dhcp6_msg ) );
		
		dhcp->state->rx ( dhcp, iobuf, peer, msgtype );
	}

err_no_src:
	free_iob ( iobuf );
	return rc;
}

/**
 * Searches for a given option in a DHCP6 packet.
 *
 * @v iobuf		iobuf to search through (must start with an option
 *			header).
 * @v optcode		Option code of the option to search for.
 * @ret found		1 if found, 0 otherwise.
 */
int dhcp6_find_opt ( struct io_buffer *iobuf, int optcode ) {
	struct dhcp6_opt_hdr *opt = iobuf->data;
	int rc = 0;
	size_t offset = 0;
	
	while ( 1 ) {
		if ( ntohs ( opt->code ) == optcode ) {
			rc = 1;
			break;
		}
		
		offset += sizeof ( *opt ) + ntohs ( opt->len );
		if ( offset > iob_len ( iobuf ) )
			break;
		
		opt = iobuf->data + offset;
		
	}
	
	return rc;
}

/**
 * Handles a specific option from a DHCP6 packet.
 *
 * @v dhcp		DHCP6 session.
 * @v opt		Option to parse.
 * @v iobuf		I/O buffer for extra data.
 * @v completed		1 if we should add addresses and nameservers as a result
 *			of this option, zero if we still have to request an
 *			address.
 * @ret rc		Return status, for error handling if options are invalid
 */
int dhcp6_handle_option ( struct dhcp6_session *dhcp,
			   struct dhcp6_opt_hdr *opt,
			   struct io_buffer *iobuf,
			   int completed ) {
	size_t datalen = ntohs ( opt->len );
	struct settings *parent = netdev_settings ( dhcp->netdev );
	struct dhcp6_opt_iaaddr *addr = dhcp6_get_encapsulated_option( iobuf, dhcp6_opt_ia_na );
	int rc = 0;
	
	/* Verify the option length. */
	if ( datalen > iob_len ( iobuf ) ) {
		DBG ( "dhcp6: option length is larger than the packet size, invalid!\n" );
		rc = -EINVAL;
		goto err;
	}
	
	/* What option is this? */
	switch ( ntohs ( opt->code ) ) {
		case DHCP6_OPT_IA_NA:
		case DHCP6_OPT_IA_TA:
			{
			DBG ( "dhcp6: IA_NA/IA_TA option\n" );
			
			DBG ( "dhcp6: assigned address is %s\n", inet6_ntoa ( addr->addr ) );
			
			if ( completed ) {
				if ( dhcp->router.no_address ) {
					/* Store the completed IPv6 address. */
					store_setting ( parent,
							&ip6_setting,
							&addr->addr,
							sizeof ( struct in6_addr ) );
					store_setting ( parent,
							&gateway6_setting,
							&dhcp->router,
							sizeof ( struct in6_addr ) );
					store_setting ( parent,
							&prefix_setting,
							&dhcp->router.prefix_length,
							sizeof ( dhcp->router.prefix_length ) );
					
					/* Add a fully-routable version now. */
					add_ipv6_address ( dhcp->netdev,
							   dhcp->router.prefix,
							   dhcp->router.prefix_length,
							   addr->addr,
							   dhcp->router.router );
				} else {
					DBG ( "dhcp6: not adding an address as SLAAC has done that\n" );
				}
			} else {
				dhcp->offer = addr->addr;
			}
			}
			break;
		case DHCP6_OPT_DNS_SERVERS:
			{
			/* This ends up being a list of IPv6 addresses. */
			struct in6_addr *addrs __unused = iobuf->data;
			size_t nAddrs = datalen / sizeof ( struct in6_addr );
			
			DBG ( "dhcp6: DNS servers option - %d addresses\n", nAddrs );
			
			/* Verify that there are addresses. */
			if ( ( datalen / sizeof ( struct in6_addr ) ) > 0 ) {
				store_setting ( NULL,
						&dns6_setting,
						iobuf->data,
						sizeof ( struct in6_addr ) );
			}
			}
			break;
		case DHCP6_OPT_DNS_DOMAINS:
			DBG ( "dhcp6: DNS search domains option\n" );
			
			/* TODO: set DNS search domain, needs parsing though. */
			break;
		case DHCP6_OPT_SERVERID:
			/* Verify the DUID if we already store one. */
			if ( dhcp->server_duid != NULL ) {
				if ( memcmp ( dhcp->server_duid,
					      iobuf->data,
					      dhcp->server_duid_len ) ) {
					DBG ( "dhcp6: server DUID is invalid\n" );
					rc = -EINVAL;
				} else {
					DBG ( "dhcp6: server DUID is valid\n" );
				}
			} else {
				/* Grab in the server DUID for this session. */
				dhcp->server_duid = malloc ( datalen );
				dhcp->server_duid_len = datalen;
				memcpy ( dhcp->server_duid, iobuf->data, datalen );
			}
			break;
		case DHCP6_OPT_CLIENTID:
			/* Verify that this client ID option matches our own ID. */
			if ( dhcp->client_duid != NULL ) {
				if ( memcmp ( dhcp->client_duid,
					      iobuf->data,
					      dhcp->client_duid_len ) ) {
					DBG ( "dhcp6: client DUID is invalid\n" );
					rc = -EINVAL;
				} else {
					DBG ( "dhcp6: client DUID is valid\n" );
				}
			} else {
				DBG ( "dhcp6: no client DUID yet, assuming unsolicited DHCP6 packet\n" );
				return -EINVAL;
			}
			break;
		default:
			DBG ( "dhcp6: unhandled option %d\n", ntohs ( opt->code ) );
			break;
	};
	
err:
	return rc;
}

/**
 * Takes options from a DHCP6 packet and configures gPXE and the network
 * face accordingly.
 *
 * @v dhcp		DHCP6 session.
 * @v iobuf		I/O buffer containing options.
 * @ret rc		Status code for return.
 * @v completed		1 if we should add addresses and nameservers as a result
 *			of these options, zero if we still have to request an
 *			address.
 */
int dhcp6_parse_config ( struct dhcp6_session *dhcp,
			 struct io_buffer *iobuf,
			 int completed ) {
	struct dhcp6_opt_hdr *opt = iobuf->data;
	int rc = 0;
	size_t offset = 0, optlen = 0;
	
	while ( 1 ) {
		/* Remove the option header to make getting data easier. */
		optlen = ntohs ( opt->len );
		iob_pull ( iobuf, sizeof ( *opt ) );
		
		/* Handle this option. */
		rc = dhcp6_handle_option ( dhcp, opt, iobuf, completed );
		if ( rc != 0 ) {
			DBG ( "dhcp6: hit an invalid option when parsing options, aborting parse\n" );
			return rc;
		}
		
		/* Grab the next option. */
		offset += optlen;
		if ( offset > iob_len ( iobuf ) )
			break;
		opt = iob_pull ( iobuf, optlen );
	}
	
	return rc;
}

/****************************************************************************
 *
 * DHCP6 Solicitation State
 *
 */

/** DHCP6 solicit state TX handler. */
int dhcp6_solicit_tx ( struct dhcp6_session *dhcp __unused,
		       struct io_buffer *iobuf,
		       struct sockaddr_in6 *peer __unused ) {
	struct dhcp6_opt_ia_na *ia_na;
	struct dhcp6_opt_iaaddr *ia_addr;
	struct dhcp6_opt_hdr *rcommit;
	
	ia_na = iob_put ( iobuf, sizeof ( *ia_na ) );
	ia_addr = iob_put ( iobuf, sizeof ( *ia_addr ) );
	rcommit = iob_put ( iobuf, sizeof ( *rcommit ) );
	
	/* Request rapid commits wherever possible. */
	rcommit->code = htons ( DHCP6_OPT_RCOMMIT );
	rcommit->len = 0;
	
	/* Set up the IA-NA option. */
	ia_na->code = htons ( DHCP6_OPT_IA_NA );
	ia_na->len = htons ( sizeof ( *ia_na ) + sizeof ( *ia_addr ) -
			     sizeof ( struct dhcp6_opt_hdr ) );
	ia_na->iaid = htonl ( 0xdeadbeef );
	ia_na->t1 = htonl ( 3600 ); // 60 minutes before expected renew.
	ia_na->t2 = htonl ( 3600 );
	
	/* Set up the IA_ADDR option. */
	ia_addr->code = htons ( DHCP6_OPT_IAADDR );
	ia_addr->len = htons ( sizeof ( *ia_addr ) -
			       sizeof ( struct dhcp6_opt_hdr ) );
	ia_addr->pref_lifetime = htonl ( 3600 );
	ia_addr->valid_lifetime = htonl ( 3600 );
	ia_addr->addr = dhcp->local.sin6_addr;
	/* memset ( &ia_addr->addr, 0, sizeof ( ia_addr->addr ) ); */
	
	return 0;
}

/** DHCP6 solicit state RX handler. */
void dhcp6_solicit_rx ( struct dhcp6_session *dhcp,
		       struct io_buffer *iobuf,
		       struct sockaddr_in6 *peer __unused,
		       uint8_t msgtype ) {
	if ( msgtype == DHCP6_REPLY ) {
		DBG ( "dhcp6: received a reply during solicit, expecting a rapid commit\n" );
		
		if ( ! dhcp6_find_opt ( iobuf, DHCP6_OPT_RCOMMIT ) ) {
			DBG ( "dhcp6: received a reply that was not a rapid commit!\n" );
		} else {
			/* Completed. */
			dhcp6_finished ( dhcp, dhcp6_parse_config ( dhcp, iobuf, 1 ) );
		}
	} else if ( msgtype == DHCP6_ADVERTISE ) {
		DBG ( "dhcp6: received an advertise during solicit, standard transaction taking place\n" );
		
		/* Grab the server ID and such. */
		if ( dhcp6_parse_config ( dhcp, iobuf, 0 ) != 0 ) {
			DBG ( "dhcp6: not a valid advertisement! retrying!\n" );
		} else {
			/* Move to the REQUEST state. */
			dhcp6_set_state ( dhcp, &dhcp6_request );
		}
	} else {
		DBG ( "dhcp6: got an unknown message during solicit, retrying!\n" );
	}
}

/** DHCP6 solicit state timer expiry handler. */
void dhcp6_solicit_expired ( struct dhcp6_session *dhcp ) {
	dhcp6_tx ( dhcp );
}

/** DHCP6 solicit state operations */
static struct dhcp6_session_state dhcp6_solicit = {
	.name			= "solicit",
	.tx			= dhcp6_solicit_tx,
	.rx			= dhcp6_solicit_rx,
	.expired		= dhcp6_solicit_expired,
	.tx_msgtype		= DHCP6_SOLICIT,
	.apply_min_timeout	= 1,
};

/****************************************************************************
 *
 * DHCP6 Request State
 *
 */

/** DHCP6 request state TX handler. */
int dhcp6_request_tx ( struct dhcp6_session *dhcp,
		       struct io_buffer *iobuf,
		       struct sockaddr_in6 *peer __unused ) {
	struct dhcp6_opt_ia_na *ia_na;
	struct dhcp6_opt_iaaddr *ia_addr;
	struct dhcp6_opt_hdr *serverid;
	void *tmp;
	
	ia_na = iob_put ( iobuf, sizeof ( *ia_na ) );
	ia_addr = iob_put ( iobuf, sizeof ( *ia_addr ) );
	serverid = iob_put ( iobuf, sizeof ( *serverid ) );
	/* Do not add any data after serverid, it is manipulated later. */
	
	/* Set up the IA-NA option. */
	ia_na->code = htons ( DHCP6_OPT_IA_NA );
	ia_na->len = htons ( sizeof ( *ia_na ) + sizeof ( *ia_addr ) -
			     sizeof ( struct dhcp6_opt_hdr ) );
	ia_na->iaid = htonl ( 0xdeadbeef );
	ia_na->t1 = htonl ( 3600 ); // 60 minutes before expected renew.
	ia_na->t2 = htonl ( 3600 );
	
	/* Set up the IA_ADDR option. */
	ia_addr->code = htons ( DHCP6_OPT_IAADDR );
	ia_addr->len = htons ( sizeof ( *ia_addr ) -
			       sizeof ( struct dhcp6_opt_hdr ) );
	ia_addr->pref_lifetime = htonl ( 3600 );
	ia_addr->valid_lifetime = htonl ( 3600 );
	ia_addr->addr = dhcp->offer;
	
	/* Add the server ID. */
	serverid->code = htons ( DHCP6_OPT_SERVERID );
	serverid->len = htons ( dhcp->server_duid_len );
	
	tmp = iob_put ( iobuf, dhcp->server_duid_len );
	memcpy ( tmp, dhcp->server_duid, dhcp->server_duid_len );
	
	return 0;
}

/** DHCP6 request state RX handler. */
void dhcp6_request_rx ( struct dhcp6_session *dhcp,
		       struct io_buffer *iobuf,
		       struct sockaddr_in6 *peer __unused,
		       uint8_t msgtype ) {
	if ( msgtype == DHCP6_REPLY ) {
		DBG ( "dhcp6: received a confirm during request, all done!\n" );
		
		/* Completed. */
		dhcp6_finished ( dhcp, dhcp6_parse_config ( dhcp, iobuf, 1 ) );
	} else {
		DBG ( "dhcp6: got an unknown message during request, retrying!\n" );
	}
}

/** DHCP6 request state timer expiry handler. */
void dhcp6_request_expired ( struct dhcp6_session *dhcp ) {
	dhcp6_tx ( dhcp );
}

/** DHCP6 request state operations */
static struct dhcp6_session_state dhcp6_request = {
	.name			= "request",
	.tx			= dhcp6_request_tx,
	.rx			= dhcp6_request_rx,
	.expired		= dhcp6_request_expired,
	.tx_msgtype		= DHCP6_REQUEST,
	.apply_min_timeout	= 1,
};

/****************************************************************************
 *
 * DHCP6 Information Request State
 *
 */

/** DHCP6 information request state TX handler. */
int dhcp6_info_request_tx ( struct dhcp6_session *dhcp __unused,
		       struct io_buffer *iobuf __unused,
		       struct sockaddr_in6 *peer __unused ) {
	/* Everything else is already provided by dhcp6_tx. */
	return 0;
}

/** DHCP6 information request state RX handler. */
void dhcp6_info_request_rx ( struct dhcp6_session *dhcp,
		       struct io_buffer *iobuf,
		       struct sockaddr_in6 *peer __unused,
		       uint8_t msgtype ) {
	if ( msgtype == DHCP6_REPLY ) {
		DBG ( "dhcp6: received a response during info request, all done!\n" );
		
		/* Completed. */
		dhcp6_finished ( dhcp, dhcp6_parse_config ( dhcp, iobuf, 1 ) );
	} else {
		DBG ( "dhcp6: got an unknown message during info request, retrying!\n" );
	}
}

/** DHCP6 information request state timer expiry handler. */
void dhcp6_info_request_expired ( struct dhcp6_session *dhcp ) {
	dhcp6_tx ( dhcp );
}

/** DHCP6 information request state operations */
static struct dhcp6_session_state dhcp6_inforeq = {
	.name			= "info_request",
	.tx			= dhcp6_info_request_tx,
	.rx			= dhcp6_info_request_rx,
	.expired		= dhcp6_info_request_expired,
	.tx_msgtype		= DHCP6_INFOREQ,
	.apply_min_timeout	= 1,
};

/****************************************************************************
 *
 * Job control interface
 *
 */

/**
 * Handle kill() event received via job control interface
 *
 * @v job		DHCP6 job control interface
 */
static void dhcp6_job_kill ( struct job_interface *job ) {
	struct dhcp6_session *dhcp =
		container_of ( job, struct dhcp6_session, job );

	/* Terminate DHCP session */
	dhcp6_finished ( dhcp, -ECANCELED );
}

/** DHCP job control interface operations */
static struct job_interface_operations dhcp6_job_operations = {
	.done		= ignore_job_done,
	.kill		= dhcp6_job_kill,
	.progress	= ignore_job_progress,
};

/****************************************************************************
 *
 * Public interface
 *
 */

/** DHCP6 data transfer interface operations */
static struct xfer_interface_operations dhcp6_xfer_operations = {
	.close		= ignore_xfer_close,
	.vredirect	= xfer_vreopen,
	.window		= unlimited_xfer_window,
	.alloc_iob	= default_xfer_alloc_iob,
	.deliver_iob	= dhcp6_deliver_iob,
	.deliver_raw	= xfer_deliver_as_iob,
};

/**
 * Start a DHCP6 transaction.
 *
 * @v job		Job control interface
 * @v netdev		Network device
 * @v onlyinfo		Only get information from the DHCPv6 server, not an
 *			actual address.
 * @ret rc		Return status code, or positive if cached
 *
 * On a return of 0, a background job has been started to perform the
 * DHCP6 transaction. Any nonzero return means the job has not been
 * started; a positive return value indicates the success condition of
 * having fetched the appropriate data from cached information.
 */
int start_dhcp6 ( struct job_interface *job, struct net_device *netdev, int onlyinfo ) {
	struct dhcp6_session *dhcp;
	int rc;
	
	dhcp = zalloc ( sizeof ( *dhcp ) );
	if ( ! dhcp )
		return -ENOMEM;
	
	
	/* Get information about routers on this network first. */
	rc = ndp_send_rsolicit ( netdev, &monojob, &dhcp->router );
	if ( rc != 0 )
		DBG ( "dhcp6: can't find a router on the network, continuing\n" );
	else
		monojob_wait ( "" );
	
	ref_init ( &dhcp->refcnt, dhcp6_free );
	job_init ( &dhcp->job, &dhcp6_job_operations, &dhcp->refcnt );
	xfer_init ( &dhcp->xfer, &dhcp6_xfer_operations, &dhcp->refcnt );
	timer_init ( &dhcp->timer, dhcp_timer_expired );
	dhcp->netdev = netdev_get ( netdev );
	dhcp->local.sin_family = AF_INET6;
	dhcp->local.sin_port = htons ( DHCP6C_PORT );
	fetch_ipv6_setting ( netdev_settings ( netdev ), &ip6_setting,
			     &dhcp->local.sin6_addr );

	/* Instantiate child objects and attach to our interfaces */
	rc = xfer_open_socket ( &dhcp->xfer, SOCK_DGRAM,
				( struct sockaddr * ) &dhcp6_peer,
				( struct sockaddr * ) &dhcp->local );

	if ( rc == 0 ) {
		if ( onlyinfo )
			dhcp6_set_state ( dhcp, &dhcp6_inforeq );
		else
			dhcp6_set_state ( dhcp, &dhcp6_solicit );
	} else {
		goto err;
	}

	/* Attach parent interface, mortalise self, and return */
	job_plug_plug ( &dhcp->job, job );
	ref_put ( &dhcp->refcnt );
	return 0;

err:
	dhcp6_free ( &dhcp->refcnt );
	return 0;
}

/****************************************************************************
 *
 * TX work.
 *
 */

/**
 * Transmit a DHCP6 packet.
 */
static int dhcp6_tx ( struct dhcp6_session *dhcp_session ) {
	struct xfer_metadata meta = {
		.netdev = dhcp_session->netdev,
		.src = ( struct sockaddr * ) &dhcp_session->local,
		.dest = ( struct sockaddr * ) &dhcp6_peer,
	};
	
	struct ll_protocol *ll_protocol = dhcp_session->netdev->ll_protocol;
	struct dhcp6_msg *dhcp;
	struct dhcp6_opt_hdr *opt_clientid;
	struct dhcp6_duid_ll *duid;
	struct dhcp6_opt_hdr *oro_hdr;	/* Option requests are the same for all */
	uint16_t *opts_to_req;		/* three DHCPv6 session types. 		*/
	uint8_t *duid_ll_addr = NULL;
	int rc = 0;

	/* Start retry timer.  Do this first so that failures to
	 * transmit will be retried.
	 */
	start_timer ( &dhcp_session->timer );
	
	struct io_buffer *iobuf = xfer_alloc_iob ( &dhcp_session->xfer, DHCP_MIN_LEN );
	if ( ! iobuf )
		return -ENOMEM;
	
	/* Set up the DHCP6 header and a DUID option. This will be common across
	 * all request types, and is fortunately quite simple. */
	iob_reserve ( iobuf, MAX_HDR_LEN );
	dhcp = iob_put ( iobuf, sizeof ( *dhcp ) );
	opt_clientid = iob_put ( iobuf, sizeof ( *opt_clientid ) );
	duid = iob_put ( iobuf, sizeof ( *duid ) );
	duid_ll_addr = iob_put ( iobuf, ll_protocol->ll_addr_len );
	oro_hdr = iob_put ( iobuf, sizeof ( *oro_hdr ) );
	opts_to_req = iob_put ( iobuf, sizeof ( uint16_t ) * 2 );
	
	memcpy ( duid_ll_addr, dhcp_session->netdev->ll_addr, ll_protocol->ll_addr_len );
	
	/* Transaction ID - bottom 8 bits are the message type, the rest is
	 * the transaction ID itself. */
	dhcp->type_id = htonl ( dhcp_session->state->tx_msgtype << 24 );
	dhcp->type_id |= htonl ( dhcp6_xid ( dhcp_session->netdev ) & 0xFFFFFF );
	
	opt_clientid->code = htons ( DHCP6_OPT_CLIENTID );
	opt_clientid->len = htons ( ll_protocol->ll_addr_len + sizeof ( *duid ) );
	
	/* DUID LL */
	duid->code = htons ( DHCP6_DUID_LL );
	duid->hwtype = ll_protocol->ll_proto;
	
	/* Set up the option request section. */
	oro_hdr->code = htons ( DHCP6_OPT_ORO );
	oro_hdr->len = htons ( sizeof ( uint16_t ) * 2 );
	
	/* Set the options we want to request. */
	opts_to_req[0] = htons ( DHCP6_OPT_DNS_SERVERS );
	opts_to_req[1] = htons ( DHCP6_OPT_DNS_DOMAINS );
	
	/* Fill the DUID in the DHCP session state if it isn't already set. */
	if ( dhcp_session->client_duid == NULL ) {
		dhcp_session->client_duid_len = ll_protocol->ll_addr_len + sizeof ( *duid );
		dhcp_session->client_duid = zalloc ( dhcp_session->client_duid_len );
		memcpy ( dhcp_session->client_duid, duid, dhcp_session->client_duid_len );
	}
	
	/* Pass up to the current transaction state to fill options and such. */
	dhcp_session->state->tx ( dhcp_session, iobuf, &dhcp6_peer );
	
	rc = xfer_deliver_iob_meta ( &dhcp_session->xfer, iob_disown ( iobuf ), &meta );
	if ( rc != 0 ) {
		DBGC ( dhcp, "DHCP %p could not transmit UDP packet: %s\n",
		       dhcp, strerror ( rc ) );
		goto done;
	}

done:
	free_iob ( iobuf );
	return rc;
}

