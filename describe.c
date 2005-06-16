/*
 * ---------------------------------------------------------------------------
 *
 * Snif: a packet sniffer and analyzer
 * Copyright (C) 2005 Benjamin Gaillard & Yannick Schuffenecker
 *
 * ---------------------------------------------------------------------------
 *
 *        File: describe.c
 *
 * Description: Packet Descripting Functions
 *
 * ---------------------------------------------------------------------------
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * ---------------------------------------------------------------------------
 */


/*****************************************************************************
 *
 * Headers
 *
 */

/* Standard C library */
#include <string.h>
#include <time.h>

/* UNIX */
#include <sys/time.h>

/* Network */
#include <netinet/in.h>

/* Current module */
#include "main.h"
#include "pkthdr.h"
#include "describe.h"


/*****************************************************************************
 *
 * Private Functions Prototypes
 *
 */

/* Packet description functions */
static void describe_ethernet(char *const buffer,
			      const struct packet_ethernet *const packet);
static void describe_ip(char *const buffer,
			const struct packet_ip *const packet);
static void describe_ip_proto(char *const buffer,
			      const struct packet_udp *const packet,
			      const unsigned char proto);


/*****************************************************************************
 *
 * Public functions
 *
 */

/*
 * Describe a packet.
 */
const char *describe_packet(struct packet *const packet)
{
    /* Local variables */
    unsigned    pos;
    struct tm  *tm;
    static char buffer[1024];

    /* Analyze packet based on its type */
    switch (packet->type) {
    case PT_RAW:
	describe_ip(buffer + 6, (struct packet_ip *) packet->data);
	break;

    case PT_ETHERNET:
	describe_ethernet(buffer + 6,
			  (struct packet_ethernet *) packet->data);
	break;

    case PT_LINUX:
	describe_ip(buffer + 6, (struct packet_ip *) (packet->data + 16));
	break;

    default:
	buffer[5] = '\0';
    }

    /* Add time */
    tm = localtime(&packet->time.tv_sec);
    pos = strftime(buffer, 11, "[%H:%M:%S]", tm);
    buffer[10] = ' ';

    return buffer;
}


/*****************************************************************************
 *
 * Private Functions
 *
 */

/*
 * Describe an Ethernet packet.
 */
static void describe_ethernet(char *const buffer,
			      const struct packet_ethernet *const packet)
{
    strcpy(buffer, " --> Ethernet");

    /* Call the right function for the nested protocol */
    switch (ntohs(packet->type)) {
    case EP_IP:
	describe_ip(buffer + 13, (const struct packet_ip *) (packet + 1));
	break;

    case EP_ARP:
	strcpy(buffer + 13, " --> ARP");
	break;

    case EP_RARP:
	strcpy(buffer + 13, " --> RARP");
	break;
    }
}

/*
 * Describe an IP packet.
 */
static void describe_ip(char *const buffer,
			const struct packet_ip *const packet)
{
    /* Local variables */
    const struct packet_ipv4 *const pipv4 =
	(const struct packet_ipv4 *) packet;
    const struct packet_ipv6 *const pipv6 =
	(const struct packet_ipv6 *) packet;

    switch (packet->ver) {
    case 4:
	/* IPv4 */
	strcpy(buffer, " --> IPv4");
	describe_ip_proto(buffer + 9, (const struct packet_udp *) (pipv4 + 1),
			  pipv4->proto);
	break;

    case 6:
	/* IPv6 */
	strcpy(buffer, " --> IPv6");
	describe_ip_proto(buffer + 9, (const struct packet_udp *) (pipv6 + 1),
			  pipv6->proto);
	break;
    }
}

/*
 * Describe an IP protocol packet.
 */
static void describe_ip_proto(char *const buffer,
			      const struct packet_udp *const packet,
			      const unsigned char proto)
{
    /* Local variables */
    const struct packet_ipv6 *const pipv6 =
	(const struct packet_ipv6 *) packet;
    unsigned short                  sport, dport;

    switch (proto) {
    case IPP_ICMP:
	strcpy(buffer, " --> ICMP");
	break;

    case IPP_TCP:
	strcpy(buffer, " --> TCP");
	break;

    case IPP_UDP:
	strcpy(buffer, " --> UDP");

	sport = ntohs(packet->sport);
	dport = ntohs(packet->dport);

	/* Describe a DHCP packet if it is one */
	if ((dport == 67 && sport == 68) || (dport == 68 && sport == 67)) {
	    strcpy(buffer + 8, " --> BOOTP");

	    /* Determine if it is a DHCP packet */
	    if ((unsigned) ntohs(packet->length) - 8
		> sizeof(struct packet_bootp) + 4) {
		/* Variables */
		const unsigned char *data = (const unsigned char *)
		    (((const struct packet_bootp *) (packet + 1)) + 1);

		/* Recognize magic cookie */
		if (data[0] == 0x63 && data[1] == 0x82 &&
		    data[2] == 0x53 && data[3] == 0x63)
		    strcpy(buffer + 18, " --> DHCP");
	    }
	}
	break;

    case IPP_6TO4:
	strcpy(buffer, " --> IPv6");
	describe_ip_proto(buffer + 9, (const struct packet_udp *) (pipv6 + 1),
			  pipv6->proto);
	break;

    case IPP_IGMP:
	strcpy(buffer, " --> IGMP");
	break;

    case IPP_RDP:
	strcpy(buffer, " --> RDP");
	break;

    case IPP_ICMPV6:
	strcpy(buffer, " --> ICMPv6");
    }
}

/* End of file */
