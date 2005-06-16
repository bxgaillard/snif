/*
 * ---------------------------------------------------------------------------
 *
 * Snif: a packet sniffer and analyzer
 * Copyright (C) 2005 Benjamin Gaillard & Yannick Schuffenecker
 *
 * ---------------------------------------------------------------------------
 *
 *        File: analyze.c
 *
 * Description: Packet Analysis Functions
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Network */
#include <netinet/in.h>

/* GTK+ */
#include <gtk/gtk.h>

/* Current module */
#include "main.h"
#include "pkthdr.h"
#include "analyze.h"


/*****************************************************************************
 *
 * Constants and Macros
 *
 */

/* Separation in packet description */
#define SEPARATION "________________________________________" \
		   "________________________________________\n\n"


/*****************************************************************************
 *
 * Private Variables
 *
 */

/* Text buffer and iterator */
static GtkTextBuffer *txt_buff;
static GtkTextIter    txt_iter;

/* Temporary buffer for packet analysis functions */
static char buffer[1024];


/*****************************************************************************
 *
 * Private Functions Prototypes
 *
 */

/* Utility functions */
static void append_text(const char *const text);
static void dump_data(const unsigned char *const data,
		      const unsigned size, const unsigned width);

/* Protocol name */
static const char *get_ethernet_proto(const unsigned short proto);
static const char *get_ip_proto(const unsigned char proto);

/* Packet analyis functions */
static void analyze_ethernet(const struct packet_ethernet *const packet,
			     const unsigned length);
static void analyze_ip(const struct packet_ip *const packet,
		       const unsigned length);
static void analyze_ipv4(const struct packet_ipv4 *const packet);
static void analyze_ipv6(const struct packet_ipv6 *const packet);
static void analyze_ip_proto(const void *packet, const unsigned char proto,
			     const unsigned length);
static void analyze_icmp(const struct packet_icmp *const packet);
static void analyze_tcp(const struct packet_tcp *const packet,
			const unsigned length);
static void analyze_udp(const struct packet_udp *const packet);
static void analyze_bootp(const struct packet_bootp *const packet,
			  const unsigned length);
static void analyze_dhcp(const unsigned char *const packet,
			 const unsigned length);
static void analyze_arp(const struct packet_arp *const packet);


/*****************************************************************************
 *
 * Public functions
 *
 */

/*
 * Analyze a packet.
 */
void analyze_packet(GtkTextBuffer *const buffer, struct packet *const packet)
{
    /* Local variables */
    GtkTextIter iter_start;

    /* Clear text buffer */
    txt_buff = buffer;
    gtk_text_buffer_get_start_iter(buffer, &iter_start);
    gtk_text_buffer_get_end_iter(buffer, &txt_iter);
    gtk_text_buffer_delete(buffer, &iter_start, &txt_iter);

    /* Analyze packet based on its type */
    switch (packet->type) {
    case PT_RAW:
	analyze_ip((struct packet_ip *) packet->data, packet->size);
	break;

    case PT_ETHERNET:
	analyze_ethernet((struct packet_ethernet *) packet->data,
			 packet->size);
	break;

    case PT_LINUX:
	analyze_ip((struct packet_ip *) (packet->data + 16), packet->size);
	break;

    default:
	break;
    }

    /* Display a dump of the packet */
    append_text("COMPLETE DUMP\n");
    dump_data(packet->data, packet->size, 16);
}


/*****************************************************************************
 *
 * Private Functions
 *
 */

/*
 * Append a text to the text buffer.
 */
static void append_text(const char *const text)
{
    /* Insert text to the end of the buffer */
    gtk_text_buffer_insert(txt_buff, &txt_iter, text, -1);
}

/*
 * Dump a packet (hexadecimal and character representations).
 */
static void dump_data(const unsigned char *const data,
		      const unsigned size, const unsigned width)
{
    /* Local variables */
    char *buffer;

    if (size > 0 && width > 0 &&
	(buffer = (char *) malloc(((size + 15) / 16 + 2) * 94 + 1)) != NULL) {
	/* Variables */
	unsigned      i, j, end, pos = 0;
	unsigned char byte;

	/* Characters for hexadecimal representation */
	static const char hex[16] = {
	    '0', '1', '2', '3', '4', '5', '6', '7',
	    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
	};

	/* Offset line */
	memset(buffer + pos, ' ', 10);
	pos += 10;
	for (i = 0; i < width; i++) {
	    sprintf(buffer + pos, " %2u", i);
	    pos += 3;
	}
	buffer[pos++] = '\n';

	/* Separation line */
	memset(buffer + pos, ' ', 9);
	pos += 9;
	buffer[pos++] = '+';
	end = width * 3;
	memset(buffer + pos, '-', end);
	pos += end;
	buffer[pos++] = '\n';

	for (i = 0; i < size; i += width) {
	    /* Start of line (offset) */
	    sprintf(buffer + pos, "    %4u | ", i);
	    pos += 11;

	    /* End of the current line */
	    end = i + width;
	    if (end > size)
		end = size;

	    /* Hexadecimal bytes */
	    for (j = i; j < end; j++) {
		byte = data[j];
		buffer[pos++] = hex[byte / sizeof(hex)];
		buffer[pos++] = hex[byte % sizeof(hex)];
		buffer[pos++] = ' ';
	    }
	    /* Remaining bytes */
	    while (j++ < i + width) {
		buffer[pos++] = ' ';
		buffer[pos++] = ' ';
		buffer[pos++] = ' ';
	    }

	    /* Separation */
	    buffer[pos++] = ' ';
	    buffer[pos++] = ' ';

	    /* Caracter representation */
	    for (j = i; j < end; j++) {
		byte = data[j];

		/* ASCII */
		if (byte >= 0x20 && byte <= 0x7E)
		    buffer[pos++] = byte;
		else if (byte >= 0xA0) {
		    /* Post-ASCII: UTF-8 conversion */
		    buffer[pos++] = '\xC0' | (byte >> 6);
		    buffer[pos++] = '\x80' | (byte & 0X3F);
		}  else
		    /* Non-displayable characters */
		    buffer[pos++] = '.';
	    }

	    /* End of line */
	    buffer[pos++] = '\n';
	}

	/* End of buffer */
	buffer[pos] = '\0';

	/* Display dump */
	append_text(buffer);
	free(buffer);
    } else if (size == 0)
	append_text("    [No data.]\n");
}

/*
 * Get an Ethernet protocol name.
 */
static const char *get_ethernet_proto(const unsigned short proto)
{
    /* Select the right Ethernet protocol name */
    switch (proto) {
    case EP_IP:
	return " (IP)";

    case EP_ARP:
	return " (ARP)";

    case EP_RARP:
	return " (RARP)";

    default:
	return "";
    }
}

/*
 * Get an IP protocol name.
 */
static const char *get_ip_proto(const unsigned char proto)
{
    /* Select the right IP protocol name */
    switch (proto) {
    case IPP_ICMP:
	return " (ICMP)";

    case IPP_IGMP:
	return " (IGMP)";

    case IPP_TCP:
	return " (TCP)";

    case IPP_UDP:
	return " (UDP)";

    case IPP_RDP:
	return " (RDP)";

    case IPP_6TO4:
	return " (6to4)";

    case IPP_ICMPV6:
	return " (ICMPv6)";

    default:
	return "";
    }
}

/*
 * Analyse an Ethernet packet.
 */
static void analyze_ethernet(const struct packet_ethernet *const packet,
			     const unsigned length)
{
    /* Local variables */
    const unsigned short type = ntohs(packet->type);

    /* Display informations */
    sprintf(buffer, "ETHERNET\n"
	    "    Source MAC address:      %02X:%02X:%02X:%02X:%02X:%02X\n"
	    "    Destination MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n"
	    "    Type:                    %u%s\n"
	    SEPARATION,
	    packet->src[0], packet->src[1], packet->src[2], packet->src[3],
	    packet->src[4], packet->src[5],
	    packet->dst[0], packet->dst[1], packet->dst[2], packet->dst[3],
	    packet->dst[4], packet->dst[5],
	    type, get_ethernet_proto(type));
    append_text(buffer);

    /* Call the right function for the nested protocol */
    switch (type) {
    case EP_IP:
	analyze_ip((const struct packet_ip *) (packet + 1),
		   length - sizeof(struct packet_ethernet));
	break;

    case EP_ARP:
	analyze_arp((const struct packet_arp *) (packet + 1));
	break;

    default:
	append_text("DATA DUMP\n");
	dump_data((const unsigned char *) (packet + 1),
		  length - sizeof(struct packet_ethernet), 16);
	append_text(SEPARATION);
    }
}

/*
 * Analyze an IP packet.
 */
static void analyze_ip(const struct packet_ip *const packet,
		       const unsigned length)
{
    /* Call the right function accordingly to the IP version */
    switch (packet->ver) {
    case 4:
	/* IPv4 */
	analyze_ipv4((const struct packet_ipv4 *) packet);
	break;

    case 6:
	/* IPv6 */
	analyze_ipv6((const struct packet_ipv6 *) packet);
	break;

    default:
	/* Unknown IP version */
	sprintf(buffer,
		"IP (UNHANDLED VERSION)\n    Version: %u\n" SEPARATION
		"DATA DUMP\n", packet->ver);
	append_text(buffer);
	dump_data((const unsigned char *) packet, length, 16);
	append_text(SEPARATION);
    }
}

/*
 * Analyze an IPv4 packet.
 */
static void analyze_ipv4(const struct packet_ipv4 *const packet)
{
    /* Local variables */
    const unsigned short flags = ntohs(packet->offset) >> 13;
    char                 flags_str[32];

    /* Make flag representation string */
    if (flags & 1) {
	strcpy(flags_str, "more fragments");
	if (flags & 2)
	    strcpy(flags_str + 14, ", don't fragment");
    } else if (flags & 2)
	strcpy(flags_str, "don't fragment");
    else
	strcpy(flags_str, "none");

    /* Display informations */
    sprintf(buffer, "IP VERSION 4 (IPv4)\n"
	    "    Source address:      %u.%u.%u.%u\n"
	    "    Destination address: %u.%u.%u.%u\n"
	    "    Protocol:            %u%s\n"
	    "    Header length:       %u bytes\n"
	    "    Total length:        %u bytes\n"
	    "    Identification:      %u\n"
	    "    Type of service:     %u\n"
	    "    Flags:               %s\n"
	    "    Fragment offset:     %u\n"
	    "    Time to live (TTL):  %u hops\n"
	    "    Header checksum:     %04X\n"
	    SEPARATION,
	    packet->src[0], packet->src[1], packet->src[2], packet->src[3],
	    packet->dst[0], packet->dst[1], packet->dst[2], packet->dst[3],
	    packet->proto, get_ip_proto(packet->proto), packet->hlen * 4,
	    ntohs(packet->length), ntohs(packet->id), packet->tos, flags_str,
	    ntohs(packet->offset), packet->ttl, ntohs(packet->sum));
    append_text(buffer);

    /* Nested protocol */
    analyze_ip_proto(packet + 1, packet->proto,
		     ntohs(packet->length) - packet->hlen * 4);
}

/*
 * Analyze an IPv6 packet.
 */
static void analyze_ipv6(const struct packet_ipv6 *const packet)
{
    /* Display informations */
    sprintf(buffer, "IP VERSION 6 (IPv6)\n"
	    "    Source address:      %x:%x:%x:%x:%x:%x:%x:%x\n"
	    "    Destination address: %x:%x:%x:%x:%x:%x:%x:%x\n"
	    "    Protocol:            %u%s\n"
	    "    Payload length:      %u bytes\n"
	    "    Traffic class:       %u\n"
	    "    Flow label:          %u\n"
	    "    Hop limit:           %u hops\n"
	    SEPARATION,
	    ntohs(packet->src[0]), ntohs(packet->src[1]),
	    ntohs(packet->src[2]), ntohs(packet->src[3]),
	    ntohs(packet->src[4]), ntohs(packet->src[5]),
	    ntohs(packet->src[6]), ntohs(packet->src[7]),
	    ntohs(packet->dst[0]), ntohs(packet->dst[1]),
	    ntohs(packet->dst[2]), ntohs(packet->dst[3]),
	    ntohs(packet->dst[4]), ntohs(packet->dst[5]),
	    ntohs(packet->dst[6]), ntohs(packet->dst[7]),
	    packet->proto, get_ip_proto(packet->proto), ntohs(packet->length),
	    packet->tc, packet->flow, packet->hlim);
    append_text(buffer);

    /* Nested protocol */
    analyze_ip_proto(packet + 1, packet->proto, ntohs(packet->length));
}

/*
 * Analyze an IP protocol packet.
 */
static void analyze_ip_proto(const void *packet, const unsigned char proto,
			     const unsigned length)
{
    /* Call the right function for a given IP protocol */
    switch (proto) {
    case IPP_ICMP:
	analyze_icmp((const struct packet_icmp *) packet);
	break;

    case IPP_TCP:
	analyze_tcp((const struct packet_tcp *) packet, length);
	break;

    case IPP_UDP:
	analyze_udp((const struct packet_udp *) packet);
	break;

    case IPP_6TO4:
	analyze_ipv6((const struct packet_ipv6 *) packet);
	break;

    default:
	append_text("DATA DUMP\n");
	dump_data((const unsigned char *) packet, length, 16);
	append_text(SEPARATION);
    }
}

/*
 * Analyze an ICMP packet.
 */
static void analyze_icmp(const struct packet_icmp *const packet)
{
    /* Local variables */
    const char *type, *code;

    /* Get type and code description */
    switch (packet->type) {
    case 0:
	type = " (Echo Reply)";
	code = "";
	break;

    case 3:
	type = " (Destination Unreachable)";
	switch (packet->code) {
	case 0:
	    code = " (Net Unreachable)";
	    break;

	case 1:
	    code = " (Host Unreachable)";
	    break;

	case 2:
	    code = " (Protocol Unreachable)";
	    break;

	case 3:
	    code = " (Port Unreachable)";
	    break;

	case 4:
	    code = " (Fragmentation Needed and Don't Fragment was Set)";
	    break;

	case 5:
	    code = " (Source Route Failed)";
	    break;

	case 6:
	    code = " (Destination Network Unknown)";
	    break;

	case 7:
	    code = " (Destination Host Unknown)";
	    break;

	case 8:
	    code = " (Source Host Isolated)";
	    break;

	case 9:
	    code = " (Communication with Destination Network is\n"
		   "                        Administratively Prohibited)";
	    break;

	case 10:
	    code = " (Communication with Destination Host is\n"
		   "                        Administratively Prohibited)";
	    break;

	case 11:
	    code = " (Destination Network Unreachable for Type of Service)";
	    break;

	case 12:
	    code = " (Destination Host Unreachable for Type of Service)";
	    break;

	case 13:
	    code = " (Communication Administratively Prohibited)";
	    break;

	case 14:
	    code = " (Host Precedence Violation)";
	    break;

	case 15:
	    code = " (Precedence cutoff in effect)";
	    break;

	default:
	    code = "";
	}
	break;

    case 4:
	type = " (Source Quench)";
	code = "";
	break;

    case 5:
	type = " (Redirect)";
	switch (packet->code) {
	case 0:
	    code = " (Redirect Datagram for the Network (or subnet))";
	    break;

	case 1:
	    code = " (Redirect Datagram for the Host)";
	    break;

	case 2:
	    code = " (Redirect Datagram for the Type of Service and Network)";
	    break;

	case 3:
	    code = " (Redirect Datagram for the Type of Service and Host)";
	    break;

	default:
	    code = "";
	}
	break;

    case 6:
	type = " (Alternate Host Address)";
	code = "";
	break;

    case 8:
	type = " (Echo)";
	code = "";
	break;

    case 9:
	type = " (Router Advertisement)";
	switch (packet->code) {
	case 0:
	    code = " (Normal router advertisement)";
	    break;

	case 16:
	    code = " (Does not route common traffic)";
	    break;

	default:
	    code = "";
	}
	break;

    case 10:
	type = " (Router Solicitation)";
	code = "";
	break;

    case 11:
	type = " (Time Exceeded)";
	switch (packet->code) {
	case 0:
	    code = " (Time to Live exceeded in Transit)";
	    break;

	case 1:
	    code = " (Fragment Reassembly Time Exceeded)";
	    break;

	default:
	    code = "";
	    break;
	}
	break;

    case 12:
	type = " (Parameter Problem)";
	switch (packet->code) {
	case 0:
	    code = " (Pointer indicates the error)";
	    break;

	case 1:
	    code = " (Missing a Required Option)";
	    break;

	case 2:
	    code = " (Bad Length)";
	    break;

	default:
	    code = "";
	    break;
	}
	break;

    case 13:
	type = " (Timestamp)";
	code = "";
	break;

    case 14:
	type = " (Timestamp Reply)";
	code = "";
	break;

    case 15:
	type = " (Information Request)";
	code = "";
	break;

    case 16:
	type = " (Information Reply)";
	code = "";
	break;

    case 17:
	type = " (Address Mask Request)";
	code = "";
	break;

    case 18:
	type = " (Address Mask Reply)";
	code = "";
	break;

    case 30:
	type = " (Traceroute)";
	code = "";
	break;

    case 31:
	type = " (Datagram Conversion Error)";
	code = "";
	break;

    case 32:
	type = " (Mobile Host Redirect)";
	code = "";
	break;

    case 33:
	type = " (IPv6 Where-Are-You)";
	code = "";
	break;

    case 34:
	type = " (IPv6 I-Am-Here)";
	code = "";
	break;

    case 35:
	type = " (Mobile Registration Request)";
	code = "";
	break;

    case 36:
	type = " (Mobile Registration Reply)";
	code = "";
	break;

    case 37:
	type = " (Domain Name Request)";
	code = "";
	break;

    case 38:
	type = " (Domain Name Reply)";
	code = "";
	break;

    case 39:
	type = " (SKIP)";
	code = "";
	break;

    case 40:
	type = " (Photuris)";
	switch (packet->code) {
	case 0:
	    code = " (Bad SPI)";
	    break;

	case 1:
	    code = " (Authentication Failed)";
	    break;

	case 2:
	    code = " (Decompression Failed)";
	    break;

	case 3:
	    code = " (Decryption Failed)";
	    break;

	case 4:
	    code = " (Need Authentication)";
	    break;

	case 5:
	    code = " (Need Authorization)";
	    break;

	default:
	    code = "";
	}
	break;

    default:
	type = "";
	code = "";
    }

    /* Display informations */
    sprintf(buffer, "ICMP\n"
	    "    Type:            %u%s\n"
	    "    Code:            %u%s\n"
	    "    Identifier:      %u\n"
	    "    Sequence number: %u\n"
	    "    Checksum:        %04X\n"
	    SEPARATION,
	    packet->type, type, packet->code, code,
	    ntohs(packet->id), ntohs(packet->seq), ntohs(packet->checksum));
    append_text(buffer);
}

/*
 * Analyze a TCP packet.
 */
static void analyze_tcp(const struct packet_tcp *const packet,
			const unsigned length)
{
    /* Local variables */
    const unsigned char flags = packet->flags;
    int                 i, pos;
    char                flags_str[6 * 5 + 1];

    /* Flags strings */
    static const char flags_strs[6][6] = {
	"FIN, ", "SYN, ", "RST, ", "PSH, ", "ACK, ", "URG, "
    };

    /* Make a string representing set flags */
    if ((flags & 0x3F) != 0) {
	pos = 0;
	for (i = 0; i < 6; i++)
	    if ((flags >> i) & 1) {
		strcpy(flags_str + pos, flags_strs[i]);
		pos += 5;
	    }
	flags_str[pos - 2] = '\0';
    } else
	flags_str[0] = '\0';

    /* Display informations */
    sprintf(buffer, "TCP\n"
	    "    Source port:                 %u\n"
	    "    Destination port:            %u\n"
	    "    Sequence number:             %u\n"
	    "    Acknowledgment number:       %u\n"
	    "    Data offset (header length): %u bytes\n"
	    "    Flags:                       %s\n"
	    "    Window:                      %u\n"
	    "    Checksum:                    %04X\n"
	    "    Urgent pointer:              %u\n"
	    SEPARATION "DATA DUMP\n",
	    ntohs(packet->sport), ntohs(packet->dport),
	    (unsigned) ntohl(packet->seq), (unsigned) ntohl(packet->ack),
	    packet->off * 4, flags_str, ntohs(packet->win),
	    ntohs(packet->sum), ntohs(packet->urp));
    append_text(buffer);
    dump_data((const unsigned char *) packet + packet->off * 4,
	      length - packet->off * 4, 16);
    append_text(SEPARATION);
}

/*
 * Analyze an UDP packet.
 */
static void analyze_udp(const struct packet_udp *const packet)
{
    /* Local variables */
    const unsigned short sport = ntohs(packet->sport);
    const unsigned short dport = ntohs(packet->dport);

    /* Display informations */
    sprintf(buffer, "UDP\n"
	    "    Source port:      %u\n"
	    "    Destination port: %u\n"
	    "    Total length:     %u bytes\n"
	    "    Checksum:         %04X\n"
	    SEPARATION,
	    sport, dport, ntohs(packet->length), ntohs(packet->checksum));
    append_text(buffer);

    if ((dport == 67 && sport == 68) || (dport == 68 && sport == 67))
	/* This is a BOOTP/DHCP packet */
	analyze_bootp((const struct packet_bootp *) (packet + 1),
		      ntohs(packet->length) - 8);
    else {
	/* Display data */
	append_text("DATA DUMP\n");
	dump_data((const unsigned char *) (packet + 1),
		  ntohs(packet->length) - 8, 16);
	append_text(SEPARATION);
    }
}

/*
 * Analyze a BOOTP/DHCP packet.
 */
static void analyze_bootp(const struct packet_bootp *const packet,
			  const unsigned length)
{
    /* Local variables */
    const char *opr;

    /* Select operation name */
    switch (packet->op) {
    case 1:
	opr = " (Request)";
	break;

    case 2:
	opr = " (Reply)";
	break;

    default:
	opr = "";
    }

    /* Display informations */
    sprintf(buffer, "BOOTP\n"
	    "    Operation:                    %u%s\n"
	    "    Transaction:                  %u\n"
	    "    Hardware address type:        %u%s\n"
	    "    Hardware address length:      %u\n"
	    "    Hops:                         %u\n"
	    "    Seconds passed:               %u\n"
	    "    Flags:                        %04X\n",
	    packet->op, opr, (unsigned) ntohl(packet->xid), packet->ht,
	    packet->ht == 1 ? " (Ethernet)" : "", packet->hl,
	    packet->hops, ntohs(packet->secs), ntohs(packet->flags));
    append_text(buffer);
    sprintf(buffer,
	    "    Client IP address:            %u.%u.%u.%u\n"
	    "    Attributed client IP address: %u.%u.%u.%u\n"
	    "    Server IP address:            %u.%u.%u.%u\n"
	    "    Relay agent IP address:       %u.%u.%u.%u\n"
	    "    Client hardware address:      "
	    "%02X:%02X:%02X:%02X:%02X:%02X\n"
	    "    Server name:                  %64s\n"
	    SEPARATION,
	    packet->ciaddr[0], packet->ciaddr[1], packet->ciaddr[2],
	    packet->ciaddr[3],
	    packet->yiaddr[0], packet->yiaddr[1], packet->yiaddr[2],
	    packet->yiaddr[3],
	    packet->siaddr[0], packet->siaddr[1], packet->siaddr[2],
	    packet->siaddr[3],
	    packet->giaddr[0], packet->giaddr[1], packet->giaddr[2],
	    packet->giaddr[3],
	    packet->chaddr[0], packet->chaddr[1], packet->chaddr[2],
	    packet->chaddr[3], packet->chaddr[4], packet->chaddr[5],
	    packet->sname);
    append_text(buffer);

    /* Determine if it is a DHCP packet */
    if (length > sizeof(struct packet_bootp) + 4) {
	/* Variables */
	const unsigned char *data = (const unsigned char *) (packet + 1);

	/* Recognize magic cookie */
	if (data[0] == 0x63 && data[1] == 0x82 &&
	    data[2] == 0x53 && data[3] == 0x63)
	    analyze_dhcp(data + 4, length - 4);
    }
}

/*
 * Analyze a DHCP packet.
 */
static void analyze_dhcp(const unsigned char *const packet,
			 const unsigned length)
{
    /* Local variables */
    unsigned             pos = 0, len, i;
    const unsigned char *op;

    /* Message Types */
    static const char *msgs[9] = {
	"",
	" (DHCP Discover)",
	" (DHCP Offer)",
	" (DHCP Request)",
	" (DHCP Decline)",
	" (DHCP Ack)",
	" (DHCP Nack)",
	" (DHCP Release)",
	" (DHCP Inform)"
    };

    /* Header */
    append_text("DHCP\n");

    while (pos < length) {
	/* Current option properties */
	op = packet + pos + 2;
	if ((len = packet[pos + 1]) == 0)
	    break;

	switch (packet[pos]) {
	case 1:
	    /* Netmask */
	    sprintf(buffer, "    Subnet mask:        %u.%u.%u.%u\n",
		    op[0], op[1], op[2], op[3]);
	    append_text(buffer);
	    break;

	case 3:
	    /* Routers */
	    for (i = 0; i < len; i += 4) {
		sprintf(buffer, "    Router:             %u.%u.%u.%u\n",
			op[i + 0], op[i + 1], op[i + 2], op[i + 3]);
		append_text(buffer);
	    }
	    break;

	case 6:
	    /* DNS */
	    for (i = 0; i < len; i += 4) {
		sprintf(buffer, "    Domain Name Server: %u.%u.%u.%u\n",
			op[i + 0], op[i + 1], op[i + 2], op[i + 3]);
		append_text(buffer);
	    }
	    break;

	case 51:
	    /* Lease time */
	    sprintf(buffer, "    Lease time:         %u s\n",
		    *((const unsigned *) op));
	    append_text(buffer);
	    break;

	case 53:
	    /* Message type */
	    sprintf(buffer, "    Message type:       %u%s\n",
		    *op, msgs[(unsigned) (*op <= 8 ? *op : 0)]);
	    append_text(buffer);
	    break;

	case 54:
	    /* Server identifier */
	    sprintf(buffer, "    Server identifier:  %u.%u.%u.%u\n",
		    op[0], op[1], op[2], op[3]);
	    append_text(buffer);
	    break;

	case 255:
	    /* End */
	    append_text("    End of options.\n");
	    break;

	default:
	    /* Unknown code */
	    sprintf(buffer,     "    Unknown code:       %u (length: %u)\n",
		    packet[pos], len);
	    append_text(buffer);
	    break;

	}

	/* Next option */
	if (packet[pos] == 0)
	    pos++;
	else if (packet[pos] == 255)
	    break;
	else
	    pos += 2 + len;
    }

    /* Final separation line */
    append_text(SEPARATION);
}

/*
 * Analyze an ARP packet.
 */
static void analyze_arp(const struct packet_arp *const packet)
{
    /* Local variables */
    const unsigned short htype = ntohs(packet->htype);
    const unsigned short ptype = ntohs(packet->ptype);
    const unsigned short opr = ntohs(packet->opr);

    /* Operations names */
    static const char *oprs[10] = {
	"",
	" (ARP Request)",
	" (ARP Response)",
	" (RARP Request)",
	" (RARP Response)",
	" (Dynamic RARP request)",
	" (Dynamic RARP reply)",
	" (Dynamic RARP error)",
	" (InARP request)",
	" (InARP reply)",
    };

    /* Display informations */
    sprintf(buffer, "ARP\n"
	    "    Hardware type:           %u%s\n"
	    "    Protocol type:           %u%s\n"
	    "    Hardware address length: %u\n"
	    "    Protocol address length: %u\n"
	    "    Operation:               %u%s\n"
	    "    Sender hardware address: %02X:%02X:%02X:%02X:%02X:%02X\n"
	    "    Sender protocol address: %u.%u.%u.%u\n"
	    "    Target hardware address: %02X:%02X:%02X:%02X:%02X:%02X\n"
	    "    Target protocol address: %u.%u.%u.%u\n"
	    SEPARATION,
	    htype, htype == 1 ? " (Ethernet)" : "",
	    ptype, get_ethernet_proto(ptype), packet->hlen, packet->plen,
	    opr, oprs[opr <= 9 ? opr : 0],
	    packet->sha[0], packet->sha[1], packet->sha[2], packet->sha[3],
	    packet->sha[4], packet->sha[5],
	    packet->spa[0], packet->spa[1], packet->spa[2], packet->spa[3],
	    packet->tha[0], packet->tha[1], packet->tha[2], packet->tha[3],
	    packet->tha[4], packet->tha[5],
	    packet->tpa[0], packet->tpa[1], packet->tpa[2], packet->tpa[3]);
    append_text(buffer);
}

/* End of file */
