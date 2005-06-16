/*
 * ---------------------------------------------------------------------------
 *
 * Snif: a packet sniffer and analyzer
 * Copyright (C) 2005 Benjamin Gaillard & Yannick Schuffenecker
 *
 * ---------------------------------------------------------------------------
 *
 *        File: pkthdr.h
 *
 * Description: Packet Header Structures Definition
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


#ifndef PKTHDR_H
#define PKTHDR_H

/* Headers */

#include <arpa/nameser_compat.h>


/* Constants and macros */

/* Packed structure */
#ifdef __GNUC__
# define PACKED __attribute__((__packed__))
#else /* __GNUC__ */
# define PACKED
#endif /* !__GNUC__ */

/* Ethernet protocols */
#define EP_IP   2048
#define EP_ARP  2054
#define EP_RARP 32821

/* IP procols */
#define IPP_ICMP   1
#define IPP_IGMP   2
#define IPP_TCP    6
#define IPP_UDP    17
#define IPP_RDP    37
#define IPP_6TO4   41
#define IPP_ICMPV6 58


/* Data types */

/* Ethernet header */
PACKED struct packet_ethernet {
    unsigned char  dst[6]; /* Destination host address */
    unsigned char  src[6]; /* Source host address      */
    unsigned short type;   /* Ethernet type            */
};

/* IP header */
PACKED struct packet_ip {
#if BYTE_ORDER == LITTLE_ENDIAN
    unsigned _0:  4; /* Unused  */
    unsigned ver: 4; /* Version */
#else
    unsigned ver: 4; /* Version */
    unsigned _0:  4; /* Unused  */
#endif
};

/* IPv4 header */
PACKED struct packet_ipv4 {
#if BYTE_ORDER == LITTLE_ENDIAN
    unsigned       hlen: 4; /* Header length         */
    unsigned       ver:  4; /* Version               */
#else
    unsigned       ver:  4; /* Version               */
    unsigned       hlen: 4; /* Header length         */
#endif
    unsigned char  tos;     /* Type of service       */
    unsigned short length;  /* Total length          */
    unsigned short id;      /* Identification        */
    unsigned short offset;  /* Fragment offset field */
    unsigned char  ttl;     /* Time to live          */
    unsigned char  proto;   /* Protocol              */
    unsigned short sum;     /* Checksum              */
    unsigned char  src[4];  /* Source address        */
    unsigned char  dst[4];  /* Destination address   */
};

/* IPv6 header */
PACKED struct packet_ipv6 {
#if BYTE_ORDER == LITTLE_ENDIAN
    unsigned       flow: 10; /* Flow label            */
    unsigned       tc:   8;  /* Traffic class         */
    unsigned       ver:  4;  /* Version               */
#else
    unsigned       ver:  4;  /* Version               */
    unsigned       tc:   8;  /* Traffic class         */
    unsigned       flow: 10; /* Flow label            */
#endif
    unsigned short length;   /* Payload length        */
    unsigned char  proto;    /* Encapsulated protocol */
    unsigned char  hlim;     /* Hop limit             */
    unsigned short src[8];   /* Source address        */
    unsigned short dst[8];   /* Destination address   */
};

/* TCP header */
PACKED struct packet_tcp {
    unsigned short sport;  /* Source port            */
    unsigned short dport;  /* Destination port       */
    unsigned long  seq;    /* Sequence number        */
    unsigned long  ack;    /* Acknowledgement number */
#if BYTE_ORDER == LITTLE_ENDIAN
    unsigned       _0:  4; /* (Unused)               */
    unsigned       off: 4; /* Data offset            */
#else
    unsigned       off: 4; /* Data offset            */
    unsigned       _0:  4; /* (Unused)               */
#endif
    unsigned char  flags;  /* Flags                  */
    unsigned short win;    /* Window                 */
    unsigned short sum;    /* Checksum               */
    unsigned short urp;    /* Urgent pointer         */
};

/* UDP header */
PACKED struct packet_udp {
    unsigned short sport;    /* Source port      */
    unsigned short dport;    /* Destination port */
    unsigned short length;   /* Length           */
    unsigned short checksum; /* Checksum         */
};

/* ICMP */
PACKED struct packet_icmp {
    unsigned char  type;     /* Type            */
    unsigned char  code;     /* Code            */
    unsigned short checksum; /* Checksum        */
    unsigned short id;       /* Identifier      */
    unsigned short seq;      /* Sequence number */
};

/* ARP */
PACKED struct packet_arp {
    unsigned short htype;  /* Hardware type           */
    unsigned short ptype;  /* Protocol type           */
    unsigned char  hlen;   /* Hardware address length */
    unsigned char  plen;   /* Protocol address length */
    unsigned short opr;    /* Operation               */
    unsigned char  sha[6]; /* Sender hardware address */
    unsigned char  spa[4]; /* Sender protocol address */
    unsigned char  tha[6]; /* Target hardware address */
    unsigned char  tpa[4]; /* Target protocol address */
};

/* BOOTP/DHCP */
PACKED struct packet_bootp {
    unsigned char  op;         /* Operation code                      */
    unsigned char  ht;         /* Hardware address type               */
    unsigned char  hl;         /* Hardware address length             */
    unsigned char  hops;       /* Hops                                */
    unsigned long  xid;        /* Transaction ID                      */
    unsigned short secs;       /* Seconds passed                      */
    unsigned short flags;      /* Flags                               */
    unsigned char  ciaddr[4];  /* Client IP address                   */
    unsigned char  yiaddr[4];  /* Client IP address (server response) */
    unsigned char  siaddr[4];  /* Server ip address                   */
    unsigned char  giaddr[4];  /* Relay agent IP address              */
    unsigned char  chaddr[16]; /* Client hardware address             */
    char           sname[64];  /* Optional server host name (ASCIIZ)  */
    char           file[128];  /* Boot file name                      */
};

#endif /* !PKTHDR_H */
