/*
 * ---------------------------------------------------------------------------
 *
 * Snif: a packet sniffer and analyzer
 * Copyright (C) 2005 Benjamin Gaillard & Yannick Schuffenecker
 *
 * ---------------------------------------------------------------------------
 *
 *        File: main.h
 *
 * Description: Main GUI Functions (Header)
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


#ifndef MAIN_H
#define MAIN_H

/* Headers */

#include <sys/time.h>


/* Data types */

enum packet_type { PT_RAW, PT_ETHERNET, PT_LINUX, PT_UNKNOWN };

struct packet {
    struct packet       *next;
    struct timeval       time;
    enum packet_type     type;
    unsigned             size;
    const unsigned char *data;
};


/* Prototypes */

int main(int argc, char *argv[]);

#endif /* MAIN_H */

/* End of file */
