/******************************************************************************

        Program: dns_flood_detector.h
         Author: Dennis Opacki <dopacki@adotout.com>
           Date: Tue Mar 18 16:46:53 EST 2003
        Purpose: Monitor DNS servers for abusive usage levels
                 and alarm to syslog

    Copyright (C) 2003 Dennis Opacki

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*******************************************************************************/

// definitions
#ifndef ETHER_HDRLEN
#define ETHER_HDRLEN 14
#endif
#define NS_MAXDNAME 1025
#define MAXSYSLOG 192
#define MAXMESSAGE 1200
#define MAXDATALET 64
#define MAXHEAD 300
#define MAX_TIME_LEN 20
#define DEFAULT_PORT 2000
#define DEFAULT_IP "226.1.1.2"
#define HOST_NAME_MAX 254

// evil Solaris hack
#ifdef __sun__
typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
#endif

// prototypes
void handle_IP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
int calculate_averages();
int saddr_stats(int sock, struct sockaddr_in addr, char *hostname);
int scour_bucket(int i);
int find_bucket(struct in_addr *ip_src);
int daemonize(void);
int malloc_fail(char * var, int size);
int microsleep(unsigned int usec);

// data structures
struct my_dns {
        u_int16_t dns_id;           /* query identification number */
        u_int8_t  dns_flags1;       /* first byte of flags */
        u_int8_t  dns_flags2;       /* second byte of flags */
        u_int16_t dns_qdcount;      /* number of question entries */
        u_int16_t dns_ancount;      /* number of answer entries */
        u_int16_t dns_nscount;      /* number of authority entries */
        u_int16_t dns_arcount;      /* number of resource entries */
};
 
struct bucket {
        struct in_addr ip_addr;
        unsigned int tcp_count;
        unsigned int udp_count;
        unsigned int qps;
	int qstats[256];
        time_t first_packet;
        time_t last_packet;
        time_t alarm_set;
};

