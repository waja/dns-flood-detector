/********************************************************************************

	Program: dns_flood_detector.c
	 Author: Dennis Opacki <dopacki@adotout.com>
	   Date: Tue Mar 18 16:46:53 EST 2003 
	Purpose: Monitor DNS servers for abusive usage levels
		 and alarm to syslog

	compile with:
	gcc -o dns_flood_detector -lpcap -lpthread -lm dns_flood_detector.c 
	
	command-line options:
	
	-i ifname	specify interface to listen on (default lets pcap pick)	
	-t n		alarm when more than n queries per second are observed
			(default 40)
	-a n		wait for n seconds before alarming again on same source
			(default 90)
	-w n		calculate statistics every n seconds 
			(default 10)
	-x n		use n buckets 
			(default 50)
	-m n		mark overall query rate every n seconds
			(default disabled)
	-b		run in foreground in "bindsnap" mode
	-d		run in background in "daemon" mode
	-v		detailed information (use twice for more detail)
	-h		usage info

    Copyright (C) 2003  Dennis Opacki

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

    --- new in v1.05 ---
    8/18/2003 - FreeBSD target - Jim Westfall <jwestfall@surrealistic.net> 
    8/18/2003 - Moved to getopt(3) for compatibility <dopacki@adotout.com>
    8/19/2003 - Added OSX/BSDI make targets - <dopacki@adotout.com>
                Added ability to specify inteface - <dopacki@adotout.com>

    --- new in v1.06 ---
    8/20/2003 - Added Solaris9 make target - <dopacki@adotout.com>
    8/26/2003 - Fixed tcp qdcount bug - <dopacki@adotout.com>

    --- new in v1.07 ---
    8/27/2003 - Fixed alarm reset bug - <dopacki@adotout.com>
    8/28/2003 - Added malloc_fail function - <dopacki@adotout.com>
    8/28/2003 - Added mutex thread locking - <dopacki@adotout.com>
    8/30/2003 - Fixed wierd qtype segfault - <jwestfall@surrealistic.net>
					     <dopacki@adotout.com>

    --- new in v1.08 ---
    9/02/2003 - Added -v -v output in daemon mode - <dopacki@adotout.com>

    --- new in v1.09 ---
    10/19/2003 - Added stdout flushing to bindsnap mode - <dopacki@adotout.com>
    10/19/2003 - Changed logging priority to LOG_NOTICE - <dopacki@adotout.com>
    10/19/2003 - Fixed low traffic verbose logging bugs - <dopacki@adotout.com>

    --- new in v1.10 ---
    10/22/2003 - Added 'mark status' option via '-m' - <dopacki@adotout.com>
    10/23/2003 - Code cleanup in verbose syslogging - <dopacki@adotout.com>

********************************************************************************/

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#ifdef __bsdi__
#include <net/if_ethernet.h>
#else
#ifdef __sun__
#include <sys/ethernet.h>
#else
#include <net/ethernet.h>
#endif
#endif
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <signal.h>
#include <syslog.h>
#include "dns_flood_detector.h"

// global variables and their defaults
pthread_mutex_t stats_lock;
struct bucket **bb;
int option_t = 60;
int option_a = 90;
int option_w = 10;
int option_x = 50;
int option_m = 0;
int option_b = 0;
int option_d = 0;
int option_v = 0;
int option_h = 0;
int totals = 0;
char VERSION[] = "1.10";

// this is our statistics thread
void *run_stats () {
	while (1) {

		// check statistical stuff
		pthread_mutex_lock(&stats_lock);
		calculate_averages();
		pthread_mutex_unlock(&stats_lock);

		sleep (option_w);
	}
}

// calculate the running average within each bucket
int calculate_averages() {
	u_int i,j,delta,cursize,newsize,qps;
	char st_time[10];
	time_t now = time(0);
	u_int types[] = {1,2,5,6,12,15,252,0};
	u_char *type;
	u_char *target;
	char *names[] = {"A","NS","CNAME","SOA","PTR","MX","AXFR",""};
	struct tm *raw_time = localtime(&now);
	snprintf(st_time, 9, "%02d:%02d:%02d",raw_time->tm_hour,raw_time->tm_min,raw_time->tm_sec);

	for (i=0; i<option_x; i++) {

		// only process valid buckets
		if ( bb[i]->ip_addr != NULL ) {
			delta = now - bb[i]->first_packet;

			// let's try to avoid a divide-by-zero, shall we?
			if (delta > 1 ) {
	
				// round our average and save it in the bucket
				bb[i]->qps = (int)ceil( (float)((((float)bb[i]->tcp_count) + bb[i]->udp_count) / delta));

				// handle threshold crossing
				if ( bb[i]->qps > option_t ) {

	
					// display detail to either syslog or stdout
					if ( option_b ) {
						if ( ! option_v ) {
							printf("[%s] source [%s] - %d qps\n",st_time,bb[i]->ip_addr,bb[i]->qps);
							fflush(stdout);
						}
						else {
							printf("[%s] source [%s] - %d qps tcp : %d qps udp ",st_time,bb[i]->ip_addr,
								(int)ceil( (float)(bb[i]->tcp_count/delta)),
								(int)ceil( (float)(bb[i]->udp_count/delta))
							);
							if ( option_v >1 ) {
								for (j=0;types[j];j++) {
									if ((int)ceil((float)(bb[i]->qstats[types[j]]/delta))){
										printf("[%d qps %s] ",(int)ceil((float)(bb[i]->qstats[types[j]]/delta)),names[j]);
									}
								}
							}
							printf("\n");
							fflush(stdout);
						}
					}
					else {
						// if running in background, use alarm reset timer
						if ((now-bb[i]->alarm_set)>option_a) {

							// display appropriate level of detail via syslog
							if ( ! option_v ) {
								syslog(LOG_NOTICE,"source [%s] - %d qps\n",bb[i]->ip_addr,bb[i]->qps);
							}
							else if (option_v > 1) {
								target = (char *)malloc(sizeof(char)*MAXSYSLOG);
								newsize = MAXSYSLOG;
								cursize = snprintf(target,newsize,"source [%s] - %d tcp qps : %d udp qps ",bb[i]->ip_addr,
										(int)ceil( (float)(bb[i]->tcp_count/delta)),				
										(int)ceil( (float)(bb[i]->udp_count/delta))
									  );
								newsize-=cursize;
	
								for (j=0;types[j];j++ ) {
									qps = (u_int)ceil((float)(bb[i]->qstats[types[j]]/delta));
									if ( ( qps > 0)  && ( newsize > 1 ) ) {
										cursize = snprintf(target+(MAXSYSLOG-newsize),newsize,"[%d qps %s] ",qps,names[j]);
										newsize-=cursize;
									}
								}
								if (newsize <= 0 ) {
									target[MAXSYSLOG-1]='\0';
								}
								syslog(LOG_NOTICE,"%s",target);
								free(target);
							}
							else {
								syslog(LOG_NOTICE,"source [%s] - %d tcp qps - %d udp qps\n",bb[i]->ip_addr,
									(int)ceil( (float)(bb[i]->tcp_count/delta)),
									(int)ceil( (float)(bb[i]->udp_count/delta))
								);
							}

							// reset alarm
							bb[i]->alarm_set = now;
						}
					}
				}
			}
		}		
	}
	
	// 'mark stats' if required and it is time
	delta = now - bb[totals]->first_packet;
	if ( (option_m > 0)&&(delta > 1)&&(delta >= option_m) ) {
	
		// handle bindsnap mode 
		if (option_b) {
			printf("[%s] totals - %d qps tcp : %d qps udp ",st_time,(int)ceil( (float)(bb[totals]->tcp_count/delta)),(int)ceil( (float)(bb[totals]->udp_count/delta)));
			if (option_v) {
				for (j=0;types[j];j++) {
					qps = (u_int)ceil((float)(bb[totals]->qstats[types[j]]/delta));
					if (qps){
						printf("[%d qps %s] ",qps,names[j]);
					}
				}
			}
			printf("\n");
			fflush(stdout);
		}
		else {
			// agonizing high verbosity code
			if (option_v) {
				target = (char *)malloc(sizeof(char)*MAXSYSLOG);
				newsize = MAXSYSLOG;
				cursize = snprintf(target,newsize,"[totals] - %d tcp qps : %d udp qps ",
						(int)ceil( (float)(bb[totals]->tcp_count/delta)),				
						(int)ceil( (float)(bb[totals]->udp_count/delta))
					  );
				newsize-=cursize;
	
				for (j=0;types[j];j++ ) {
					qps = (u_int)ceil((float)(bb[totals]->qstats[types[j]]/delta));
					if ( ( qps > 0)  && ( newsize > 1 ) ) {
							cursize = snprintf(target+(MAXSYSLOG-newsize),newsize,"[%d qps %s] ",qps,names[j]);
							newsize-=cursize;
					}
				}
				if (newsize <= 0 ) {
					target[MAXSYSLOG-1]='\0';
				}
				syslog(LOG_NOTICE,"%s",target);
				free(target);
			}
			else {
				syslog(LOG_NOTICE,"[totals] - %d tcp qps : %d udp qps\n",
					(int)ceil( (float)(bb[totals]->tcp_count/delta)),
					(int)ceil( (float)(bb[totals]->udp_count/delta))
				);
			}
		}	
		scour_bucket(totals);
	}

	return 1;
}

// purge and initialize all buckets
void init_buckets() {
	u_int i;

	// create bucket brigade (final bucket is for totals)
	pthread_mutex_lock(&stats_lock);
	if ( ( bb = malloc( sizeof(struct bucket *) * (option_x+1)) ) == NULL ) malloc_fail("bb", sizeof(struct bucket *) * (option_x+1));
	for (i=0; i <=option_x; i++ ) {
		if ( ( bb[i] = (struct bucket *)malloc( sizeof(struct bucket) ) ) == NULL) malloc_fail("bb[i]", sizeof(struct bucket) );
		bb[i]->ip_addr=NULL;
		scour_bucket(i);
	}
	pthread_mutex_unlock(&stats_lock);
}

// clean out a bucket while avoiding obvious memory leak
int scour_bucket( int i ) {
	int j;

	if ( bb[i]->ip_addr != NULL ) {
		free ( bb[i]->ip_addr );
	}
	bb[i]->ip_addr=NULL;
	bb[i]->tcp_count=0;
	bb[i]->udp_count=0;
	bb[i]->qps=0;
	bb[i]->first_packet=time(0);
	bb[i]->last_packet=(time_t)0;
	bb[i]->alarm_set=(time_t)0;
	
	for (j=0;j<256;j++) {
		bb[i]->qstats[j]=0;
	}
	return 1;
}

// add a packet to a bucket
int add_to_bucket ( char * ip_src, int ip_proto, int num_queries, u_int8_t qtype) {
	int bucket = 0;

	// get the bucket to put packet in	
	pthread_mutex_lock(&stats_lock);
	bucket = find_bucket(ip_src);

	// set bucket fields
	bb[bucket]->last_packet = time(0);
	if (ip_proto == 6 ) {
		bb[bucket]->tcp_count+=num_queries;
		bb[totals]->tcp_count+=num_queries;
	}
	else {
		bb[bucket]->udp_count+=num_queries;
		bb[totals]->udp_count+=num_queries;
	}

	bb[bucket]->qstats[qtype]+=num_queries;
	bb[totals]->qstats[qtype]+=num_queries;
	pthread_mutex_unlock(&stats_lock);

	return 1;
}

// figure out where to put this packet
int find_bucket(char *ip_src) {
	int i, bucket=0;
	time_t oldest=0;

	// look for an existing bucket for this IP
	for (i=0; i< option_x; i++ ){
		// ip field of bucket is not null and seems to match the ip we are checking
		if ((bb[i]->ip_addr != NULL)&&(strncmp(bb[i]->ip_addr, ip_src, strlen(bb[i]->ip_addr))==0)) {
			return i;
		}
	}

	// look for unused buckets
	for (i=0; i< option_x; i++ ) {

		// found an unused one - clean it, init it, and return it
		if ( bb[i]->ip_addr == NULL ) {
			scour_bucket(i);
			if ( ( bb[i]->ip_addr = (char *)strdup(ip_src) ) == NULL) malloc_fail("bb[i]->ip_addr", strlen(ip_src) );
			return i;
		}

		// find the most stagnant bucket in case we need it
		// avoids another loop through the buckets
		if ( ( bb[i]->last_packet != 0 ) && ((oldest==0)||( bb[i]->last_packet < oldest))) {
			oldest = bb[i]->last_packet;
			bucket = i;			
		}
	}

	// use the most stagnant bucket since all are in use
	// clean it, init it, and return it
	scour_bucket(bucket);
	if ( ( bb[bucket]->ip_addr = (char *)strdup(ip_src) ) == NULL) malloc_fail("bb[bucket]->ip_addr", strlen(ip_src) );

	return bucket;
}

// handle all packets we throw at it 
void handle_IP(u_char *args, const struct pcap_pkthdr* pkthdr,const u_char* packet){
	const struct ip* ip;
	const struct my_dns *dns;
	const struct tcphdr *tcp;
	const struct udphdr *udp;
	u_int length = pkthdr->len;
	u_int caplen = pkthdr->caplen;
	u_int hlen,off,version;
	unsigned char dname[NS_MAXDNAME]="";
	char *ip_src;
	unsigned char *data;
	u_int i,len,dpos;
	u_int8_t qtype,qclass,tlen;

	// skip the ethernet header
	length -= sizeof(struct ether_header); 

	// make sure packet is a valid length
	if (length < sizeof(struct ip)) {
		return;
	}

	// snap off the ip portion
	ip = (struct ip*)(packet + sizeof(struct ether_header));

	// get utility params for sanity checking
	len     = ntohs(ip->ip_len);
	hlen    = ip->ip_hl;
	version = ip->ip_v;

	// let's not do ipv6 just yet
	if(version != 4) {
		return;
	}

	// make sure we have a sane header length
	if(hlen < 5 ) {
		return;
	}

	// do we have the everything we are supposed to?
	if(length < len) {
		return;
	}

	// make sure we are only processing the first fragment
	off = ntohs(ip->ip_off);
	if((off & 0x1fff) == 0 ) {

		// get the source ip as a string (probably more efficient to use decimal)
		ip_src = (char *)inet_ntoa(ip->ip_src);

		// process udp packets
		if ( ip->ip_p == 17 ) {
			udp = (struct udphdr *) ( (char *) packet + sizeof(struct ether_header)+ sizeof (struct ip) );

			// try to make sure it is safe to cast packet into dns structure
			if ( (sizeof(struct my_dns)+sizeof(struct ether_header)+sizeof(struct ip)+sizeof(struct udphdr)) >= caplen ) {
				return;
			}
			else {
				// populate dns header
				dns = (struct my_dns *) ( (char *) packet + sizeof(struct ether_header) + sizeof (struct ip) + sizeof (struct udphdr) );
				data = (char *) packet +sizeof(struct ether_header) + sizeof (struct ip) + sizeof (struct udphdr) + sizeof(struct my_dns);
			}
		}

		// process tcp packets
		else if ( ip->ip_p == 6 ) {
			tcp = (struct tcphdr *) ( (char *) packet + sizeof(struct ether_header)+ sizeof (struct ip) );

			// ignore packets without push flag set
			if (! tcp->th_flags & TH_PUSH) return;
	
			// try to make sure it is safe to cast packet into dns structure
			if ( (sizeof(struct my_dns)+sizeof(struct ether_header)+sizeof(struct ip)+(tcp->th_off * sizeof(u_int32_t))) >= caplen ) {
				return;
			}
			else {
				// populate dns header
				dns = (struct my_dns *) ( (char *) packet + sizeof(struct ether_header)+ sizeof (struct ip) + (tcp->th_off * sizeof(u_int32_t)));
				data = (char *) packet + sizeof(struct ether_header) + sizeof (struct ip) + (tcp->th_off * sizeof(u_int32_t)) + sizeof(struct my_dns);
			}
		}
	
		// hmm.. not tcp, not udp.. move on.
		else {
			return;
		}

		// we only want queries, not responses
		if (  dns->dns_flags1 & 0x80 ) {
			return;
		}

		// ignore seemingly bogus queries with multiple flags set
		if ((ntohs(dns->dns_qdcount)>0)+(ntohs(dns->dns_ancount)>0)+(ntohs(dns->dns_nscount)>0)+(ntohs(dns->dns_arcount)>0)>1 ) {
			return;
		}
		
		// get the domain name and query type
		tlen=dpos=0;
		for (;(*data)&&((void *)data<((void *)packet+caplen-1)); data++) {
			if (!tlen) tlen=*data;
			for (;(tlen&&((void *)data<((void *)packet+caplen-1)));tlen--){
				data++;
				if (dpos<NS_MAXDNAME) dname[dpos++] = *data;
			}
			if (dpos<NS_MAXDNAME) dname[dpos++] = '.';
		}
		dname[dpos]='\0';

		// be careful not to walk past the end of the captured data
		if ( (void *)data < ((void *)packet+caplen-3) ) {
			data+=2;
			qtype = *data;
		}
		else {
			return;
		}

		// add packet to bucket array
		if (ntohs(dns->dns_qdcount)&&qtype) {
			add_to_bucket( ip_src, ip->ip_p, 1, qtype );
		}
	}
	return;
}

// main logic
// some pcap code borrowed from http://www.cet.nau.edu/~mc8/Socket/Tutorials/section1.html
int main(int argc,char **argv){ 
	char *dev = NULL; 
	pthread_t thread;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	struct bpf_program fp;      /* hold compiled program     */
	bpf_u_int32 maskp=0;          /* subnet mask               */
	bpf_u_int32 netp=0;           /* ip                        */
	char *filter = NULL;
	char *dst_addr = NULL;
	char *dst_mask = NULL;
	struct sigaction sa;
	struct in_addr addr;
	u_int f_size;
	char *args = NULL;
	u_int c = 0;

	// loop through command line options and get options
	while(1) {
		int option_index = 0;
		c = getopt(argc, argv,"i:t:a:w:x:m:bdvh");
		
		if (c==-1) break;
		switch(c) {
			case 0:
				break;
			case 'i':
				if (optarg) {
					if ( ( dev = (char *)strdup(optarg) ) == NULL) malloc_fail("dev", strlen(optarg) );
				}
				break;
			case 't':
				if (optarg) {
					if ( abs (atoi(optarg)) > 0) {
						option_t = abs( atoi(optarg));
					}
				}
				break;
			case 'a':
				if (optarg) {
					if ( abs (atoi(optarg)) > 10) {
						option_a = abs( atoi(optarg));
					}
				}
				break;
			case 'w':
				if (optarg) {
					if ( abs (atoi(optarg)) > 1) {
						option_w = abs( atoi(optarg));
					}
				}
				break;
			case 'x':
				if (optarg) {
					if ( abs (atoi(optarg)) > 10) {
						option_x = abs( atoi(optarg));
					}
				}
				break;
			case 'm':
				if (optarg) {
					if ( abs (atoi(optarg)) > 0) {
						option_m = abs( atoi(optarg));
					}
				}
				break;
			case 'b':
				option_b = 1;
				break;
			case 'd':
				option_d = 1;
				break;
			case 'v':
				option_v++;
				break;
			case 'h':
				option_h = 1;
			default:
				break;
		}
	}

	// display usage info if needed
	if (optind<argc) option_h = 1;
	if (option_h) {
		fprintf(stderr,"dns_flood_detector, version %s\n",VERSION);
		fprintf(stderr,"Usage: %s [OPTION]\n\n",argv[0]);
		fprintf(stderr,"-i IFNAME		specify device name to listen on\n");
		fprintf(stderr,"-t N			alarm at >N queries per second\n");
		fprintf(stderr,"-a N			reset alarm after N seconds\n");
		fprintf(stderr,"-w N			calculate stats every N seconds\n");
		fprintf(stderr,"-x N			create N buckets\n");
		fprintf(stderr,"-m N			report overall stats every N seconds\n");
		fprintf(stderr,"-b			run in foreground in bindsnap mode\n");
		fprintf(stderr,"-d			run in background in daemon mode\n");
		fprintf(stderr,"-v			verbose output - use again for more verbosity\n");
		fprintf(stderr,"-h			display this usage information\n");
		exit(1);
	}

	if ( ( ! option_d ) && ( ! option_b ) ) {
		fprintf(stderr,"%s couldn't start\n",argv[0]);
		fprintf(stderr,"You must specify either either -d (daemon) or -b (bindsnap)\n");
		exit(1);
	}
	// set up for daemonized operation unless running in bindsnap mode
	if ( ! option_b ) {
		openlog("dns_flood_detector",LOG_PID|LOG_CONS,LOG_DAEMON);
		syslog(LOG_NOTICE,"dns_flood_detector starting");

		// daemonize unless running in bindsnap mode
		daemonize();

		// set up signal handlers
		sa.sa_handler=exit;
		sa.sa_flags=0;
		if(sigaction(SIGTERM,&sa,NULL)) {
			syslog(LOG_ERR,"Unable to set signal handler: %s.  Exiting.",
			strerror(errno));
		}
	}

	// find a valid device to open
    	if(dev == NULL && ( (dev=pcap_lookupdev(errbuf)) == NULL ) ){
		fprintf(stderr,"unable to bind to valid device\n");
		exit(1);
	}

	// get network address and netmask for device
	pcap_lookupnet(dev,&netp,&maskp,errbuf);

	// set up filter with local network
	addr.s_addr = (unsigned long int)netp;
	if ( ( dst_addr = (char *)malloc( strlen((char *)inet_ntoa(addr))+1) ) == NULL ) malloc_fail("dest_addr", strlen((char *)inet_ntoa(addr))+1 );
	strncpy(dst_addr,(char*)inet_ntoa(addr),strlen((char *)inet_ntoa(addr)));
	dst_addr[strlen((char *)inet_ntoa(addr))]='\0';

	addr.s_addr = (unsigned long int)maskp;
	if ( ( dst_mask = (char *)malloc( strlen((char *)inet_ntoa(addr))+1) ) == NULL ) malloc_fail("dest_mask", strlen((char *)inet_ntoa(addr))+1 );
	strncpy(dst_mask,(char*)inet_ntoa(addr),strlen((char *)inet_ntoa(addr)));
	dst_mask[strlen((char *)inet_ntoa(addr))]='\0';

	f_size = strlen("port 53 and dst net mask   ")+ strlen(dst_mask)+ strlen(dst_addr);
	if ( ( filter = (char *) malloc ( f_size+1) ) == NULL ) malloc_fail( "filter", f_size+1 );
	snprintf( filter, f_size, "port 53 and dst net %s mask %s", dst_addr, dst_mask);

	free (dst_mask);
	free (dst_addr);

	// open device for reading only local traffic
	descr = pcap_open_live(dev,1500,0,1,errbuf);
	if(descr == NULL) { 
		fprintf(stderr,"unable to open device %s\n",dev);
		exit(1);
	}

	// compile filter
	if(pcap_compile(descr,&fp,filter,0,netp) == -1) { 
		exit(1);
	}

	// set filter
        if(pcap_setfilter(descr,&fp) == -1){ 
		exit(1); 
	}

	// initialize buckets and mark overall stats bucket
	init_buckets();
	totals = option_x;

	// create mutex lock
	if (pthread_mutex_init(&stats_lock, NULL) < 0) {
		exit(1);
	}

	// launch watcher thread
	if (pthread_create (&thread, NULL, run_stats, (void *)0)) {
		exit(1);
	}

	// main pcap loop
	pcap_loop(descr,-1,handle_IP,args);

	// done
	closelog();
	return 0;
}

// daemonize the process
int daemonize(void) {
	pid_t pid;
	int fd;   
  
	fd=open("/dev/null",O_RDWR);
	if(fd<0) {
		syslog(LOG_ERR,"Failed to open /dev/null: %s.  Exiting.",strerror(errno));
		exit(1); 
	}
 
	dup2(fd,0);
	dup2(fd,1);
	dup2(fd,2);

	if((pid=fork())<0) {
		syslog(LOG_ERR,"Fork failed: %s.  Exiting.",strerror(errno));
		exit(1);
	} 
	else if (pid!=0) {
		exit(0);
	}
           
	setsid();  
	chdir("/");
	umask(0);
	return 0;  
}

int malloc_fail( char * var, int size ) {
	// print error to stderr if running in bindsnap mode
	if (option_b) {
		fprintf(stderr, "our OS wouldn't let me malloc %d bytes for a new %s. giving up", size, var);
	}
	else {
		syslog(LOG_ERR, "our OS wouldn't let me malloc %d bytes for a new %s. giving up", size, var);
	}
	exit(1);
}
