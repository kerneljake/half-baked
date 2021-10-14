/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2021 Jake Angerman
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stdint.h>

#include <net/if.h>
#include <net/bpf.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#define  BPFHDRSIZ (sizeof(struct bpf_hdr))
#define  ETHHDRSIZ (sizeof(struct ether_header))
#define  IPHDRSIZ  (sizeof(struct ip))
#define  TCPHDRSIZ (sizeof(struct tcphdr))

#define NUM_SLOTS 128   /* set this to the pool size of blocked IPs */
#define BASE_RULE 20000 /* set this to the ipfw base rule number */

/* globals */
#ifndef BLOCKED_PORTS
#define BLOCKED_PORTS "80,443"
#endif
uint32_t my_ip; /* address in network byte order */
char *my_ip_str = NULL;
char *progname = NULL;
int verbose = 1;
int debug = 0;
uint32_t seed;

struct fingerprint {
    struct in_addr ip; /* suspect IP address */
    u_short port; /* source port */
    u_short syn_ack_count;
    tcp_seq ack;
    unsigned long timestamp; /* milliseconds */
} evidence[NUM_SLOTS];

/* Jenkins hash */
#define rot(x,k) (((x)<<(k)) | ((x)>>(32-(k))))
#define mix(a,b,c) \
    { \
    a -= c;  a ^= rot(c, 4);  c += b; \
    b -= a;  b ^= rot(a, 6);  a += c; \
    c -= b;  c ^= rot(b, 8);  b += a; \
    a -= c;  a ^= rot(c,16);  c += b; \
    b -= a;  b ^= rot(a,19);  a += c; \
    c -= b;  c ^= rot(b, 4);  b += a; \
    }

#define final(a,b,c) \
    { \
    c ^= b; c -= rot(b,14); \
    a ^= c; a -= rot(c,11); \
    b ^= a; b -= rot(a,25); \
    c ^= b; c -= rot(b,16); \
    a ^= c; a -= rot(c,4);  \
    b ^= a; b -= rot(a,14); \
    c ^= b; c -= rot(b,24); \
    }

uint32_t hashword(const uint32_t *k,               /* the key, an array of uint32_t values */
		  size_t          length,          /* the length of the key, in uint32_ts */
		  uint32_t        initval)         /* the previous hash, or an arbitrary value */
{
    uint32_t a,b,c;

    /* Set up the internal state */
    a = b = c = 0xdeadbeef + (((uint32_t)length)<<2) + initval;

    /*------------------------------------------------- handle most of the key */
    while (length > 3)
	{
	    a += k[0];
	    b += k[1];
	    c += k[2];
	    mix(a,b,c);
	    length -= 3;
	    k += 3;
	}

    /*------------------------------------------- handle the last 3 uint32_t's */
    switch(length)                     /* all the case statements fall through */
	{
	case 3 : c+=k[2];
	case 2 : b+=k[1];
	case 1 : a+=k[0];
	    final(a,b,c);
	case 0:     /* case 0: nothing left to add */
	    break;
	}
    /*------------------------------------------------------ report the result */
    return c;
}

/* block the perp */
void guilty(const int slot) {
    struct fingerprint *ep = &evidence[slot];
    char command[128] = "";
    const float bucket_size = 10; /* max tokens */
    const float ticks = 1000; /* milliseconds */
    static float tokens = bucket_size;
    static unsigned long last_check = 0;

    if (0 == last_check) {
	last_check = ep->timestamp; /* initial setup */
    }
    tokens += (ep->timestamp - last_check) * (bucket_size / ticks);
    last_check = ep->timestamp;
    if (tokens > bucket_size) {
	tokens = bucket_size; /* capped */
    }
    if (tokens < 1.0) {
	ep->ip.s_addr = 0; /* reset slot */
	return;
    } else {
	tokens -= 1.0;
    }

    pid_t pid = fork();
    if (-1 == pid) {
	fprintf(stderr, "fork() failed\n");
    } else if (0 == pid) {
	/* child */
	const int rulenum = BASE_RULE + slot;

	snprintf(command, sizeof(command), "/sbin/ipfw -q delete %d", rulenum);
	(void) system(command); /* ignore if rule not present */

	snprintf(command, sizeof(command), "/sbin/ipfw -q add %d deny tcp from %s to any dst-port %s // %lu",
		 rulenum, inet_ntoa(ep->ip), BLOCKED_PORTS, ep->timestamp);
	if (verbose) {
	    printf("%s\n", command);
	}
	if (system(command) == 127) {
	    fprintf(stderr, "system() failed: %s\n", command);
	}
	exit(0);
    }
    ep->ip.s_addr = 0; /* reset slot */
}

/* parse packet */
void parse_packet(const struct bpf_hdr *bp) {
    const struct ether_header *ethernet_h;
    const struct ip *ip_h;
    const char *p = (const char *) bp; /* first byte */
    const int len = bp->bh_hdrlen + bp->bh_caplen;

    ethernet_h = (struct ether_header *)(p + bp->bh_hdrlen);
    const int eth_type = ntohs(ethernet_h->ether_type);

    if (ETHERTYPE_IP == eth_type) {

	if (len >= (bp->bh_hdrlen + ETHHDRSIZ + IPHDRSIZ)) {
	    /* skip over ethernet header to get IP header */
	    ip_h = (struct ip *)(p + bp->bh_hdrlen + ETHHDRSIZ);

	    /* printf("Source address: %s, Destination address: %s, Protocol: %d\n",
	       inet_ntoa(ip_h->ip_src), inet_ntoa(ip_h->ip_dst),  ip_h->ip_p);
	    */

	    if (IPPROTO_TCP == ip_h->ip_p) {
		const struct tcphdr *tcph;

		if (len >= (bp->bh_hdrlen + ETHHDRSIZ + IPHDRSIZ + TCPHDRSIZ)) {
		    tcph = (struct tcphdr *)(p + bp->bh_hdrlen + ETHHDRSIZ + IPHDRSIZ);
		    /* printf("Source port: %d, Destination port: %d\n", ntohs(tcph->th_sport), ntohs(tcph->th_dport)); */

		    if (TH_SYN & tcph->th_flags && TH_ACK & tcph->th_flags) {
			/* SYN-ACK */
			if (ip_h->ip_src.s_addr == my_ip) {
			    const uint32_t suspect_ip = ip_h->ip_dst.s_addr; /* avoid compiler warning for packed struct */
			    const uint32_t slot = hashword(&suspect_ip, 1, seed) % NUM_SLOTS;
			    struct fingerprint *ep = &evidence[slot];

			    if (debug) {
				printf("SYN-ACK %u from port %d to %s hash slot = %d\n",
				       ntohl(tcph->th_ack), ntohs(tcph->th_sport), inet_ntoa(ip_h->ip_dst), slot);
			    }

			    long bpf_timestamp = bp->bh_tstamp.tv_sec*1000 + bp->bh_tstamp.tv_usec/1000; /*millis*/
			    if (suspect_ip != ep->ip.s_addr) {
				/* new suspect, recycle the slot */
				ep->syn_ack_count = 1;
				ep->ip = ip_h->ip_dst;
				ep->port = ntohs(tcph->th_dport);
				ep->ack = ntohl(tcph->th_ack);
				ep->timestamp = bpf_timestamp;
			    } else if (ntohl(tcph->th_ack) == ep->ack) {
				ep->syn_ack_count++;
				if (ep->syn_ack_count > 2 && (bpf_timestamp - ep->timestamp < 10000)) {
				    /* guilty: ignored my SYN-ACK */
				    if (verbose) {
					printf("!!! GUILTY %s ignored my ACK %u\n", inet_ntoa(ip_h->ip_dst), ntohl(tcph->th_ack));
				    }
				    guilty(slot);
				}
			    }
			}
		    } else if (TH_RST & tcph->th_flags) {
			/* RST */
			if (ip_h->ip_dst.s_addr == my_ip) {
			    const uint32_t suspect_ip = ip_h->ip_src.s_addr; /* avoid compiler warning for packed struct */
			    const uint32_t slot = hashword(&suspect_ip, 1, seed) % NUM_SLOTS;
			    struct fingerprint *ep = &evidence[slot];

			    if (debug) {
				printf("RST %u to port %d from %s hash slot = %d\n",
				       ntohl(tcph->th_seq), ntohs(tcph->th_dport), inet_ntoa(ip_h->ip_src), slot);
			    }

			    long bpf_timestamp = bp->bh_tstamp.tv_sec*1000 + bp->bh_tstamp.tv_usec/1000; /*millis*/
			    if (suspect_ip == ep->ip.s_addr && ntohl(tcph->th_seq) == ep->ack &&
				ntohs(tcph->th_sport) == ep->port && (bpf_timestamp - ep->timestamp < 1000)) {
				/* guilty: RST received in reply to my SYN-ACK */
				if (verbose) {
				    printf("!!! GUILTY %s replied RST to my ACK %u\n", inet_ntoa(ip_h->ip_src), ntohl(tcph->th_seq));
				}
				guilty(slot);
			    }
			}
		    }
		} else {
		    fprintf(stderr, "the TCP packet is too short\n");
		}
	    }
	} else {
	    fprintf(stderr, "the IP packet is too short\n");
	}
    }
}

/* get IP address of the interface */
char * get_myip(const char *ifname) {
    struct ifaddrs *ifaddrs, *ifa;
    char *str = NULL;

    if (getifaddrs(&ifaddrs) == -1) {
	fprintf(stderr, "getifaddrs() failed, cannot get ip address for %s\n", ifname);
	return(NULL);
    }

    for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
	if (strcmp(ifname, ifa->ifa_name) == 0) {
	    int family = ifa->ifa_addr->sa_family;
	    if (AF_INET == family) {
		if ( (str = inet_ntoa(((struct sockaddr_in *)(ifa->ifa_addr))->sin_addr)) != NULL) {
		    my_ip = ((struct sockaddr_in *)(ifa->ifa_addr))->sin_addr.s_addr; /* side effect */
		    break;
		} else {
		    fprintf(stderr, "inet_ntop() failed.\n");
		}
	    }
	}
    }
    freeifaddrs(ifaddrs);
    if (str) {
	return(strdup(str)); /* caller must free() */
    } else {
	return(NULL);
    }
}

/* open /dev/bpf and return a file descriptor */
int get_bpf(const char *ifname) {
    int bpf = -1;
    char devname[11] = "";
    int i;

    /* find next available bpf device */
    for (i = 0; i < 99; i++) {
	sprintf(devname, "/dev/bpf%i", i);
	if ((bpf = open(devname, O_RDONLY)) != -1) {
	    break;
	}
    }
    if (-1 == bpf) {
	fprintf(stderr, "couldn't open /dev/bpf, are you root?\n");
	return(-1);
    }

    /* bind the bpf to the interface */
    struct ifreq ifrq;
    bzero(&ifrq, sizeof(ifrq));
    strncpy(ifrq.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(bpf, BIOCSETIF, &ifrq) < 0) {
	fprintf(stderr, "BIOCSETIF ioctl failed on ifname %s\n", ifname);
	return(-1);
    }

    /* force the interface into promiscuous mode */
    if(ioctl(bpf, BIOCPROMISC) < 0) {
	fprintf(stderr, "BIOCPROMISC ioctl failed");
	return(-1);
    }

    int num = 1; /* turn on immediate reading */
    if(ioctl(bpf, BIOCIMMEDIATE, &num) < 0) {
	fprintf(stderr, "BIOCIMMEDIATE ioctl failed\n");
	return(-1);
    }

    if ((my_ip_str = get_myip(ifname)) != NULL) {
	printf("%s listening on %s IP address %s\n", progname, ifname, my_ip_str);
    } else {
	fprintf(stderr, "get_myip() failed\n");
	return(-1);
    }

    return bpf;
}

void usage(void) {
    printf("USAGE: %s [OPTIONS] ifname\n"
	   " -q\tquiet\n"
	   " -v\tverbose (default)\n"
	   " -d\tdebug (implies -v)\n"
	   " ifname interface name like eth0\n", progname);
}

int main (int argc, char **argv) {
    int option;

    /* setup */
    setlinebuf(stdout);
    setlinebuf(stderr);
    signal(SIGCHLD, SIG_IGN);
    seed = arc4random();
    
    /* parse options */
    progname = argv[0];
    while ((option = getopt(argc, argv, "dvqh")) != -1) {
	switch (option) {
	case 'd':
	    debug = 1;
	case 'v':
	    break;
	case 'q':
	    verbose = 0;
	    break;
	case 'h':
	default:
	    usage();
	    exit(0);
	}
    }
    argc -= optind;
    argv += optind;

    if (NULL == *argv) {
	usage(); /* no ifname specified */
	exit(1);
    }
     /* open bpf file descriptor */
    int bpf;
    if ((bpf = get_bpf(*argv)) < 0) {
	return(1);
    }

    /* get required buffer length for bpf */
    int buflen = 0;
    if(ioctl(bpf, BIOCGBLEN, &buflen) < 0) {
	fprintf(stderr, "BIOCGBLEN ioctl failed\n");
	return(1);
    }
    char *fbuff = (char *) malloc(buflen);
    bzero(fbuff, buflen);

    int read_bytes = 0;
    while ((read_bytes = read(bpf, fbuff, buflen)) > 0) {
	char *ptr = fbuff;
	/* the kernel could deliver multiple packets in the buffer, in theory */
	while (ptr < fbuff + read_bytes) {
	    struct bpf_hdr *bpf_packet = (struct bpf_hdr *) ptr;
	    parse_packet(bpf_packet);
	    ptr += BPF_WORDALIGN(bpf_packet->bh_hdrlen + bpf_packet->bh_caplen);
	}
    }

    return(0); /* never reached */
}
