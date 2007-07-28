/*
 * sll_sniff: llstat/tfilter demo for linux 2.6.
 *
 * This demo requires the kernel patch sll_af_packet-2.6.patch
 *
 * The patch provides the PF_PACKET socket with two new socket options, yet outdates
 * the sockopt PACKET_MACSTAT previously used by lindump. 
 * A new version of lindump compliant with this patch will be released soon.
 *
 * socket options: PACKET_LLSTAT and PACKET_TFILTER.
  
 * PACKET_LLSTAT  if set, replaces the struct sockaddr_ll with sockaddr_stat_ll.
                  sockaddr_stat_ll provides the user-space with alternate 
                  information userful for building high-performance userspace sniffers.
                  It is possible to get timestamp, ip_id and tos without actually
                  reading the whole packet headers and calling ioctl(SIOCGSTAMP).  
  
 * PACKET_TFILTER allow to attach a filter to the socket on the basis of pkt_type. 
                  Packets that match the filter are not sent to the socket. 
                  Userspace applications take advantage of it under certain circumstances 
                  saving the CPU workload. 
                  (ie: an application that sends and receives frames with a 
                  couple of PF_PACKET socket, can filter PACKET_HOST from a socket,
                  PACKET_OUTGOING from the other and filter PACKET_BROADCAST from both)
  
 * Copyright (c) 2007 Nicola Bonelli <bonelli@antifork.org>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. 2.
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <netpacket/packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <arpa/inet.h>

#include <stdio.h>
#include <err.h>

#define PACKET_LLSTAT    10 
#define PACKET_TFILTER   11 

#define TFILTER(x)              (1<<(x))
#define TFILTER_HOST            TFILTER(PACKET_HOST)
#define TFILTER_BROADCAST       TFILTER(PACKET_BROADCAST)
#define TFILTER_MULTICAST       TFILTER(PACKET_MULTICAST)
#define TFILTER_OTHERHOST       TFILTER(PACKET_OTHERHOST)
#define TFILTER_OUTGOING        TFILTER(PACKET_OUTGOING )
#define TFILTER_LOOPBACK        TFILTER(PACKET_LOOPBACK )
#define TFILTER_FASTROUTE       TFILTER(PACKET_FASTROUTE)

struct sockaddr_stat_ll {
        unsigned short sll_family;   /* Always AF_PACKET */
        unsigned short sll_protocol; /* Physical layer protocol */
        int            sll_ifindex;  /* Interface number */
        unsigned short sll_ipid;     /* ip_id field */
        unsigned char  sll_pkttype;  /* Packet type */
        unsigned char  sll_halen;    /* packet halen */
        struct timeval sll_tstamp;   /* Timestamp */
} __attribute__((packed));


char frame_t[] = {
        '<',                    /* incoming */
        'B',                    /* broadcast */
        'M',                    /* multicast */
        'O',                    /* promisc */
        '>',                    /* outgoing */
        'L',                    /* loopback */
        'F',                    /* fastroute */
};


int 
main (int argc, char *argv[])
{
        char buffer[16];
        int n,s;

        /* open a PF_PACKET socket */
        s = socket(PF_PACKET, SOCK_RAW,  htons(ETH_P_ALL) );
        if (s == -1)
                err(1,"can't open socket");

        /* set llstat */
        int val = 1;
        if ((setsockopt(s, SOL_PACKET, PACKET_LLSTAT, (char *) &val, sizeof(int))) == -1)
                err(2,"kernel lacks PACKET_LLSTAT sockopt");

        /* ie: drop outgoing and loopback packets */
        // int filter = TFILTER_OUTGOING|TFILTER_LOOPBACK;
        int filter = TFILTER_LOOPBACK;
        if ((setsockopt(s, SOL_PACKET, PACKET_TFILTER, (char *) &filter, sizeof(int))) == -1)
                err(3,"kernel lacks PACKET_TFILTER sockopt");

        struct sockaddr_stat_ll l;
        socklen_t len = sizeof(struct sockaddr_stat_ll);

        /* start reading from the socket */
        for(;;) {
                if ( (n=recvfrom(s, buffer, 16, MSG_TRUNC, (struct sockaddr *)&l, &len )) == -1 )
                        continue;

                printf("%c[%d]: %lu:%lu len:%d proto:%d ipid:%d\n", 
                                frame_t[l.sll_pkttype], l.sll_ifindex,
                                l.sll_tstamp.tv_sec, l.sll_tstamp.tv_usec,
                                n, l.sll_protocol, ntohs(l.sll_ipid));
        }

        return 0;
}
