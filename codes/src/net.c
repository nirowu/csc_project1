#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <unistd.h>

#include "net.h"
#include "transport.h"
#include "esp.h"

uint16_t cal_ipv4_cksm(struct iphdr iphdr)
{
    // [TODO]: Finish IP checksum calculation
    iphdr.check = 0;

    uint16_t *addr = (uint16_t *) &iphdr;
    uint32_t cnt = iphdr.ihl * 4;
    unsigned long sum = 0;
    
    while (cnt > 1) {
        sum += *addr++;
        cnt -= 2;
    }
    if (cnt == 1) {
        sum += ((*addr)&htons(0xff00));
    }
    while (sum >> 16) {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    sum = ~sum;
    iphdr.check = (uint16_t)sum;

    return ((uint16_t)sum);
}

uint8_t *dissect_ip(Net *self, uint8_t *pkt, size_t pkt_len)
{
    // [TODO]: Collect information from pkt.
    // Return payload of network layer

    struct iphdr *ip = (struct iphdr *)pkt;
    memcpy(&(self->ip4hdr), ip, sizeof(struct iphdr));
	self->hdrlen = (size_t) ip->ihl * 4;
    self->plen = pkt_len - self->hdrlen;

    // store the ip address into self->src_ip and self->dst_ip
    struct sockaddr_in src, dst;
	bzero(&src, sizeof(src));
	bzero(&dst, sizeof(dst));
	src.sin_addr.s_addr = ip->saddr;
	dst.sin_addr.s_addr = ip->daddr;
    strcpy(self->src_ip, inet_ntoa(src.sin_addr));
    strcpy(self->dst_ip, inet_ntoa(dst.sin_addr));
    
    // get the ip protocol
    self->pro = ip->protocol;

    return pkt + self->hdrlen;
}

Net *fmt_net_rep(Net *self)
{
    // [TODO]: Fill up self->ip4hdr (prepare to send)

    self->ip4hdr.tot_len = htons(sizeof(struct iphdr) + self->plen);
    
    self->ip4hdr.check = 0;
    self->ip4hdr.check = cal_ipv4_cksm(self->ip4hdr);
    
    return self;
}

void init_net(Net *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    self->src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->hdrlen = sizeof(struct iphdr);

    self->dissect = dissect_ip;
    self->fmt_rep = fmt_net_rep;
}