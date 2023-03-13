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

uint16_t ipv4_checksum(const void *data, size_t len) {
    const uint16_t *buf = data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if (len == 1) {
        sum += *(uint8_t *)buf;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (uint16_t)~sum;
}

uint16_t cal_ipv4_cksm(struct iphdr iphdr)
{
    // [TODO]: Finish IP checksum calculation
    iphdr.check = ipv4_checksum(&iphdr, sizeof(iphdr));
    return iphdr.check;
}

uint8_t *dissect_ip(Net *self, uint8_t *pkt, size_t pkt_len)
{
    // [TODO]: Collect information from pkt.
    // Return payload of network layer


    self->plen= (uint16_t) (pkt_len - sizeof(self->ip4hdr));
    uint8_t *pl = (uint8_t*) malloc(self->plen);

    memcpy(&self->ip4hdr, pkt, sizeof(self->ip4hdr));
    memcpy(pl, pkt + sizeof(self->ip4hdr), self->plen);

    self->pro = self->ip4hdr.protocol;
    self->hdrlen = self->ip4hdr.ihl * 4; 
    self->ip4hdr.tot_len = (uint16_t)pkt_len;

    // self->x_src_ip = self->ip4hdr.saddr;
    // self->x_dst_ip = self->ip4hdr.daddr;
    strcpy(self->x_src_ip, &self->ip4hdr.saddr);
    strcpy(self->x_dst_ip, &self->ip4hdr.daddr);


    return pl;
}
Net *fmt_net_rep(Net *self)
{
    // [TODO]: Fill up self->ip4hdr (prepare to send)
    self->ip4hdr.check = cal_ipv4_cksm(self->ip4hdr);
    self->ip4hdr.tot_len = htons(sizeof(struct iphdr) + self->plen);
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