#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "net.h"
#include "transport.h"

uint16_t cal_tcp_cksm(struct iphdr iphdr, struct tcphdr tcphder, uint8_t *pl, int plen)
{
    // // // [TODO]: Finish TCP checksum calculation

    uint32_t sum = 0;

    uint8_t headerlen = tcphder.doff << 2;
    uint8_t tcplen = headerlen + plen;

    sum += (iphdr.saddr >> 16) & 0xFFFF;
    sum += (iphdr.saddr) & 0xFFFF;
    sum += (iphdr.daddr >> 16) & 0xFFFF;
    sum += (iphdr.daddr) & 0xFFFF;

    sum += htons(IPPROTO_TCP);
    sum += htons(tcplen);

    /* tcp header */
    uint8_t *tcp = (uint8_t*)(void *)&tcphder;

    while(headerlen > 1){
        sum += *tcp;
        tcp++;
        headerlen -= 2;
    }
    /* tcp payload */
    tcp = (uint8_t*)pl;
    tcplen = plen;

    while(tcplen > 1){
        sum += *tcp;
        tcp++;
        tcplen -= 2;
    }

    if(tcplen > 0){
        sum += ((*tcp)&htons(0xff00));
    }

    while(sum >> 16){
        sum = (sum & 0xffff) + (sum >> 16);
    }

    sum = ~sum;
    return (uint16_t)sum;

}

uint8_t *dissect_tcp(Net *net, Txp *self, uint8_t *segm, size_t segm_len)
{
    // [TODO]: Collect information from segm
    // (Check IP addr & port to determine the next seq and ack value)
    // Return payload of TCP

    // check IP addrress and port

    memcpy(&self->thdr, segm, sizeof(self->thdr));
    self->hdrlen = self->thdr.doff * 4;
    self->plen = (uint16_t)segm_len - self->hdrlen;
    memcpy(self->pl, segm + segm_len, self->plen);

    // if (strcmp(net->x_src_ip, net->src_ip) == 0) {
    //     self->x_tx_seq = self->thdr.th_seq + self->plen;
    //     self->x_tx_ack = self->thdr.th_ack;
    // }

    // if (strcmp(net->x_src_ip, net->dst_ip) == 0) {
    //     self->x_tx_seq = self->thdr.th_ack;
    //     self->x_tx_ack = self->thdr.th_seq + self->plen;
    // }

    return self->pl;
}

Txp *fmt_tcp_rep(Txp *self, struct iphdr iphdr, uint8_t *data, size_t dlen)
{
  // [TODO]: Fill up self->tcphdr (prepare to send)
  // reference: https://github.com/imjdl/rowsock/blob/master/tcp4/sendData.c (145)
    
    
    self->thdr.th_sport = htons(self->x_src_port);
    self->thdr.th_dport = htons(self->x_dst_port);

    // self->thdr.source = htons(self->x_src_port);
    // self->thdr.dest = htons(self->x_dst_port);

    self->thdr.seq = htonl(self->x_tx_seq); // htons?
    self->thdr.ack_seq = htonl(self->x_tx_ack); // htons?

    memcpy(self->pl, data, dlen);

    // if (dlen > 0)
    //   self->thdr.psh = 1;
    // else
    //   self->thdr.psh = 0;

    // self->thdr.th_flags |= 0x08; 
    // self->thdr.th_sum = 0;
    self->thdr.psh = self->thdr.psh;

    self->thdr.check = (cal_tcp_cksm(iphdr, self->thdr, data, dlen));

    return self;
}

inline void init_txp(Txp *self)
{
	self->pl = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
	self->hdrlen = sizeof(struct tcphdr);

	self->dissect = dissect_tcp;
	self->fmt_rep = fmt_tcp_rep;
}