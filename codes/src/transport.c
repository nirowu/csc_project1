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
    // [TODO]: Finish TCP checksum calculation

    uint16_t    hdrlen = tcphder.th_off * 4,
                len = hdrlen + plen;

    uint32_t    sum = 0;
    
    sum += (iphdr.saddr >> 16) & 0xFFFF;
    sum += (iphdr.saddr) & 0xFFFF;
    sum += (iphdr.daddr >> 16) & 0xFFFF;
    sum += (iphdr.daddr) & 0xFFFF;

    // protocol and reserved
    sum += htons(IPPROTO_TCP);
    sum += htons(len);

    // tcp header 
    uint16_t *tcp = (uint16_t*)(void *)&tcphder;

    while (hdrlen > 1) {
        sum += (*tcp++);
        hdrlen -= 2;
    }
    // tcp payload 
    tcp = (uint16_t*)pl;
    len = plen;

    while (len > 1){
        sum += (*tcp++);
        len -= 2;
    }
    if (len == 1){
        sum += ((*tcp) &htons(0xff00));
    }

    while (sum >> 16){
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

    struct tcphdr *tcp = (struct tcphdr *)segm;
    memcpy(&self->thdr, tcp, sizeof(struct tcphdr));
    self->hdrlen = (uint8_t)tcp->th_off * 4;

    uint8_t* pl = segm;
    uint8_t count = self->hdrlen;

    while(pl[count] != 0x00 && pl[count+1] != 0x01){
        count++;
    }
    count++;

    self->pl = segm + self->hdrlen;
    self->plen = count-(self->hdrlen);

    return  self->pl;
}

Txp *fmt_tcp_rep(Txp *self, struct iphdr iphdr, uint8_t *data, size_t dlen)
{
    // [TODO]: Fill up self->tcphdr (prepare to send)
    self->thdr.th_sport = htons(self->x_src_port);
    self->thdr.th_dport = htons(self->x_dst_port);

    self->thdr.ack_seq = htonl(self->x_tx_ack);
    self->thdr.seq = htonl(self->x_tx_seq);
    memcpy(self->pl, data, dlen);

    self->thdr.psh = self->thdr.psh;
    self->thdr.th_sum= 0;
    self->thdr.th_sum = cal_tcp_cksm(iphdr, self->thdr, data, dlen);
    
    return self;
}

inline void init_txp(Txp *self)
{
    self->pl = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
    self->hdrlen = sizeof(struct tcphdr);

    self->dissect = dissect_tcp;
    self->fmt_rep = fmt_tcp_rep;
}