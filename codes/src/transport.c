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

uint16_t cal_tcp_cksm(struct iphdr iphdr, struct tcphdr tcphdr, uint8_t *pl, int plen)
{
  // [TODO]: Finish TCP checksum calculation
  // reference: https://gist.github.com/david-hoze/0c7021434796997a4ca42d7731a7073a
  // reference: https://github.com/imjdl/rowsock/blob/master/tcp4/sendData.c (320)

	unsigned int sum = 0;
	uint8_t *buffer = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));

	// TCP segment
	memcpy(buffer, &tcphdr, sizeof(struct tcphdr));
	memcpy(buffer + sizeof(struct tcphdr), pl, plen);
	uint8_t tcpLen = sizeof(struct tcphdr) + plen; /* TCP segment length */

	// add psuedo IP header
	// source IP
    sum += (iphdr.saddr >> 16) & 0xFFFF; 
    sum += (iphdr.saddr) & 0xFFFF;

    // destination IP
    sum += (iphdr.daddr >> 16) & 0xFFFF;
    sum += (iphdr.daddr) & 0xFFFF;
	
	// protocol and reserved: 6
	sum += htons(IPPROTO_TCP);
    // the TCP length
    sum += htons(tcpLen);   
	
	while (tcpLen > 1)
	{
		sum += *buffer++;
		tcpLen -= 2;
	}

	// if tcpLen is odd
	if (tcpLen == 1)
		sum += *((uint8_t *)buffer);
	
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	
	sum = ~sum;
	
	free(buffer);

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

    if (strcmp(net->x_src_ip, net->src_ip) == 0) {
        self->x_tx_seq = self->thdr.th_seq + self->plen;
        self->x_tx_ack = self->thdr.th_ack;
    }

    if (strcmp(net->x_src_ip, net->dst_ip) == 0) {
        self->x_tx_seq = self->thdr.th_ack;
        self->x_tx_ack = self->thdr.th_seq + self->plen;
    }

    return self->pl;
}

Txp *fmt_tcp_rep(Txp *self, struct iphdr iphdr, uint8_t *data, size_t dlen)
{
  // [TODO]: Fill up self->tcphdr (prepare to send)
  // reference: https://github.com/imjdl/rowsock/blob/master/tcp4/sendData.c (145)
    
    self->thdr.seq = self->x_tx_seq;
    self->thdr.ack_seq = self->x_tx_ack;

    self->thdr.th_sum = cal_tcp_cksm(iphdr, self->thdr, data, dlen);

    char tcp_flags[8];
    // FIN
    tcp_flags[0] = 0;
    // SYN
    tcp_flags[1] = 0;
    // RST
    tcp_flags[2] = 0;
    // PSH
    tcp_flags[3] = 1;
    // ACK
    tcp_flags[4] = 0;
    // URG
    tcp_flags[5] = 0;
    // ECE
    tcp_flags[6] = 0;
    // CWR
    tcp_flags[7] = 0;

    self->thdr.th_flags = 0;

    int r;
    for (r = 0; r < 8; r++){
        self->thdr.th_flags += (tcp_flags[r] << r);
    }

    return self;
}

inline void init_txp(Txp *self)
{
	self->pl = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
	self->hdrlen = sizeof(struct tcphdr);

	self->dissect = dissect_tcp;
	self->fmt_rep = fmt_tcp_rep;
}