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

// uint32_t little_endian(uint32_t num){
//     uint32_t ans = 0;
//     ans += (num & 0xff000000) >> 24;
//     ans += (num & 0x00ff0000) >> 8;
//     ans += (num & 0x0000ff00) << 8;
//     ans += (num & 0x000000ff) << 24;

//     return ans;
// }

// void helper(char* ip_char, uint32_t num) {
//     if (num <= 0) return;
//     uint32_t n = num % 16;
//     helper(ip_char, num / 16);
//     // to char
//     char c = 100;
//     if(0 <= n && n <= 9) c = '0'+n;
//     else if(10 <= n && n <= 15) c = 'a'+(n-10);

//     // cat
//     ip_char[strlen(ip_char)] = c;
// }
// void uint16_to_char_ip(uint32_t ip, char* ip_char){
//     ip = little_endian(ip);
//     helper(ip_char, ip);
// }

uint16_t cksm_helper(struct iphdr* iphdr)
{
    iphdr->check = 0;
    uint16_t *addr = (uint16_t *)iphdr;
    uint32_t count = iphdr->ihl<<2;
    register unsigned long sum = 0;
    while ( count > 1) {
        sum += *addr++;
        count -= 2;
    }
    if (count > 0) {
        sum += ((*addr) &htons(0xff00));
    }
    while ( sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    iphdr->check = (uint16_t)sum;
    return ((uint16_t)sum);
}

uint16_t cal_ipv4_cksm(struct iphdr iphdr)
{
    // [TODO]: Finish IP checksum calculation
    // puts("ipv4");
    // iphdr.check = 0;
    iphdr.check = cksm_helper(&iphdr);
    // printf("sum:%x\n", htons(sum));
    // iphdr.check = sum;
    return iphdr.check;
}

uint8_t *dissect_ip(Net *self, uint8_t *pkt, size_t pkt_len)
{
    // [TODO]: Collect information from pkt.
    // Return payload of network layer


    // uint8_t *pl = (uint8_t*) malloc(self->plen);

    memcpy(&(self->ip4hdr), pkt, sizeof(self->ip4hdr));
    // memcpy(pl, pkt + sizeof(self->ip4hdr), self->plen);

    self->pro = self->ip4hdr.protocol;
    // self->ip4hdr.tot_len = (uint16_t)pkt_len;

    bzero(self->src_ip, strlen(self->src_ip));
    bzero(self->dst_ip, strlen(self->dst_ip));

    // inet_ntop(AF_INET, &self->ip4hdr.saddr, self->x_src_ip, sizeof(self->ip4hdr.saddr));
    // inet_ntop(AF_INET, &self->ip4hdr.daddr, self->x_dst_ip, sizeof(self->ip4hdr.daddr));

    // uint16_to_char_ip(self->ip4hdr.saddr, self->src_ip); 
    // uint16_to_char_ip(self->ip4hdr.daddr, self->dst_ip);

    self->hdrlen = self->ip4hdr.ihl * 4; 
    self->plen= (uint16_t) (pkt_len - self->hdrlen);

    self->pro = self->ip4hdr.protocol;

    struct sockaddr_in src, dst;
    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));

    src.sin_addr.s_addr = self->ip4hdr.saddr;
    dst.sin_addr.s_addr = self->ip4hdr.daddr;

    strcpy(self->src_ip, inet_ntoa(src.sin_addr));
    strcpy(self->dst_ip, inet_ntoa(dst.sin_addr));


    return pkt + self->hdrlen;
}
Net *fmt_net_rep(Net *self)
{
    // [TODO]: Fill up self->ip4hdr (prepare to send)
    self->ip4hdr.check = 0;
    self->ip4hdr.check = cal_ipv4_cksm(self->ip4hdr);
    self->ip4hdr.tot_len = htons(sizeof(struct iphdr) + self->plen);


    // memcpy(&self->ip4hdr.saddr, self->x_src_ip, sizeof(self->ip4hdr.saddr));
    // memcpy(&self->ip4hdr.daddr, self->x_dst_ip, sizeof(self->ip4hdr.daddr));

    // struct in_addr *saddr = (struct in_addr *)&(self->ip4hdr.saddr);
    // struct in_addr *daddr = (struct in_addr *)&(self->ip4hdr.daddr);

    // inet_pton(AF_INET, self->x_src_ip, saddr);
    // inet_pton(AF_INET, self->x_dst_ip, daddr);

    // if (strcmp(self->x_dst_ip, self->src_ip) == 0) {
    //     uint32_t tmp = self->ip4hdr.saddr;
    //     self->ip4hdr.saddr = self->ip4hdr.daddr;
    //     self->ip4hdr.daddr = tmp;
    // }

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