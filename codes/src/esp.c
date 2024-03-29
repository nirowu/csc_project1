#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/pfkeyv2.h>

#include "esp.h"
#include "transport.h"
#include "hmac.h"

EspHeader esp_hdr_rec;

void get_ik(int type, uint8_t *key)
{
 // [TODO]: Dump authentication key from security association database (SADB)
    // (Ref. RFC2367 Section 2.3.4 & 2.4 & 3.1.10)

    int     sockfd,
            mypid = getpid();
    char    buf[4096];
    uint8_t keylen; 
    
    struct sadb_msg req;
    req.sadb_msg_version = PF_KEY_V2;
    req.sadb_msg_type = SADB_DUMP;
    req.sadb_msg_satype = (type);
    req.sadb_msg_len = sizeof(struct sadb_msg) / 8;
    req.sadb_msg_pid = (mypid);
    req.sadb_msg_seq = (1);

    sockfd = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    if (write(sockfd, &req, sizeof(req)) < 0) {
        perror("write_msg()");
    }

    if (read(sockfd, &buf, sizeof(buf)) < 0) {
        perror("read_msg()");
    }

    size_t offset = sizeof(struct sadb_msg);
    struct sadb_ext *ext;

    while (true) {
        ext = (struct sadb_ext*) (buf + offset);
        if (ext->sadb_ext_type == SADB_EXT_KEY_AUTH) {
            break;
        }
        offset += ext->sadb_ext_len * 8;
    }
    struct sadb_key* keyptr = (struct sadb_key*) (buf + offset);
    keylen = (keyptr->sadb_key_len * 8) - sizeof(struct sadb_key);

    memcpy(key, buf + (offset + sizeof(struct sadb_key)), keylen);

    close(sockfd);
    return;
}

void get_esp_key(Esp *self)
{
    get_ik(SADB_SATYPE_ESP, self->esp_key);
}

uint8_t *set_esp_pad(Esp *self)
{
    
    // [TODO]: Fiill up self->pad and self->pad_len (Ref. RFC4303 Section 2.4)

	if ((self->plen % 4)!= 0) {
		self->tlr.pad_len = 2 + (4-(self->plen % 4));
	}
    else {
		self->tlr.pad_len = 2;
	}

	int n = (int)(self->tlr.pad_len);

	if (n != 0) {
		uint8_t *pad = (uint8_t *)realloc(self->pad, n*sizeof(uint8_t));
		for (int i = 1; i <= n; i++){
			pad[i - 1] = (uint8_t)(i);
		}
	}

    return self->pad;
}

uint8_t *set_esp_auth(Esp *self,
                      ssize_t (*hmac)(uint8_t const *, size_t,
                                      uint8_t const *, size_t,
                                      uint8_t *))
{
    if (!self || !hmac) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
    }

    uint8_t buff[BUFSIZE];
    size_t esp_keylen = 16;
    size_t nb = 0;  // Number of bytes to be hashed
    ssize_t ret;
    // [TODO]: Put everything needed to be authenticated into buff and add up nb

	memcpy(buff, &self->hdr, sizeof(struct esp_header));
	nb += sizeof(struct esp_header);
	memcpy(buff + nb, self->pl, self->plen);
	nb += self->plen;
	memcpy(buff + nb, self->pad, self->tlr.pad_len);
	nb += self->tlr.pad_len;
	memcpy(buff+nb, &self->tlr, sizeof(struct esp_trailer));
	nb += sizeof(struct esp_trailer);

    ret = hmac(self->esp_key, esp_keylen, buff, nb, self->auth);

    if (ret == -1) {
        fprintf(stderr, "Error occurs when try to compute authentication data");
        return NULL;
    }

    self->authlen = ret;
    return self->auth;
}

uint8_t *dissect_esp(Esp *self, uint8_t *esp_pkt, size_t esp_len)
{
    // [TODO]: Collect information from esp_pkt.
    // Return payload of ESP

    // header
    struct esp_header *esphdr = (struct esp_header *)esp_pkt;
    self->hdr.seq = esphdr->seq;
    self->hdr.spi = esphdr->spi;
    
    // payload
    self->pl = esp_pkt + sizeof(self->hdr);
    self->plen = esp_len - sizeof(self->hdr);

    return self->pl;
}

Esp *fmt_esp_rep(Esp *self, Proto p)
{
    // [TODO]: Fill up ESP header and trailer (prepare to send)
	self->hdr.seq = htonl(ntohl(self->hdr.seq) + 1);
	self->tlr.nxt = (uint8_t)p; // protocol

	return self;
}

void init_esp(Esp *self)
{
    self->pl = (uint8_t *)malloc(MAXESPPLEN * sizeof(uint8_t));
    self->pad = (uint8_t *)malloc(MAXESPPADLEN * sizeof(uint8_t));
    self->auth = (uint8_t *)malloc(HMAC96AUTHLEN * sizeof(uint8_t));
    self->authlen = HMAC96AUTHLEN;
    self->esp_key = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));

    self->set_padpl = set_esp_pad;
    self->set_auth = set_esp_auth;
    self->get_key = get_esp_key;
    self->dissect = dissect_esp;
    self->fmt_rep = fmt_esp_rep;
}