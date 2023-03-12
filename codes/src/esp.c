#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/pfkeyv2.h>
#include <sys/uio.h>
#include <errno.h>
#include "esp.h"
#include "transport.h"
#include "hmac.h"
#ifndef SHA_BLOCKSIZE
#define SHA_BLOCKSIZE 64
#endif


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

    sockfd = socket(AF_KEY, SOCK_RAW, PF_KEY_V2);
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
    keylen = keyptr->sadb_key_len * 8;

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
    // [TODO]: Fill up self->pad and self->pad_len (Ref. RFC4303 Section 2.4)
    int pad_len = SHA_BLOCKSIZE * ((self->plen + SHA_BLOCKSIZE - 1) / SHA_BLOCKSIZE);
    int w = pad_len - self->plen;
    self->tlr.pad_len = (uint8_t)w;

    // Generating the padding field
    int r;
    for (r = 0; r < w - 1; r++)
        self->pad[r] = rand() & 0xff;
    
    self->pad[w-1] = (uint8_t) w;

    memcpy(self->pl + self->plen, self->pad, w);
    puts("uu");
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

    nb = sizeof(self->hdr) + self->plen + sizeof(self->tlr);
    memcpy(buff, self, nb);

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

    self->plen = esp_len - (sizeof(self->hdr) + sizeof(self->tlr));
    size_t offset = 0;
    memcpy(&(self->hdr), esp_pkt, sizeof(self->hdr));
    offset += sizeof(self->hdr);
    memcpy(self->pl, esp_pkt + offset, self->plen);
    offset += self->plen;
    memcpy(&(self->tlr), esp_pkt + offset, sizeof(self->tlr));
    return self->pl;
}

Esp *fmt_esp_rep(Esp *self, Proto p)
{
    // [TODO]: Fill up ESP header and trailer (prepare to send)
    self->pl = self->dissect;
    self->pad = self->set_padpl;
    self->tlr.nxt = p;
    self->auth = self->set_auth;

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
