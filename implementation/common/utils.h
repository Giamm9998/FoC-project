#include "types.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <stdio.h>

#ifndef utils_h
#define utils_h

#ifdef DEBUG
void print_shared_key(unsigned char *key, int len);
#endif

const EVP_CIPHER *get_symmetric_cipher();
int get_symmetric_key_length();

mtype get_mtype(BIO *socket);
mlen get_mlen(BIO *socket);

void send_header(BIO *socket, mtype type, mlen len);
void send_header(BIO *socket, mtype type, mlen len, uchar *iv, int iv_len);

void send_field(BIO *socket, flen len, void *data);
void read_field(BIO *socket);

#endif
