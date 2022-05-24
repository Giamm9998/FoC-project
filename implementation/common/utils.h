#include "types.h"
#include <openssl/evp.h>
#include <stdio.h>

#ifndef utils_h
#define utils_h

#ifdef DEBUG
void print_shared_key(unsigned char *key, int len);
#endif

const EVP_CIPHER *get_symmetric_cipher();
int get_symmetric_key_length();

mtype get_mtype(int sock);
mlen get_mlen(int sock);

void send_header(int sock, mtype type, mlen len);
void send_header(int sock, mtype type, mlen len, uchar *iv, int iv_len);

void send_field(int sock, flen len, void *data);
void read_field(int sock);

#endif
