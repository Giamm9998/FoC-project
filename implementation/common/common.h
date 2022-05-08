#include <openssl/evp.h>
#include <stdio.h>

#ifndef common_h
#define common_h

#ifdef DEBUG
void print_shared_key(unsigned char *key, int len);
#endif

const EVP_CIPHER *get_symmetric_cipher();
int get_symmetric_key_length();

#endif
