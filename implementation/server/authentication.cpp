#include "authentication.h"
#include <new>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <string.h>

// TODO!
unsigned char *authenticate(int fd, int key_len) {
    unsigned char *key;
    key = new unsigned char[key_len];
    memset(key, 0, key_len);
    return key;
}
