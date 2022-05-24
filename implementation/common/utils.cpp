#include "utils.h"
#include <iostream>
#include <openssl/evp.h>

using namespace std;

#ifdef DEBUG
void print_shared_key(unsigned char *key, int len) {
    cout << "Shared key: ";
    for (int i = 0; i < len; i++)
        printf("%02x", (int)key[i]);
    cout << endl;
}
#endif

const EVP_CIPHER *get_symmetric_cipher() { return EVP_aes_256_gcm(); }

int get_symmetric_key_length() {
    const EVP_CIPHER *cipher = get_symmetric_cipher();
    return EVP_CIPHER_key_length(cipher);
}
