#include "utils.h"
#include "types.h"
#include <errno.h>
#include <iostream>
#include <openssl/evp.h>
#include <stdio.h>
#include <tuple>
#include <unistd.h>

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
    auto cipher = get_symmetric_cipher();
    return EVP_CIPHER_key_length(cipher);
}

mtype get_mtype(BIO *socket) {
    mtype res;
    if (BIO_read(socket, &res, sizeof(mtype)) != sizeof(mtype)) {
        perror("Error when reading mtype");
        abort();
    };
    return res;
}

void send_header(BIO *socket, mtype type) {
    if (BIO_write(socket, &type, sizeof(mtype)) != sizeof(mtype)) {
        perror("Error when writing mtype");
        abort();
    };
}

void send_header(BIO *socket, mtype type, uchar *iv, int iv_len) {
    send_header(socket, type);

    if (BIO_write(socket, iv, iv_len) != iv_len) {
        perror("Error when writing iv");
        abort();
    };
}
