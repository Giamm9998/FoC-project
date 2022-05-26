#include "types.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <tuple>

using namespace std;

#ifndef utils_h
#define utils_h

#ifdef DEBUG
void print_shared_key(unsigned char *key, int len);
#endif

const EVP_CIPHER *get_symmetric_cipher();
int get_symmetric_key_length();

mtype get_mtype(BIO *socket);

void send_header(BIO *socket, mtype type);
void send_header(BIO *socket, mtype type, uchar *iv, int iv_len);

template <typename T> void send_field(BIO *socket, flen len, T *data) {
    if (BIO_write(socket, &len, sizeof(flen)) != sizeof(flen)) {
        perror("Error when writing field length");
        abort();
    }
    if (BIO_write(socket, data, len) != len) {
        perror("Error when writing field data");
        abort();
    }
}

template <typename T> tuple<flen, T *> read_field(BIO *socket) {
    flen len;
    if (BIO_read(socket, &len, sizeof(flen)) != sizeof(flen)) {
        perror("Error when reading field length");
        abort();
    }
    T *res = new T[len];

    if (BIO_read(socket, res, len) != len) {
        perror("Error when reading field");
        abort();
    }

    return {len, res};
}

#endif
