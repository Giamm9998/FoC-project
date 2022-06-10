#include "maybe.h"
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

Maybe<mtype> get_mtype(BIO *socket);

Maybe<bool> send_header(BIO *socket, mtype type);
Maybe<bool> send_header(BIO *socket, mtype type, uchar *iv, int iv_len);

template <typename T> Maybe<bool> send_field(BIO *socket, flen len, T *data) {
    Maybe<bool> res;
    if (BIO_write(socket, &len, sizeof(flen)) != sizeof(flen)) {
        res.set_error("Error when writing field length");
        return res;
    }
    if (BIO_write(socket, data, len) != len) {
        res.set_error("Error when writing field data");
        return res;
    }
    res.set_result(true);
    return res;
}

template <typename T> Maybe<tuple<flen, T *>> read_field(BIO *socket) {
    Maybe<tuple<flen, T *>> res;

    flen len;
    if (BIO_read(socket, &len, sizeof(flen)) != sizeof(flen)) {
        res.set_error("Error when reading field length");
        return res;
    }
    T *r = new T[len];

    if (BIO_read(socket, r, len) != len) {
        delete[] r;
        res.set_error("Error when reading field");
        return res;
    }

    res.set_result({len, r});
    return res;
}

#endif
