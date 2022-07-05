#include "maybe.h"
#include "types.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <tuple>
#include <unistd.h>

using namespace std;

#ifndef utils_h
#define utils_h

#ifdef DEBUG
void print_shared_key(unsigned char *key, int len);
#endif

const EVP_CIPHER *get_symmetric_cipher();
int get_symmetric_key_length();

const EVP_MD *get_hash_type();
int get_hash_type_length();
int get_signature_max_length(EVP_PKEY *privkey);

Maybe<unsigned char *> kdf(unsigned char *shared_secret, int shared_secret_len,
                           unsigned int key_len);

Maybe<mtype> get_mtype(int socket);

Maybe<bool> send_header(int socket, mtype type);
Maybe<bool> send_header(int socket, mtype type, uchar *iv, int iv_len);

template <typename T> Maybe<bool> send_field(int socket, flen len, T *data) {
    Maybe<bool> res;
    if (write(socket, &len, sizeof(flen)) != sizeof(flen)) {
        res.set_error("Error when writing field length");
        return res;
    }
    if (write(socket, data, len) != len) {
        res.set_error("Error when writing field data");
        return res;
    }
    res.set_result(true);
    return res;
}

template <typename T> Maybe<tuple<flen, T *>> read_field(int socket) {
    Maybe<tuple<flen, T *>> res;

    flen len;
    if (read(socket, &len, sizeof(flen)) != sizeof(flen)) {
        res.set_error("Error when reading field length");
        return res;
    }
    T *r = new T[len];

    if (read(socket, r, len) != len) {
        delete[] r;
        res.set_error("Error when reading field");
        return res;
    }

    res.set_result({len, r});
    return res;
}

#endif
