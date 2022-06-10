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

Maybe<mtype> get_mtype(BIO *socket) {
    Maybe<mtype> res;
    if (BIO_read(socket, &res.result, sizeof(mtype)) != sizeof(mtype)) {
        res.set_error("Error when reading mtype");
    };
    return res;
}

Maybe<bool> send_header(BIO *socket, mtype type) {
    Maybe<bool> res;
    if (BIO_write(socket, &type, sizeof(mtype)) != sizeof(mtype)) {
        res.set_error("Error when writing mtype");
        return res;
    }
    res.set_result(true);
    return res;
}

Maybe<bool> send_header(BIO *socket, mtype type, uchar *iv, int iv_len) {
    auto res = send_header(socket, type);
    if (res.is_error) {
        return res;
    }

    if (BIO_write(socket, iv, iv_len) != iv_len) {
        res.set_error("Error when writing iv");
        return res;
    };
    res.set_result(true);
    return res;
}
