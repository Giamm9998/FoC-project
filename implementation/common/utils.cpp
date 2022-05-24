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

mtype get_mtype(int sock) {
    mtype res;
    if (read(sock, &res, sizeof(mtype)) != sizeof(mtype)) {
        perror("Error when reading mtype");
        abort();
    };
    return res;
}

mlen get_mlen(int sock) {
    mlen res;
    if (read(sock, &res, SIZEOF_MLEN) != SIZEOF_MLEN) {
        perror("Error when reading mlen");
        abort();
    };
    return res;
}

void send_header(int sock, mtype type, mlen len) {
    if (len > MLEN_MAX) {
        cerr << "Maximum size of message exceeded. Aborting." << endl;
        abort();
    }

    if (write(sock, &type, sizeof(mtype)) != sizeof(mtype)) {
        perror("Error when writing mtype");
        abort();
    };

    if (write(sock, &len, SIZEOF_MLEN) != SIZEOF_MLEN) {
        perror("Error when writing mtype");
        abort();
    };
}

void send_header(int sock, mtype type, mlen len, uchar *iv, int iv_len) {
    send_header(sock, type, len);

    if (write(sock, iv, iv_len) != iv_len) {
        perror("Error when writing iv");
        abort();
    };
}

void send_field(int sock, flen len, void *data) {
    if (write(sock, &len, sizeof(flen)) != sizeof(flen)) {
        perror("Error when writing field length");
        abort();
    }
    if (write(sock, data, len) != len) {
        perror("Error when writing field data");
        abort();
    }
}

template <typename T> std::tuple<flen, T *> read_field(int sock) {
    flen len;
    if (read(sock, &len, sizeof(flen)) != sizeof(flen)) {
        perror("Error when reading field length");
        abort();
    }
    T *res = (T *)malloc(len);
    if (res == NULL) {
        perror("Could not allocated memory");
        abort();
    }

    return {len, res};
}
