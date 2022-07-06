#include "utils.h"
#include "types.h"
#include <errno.h>
#include <iostream>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <tuple>
#include <unistd.h>

using namespace std;

void print_shared_key(unsigned char *key, int len) {
    cout << "Shared key: ";
    for (int i = 0; i < len; i++)
        printf("%02x", (int)key[i]);
    cout << endl;
}

const EVP_CIPHER *get_symmetric_cipher() { return EVP_aes_256_gcm(); }

int get_symmetric_key_length() {
    auto cipher = get_symmetric_cipher();
    return EVP_CIPHER_key_length(cipher);
}

const EVP_MD *get_hash_type() { return EVP_sha256(); }
int get_hash_type_length() { return EVP_MD_size(get_hash_type()); }
int get_signature_max_length(EVP_PKEY *privkey) {
    return EVP_PKEY_size(privkey);
}

/*
 * Key derivation function: given a shared secret, its length, and the required
 * length of the key, gets a key from the shared secret of the specified length.
 * The caller is responsible for the de-allocation of the key memory, and it
 * must be freed using `delete[]`
 */
Maybe<unsigned char *> kdf(unsigned char *shared_secret, int shared_secret_len,
                           unsigned int key_len) {
    Maybe<unsigned char *> res;
    unsigned char *key = new unsigned char[key_len];

    unsigned char *digest = new unsigned char[get_hash_type_length()];
    unsigned int digest_len;
    EVP_MD_CTX *ctx;
    if ((ctx = EVP_MD_CTX_new()) == nullptr ||
        EVP_DigestInit(ctx, get_hash_type()) != 1 ||
        EVP_DigestUpdate(ctx, shared_secret, shared_secret_len) != 1 ||
        EVP_DigestFinal(ctx, digest, &digest_len) != 1) {
        delete[] key;
        delete[] digest;
        EVP_MD_CTX_free(ctx);
        res.set_error("Could not create hashing context for kdf");
        return res;
    }

    EVP_MD_CTX_free(ctx);

    if (digest_len < key_len) {
        delete[] key;
        delete[] digest;
        res.set_error("Cannot derive a key: key length is bigger than the "
                      "digest's length.");
        return res;
    }

    memcpy(key, digest, key_len);
    delete[] digest;

    res.set_result(key);
    return res;
}

Maybe<mtype> get_mtype(int socket) {
    Maybe<mtype> res;
    if (read(socket, &res.result, sizeof(mtype)) != sizeof(mtype)) {
        res.set_error("Error when reading mtype");
    };
    return res;
}

Maybe<bool> send_header(int socket, mtype type) {
    Maybe<bool> res;
    if (write(socket, &type, sizeof(mtype)) != sizeof(mtype)) {
        res.set_error("Error when writing mtype");
        return res;
    }
    res.set_result(true);
    return res;
}

Maybe<bool> send_header(int socket, mtype type, uchar *iv, int iv_len) {
    auto res = send_header(socket, type);
    if (res.is_error) {
        return res;
    }

    if (write(socket, iv, iv_len) != iv_len) {
        res.set_error("Error when writing iv");
        return res;
    };
    res.set_result(true);
    return res;
}
