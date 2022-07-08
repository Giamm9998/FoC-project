#include "maybe.h"
#include "types.h"
#include <filesystem>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <tuple>
#include <unistd.h>

using namespace std;
namespace fs = std::filesystem;

#ifndef utils_h
#define utils_h

#define GREEN "\033[1;32m"
#define RESET "\033[0m"

void print_shared_key(unsigned char *key, int len);
void print_debug(unsigned char *x, int len);

const EVP_CIPHER *get_symmetric_cipher();
int get_symmetric_key_length();
int get_iv_len();
int get_block_size();

const EVP_MD *get_hash_type();
int get_hash_type_length();
int get_signature_max_length(EVP_PKEY *privkey);

/*
 * Key derivation function: given a shared secret, its length, and the required
 * length of the key, gets a key from the shared secret of the specified length.
 * The caller is responsible for the de-allocation of the key memory, and it
 * must be freed using `delete[]`
 */
Maybe<unsigned char *> kdf(unsigned char *shared_secret, int shared_secret_len,
                           unsigned int key_len);

/*
 * The caller is responsible for the de-allocation of the returned pointer, if
 * any
 */
Maybe<unsigned char *> gen_iv();

/*
 * The caller is responsible for the de-allocation of the returned pointer, if
 * any
 */
#define DUMMY_LEN 12
Maybe<unsigned char *> get_dummy();

Maybe<mtypes> get_mtype(int socket);

Maybe<bool> send_header(int socket, mtype type);
Maybe<bool> send_header(int socket, mtype type, seqnum seq_num, uchar *iv,
                        int iv_len);

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
#ifdef DEBUG
    cout << GREEN << "Field length: " << len << RESET << endl;
#endif
    T *r = new T[len];

    if (read(socket, r, len) != len) {
        delete[] r;
        cout << "len: " << len << endl;
        res.set_error("Error when reading field");
        return res;
    }

#ifdef DEBUG
    cout << GREEN;
    print_debug((unsigned char *)r, len);
    cout << RESET;
#endif

    res.set_result({len, r});
    return res;
}

unsigned char mtype_to_uc(mtypes m);
Maybe<tuple<seqnum, unsigned char *>> read_header(int socket);

unsigned char *string_to_uchar(string my_string);

/* Returns the path to the user storage */
fs::path get_user_storage_path(char *username);

/*
 * Used to validate paths taken by the user.
 * Checks for path traversals
 */
bool is_path_valid(char *username, fs::path user_path);

#endif
