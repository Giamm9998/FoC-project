#include "authentication.h"
#include "../common/dhparams.h"
#include "../common/errors.h"
#include "../common/types.h"
#include "../common/utils.h"
#include <new>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <string>

// TODO!
void get_dh_pubkey(EVP_PKEY *priv_key) {}

unsigned char *authenticate(int fd, int key_len) {
    // generates x from dh params g and p
    auto priv_key = gen_priv_key();
    std::string name;

    // get g^x
    get_dh_pubkey(priv_key);

    // send_header(sock,AuthStart,payload_len)
}