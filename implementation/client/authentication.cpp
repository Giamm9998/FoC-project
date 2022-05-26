#include "authentication.h"
#include "../common/dhparams.h"
#include "../common/errors.h"
#include "../common/types.h"
#include "../common/utils.h"
#include <new>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string>
#include <tuple>

// TODO!

unsigned char *authenticate(BIO *socket, int key_len) {
    auto keypair = gen_keypair();
    std::string name = "Rick Astley";
    EVP_PKEY *server_pubkey;
    X509 *certificate;

    // Authentication start
    // send_header(socket, AuthStart);
    send_field(socket, name.length(), name.c_str());
    PEM_write_bio_PUBKEY(socket, keypair);
#ifdef DEBUG
    std::cout << "Client pubkey:" << endl;
    PEM_write_PUBKEY(stdout, keypair);
#endif

    // Authentication server answer
    // read server name
    auto [server_name_len, server_name] = read_field<char>(socket);

    // read g^y pubkey of server
    server_pubkey = PEM_read_bio_PUBKEY(socket, nullptr, nullptr, nullptr);
    if (server_pubkey == nullptr)
        handle_errors();

    // read certificate
    certificate = PEM_read_bio_X509(socket, nullptr, nullptr, nullptr);
    if (certificate == nullptr)
        handle_errors();

    // read digital signature
    auto [dsa_len, dsa] = read_field<uchar>(socket);

    // Verifies certificate

    // Verifies digital signature

    // Computes shared secret
}
