#include "authentication.h"
#include "../common/dhparams.h"
#include "../common/errors.h"
#include "../common/types.h"
#include "../common/utils.h"
#include <iostream>
#include <new>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string>
#include <tuple>

using namespace std;
// TODO!

unsigned char *authenticate(BIO *socket, int key_len) {
    auto keypair = gen_keypair();
    string name = "alice";
    EVP_PKEY *server_pubkey;
    X509 *certificate;

    // Authentication start
    auto send_res = send_header(socket, AuthStart);
    if (send_res.is_error) {
        cerr << send_res.error << endl;
        // TODO: free stuff that needs to be freed
        abort();
    }

    send_res = send_field(socket, name.length() + 1, name.c_str());
    if (send_res.is_error) {
        cerr << send_res.error << endl;
        // TODO: free stuff that needs to be freed
        abort();
    }
    PEM_write_bio_PUBKEY(socket, keypair);
#ifdef DEBUG
    cout << "Client pubkey:" << endl;
    PEM_write_PUBKEY(stdout, keypair);
#endif

    // Authentication server answer
    // read server name
    auto server_name_result = read_field<char>(socket);
    if (server_name_result.is_error) {
        cout << server_name_result.error << endl;
        // TODO: free stuff that needs to be freed
        abort();
    }
    auto [server_name_len, server_name] = server_name_result.result;

    // read g^y pubkey of server
    server_pubkey = PEM_read_bio_PUBKEY(socket, nullptr, nullptr, nullptr);
    if (server_pubkey == nullptr)
        handle_errors();

    // read certificate
    certificate = PEM_read_bio_X509(socket, nullptr, nullptr, nullptr);
    if (certificate == nullptr)
        handle_errors();

    // read digital signature
    auto dsa_result = read_field<uchar>(socket);
    if (dsa_result.is_error) {
        cout << dsa_result.error << endl;
        // TODO: free stuff that needs to be freed
        abort();
    }
    auto [dsa_len, dsa] = dsa_result.result;

    // Verifies certificate

    // Verifies digital signature

    // Computes shared secret
}
