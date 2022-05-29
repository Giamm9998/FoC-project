#include "authentication.h"
#include "../common/errors.h"
#include "../common/utils.h"
#include <filesystem>
#include <iostream>
#include <map>
#include <new>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>
#include <tuple>

using namespace std;

// Possible users of the server
string users[2] = {"alice", "bob"};
char server_name[] = "server";

/* Reads all the public keys of the registered users */
static map<string, EVP_PKEY *> setup_keys() {
    auto user_map = map<string, EVP_PKEY *>();
    FILE *public_key_fp;
    EVP_PKEY *pubkey;

    for (string user : users) {

        // Get the user public key path
        auto user_key_path =
            (std::filesystem::canonical(".") / "certificates" / (user + ".pub"))
                .string();

        // Open the public key file
        if ((public_key_fp = fopen(user_key_path.c_str(), "r")) == nullptr) {
            user_map.clear();
            perror("Cannot read user key");
            abort();
        }

        // ... and read it as a public key
        if ((pubkey = PEM_read_PUBKEY(public_key_fp, nullptr, nullptr,
                                      nullptr)) == nullptr) {
            user_map.clear();
            handle_errors();
        }

        // ... and save it into the list of users
        user_map.insert({user, pubkey});

#ifdef DEBUG
        cout << "Loaded public key for " << user << endl
             << "Path: " << user_key_path << endl
             << endl;
        ;
#endif
    }

    return user_map;
}

unsigned char *authenticate(BIO *socket, int key_len) {
    // Setup simple associations of usernames and public keys
    auto user_keys = setup_keys();

    // Receive first client message
    auto type = get_mtype(socket);

    // Check the correctness of the message type
    if (type != AuthStart) {
        cerr << "Incorrect message type" << endl;
        user_keys.clear();
        BIO_free(socket);
        abort();
    }

    // Read the username of the client
    auto [username_len, username] = read_field<char>(socket);

#ifdef DEBUG
    cout << "Username length: " << username_len << endl;
    cout << "Username: " << username << endl;
#endif

    // Check that it is registered on the server
    auto finder = user_keys.find(username);
    if (finder != user_keys.end()) {
        auto client_pubkey = finder->second;
    } else {
        cerr << "User not registered!" << endl;
        user_keys.clear();
        BIO_free(socket);
        abort();
    }

    // Load the client half key
    BIO *tmp_bio;
    if ((tmp_bio = BIO_new(BIO_s_mem())) == NULL) {
        user_keys.clear();
        BIO_free(socket);
        handle_errors();
    }

    // Read client half key in PEM format
    // TODO: this can fail too possibly, therefore we need to check for errors
    // and free memory correctly!
    // See
    // https://stackoverflow.com/questions/3157098/whats-the-right-approach-to-return-error-codes-in-c
    // for an elegant solution to the problem!
    auto [client_half_key_len, client_half_key_bin] = read_field<uchar>(socket);

    // Write it to memory bio
    if (BIO_write(tmp_bio, client_half_key_bin, client_half_key_len) !=
        client_half_key_len) {
        user_keys.clear();
        BIO_free(socket);
        BIO_free(tmp_bio);
        handle_errors();
    }

    // ... and extract it as the client half key
    auto client_half_key = PEM_read_bio_PUBKEY(tmp_bio, NULL, NULL, NULL);
    if (client_half_key == NULL) {
        user_keys.clear();
        BIO_free(socket);
        BIO_free(tmp_bio);
        handle_errors();
    }

#ifdef DEBUG
    cout << "Received PEM pubkey: " << endl;
    PEM_write_PUBKEY(stderr, client_half_key);
#endif

    // Send server name ("server")
    send_field(socket, sizeof(server_name), server_name);

    // Send server half key

    // Send server certificate

    // Sign {g^x, g^y, C} with server's private key and send it

    // Receive client signature and check it

    // Derive shared key
}
