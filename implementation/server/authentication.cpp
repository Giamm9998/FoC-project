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

#ifdef DEBUG
        cout << "Loading public key for user: " << user << endl
             << "Path: " << user_key_path << endl;
#endif

        // Open the public key
        if ((public_key_fp = fopen(user_key_path.c_str(), "r")) == nullptr) {
            perror("Cannot read user key");
            abort();
        }

        // ... and save it into the list of users
        if ((pubkey = PEM_read_PUBKEY(public_key_fp, nullptr, nullptr,
                                      nullptr)) == nullptr)
            handle_errors();

        // ... and save it into the list of users
        user_map.insert({user, pubkey});

#ifdef DEBUG
        cout << "Loaded public key for " << user << endl;
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
        cerr << "Incorrect message type";
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
        abort();
    }

    // Load the client half key (TODO)
    auto client_half_key = PEM_read_bio_PUBKEY(socket, NULL, NULL, NULL);
    if (client_half_key == NULL)
        handle_errors();

#ifdef DEBUG
    cout << "Received PEM pubkey: " << endl;
    PEM_write_PUBKEY(stderr, client_half_key);
#endif

    // Send server name ("server")

    // Send server half key

    // Send server certificate

    // Sign {g^x, g^y, C} with server's private key and send it

    // Receive client signature and check it

    // Derive shared key
}
