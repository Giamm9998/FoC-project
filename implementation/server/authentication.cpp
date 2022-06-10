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

void free_user_keys(map<string, EVP_PKEY *> keys) {
    for (auto it = keys.begin(); it != keys.end(); it++) {
        EVP_PKEY_free(it->second);
    }
    keys.clear();
}

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
            free_user_keys(user_map);
            handle_errors();
        }

        fclose(public_key_fp);

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
    auto type_result = get_mtype(socket);

    // Check the correctness of the message type
    if (type_result.is_error || type_result.result != AuthStart) {
        free_user_keys(user_keys);
        throw "Incorrect message type";
    }

    // Read the username of the client
    auto username_result = read_field<char>(socket);
    if (username_result.is_error) {
        free_user_keys(user_keys);
        throw username_result.error;
    }
    auto [username_len, username] = username_result.result;

#ifdef DEBUG
    cout << "Username length: " << username_len << endl;
    cout << "Username: " << username << endl;
#endif

    // Check that it is registered on the server
    auto finder = user_keys.find(username);
    if (finder != user_keys.end()) {
        auto client_pubkey = finder->second;
    } else {
        free_user_keys(user_keys);
        delete[] username;
        username = nullptr;
        throw "User not registered!";
    }

    // Load the client half key
    BIO *tmp_bio;
    if ((tmp_bio = BIO_new(BIO_s_mem())) == nullptr) {
        free_user_keys(user_keys);
        delete[] username;
        username = nullptr;
        handle_errors();
    }

    // Read client half key in PEM format
    auto half_key_result = read_field<uchar>(socket);
    if (half_key_result.is_error) {
        free_user_keys(user_keys);
        delete[] username;
        username = nullptr;
        BIO_free(tmp_bio);
        throw half_key_result.error;
    }
    auto [client_half_key_len, client_half_key_bin] = half_key_result.result;

    // Write it to memory bio
    if (BIO_write(tmp_bio, client_half_key_bin, client_half_key_len) !=
        client_half_key_len) {
        free_user_keys(user_keys);
        delete[] username;
        username = nullptr;
        BIO_free(tmp_bio);
        handle_errors();
    }

    // ... and extract it as the client half key
    auto client_half_key =
        PEM_read_bio_PUBKEY(tmp_bio, nullptr, nullptr, nullptr);
    if (client_half_key == nullptr) {
        free_user_keys(user_keys);
        delete[] username;
        username = nullptr;
        BIO_free(tmp_bio);
        handle_errors();
    }

#ifdef DEBUG
    cout << "Received PEM pubkey: " << endl;
    PEM_write_PUBKEY(stderr, client_half_key);
#endif

    // Send server name ("server")
    auto res = send_field(socket, sizeof(server_name), server_name);
    if (res.is_error) {
        free_user_keys(user_keys);
        delete[] username;
        username = nullptr;
        BIO_free(tmp_bio);
        EVP_PKEY_free(client_half_key);
        throw res.error;
    }

    // Send server half key

    // Send server certificate

    // Sign {g^x, g^y, C} with server's private key and send it

    // Receive client signature and check it

    // Derive shared key
}
