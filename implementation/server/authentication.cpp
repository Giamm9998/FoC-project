#include "authentication.h"
#include "../common/utils.h"
#include <new>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string.h>
#include <tuple>

using namespace std;

// TODO!
unsigned char *authenticate(BIO *socket, int key_len) {
    auto [username_len, username] = read_field<char>(socket);

#ifdef DEBUG
    cout << "Username length: " << username_len << endl;
    cout << "Username: " << username << endl;
#endif
}
