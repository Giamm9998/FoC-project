#include "../../common/errors.h"
#include "../../common/seq.h"
#include "../../common/types.h"
#include "../../common/utils.h"
#include <filesystem>
#include <openssl/evp.h>
#include <string.h>

#define RENAME_OK 0
#define FILE_NOT_FOUND 1
#define ILLEGAL_PATH 2

using namespace std;

bool is_path_illegal(string path) {
    return path.find("..") != string::npos || path.find("/") != string::npos;
}

int handle_renaming(unsigned char *msg, int msg_len, char *username) {
    // split msg in f_old and f_new
    string f_old = "lol.txt";
    string f_new = "xoxo.txt";

    // check if old filename is illegal TODO: con realpath
    if (is_path_illegal(f_old)) {
        cout << "ILLEGAL PATH";
        return ILLEGAL_PATH;
    }

    // check if file exists
    string user(username);
    string path = filesystem::path("server/storage/" + user + "/");
    if (!filesystem::exists(path + f_old)) {
        cout << "FILE NOT FOUND";
        return FILE_NOT_FOUND;
    }

    // check if new filename is illegal
    if (is_path_illegal(f_new)) {
        cout << "ILLEGAL PATH";
        return ILLEGAL_PATH;
    }

    // renaming
    filesystem::rename(path + f_old, path + f_new);

    return RENAME_OK;
}

void rename(int sock, unsigned char *key, char *username) {

    // -----------receive client list request-----------

    auto server_header_res = read_header(sock);
    if (server_header_res.is_error) {
        handle_errors();
    }
    auto [seq, iv] = server_header_res.result;

    if (seq != seq_num) {
        delete[] iv;
        handle_errors("Incorrect sequence number");
    }

    // read ciphertext
    auto ct_res = read_field<uchar>(sock);
    if (ct_res.is_error) {
        delete[] iv;
        handle_errors("Incorrect message type");
    }
    auto [ct_len, ct] = ct_res.result;
    auto *pt = new unsigned char[ct_len];

    // read tag
    auto tag_res = read_field<uchar>(sock);
    if (tag_res.is_error) {
        delete[] ct;
        delete[] pt;
        delete[] iv;
        handle_errors("Incorrect message type");
    }
    auto [_, tag] = tag_res.result;

    // Initialize decryption
    EVP_CIPHER_CTX *ctx;
    if ((ctx = EVP_CIPHER_CTX_new()) == nullptr) {
        delete[] iv;
        delete[] ct;
        delete[] tag;
        delete[] pt;
        handle_errors("Could not decrypt message (alloc)");
    }
    int len;

    if (EVP_DecryptInit(ctx, get_symmetric_cipher(), key, iv) != 1) {
        delete[] iv;
        delete[] ct;
        delete[] tag;
        delete[] pt;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    delete[] iv;

    unsigned char header = mtype_to_uc(RenameReq);

    /* Specify authenticated data */
    int err = 0;
    err |= EVP_DecryptUpdate(ctx, nullptr, &len, &header, sizeof(mtype));
    err |=
        EVP_DecryptUpdate(ctx, nullptr, &len, seqnum_to_uc(), sizeof(seqnum));

    if (err != 1) {
        delete[] ct;
        delete[] tag;
        delete[] pt;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    int pt_len;
    // Encrypt Update: one call is enough because our mesage is very short.
    if (EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len) != 1) {
        delete[] ct;
        delete[] tag;
        delete[] pt;
        EVP_CIPHER_CTX_free(ctx);
    }
    pt_len = len;

    // GCM tag check
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);

    // Encrypt Final. Finalize the encryption and adds the padding
    if (EVP_DecryptFinal(ctx, pt + len, &len) != 1) {
        delete[] ct;
        delete[] tag;
        delete[] pt;
        EVP_CIPHER_CTX_free(ctx);
    }
    pt_len += len;

    // free variables
    delete[] ct;
    delete[] tag;

    // free context
    EVP_CIPHER_CTX_free(ctx);

    inc_seqnum();

#ifdef DEBUG
    cout << endl << GREEN << "f_old || f_new: ";
    for (int i = 0; i < pt_len; i++)
        printf("%c", pt[i]);
    cout << RESET << endl;
#endif

    // handle renaming
    handle_renaming(pt, pt_len, username);
}