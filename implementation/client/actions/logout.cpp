#include "../../common/errors.h"
#include "../../common/seq.h"
#include "../../common/types.h"
#include "../../common/utils.h"
#include <openssl/evp.h>

void logout(int sock, unsigned char *key) {

    // Generate iv for message
    auto iv_res = gen_iv();
    if (iv_res.is_error) {
        handle_errors(iv_res.error);
    }
    auto iv = iv_res.result;

    // Send logout request plaintext part
    auto send_packet_header_res =
        send_header(sock, LogoutReq, seq_num, iv, get_iv_len());
    if (send_packet_header_res.is_error) {
        delete[] iv;
        handle_errors(send_packet_header_res.error);
    }

    // Initialize encryption context
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int ct_len;
    if ((ctx = EVP_CIPHER_CTX_new()) == nullptr) {
        delete[] iv;
        handle_errors("Could not encrypt message (alloc)");
    }

    if (EVP_EncryptInit(ctx, get_symmetric_cipher(), key, iv) != 1) {
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    int err = 0;
    unsigned char header = mtype_to_uc(LogoutReq);
    err |=
        EVP_EncryptUpdate(ctx, nullptr, &len, &header, sizeof(unsigned char));
    err |=
        EVP_EncryptUpdate(ctx, nullptr, &len, seqnum_to_uc(), sizeof(seqnum));
    if (err != 1) {
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    // Get dummy value to encrypt
    auto dummy_res = get_dummy();
    if (dummy_res.is_error) {
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    auto dummy = dummy_res.result;

    unsigned char *ct = new unsigned char[DUMMY_LEN + get_block_size()];
    if (EVP_EncryptUpdate(ctx, ct, &len, dummy, DUMMY_LEN) != 1) {
        delete[] iv;
        delete[] dummy;
        delete[] ct;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    ct_len = len;

    if (EVP_EncryptFinal(ctx, ct + len, &len) != 1) {
        delete[] iv;
        delete[] dummy;
        delete[] ct;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    ct_len += len;

    unsigned char *tag = new unsigned char[TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag) != 1) {
        delete[] iv;
        delete[] dummy;
        delete[] ct;
        delete[] tag;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    delete[] iv;
    delete[] dummy;
    EVP_CIPHER_CTX_free(ctx);

    auto ct_send_res = send_field(sock, (flen)ct_len, ct);
    if (ct_send_res.is_error) {
        delete[] ct;
        delete[] tag;
        handle_errors(ct_send_res.error);
    }

    auto tag_send_res = send_field(sock, (flen)TAG_LEN, tag);
    if (tag_send_res.is_error) {
        delete[] ct;
        delete[] tag;
        handle_errors(tag_send_res.error);
    }

    // Manually increase sequence number without any check, otherwise we may
    // trigger the SIGUSR1 signal again
    seq_num++;
}
