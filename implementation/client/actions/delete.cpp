#include "../../common/errors.h"
#include "../../common/seq.h"
#include "../../common/types.h"
#include "../../common/utils.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

#define CONF_LEN 3

void delete_file(int sock, unsigned char *key) {
    unsigned char f[FNAME_MAX_LEN] = {0};

    cout << "File to delete: ";
    if (fgets((char *)f, FNAME_MAX_LEN, stdin) == nullptr) {
        handle_errors();
    }
    f[strcspn((char *)f, "\n")] = '\0';

    // Generate iv for message
    auto iv_res = gen_iv();
    if (iv_res.is_error) {
        handle_errors(iv_res.error);
    }
    auto iv = iv_res.result;

    // Send delete request
    auto send_packet_header_res =
        send_header(sock, DeleteReq, seq_num, iv, get_iv_len());
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
    unsigned char header = mtype_to_uc(DeleteReq);
    err |=
        EVP_EncryptUpdate(ctx, nullptr, &len, &header, sizeof(unsigned char));
    err |=
        EVP_EncryptUpdate(ctx, nullptr, &len, seqnum_to_uc(), sizeof(seqnum));
    if (err != 1) {
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    // Actual encryption
    // Encrypt 128 bytes for f
    unsigned char *ct = new unsigned char[FNAME_MAX_LEN + get_block_size()];
    if (EVP_EncryptUpdate(ctx, ct, &len, f, FNAME_MAX_LEN) != 1) {
        delete[] iv;
        delete[] ct;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    ct_len = len;

    // Finalize encryption
    if (EVP_EncryptFinal(ctx, ct + ct_len, &len) != 1) {
        delete[] iv;
        delete[] ct;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    ct_len += len;

    unsigned char *tag = new unsigned char[TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag) != 1) {
        delete[] iv;
        delete[] ct;
        delete[] tag;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    delete[] iv;
    EVP_CIPHER_CTX_free(ctx);

    // Send ciphertext
    auto ct_send_res = send_field(sock, (flen)ct_len, ct);
    if (ct_send_res.is_error) {
        delete[] ct;
        delete[] tag;
        handle_errors(ct_send_res.error);
    }
    delete[] ct;

    auto tag_send_res = send_field(sock, (flen)TAG_LEN, tag);
    if (tag_send_res.is_error) {
        delete[] tag;
        handle_errors(tag_send_res.error);
    }
    delete[] tag;

    inc_seqnum();

    //------------------Wait server response------------------

    auto mtype_res = get_mtype(sock);
    if (mtype_res.is_error || mtype_res.result != DeleteConfirm) {
        handle_errors("Incorrect message type");
    }

    // read iv and sequence number
    auto server_header_res = read_header(sock);
    if (server_header_res.is_error) {
        handle_errors();
    }
    auto [seq, in_iv] = server_header_res.result;
    iv = in_iv;

    // Check correctness of the sequence number
    if (seq != seq_num) {
        delete[] iv;
        handle_errors("Incorrect sequence number");
    }

    // read ciphertext
    auto ct_res = read_field<uchar>(sock);
    if (ct_res.is_error) {
        delete[] iv;
        handle_errors();
    }
    auto ct_tuple = ct_res.result;
    ct_len = get<0>(ct_tuple);
    ct = get<1>(ct_tuple);

    // Allocate plaintext of the length == ciphertext length
    auto *pt = new unsigned char[ct_len];

    // read tag
    auto tag_res = read_field<uchar>(sock);
    if (tag_res.is_error) {
        delete[] ct;
        delete[] pt;
        delete[] iv;
        handle_errors();
    }
    tag = get<1>(tag_res.result);

    // Initialize decryption
    if ((ctx = EVP_CIPHER_CTX_new()) == nullptr) {
        delete[] iv;
        delete[] ct;
        delete[] tag;
        delete[] pt;
        handle_errors("Could not decrypt message (alloc)");
    }

    if (EVP_DecryptInit(ctx, get_symmetric_cipher(), key, iv) != 1) {
        delete[] iv;
        delete[] ct;
        delete[] tag;
        delete[] pt;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    delete[] iv;

    header = mtype_to_uc(mtype_res.result);

    /* Specify authenticated data */
    err = 0;
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

    // free context
    EVP_CIPHER_CTX_free(ctx);

    inc_seqnum();

    // ------------------Confirm deletion----------------------

    // No need to continue if there is an error TODO: change with header error
    cout << endl << pt << endl;
    if (strstr((char *)pt, "Error")) {
        return;
    }
    unsigned char confirm[CONF_LEN] = {0};
    if (fgets((char *)confirm, CONF_LEN, stdin) == nullptr) {
        handle_errors();
    }
    confirm[strcspn((char *)confirm, "\n")] = '\0';

#ifdef DEBUG
    // Check whether confirmation is yes (y)
    if (strncmp((char *)confirm, "y", 1) != 0) {
        cout << "Deletion NOT confirmed" << endl << endl;
    } else {
        cout << "Deletion confimed";
    }
#endif

    // Generate iv for message
    iv_res = gen_iv();
    if (iv_res.is_error) {
        handle_errors(iv_res.error);
    }
    iv = iv_res.result;

    // Send delete request
    send_packet_header_res =
        send_header(sock, DeleteRes, seq_num, iv, get_iv_len());
    if (send_packet_header_res.is_error) {
        delete[] iv;
        handle_errors(send_packet_header_res.error);
    }

    // Initialize encryption context
    if ((ctx = EVP_CIPHER_CTX_new()) == nullptr) {
        delete[] iv;
        handle_errors("Could not encrypt message (alloc)");
    }

    if (EVP_EncryptInit(ctx, get_symmetric_cipher(), key, iv) != 1) {
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    err = 0;
    header = mtype_to_uc(DeleteRes);
    err |=
        EVP_EncryptUpdate(ctx, nullptr, &len, &header, sizeof(unsigned char));
    err |=
        EVP_EncryptUpdate(ctx, nullptr, &len, seqnum_to_uc(), sizeof(seqnum));
    if (err != 1) {
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    // Actual encryption
    // Encrypt 128 bytes for confirmation
    ct = new unsigned char[CONF_LEN + get_block_size()];
    if (EVP_EncryptUpdate(ctx, ct, &len, confirm, CONF_LEN) != 1) {
        delete[] iv;
        delete[] ct;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    ct_len = len;

    // Finalize encryption
    if (EVP_EncryptFinal(ctx, ct + ct_len, &len) != 1) {
        delete[] iv;
        delete[] ct;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    ct_len += len;

    tag = new unsigned char[TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag) != 1) {
        delete[] iv;
        delete[] ct;
        delete[] tag;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    delete[] iv;
    EVP_CIPHER_CTX_free(ctx);

    // Send ciphertext
    ct_send_res = send_field(sock, (flen)ct_len, ct);
    if (ct_send_res.is_error) {
        delete[] ct;
        delete[] tag;
        handle_errors(ct_send_res.error);
    }
    delete[] ct;

    tag_send_res = send_field(sock, (flen)TAG_LEN, tag);
    if (tag_send_res.is_error) {
        delete[] tag;
        handle_errors(tag_send_res.error);
    }
    delete[] tag;

    inc_seqnum();

    //------------------Wait server response------------------

    mtype_res = get_mtype(sock);
    if (mtype_res.is_error || mtype_res.result != DeleteAns) {
        handle_errors("Incorrect message type");
    }

    // read iv and sequence number
    server_header_res = read_header(sock);
    if (server_header_res.is_error) {
        handle_errors();
    }
    seq = get<0>(server_header_res.result);
    in_iv = get<1>(server_header_res.result);
    iv = in_iv;

    // Check correctness of the sequence number
    if (seq != seq_num) {
        delete[] iv;
        handle_errors("Incorrect sequence number");
    }

    // read ciphertext
    ct_res = read_field<uchar>(sock);
    if (ct_res.is_error) {
        delete[] iv;
        handle_errors();
    }
    ct_tuple = ct_res.result;
    ct_len = get<0>(ct_tuple);
    ct = get<1>(ct_tuple);

    // Allocate plaintext of the length == ciphertext length
    pt = new unsigned char[ct_len];

    // read tag
    tag_res = read_field<uchar>(sock);
    if (tag_res.is_error) {
        delete[] ct;
        delete[] pt;
        delete[] iv;
        handle_errors();
    }
    tag = get<1>(tag_res.result);

    // Initialize decryption
    if ((ctx = EVP_CIPHER_CTX_new()) == nullptr) {
        delete[] iv;
        delete[] ct;
        delete[] tag;
        delete[] pt;
        handle_errors("Could not decrypt message (alloc)");
    }

    if (EVP_DecryptInit(ctx, get_symmetric_cipher(), key, iv) != 1) {
        delete[] iv;
        delete[] ct;
        delete[] tag;
        delete[] pt;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    delete[] iv;

    header = mtype_to_uc(mtype_res.result);

    /* Specify authenticated data */
    err = 0;
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

    // free context
    EVP_CIPHER_CTX_free(ctx);

    inc_seqnum();

    cout << endl << pt << endl;
}