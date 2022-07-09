#include "../../common/errors.h"
#include "../../common/seq.h"
#include "../../common/types.h"
#include "../../common/utils.h"
#include <filesystem>
#include <openssl/evp.h>
#include <string.h>

using namespace std;
namespace fs = std::filesystem;

void upload(int sock, unsigned char *key) {
    cout << "What do you want to upload? ";
    unsigned char filename[FNAME_MAX_LEN] = {0};
    if (fgets((char *)filename, FNAME_MAX_LEN, stdin) == nullptr) {
        handle_errors();
    }
    filename[strcspn((char *)filename, "\n")] = '\0';

    // Make sure that the file can be read before
    FILE *input_file_fp;
    if ((input_file_fp = fopen((char *)filename, "r")) == nullptr) {
        cout << "Error - Could not open input file for reading" << endl;
        return;
    }

    // Generate iv for message
    auto iv_res = gen_iv();
    if (iv_res.is_error) {
        handle_errors(iv_res.error);
    }
    auto iv = iv_res.result;

    // Send upload request
    auto send_packet_header_res =
        send_header(sock, UploadReq, seq_num, iv, get_iv_len());
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

    // Authenticated data
    int err = 0;
    unsigned char header = mtype_to_uc(UploadReq);
    err |=
        EVP_EncryptUpdate(ctx, nullptr, &len, &header, sizeof(unsigned char));
    err |=
        EVP_EncryptUpdate(ctx, nullptr, &len, seqnum_to_uc(), sizeof(seqnum));
    if (err != 1) {
        delete[] iv;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    // Encryption of the filename
    unsigned char *ct = new unsigned char[FNAME_MAX_LEN + get_block_size()];
    if (EVP_EncryptUpdate(ctx, ct, &len, filename, FNAME_MAX_LEN) != 1) {
        delete[] iv;
        delete[] ct;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    ct_len = len;

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
    EVP_CIPHER_CTX_reset(ctx);

    // Send ciphertext
    auto ct_send_res = send_field(sock, (flen)ct_len, ct);
    if (ct_send_res.is_error) {
        delete[] ct;
        delete[] tag;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors(ct_send_res.error);
    }
    delete[] ct;

    auto tag_send_res = send_field(sock, (flen)TAG_LEN, tag);
    if (tag_send_res.is_error) {
        delete[] tag;
        EVP_CIPHER_CTX_free(ctx);
        handle_errors(tag_send_res.error);
    }
    delete[] tag;

    inc_seqnum();

    //------------------Wait server response------------------

    auto mtype_res = get_mtype(sock);

    if (mtype_res.is_error ||
        (mtype_res.result != UploadAns && mtype_res.result != Error)) {
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

    delete[] ct;
    delete[] tag;

    // free context
    EVP_CIPHER_CTX_free(ctx);

    inc_seqnum();

    cout << endl << pt << endl;
    delete[] pt;
    if (mtype_res.result == Error) {
        return;
    }

    // Send the file 1KB at a time
    unsigned char buffer[CHUNK_SIZE] = {0};
    size_t read_len;
    ct = new unsigned char[sizeof(buffer) + get_block_size()];
    tag = new unsigned char[TAG_LEN];
    mtypes msg_type = UploadChunk;

    if ((ctx = EVP_CIPHER_CTX_new()) == nullptr) {
        delete[] ct;
        delete[] tag;
        fclose(input_file_fp);
        handle_errors("Could not encrypt message (alloc)");
    }

    for (;;) {
        if ((read_len = fread(buffer, sizeof(*buffer), sizeof(buffer),
                              input_file_fp)) != sizeof(buffer)) {
            // When we read less than expected we could either have an error, or
            // we could have reached eof
            if (feof(input_file_fp) != 0) {
                // Change message type, as this is the last chunk of data
                msg_type = UploadEnd;
            } else if (ferror(input_file_fp) != 0) {
                cout << endl << ferror(input_file_fp) << endl;
                delete[] ct;
                delete[] tag;
                fclose(input_file_fp);
                send_error_response(sock, key, "Error - Could not read file");
                return;
            } else {
                delete[] ct;
                delete[] tag;
                fclose(input_file_fp);
                send_error_response(sock, key, "Error - Cosmic rays uh?");
                return;
            }
        }
        // Generate iv for message
        auto iv_res = gen_iv();
        if (iv_res.is_error) {
            delete[] ct;
            delete[] tag;
            fclose(input_file_fp);
            handle_errors(iv_res.error);
        }
        iv = iv_res.result;

        // Send chunk header
        auto send_packet_header_res =
            send_header(sock, msg_type, seq_num, iv, get_iv_len());
        if (send_packet_header_res.is_error) {
            delete[] iv;
            delete[] ct;
            delete[] tag;
            fclose(input_file_fp);
            handle_errors(send_packet_header_res.error);
        }

        if (EVP_EncryptInit(ctx, get_symmetric_cipher(), key, iv) != 1) {
            delete[] iv;
            delete[] ct;
            delete[] tag;
            EVP_CIPHER_CTX_free(ctx);
            fclose(input_file_fp);
            handle_errors();
        }
        delete[] iv;

        // Authenticated data
        err = 0;
        unsigned char header = mtype_to_uc(msg_type);
        err |= EVP_EncryptUpdate(ctx, nullptr, &len, &header,
                                 sizeof(unsigned char));
        err |= EVP_EncryptUpdate(ctx, nullptr, &len, seqnum_to_uc(),
                                 sizeof(seqnum));
        if (err != 1) {
            delete[] ct;
            delete[] tag;
            EVP_CIPHER_CTX_free(ctx);
            fclose(input_file_fp);
            handle_errors();
        }

        // Encrypt the chunk
        if (EVP_EncryptUpdate(ctx, ct, &len, buffer, read_len) != 1) {
            delete[] ct;
            delete[] tag;
            EVP_CIPHER_CTX_free(ctx);
            fclose(input_file_fp);
            handle_errors();
        }
        ct_len = len;

        // Finalize encryption
        if (EVP_EncryptFinal(ctx, ct + ct_len, &len) != 1) {
            delete[] ct;
            delete[] tag;
            EVP_CIPHER_CTX_free(ctx);
            fclose(input_file_fp);
            handle_errors();
        }
        ct_len += len;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag) !=
            1) {
            delete[] ct;
            delete[] tag;
            EVP_CIPHER_CTX_free(ctx);
            fclose(input_file_fp);
            handle_errors();
        }

        // Send ciphertext
        auto ct_send_res = send_field(sock, (flen)ct_len, ct);
        if (ct_send_res.is_error) {
            delete[] ct;
            delete[] tag;
            EVP_CIPHER_CTX_free(ctx);
            fclose(input_file_fp);
            handle_errors(ct_send_res.error);
        }

        auto tag_send_res = send_field(sock, (flen)TAG_LEN, tag);
        if (tag_send_res.is_error) {
            delete[] tag;
            delete[] ct;
            EVP_CIPHER_CTX_free(ctx);
            fclose(input_file_fp);
            handle_errors(tag_send_res.error);
        }

        // At the end, reset the context and increase the sequence number
        EVP_CIPHER_CTX_reset(ctx);
        inc_seqnum();

        // We have reached EOF, thus the upload has ended
        // Note that we already sent the full file to the client, correctly
        // ending with a UploadEnd message
        if (feof(input_file_fp) != 0) {
            break;
        }
    }

    delete[] tag;
    delete[] ct;
    EVP_CIPHER_CTX_free(ctx);
    fclose(input_file_fp);

    //-------------Wait server response--------------

    mtype_res = get_mtype(sock);

    if (mtype_res.is_error || mtype_res.result != UploadRes) {
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

    pt_len;
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

    delete[] ct;
    delete[] tag;

    // free context
    EVP_CIPHER_CTX_free(ctx);

    inc_seqnum();

    cout << endl << pt << endl;
}