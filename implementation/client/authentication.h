#include <openssl/bio.h>
#include <openssl/evp.h>

#ifndef authentication_h
#define authentication_h
/*
 * Runs the authentication protocol with the entity on the other side of the
 * passed socket.
 *
 * Returns the key shared with the other party of len [key_len], if the run was
 * successful. If the run failed, it aborts the program execution.
 */
unsigned char *authenticate(BIO *socket, int key_len);
void get_dh_pubkey(EVP_PKEY *priv_key);
#endif
