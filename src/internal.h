#ifndef ADATP_INTERNAL_H
#define ADATP_INTERNAL_H

#include "adatp.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#define KEY_LEN 32
#define IV_LEN 12
#define TAG_LEN 16

typedef struct {
    uint8_t client_write_key[KEY_LEN];
    uint8_t server_write_key[KEY_LEN];
    uint8_t client_iv_root[IV_LEN];
    uint8_t server_iv_root[IV_LEN];
    uint64_t my_sequence;
    uint64_t peer_sequence;
    int role; // 0=Client, 1=Server
} secure_session_t;

// Crypto Helper Functions
int crypto_generate_x25519(EVP_PKEY **pkey, uint8_t *pub_bytes);
int crypto_compute_shared(EVP_PKEY *priv_key, const uint8_t *peer_pub_bytes, uint8_t *shared_secret);
int crypto_hkdf_derive(const uint8_t *shared_secret, secure_session_t *session);

int crypto_encrypt_gcm(secure_session_t *session, const uint8_t *plaintext, size_t plen, 
                       uint8_t *ciphertext, uint8_t *tag, uint64_t *out_seq);

int crypto_decrypt_gcm(secure_session_t *session, const uint8_t *ciphertext, size_t clen, 
                       const uint8_t *tag, uint64_t seq, uint8_t *plaintext);

// Serialization Helpers
void packet_encode(const adatp_packet_t* packet, uint8_t* buffer, size_t* len);
void packet_decode_header(const uint8_t* buffer, adatp_packet_t* packet); // Minimal header decode
// Full decode usually requires reading payload first based on header length

#endif
