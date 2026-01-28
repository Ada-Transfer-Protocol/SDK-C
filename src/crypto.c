#include "internal.h"
#include <string.h>
#include <stdio.h>

// X25519 Keygen
int crypto_generate_x25519(EVP_PKEY **pkey, uint8_t *pub_bytes) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) return 0;
    
    if (EVP_PKEY_keygen_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); return 0; }
    if (EVP_PKEY_keygen(pctx, pkey) <= 0) { EVP_PKEY_CTX_free(pctx); return 0; }
    EVP_PKEY_CTX_free(pctx);

    // Use correct OpenSSL 3.0+ API
    size_t len = 32;
    if (EVP_PKEY_get_raw_public_key(*pkey, pub_bytes, &len) <= 0) return 0;
    return 1;
}

int crypto_compute_shared(EVP_PKEY *priv_key, const uint8_t *peer_pub_bytes, uint8_t *shared_secret) {
    EVP_PKEY *peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub_bytes, 32);
    if (!peer_key) return 0;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx) { EVP_PKEY_free(peer_key); return 0; }
    
    if (EVP_PKEY_derive_init(ctx) <= 0) goto err;
    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) goto err;
    
    size_t len = 32;
    if (EVP_PKEY_derive(ctx, shared_secret, &len) <= 0) goto err;
    
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_key);
    return 1;

err:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_key);
    return 0;
}

static int hkdf_expand(const uint8_t *secret, const uint8_t *info, size_t infolen, size_t outlen, uint8_t *out) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return 0;
    
    uint8_t salt[32] = {0}; // Fixed salt
    
    if (EVP_PKEY_derive_init(pctx) <= 0) goto err;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) goto err;
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, 32) <= 0) goto err;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, 32) <= 0) goto err;
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)infolen) <= 0) goto err;
    
    if (EVP_PKEY_derive(pctx, out, &outlen) <= 0) goto err;
    
    EVP_PKEY_CTX_free(pctx);
    return 1;
err:
    EVP_PKEY_CTX_free(pctx);
    return 0;
}

int crypto_hkdf_derive(const uint8_t *shared_secret, secure_session_t *session) {
    if(!hkdf_expand(shared_secret, (uint8_t*)"client_write", 12, 32, session->client_write_key)) return 0;
    if(!hkdf_expand(shared_secret, (uint8_t*)"server_write", 12, 32, session->server_write_key)) return 0;
    if(!hkdf_expand(shared_secret, (uint8_t*)"client_iv", 9, 12, session->client_iv_root)) return 0;
    if(!hkdf_expand(shared_secret, (uint8_t*)"server_iv", 9, 12, session->server_iv_root)) return 0;
    return 1;
}

static void compute_iv(uint8_t* iv, const uint8_t* root, uint64_t seq) {
    memcpy(iv, root, 12);
    for(int i=0; i<8; i++) {
        iv[4+i] ^= (seq >> (i*8)) & 0xFF; // Little Endian XOR
    }
}

int crypto_encrypt_gcm(secure_session_t *session, const uint8_t *plaintext, size_t plen, 
                       uint8_t *ciphertext, uint8_t *tag, uint64_t *out_seq) {
    *out_seq = session->my_sequence;
    
    uint8_t iv[12];
    const uint8_t *key = (session->role == 0) ? session->client_write_key : session->server_write_key;
    const uint8_t *iv_root = (session->role == 0) ? session->client_iv_root : session->server_iv_root;
    
    compute_iv(iv, iv_root, *out_seq);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return 0;
    
    int len;
    int ciphertext_len;
    
    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto err;
    if(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto err;
    
    if(EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plen) != 1) goto err;
    ciphertext_len = len;
    
    if(EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) goto err;
    ciphertext_len += len;
    
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) goto err;
    
    EVP_CIPHER_CTX_free(ctx);
    session->my_sequence++;
    return ciphertext_len;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int crypto_decrypt_gcm(secure_session_t *session, const uint8_t *ciphertext, size_t clen, 
                       const uint8_t *tag, uint64_t seq, uint8_t *plaintext) {
    
    uint8_t iv[12];
    // Peer's role is opposite
    const uint8_t *key = (session->role == 0) ? session->server_write_key : session->client_write_key;
    const uint8_t *iv_root = (session->role == 0) ? session->server_iv_root : session->client_iv_root;
    
    compute_iv(iv, iv_root, seq);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return 0;
    
    int len;
    int plaintext_len;
    
    if(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto err;
    if(EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto err;
    
    if(EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, clen) != 1) goto err;
    plaintext_len = len;
    
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) goto err;
    
    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    
    if (ret > 0) {
        if (seq >= session->peer_sequence) session->peer_sequence = seq + 1;
        plaintext_len += len;
        return plaintext_len;
    } else {
        return -1;
    }
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}
