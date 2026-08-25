/*
 * v2 authenticated-handshake conformance for the C SDK.
 *
 * Replays the shared golden vectors
 * (tests/conformance/vectors/adatp-v2-handshake-vectors.json in the server repo)
 * against this SDK's crypto: the transcript hash and the Ed25519 signature
 * verification must be byte-identical to the Rust reference. No server needed.
 *
 * The values below are copied from that JSON (server seed 0x11*32 -> spk_s).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Exported by libadatp (src/crypto.c). */
extern int crypto_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
extern int crypto_ed25519_verify(const uint8_t pub[32], const uint8_t *msg, size_t msglen,
                                 const uint8_t sig[64]);

static int unhex(const char *h, uint8_t *out, size_t out_len) {
    if (strlen(h) != out_len * 2) return 0;
    for (size_t i = 0; i < out_len; i++) {
        unsigned v;
        if (sscanf(h + i * 2, "%2x", &v) != 1) return 0;
        out[i] = (uint8_t)v;
    }
    return 1;
}

/* --- golden vector (adatp-v2-handshake-vectors.json) --- */
static const char *SPK_S_HEX = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
static const char *EPK_C_HEX = "0101010101010101010101010101010101010101010101010101010101010101";
static const char *EPK_S_HEX = "0202020202020202020202020202020202020202020202020202020202020202";
static const char *TH_HEX    = "c1160ba8a8f18442927b9b70db0cd8ebab8c6ddfd5a1b8b1ea5ad2db86dc47e1";
static const char *SIG_HEX   =
    "d4fb201f891dc7136de3970189638f39aa6218860e047938befb5528ed85f9ee"
    "98dfdf2421f6ce3d62343b92ff8229f13d03ee03811f74a7e2f07f655da3830b";

static int failures = 0;
static void check(int cond, const char *name) {
    if (cond) { printf("  ok  %s\n", name); }
    else      { printf("  FAIL %s\n", name); failures++; }
}

int main(void) {
    uint8_t spk_s[32], epk_c[32], epk_s[32], want_th[32], sig[64];
    if (!unhex(SPK_S_HEX, spk_s, 32) || !unhex(EPK_C_HEX, epk_c, 32) ||
        !unhex(EPK_S_HEX, epk_s, 32) || !unhex(TH_HEX, want_th, 32) ||
        !unhex(SIG_HEX, sig, 64)) {
        printf("bad test vectors\n");
        return 2;
    }

    /* 1. transcript hash: th = SHA-256(LABEL || 0x02 || epk_c || epk_s || spk_s) */
    uint8_t tbuf[18 + 1 + 32 + 32 + 32];
    size_t o = 0;
    memcpy(tbuf + o, "AdaTP-v2-handshake", 18); o += 18;
    tbuf[o++] = 2;
    memcpy(tbuf + o, epk_c, 32); o += 32;
    memcpy(tbuf + o, epk_s, 32); o += 32;
    memcpy(tbuf + o, spk_s, 32); o += 32;
    uint8_t th[32];
    crypto_sha256(tbuf, o, th);
    check(memcmp(th, want_th, 32) == 0, "transcript hash matches Rust reference");

    /* 2. signature verifies under the pinned key */
    check(crypto_ed25519_verify(spk_s, th, 32, sig) == 1,
          "server signature verifies under spk_s");

    /* 3. tampered signature is rejected */
    uint8_t bad_sig[64];
    memcpy(bad_sig, sig, 64);
    bad_sig[10] ^= 0x01;
    check(crypto_ed25519_verify(spk_s, th, 32, bad_sig) == 0,
          "tampered signature rejected");

    /* 4. a different (wrong-pin) key does not verify the signature */
    uint8_t wrong_key[32];
    memset(wrong_key, 0, 32);
    check(crypto_ed25519_verify(wrong_key, th, 32, sig) == 0,
          "signature does not verify under a wrong key");

    /* 5. substituted transcript (e.g. attacker's epk_s) breaks verification */
    uint8_t th2[32];
    tbuf[19 + 32] ^= 0x01; /* flip a byte of epk_s in the transcript */
    crypto_sha256(tbuf, o, th2);
    check(crypto_ed25519_verify(spk_s, th2, 32, sig) == 0,
          "signature over a substituted-ephemeral transcript rejected");

    printf("\nC v2 handshake conformance: %s (%d failure%s)\n",
           failures == 0 ? "PASS" : "FAIL", failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
