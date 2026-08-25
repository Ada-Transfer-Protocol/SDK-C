#include "adatp.h"
#include "internal.h"
#include "ws.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

struct adatp_client {
    ws_conn_t* ws;
    char* host;
    int port;
    char* path;
    int connected;
    secure_session_t session;
    uint8_t session_id[16];
    char locale[6]; // SDK language, e.g. "en", "tr"
    int use_v2;                      // 1 when a server key is pinned (v2 handshake)
    uint8_t pinned_server_key[32];   // the pinned Ed25519 identity (spk_S)
};

// --- Protocol v2 (authenticated handshake) constants ---
#define ADATP_PROTOCOL_V2 2
// 18 bytes, no NUL in the hashed input.
static const uint8_t ADATP_LABEL_HS[18] = "AdaTP-v2-handshake";
// 17 bytes.
static const uint8_t ADATP_FINISHED_LABEL[17] = "AdaTP-v2-finished";

// Serialize the 45-byte frame header (little-endian, wire layout). Used as the
// AEAD AAD in v2 — must match the server's PacketHeader::header_bytes() exactly.
static void serialize_header(const adatp_header_t* h, uint8_t out[45]) {
    out[0] = h->magic & 0xFF; out[1] = (h->magic >> 8) & 0xFF;
    out[2] = (h->magic >> 16) & 0xFF; out[3] = (h->magic >> 24) & 0xFF;
    out[4] = h->version;
    out[5] = h->flags & 0xFF; out[6] = (h->flags >> 8) & 0xFF;
    out[7] = h->length & 0xFF; out[8] = (h->length >> 8) & 0xFF;
    out[9] = (h->length >> 16) & 0xFF; out[10] = (h->length >> 24) & 0xFF;
    for (int i = 0; i < 8; i++) out[11 + i] = (h->sequence >> (i * 8)) & 0xFF;
    out[19] = h->msg_type & 0xFF; out[20] = (h->msg_type >> 8) & 0xFF;
    for (int i = 0; i < 8; i++) out[21 + i] = (h->timestamp >> (i * 8)) & 0xFF;
    memcpy(out + 29, h->session_id, 16);
}

// th = SHA-256(LABEL_HS || 0x02 || epk_c || epk_s || spk_s).
static int v2_transcript_hash(const uint8_t epk_c[32], const uint8_t epk_s[32],
                              const uint8_t spk_s[32], uint8_t th[32]) {
    uint8_t buf[18 + 1 + 32 + 32 + 32];
    size_t o = 0;
    memcpy(buf + o, ADATP_LABEL_HS, 18); o += 18;
    buf[o++] = ADATP_PROTOCOL_V2;
    memcpy(buf + o, epk_c, 32); o += 32;
    memcpy(buf + o, epk_s, 32); o += 32;
    memcpy(buf + o, spk_s, 32); o += 32;
    return crypto_sha256(buf, o, th);
}

// Pin the server's long-term Ed25519 identity (spk_S, 32 bytes). Enabling this
// switches connect() to the authenticated v2 handshake: the client verifies the
// server's signature over the transcript before deriving any key.
void adatp_client_set_server_key(adatp_client_t* client, const uint8_t server_key[32]) {
    if (!client || !server_key) return;
    memcpy(client->pinned_server_key, server_key, 32);
    client->use_v2 = 1;
}

static const char* ADATP_SDK_LOCALES[] = {
    "en", "tr", "it", "fr", "de", "zh", "ja", "hi", "ar", NULL,
};

void adatp_client_set_locale(adatp_client_t* client, const char* locale) {
    if (!client) return;
    const char* chosen = "en";
    if (locale) {
        for (int i = 0; ADATP_SDK_LOCALES[i]; i++) {
            if (strcmp(ADATP_SDK_LOCALES[i], locale) == 0) { chosen = ADATP_SDK_LOCALES[i]; break; }
        }
    }
    snprintf(client->locale, sizeof(client->locale), "%s", chosen);
}

const char* adatp_client_get_locale(const adatp_client_t* client) {
    return client && client->locale[0] ? client->locale : "en";
}

adatp_client_t* adatp_client_create(const char* host, int port) {
    adatp_client_t* client = calloc(1, sizeof(adatp_client_t));
    if (!client) return NULL;
    client->host = strdup(host);
    client->port = port > 0 ? port : 3000;
    client->path = strdup("/ws");
    snprintf(client->locale, sizeof(client->locale), "en");
    client->ws = NULL;
    client->connected = 0;
    RAND_bytes(client->session_id, 16);
    return client;
}

void adatp_client_destroy(adatp_client_t* client) {
    if (client) {
        if (client->connected) adatp_client_disconnect(client);
        free(client->host);
        free(client->path);
        free(client);
    }
}

// Serializes and sends one packet as a single WebSocket binary message.
static int send_raw_packet(adatp_client_t* client, adatp_packet_t* packet) {
    size_t size = adatp_packet_serialized_size(packet);
    uint8_t* buf = malloc(size);
    if (!buf) return -1;
    adatp_packet_serialize(packet, buf);
    int rc = ws_send_binary(client->ws, buf, size);
    free(buf);
    return rc;
}

// Reads one packet from the next WebSocket binary message.
// packet->payload is malloc'd; caller frees.
int adatp_client_read_packet(adatp_client_t* client, adatp_packet_t* packet) {
    uint8_t* frame = NULL;
    size_t frame_len = 0;
    if (ws_recv_binary(client->ws, &frame, &frame_len) != 0) return -1;
    if (frame_len < ADATP_HEADER_SIZE) { free(frame); return -1; }

    // Little-endian host assumed (x86/ARM). Offsets per the 45-byte header.
    memcpy(&packet->header.magic, frame, 4);
    packet->header.version = frame[4];
    memcpy(&packet->header.flags, frame + 5, 2);
    memcpy(&packet->header.length, frame + 7, 4);
    memcpy(&packet->header.sequence, frame + 11, 8);
    memcpy(&packet->header.msg_type, frame + 19, 2);
    memcpy(&packet->header.timestamp, frame + 21, 8);
    memcpy(packet->header.session_id, frame + 29, 16);

    if (packet->header.magic != ADATP_MAGIC_NUMBER) { free(frame); return -1; }

    size_t need = ADATP_HEADER_SIZE + (size_t)packet->header.length +
                  ((packet->header.flags & ADATP_FLAG_ENCRYPTED) ? 16 : 0);
    if (frame_len < need) { free(frame); return -1; }

    packet->payload = NULL;
    if (packet->header.length > 0) {
        packet->payload = malloc(packet->header.length);
        if (!packet->payload) { free(frame); return -1; }
        memcpy(packet->payload, frame + ADATP_HEADER_SIZE, packet->header.length);
    }
    if (packet->header.flags & ADATP_FLAG_ENCRYPTED) {
        memcpy(packet->auth_tag, frame + ADATP_HEADER_SIZE + packet->header.length, 16);
    }
    free(frame);
    return 0;
}

// Waits for a packet of one of `types` (n types); other packets are
// discarded (their payloads freed). Returns 0 and fills `packet`.
static int read_packet_of_type(adatp_client_t* client, const uint16_t* types, size_t n,
                               adatp_packet_t* packet) {
    for (int guard = 0; guard < 256; guard++) {
        if (adatp_client_read_packet(client, packet) != 0) return -1;
        for (size_t i = 0; i < n; i++) {
            if (packet->header.msg_type == types[i]) return 0;
        }
        free(packet->payload);
        packet->payload = NULL;
    }
    return -1;
}

// Protocol v2 — authenticated handshake against the pinned server identity.
// The server signs the transcript; we verify (pin + signature) BEFORE deriving
// keys, then send an encrypted, AAD-bound Finished that binds the transcript.
static int handshake_v2(adatp_client_t* client, EVP_PKEY* my_key, const uint8_t my_pub[32]) {
    // 1. HANDSHAKE_INIT (version=2) carries our ephemeral public key.
    adatp_packet_t init_pkt;
    memset(&init_pkt, 0, sizeof(init_pkt));
    init_pkt.header.magic = ADATP_MAGIC_NUMBER;
    init_pkt.header.version = ADATP_PROTOCOL_V2;
    init_pkt.header.msg_type = ADATP_MSG_HANDSHAKE_INIT;
    init_pkt.header.length = 32;
    memcpy(init_pkt.header.session_id, client->session_id, 16);
    init_pkt.payload = (uint8_t*)my_pub;
    send_raw_packet(client, &init_pkt);

    // 2. HANDSHAKE_RESPONSE = epk_s(32) || spk_s(32) || sig(64).
    adatp_packet_t resp;
    uint16_t want[] = { ADATP_MSG_HANDSHAKE_RESPONSE };
    if (read_packet_of_type(client, want, 1, &resp) != 0) return -3;
    if (resp.header.length != 128) {
        printf("v2: malformed ServerHello (len %u, want 128)\n", resp.header.length);
        free(resp.payload);
        return -3;
    }
    const uint8_t* epk_s = resp.payload;
    const uint8_t* spk_s = resp.payload + 32;
    const uint8_t* sig   = resp.payload + 64;

    // 3a. Identity pin: the offered key MUST equal the pinned key.
    if (memcmp(spk_s, client->pinned_server_key, 32) != 0) {
        printf("v2: server key does not match the pinned key (unknown identity)\n");
        free(resp.payload);
        return -6;
    }
    // 3b. Authenticity: the signature MUST verify over the transcript.
    uint8_t th[32];
    if (!v2_transcript_hash(my_pub, epk_s, spk_s, th)) { free(resp.payload); return -6; }
    if (!crypto_ed25519_verify(spk_s, th, 32, sig)) {
        printf("v2: server signature did not verify\n");
        free(resp.payload);
        return -6;
    }

    // 4. Only now derive the shared secret + session keys.
    uint8_t shared[32];
    if (!crypto_compute_shared(my_key, epk_s, shared)) { free(resp.payload); return -4; }
    free(resp.payload);

    memset(&client->session, 0, sizeof(secure_session_t));
    client->session.role = 0;
    client->session.my_sequence = 1;
    client->session.peer_sequence = 1;
    crypto_hkdf_derive(shared, &client->session);

    // 5. HANDSHAKE_COMPLETE: Finished = FINISHED_LABEL || th, encrypted + header-AAD.
    uint8_t fin[17 + 32];
    memcpy(fin, ADATP_FINISHED_LABEL, 17);
    memcpy(fin + 17, th, 32);

    adatp_packet_t cur;
    memset(&cur, 0, sizeof(cur));
    cur.header.magic = ADATP_MAGIC_NUMBER;
    cur.header.version = ADATP_PROTOCOL_V2;
    cur.header.msg_type = ADATP_MSG_HANDSHAKE_COMPLETE;
    cur.header.flags = ADATP_FLAG_ENCRYPTED;
    cur.header.length = (uint32_t)sizeof(fin);
    cur.header.sequence = client->session.my_sequence;
    memcpy(cur.header.session_id, client->session_id, 16);

    uint8_t aad[45];
    serialize_header(&cur.header, aad);

    uint8_t ciphertext[64];
    uint8_t tag[16];
    uint64_t seq;
    int clen = crypto_encrypt_gcm(&client->session, fin, sizeof(fin), aad, 45, ciphertext, tag, &seq);
    if (clen < 0) return -5;
    cur.header.length = clen;
    cur.header.sequence = seq;
    cur.payload = ciphertext;
    memcpy(cur.auth_tag, tag, 16);
    send_raw_packet(client, &cur);

    printf("C Client: v2 authenticated handshake complete (pinned key verified).\n");
    return 0;
}

int adatp_client_connect(adatp_client_t* client) {
    client->ws = ws_connect(client->host, client->port, client->path);
    if (!client->ws) return -1;
    client->connected = 1;

    printf("C Client: Connected to ws://%s:%d%s, starting handshake...\n",
           client->host, client->port, client->path);

    // 1. Ephemeral X25519 key pair
    EVP_PKEY *my_key = NULL;
    uint8_t my_pub[32];
    if (!crypto_generate_x25519(&my_key, my_pub)) {
        printf("Keygen failed\n");
        return -2;
    }

    // Authenticated v2 handshake when a server key is pinned.
    if (client->use_v2) {
        int rc = handshake_v2(client, my_key, my_pub);
        EVP_PKEY_free(my_key);
        return rc;
    }

    // 2. HANDSHAKE_INIT carries our public key
    adatp_packet_t init_pkt;
    memset(&init_pkt, 0, sizeof(init_pkt));
    init_pkt.header.magic = ADATP_MAGIC_NUMBER;
    init_pkt.header.version = 1;
    init_pkt.header.msg_type = ADATP_MSG_HANDSHAKE_INIT;
    init_pkt.header.length = 32;
    memcpy(init_pkt.header.session_id, client->session_id, 16);
    init_pkt.payload = my_pub;
    send_raw_packet(client, &init_pkt);

    // 3. HANDSHAKE_RESPONSE carries the server's public key
    adatp_packet_t resp_pkt;
    uint16_t want_resp[] = { ADATP_MSG_HANDSHAKE_RESPONSE };
    if (read_packet_of_type(client, want_resp, 1, &resp_pkt) != 0) { EVP_PKEY_free(my_key); return -3; }
    if (resp_pkt.header.length < 32) {
        printf("Server did not provide a key\n");
        free(resp_pkt.payload);
        EVP_PKEY_free(my_key);
        return -3;
    }

    // 4. Shared secret
    uint8_t shared_secret[32];
    if (!crypto_compute_shared(my_key, resp_pkt.payload, shared_secret)) {
        printf("Shared secret failed\n");
        free(resp_pkt.payload);
        EVP_PKEY_free(my_key);
        return -4;
    }
    EVP_PKEY_free(my_key);
    free(resp_pkt.payload);

    // 5. Session keys
    memset(&client->session, 0, sizeof(secure_session_t));
    client->session.role = 0; // client
    client->session.my_sequence = 1;
    client->session.peer_sequence = 1;
    crypto_hkdf_derive(shared_secret, &client->session);

    // 6. HANDSHAKE_COMPLETE proves both sides derived the same keys
    uint8_t verify_plain[] = "Verification OK";
    uint8_t ciphertext[64];
    uint8_t tag[16];
    uint64_t seq;
    int clen = crypto_encrypt_gcm(&client->session, verify_plain,
                                  strlen((char*)verify_plain), NULL, 0, ciphertext, tag, &seq);
    if (clen < 0) return -5;

    adatp_packet_t cur;
    memset(&cur, 0, sizeof(cur));
    cur.header.magic = ADATP_MAGIC_NUMBER;
    cur.header.version = 1;
    cur.header.msg_type = ADATP_MSG_HANDSHAKE_COMPLETE;
    cur.header.flags = ADATP_FLAG_ENCRYPTED;
    cur.header.length = clen;
    cur.header.sequence = seq;
    memcpy(cur.header.session_id, client->session_id, 16);
    cur.payload = ciphertext;
    memcpy(cur.auth_tag, tag, 16);
    send_raw_packet(client, &cur);

    printf("C Client: Handshake complete.\n");
    return 0;
}

void adatp_client_disconnect(adatp_client_t* client) {
    if (client->ws) {
        adatp_packet_t pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.header.magic = ADATP_MAGIC_NUMBER;
        pkt.header.version = 1;
        pkt.header.msg_type = ADATP_MSG_DISCONNECT;
        pkt.header.length = 0;
        memcpy(pkt.header.session_id, client->session_id, 16);
        pkt.payload = NULL;
        send_raw_packet(client, &pkt);

        ws_close(client->ws);
        client->ws = NULL;
    }
    client->connected = 0;
}

// Encrypts and sends a packet of the given type.
static int send_encrypted(adatp_client_t* client, uint16_t type,
                          const uint8_t* payload, size_t len) {
    if (!client->ws || len > 4096) return -1;

    // Build the header first; a v2 session binds it as AEAD AAD. For GCM the
    // ciphertext length equals the plaintext length, so the header is final
    // before we encrypt (only the returned sequence is echoed back, unchanged).
    adatp_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.header.magic = ADATP_MAGIC_NUMBER;
    pkt.header.version = 1;
    pkt.header.msg_type = type;
    pkt.header.flags = ADATP_FLAG_ENCRYPTED;
    pkt.header.length = (uint32_t)len;
    pkt.header.sequence = client->session.my_sequence;
    memcpy(pkt.header.session_id, client->session_id, 16);

    uint8_t aad[45];
    const uint8_t* aad_ptr = NULL;
    size_t aad_len = 0;
    if (client->use_v2) {
        serialize_header(&pkt.header, aad);
        aad_ptr = aad;
        aad_len = 45;
    }

    uint8_t ciphertext[4128];
    uint8_t tag[16];
    uint64_t seq;
    int clen = crypto_encrypt_gcm(&client->session, payload, len, aad_ptr, aad_len,
                                  ciphertext, tag, &seq);
    if (clen < 0) return -1;

    pkt.header.length = clen;
    pkt.header.sequence = seq;
    pkt.payload = ciphertext;
    memcpy(pkt.auth_tag, tag, 16);

    return send_raw_packet(client, &pkt);
}

int adatp_client_authenticate(adatp_client_t* client, const char* username, const char* password) {
    char json[512];
    snprintf(json, sizeof(json), "{\"username\": \"%s\", \"password\": \"%s\"}", username, password);

    if (send_encrypted(client, ADATP_MSG_AUTH_REQUEST, (uint8_t*)json, strlen(json)) != 0) return -1;

    adatp_packet_t resp;
    uint16_t want[] = { ADATP_MSG_AUTH_SUCCESS, ADATP_MSG_AUTH_FAILURE };
    if (read_packet_of_type(client, want, 2, &resp) != 0) return -2;

    uint8_t plain[1024];
    int plen = adatp_client_decrypt_packet(client, &resp, plain);
    free(resp.payload);
    if (plen < 0 || plen >= (int)sizeof(plain)) return -3;
    plain[plen] = 0;

    if (resp.header.msg_type == ADATP_MSG_AUTH_SUCCESS) {
        printf("Auth success: %s\n", plain);
        return 0;
    }
    printf("Auth failed: %s\n", plain);
    return -4;
}

int adatp_client_join_room(adatp_client_t* client, const char* room) {
    if (send_encrypted(client, ADATP_MSG_JOIN_ROOM, (uint8_t*)room, strlen(room)) != 0) return -1;

    // Wait for the server's confirmation.
    adatp_packet_t resp;
    uint16_t want[] = { ADATP_MSG_ROOM_JOINED, ADATP_MSG_AUTH_FAILURE };
    if (read_packet_of_type(client, want, 2, &resp) != 0) return -2;

    int ok = (resp.header.msg_type == ADATP_MSG_ROOM_JOINED) ? 0 : -3;
    free(resp.payload);
    return ok;
}

int adatp_client_send_text(adatp_client_t* client, const char* text) {
    return send_encrypted(client, ADATP_MSG_TEXT_MESSAGE, (uint8_t*)text, strlen(text));
}

int adatp_client_send(adatp_client_t* client, adatp_msg_type_t type, const uint8_t* payload, size_t len) {
    if (!client) return -1;
    return send_encrypted(client, (uint16_t)type, payload, len);
}

int adatp_client_get_socket(adatp_client_t* client) {
    return ws_get_fd(client->ws);
}

int adatp_client_decrypt_packet(adatp_client_t* client, const adatp_packet_t* packet, uint8_t* out_buf) {
    if (!packet->payload && packet->header.length > 0) return -1;
    if (!(packet->header.flags & ADATP_FLAG_ENCRYPTED)) {
        if (packet->header.length > 0) memcpy(out_buf, packet->payload, packet->header.length);
        return packet->header.length;
    }

    uint8_t aad[45];
    const uint8_t* aad_ptr = NULL;
    size_t aad_len = 0;
    if (client->use_v2) {
        serialize_header(&packet->header, aad);
        aad_ptr = aad;
        aad_len = 45;
    }

    return crypto_decrypt_gcm(
        &client->session,
        packet->payload,
        packet->header.length,
        aad_ptr,
        aad_len,
        packet->auth_tag,
        packet->header.sequence,
        out_buf
    );
}
