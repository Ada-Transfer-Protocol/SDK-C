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
};

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
                                  strlen((char*)verify_plain), ciphertext, tag, &seq);
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

    uint8_t ciphertext[4128];
    uint8_t tag[16];
    uint64_t seq;
    int clen = crypto_encrypt_gcm(&client->session, payload, len, ciphertext, tag, &seq);
    if (clen < 0) return -1;

    adatp_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.header.magic = ADATP_MAGIC_NUMBER;
    pkt.header.version = 1;
    pkt.header.msg_type = type;
    pkt.header.flags = ADATP_FLAG_ENCRYPTED;
    pkt.header.length = clen;
    pkt.header.sequence = seq;
    memcpy(pkt.header.session_id, client->session_id, 16);
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

    return crypto_decrypt_gcm(
        &client->session,
        packet->payload,
        packet->header.length,
        packet->auth_tag,
        packet->header.sequence,
        out_buf
    );
}
