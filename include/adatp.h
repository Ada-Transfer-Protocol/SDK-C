#ifndef ADATP_H
#define ADATP_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Constants
#define ADATP_MAGIC_NUMBER 0x41444154
#define ADATP_HEADER_SIZE 45

// Message Types
typedef enum {
    ADATP_MSG_HANDSHAKE_INIT = 0x0001,
    ADATP_MSG_HANDSHAKE_RESPONSE = 0x0002,
    ADATP_MSG_HANDSHAKE_COMPLETE = 0x0003,
    ADATP_MSG_AUTH_REQUEST = 0x0010,
    ADATP_MSG_AUTH_SUCCESS = 0x0013,
    ADATP_MSG_AUTH_FAILURE = 0x0014,
    ADATP_MSG_TEXT_MESSAGE = 0x0020,

    ADATP_MSG_FILE_INIT = 0x0030,
    ADATP_MSG_FILE_CHUNK = 0x0031,
    ADATP_MSG_FILE_ACK = 0x0032,
    ADATP_MSG_FILE_COMPLETE = 0x0033,
    ADATP_MSG_FILE_CANCEL = 0x0034,

    ADATP_MSG_GAME_STATE = 0x0050,

    ADATP_MSG_TOOL_CALL = 0x0070,
    ADATP_MSG_TOOL_RESULT = 0x0071,
    ADATP_MSG_TOOL_ERROR = 0x0072,

    ADATP_MSG_PING = 0x0080,
    ADATP_MSG_PONG = 0x0081,

    ADATP_MSG_JOIN_ROOM = 0x00A0,
    ADATP_MSG_ROOM_JOINED = 0x00A1,
    ADATP_MSG_DISCONNECT = 0x00FF
} adatp_msg_type_t;

// Packet Flags
typedef enum {
    ADATP_FLAG_NONE = 0,
    ADATP_FLAG_ENCRYPTED = 0x0001
} adatp_flag_t;

// Structures
typedef struct {
    uint32_t magic;
    uint8_t version;
    uint16_t flags;
    uint32_t length;
    uint64_t sequence;
    uint16_t msg_type;
    uint64_t timestamp;
    uint8_t session_id[16];
} adatp_header_t;

typedef struct {
    adatp_header_t header;
    uint8_t *payload;
    uint8_t auth_tag[16]; // Only valid if encrypted
} adatp_packet_t;

typedef struct adatp_client adatp_client_t;

// API

// Create and destroy client
adatp_client_t* adatp_client_create(const char* host, int port);
void adatp_client_destroy(adatp_client_t* client);

// SDK language (client-side metadata; the wire protocol is language-neutral).
// Supported codes: en tr it fr de zh ja hi ar. Unknown codes fall back to "en".
void adatp_client_set_locale(adatp_client_t* client, const char* locale);
const char* adatp_client_get_locale(const adatp_client_t* client);

// Pin the server's long-term Ed25519 identity public key (32 bytes). Calling
// this BEFORE connect() switches the handshake to the authenticated protocol
// v2: the client verifies the server's signature over the transcript (and binds
// the frame header as AEAD AAD) before deriving any key, defeating an active
// man-in-the-middle even without TLS. Without it, the v1 (unauthenticated)
// handshake is used and TLS is required for that guarantee.
void adatp_client_set_server_key(adatp_client_t* client, const uint8_t server_key[32]);

// Connection
int adatp_client_connect(adatp_client_t* client);
void adatp_client_disconnect(adatp_client_t* client);

// Messaging
int adatp_client_send_text(adatp_client_t* client, const char* text);
int adatp_client_send(adatp_client_t* client, adatp_msg_type_t type, const uint8_t* payload, size_t len);
int adatp_client_join_room(adatp_client_t* client, const char* room);
int adatp_client_authenticate(adatp_client_t* client, const char* username, const char* password);
int adatp_client_read_packet(adatp_client_t* client, adatp_packet_t* packet);
int adatp_client_get_socket(adatp_client_t* client);
int adatp_client_decrypt_packet(adatp_client_t* client, const adatp_packet_t* packet, uint8_t* out_buf);

// Serialization (Internal use but exposed for now)
void adatp_packet_serialize(const adatp_packet_t* packet, uint8_t* buf);
size_t adatp_packet_serialized_size(const adatp_packet_t* packet);

#ifdef __cplusplus
}
#endif

#endif // ADATP_H
