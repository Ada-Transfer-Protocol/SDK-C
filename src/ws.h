#ifndef ADATP_WS_H
#define ADATP_WS_H

// Minimal RFC 6455 WebSocket client used as the AdaTP transport.
// POSIX sockets + OpenSSL (SHA1/base64/random) only. Supports ws:// (plain
// TCP); TLS termination is expected at a proxy for wss:// deployments.

#include <stdint.h>
#include <stddef.h>

typedef struct ws_conn ws_conn_t;

// Connects and performs the HTTP Upgrade handshake.
// Returns NULL on failure. `host` may be a hostname or IP.
ws_conn_t* ws_connect(const char* host, int port, const char* path);

// Sends one binary WebSocket message (client frames are masked).
int ws_send_binary(ws_conn_t* ws, const uint8_t* data, size_t len);

// Receives the next complete binary message. Reassembles fragments and
// transparently answers pings. On success returns 0 and sets *out (malloc'd,
// caller frees) and *out_len. Returns -1 on close/error.
int ws_recv_binary(ws_conn_t* ws, uint8_t** out, size_t* out_len);

// Sends a close frame (best effort) and releases the connection.
void ws_close(ws_conn_t* ws);

// Underlying socket fd (for select/poll integration).
int ws_get_fd(ws_conn_t* ws);

#endif // ADATP_WS_H
