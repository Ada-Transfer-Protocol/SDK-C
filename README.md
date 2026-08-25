# AdaTP C SDK

A high-performance C11 client library for the **Ada Transfer Protocol (AdaTP)**. Designed for embedded systems and performant native applications, this SDK provides direct access to the binary protocol with full encryption support.

**Transport:** WebSocket (`ws://<host>:3000/ws` by default) with a built-in dependency-free RFC 6455 client. TLS (`wss://`) is expected to be terminated by a proxy/load balancer in front of the server.

## 📦 Features
*   **Performance:** written in pure C11 with minimal overhead.
*   **Security:** Uses OpenSSL `libcrypto` and `libssl` for X25519/AES-GCM.
*   **Portability:** Tested on macOS (Clang) and Linux (GCC).
*   **Authenticated handshake (protocol v2):** pin the server's Ed25519 key to get
    an authenticated, MITM-resistant handshake with header-AAD — no TLS required
    for that guarantee (opt-in; v1 stays the default and unchanged).

## 🔐 Authenticated handshake (v2)

By default the client runs the v1 (unauthenticated) handshake, which relies on
TLS at the edge for server authentication. Pinning the server's long-term
Ed25519 identity switches to **protocol v2**: the client verifies the server's
signature over the handshake transcript (and binds the frame header as AEAD AAD)
**before** deriving any key, defeating an active man-in-the-middle even without
TLS.

```c
adatp_client_t* client = adatp_client_create("127.0.0.1", 3000);

// The server's 32-byte Ed25519 public key, obtained out of band (the server
// logs its fingerprint at startup; the control plane can hand it to clients).
uint8_t server_key[32] = { /* ... */ };
adatp_client_set_server_key(client, server_key);   // <-- enables v2 + pinning

adatp_client_connect(client);   // authenticated handshake; aborts on a bad key/signature
```

Verified against the Rust reference server end to end (`test/run_e2e_v2.sh`) and
by golden-vector conformance (`ctest`, `test/conformance_v2.c`). Require v2
server-side with `ADATP_MIN_PROTOCOL_VERSION=2`. See
[`docs/spec/12-authenticated-handshake.md`](https://github.com/Ada-Transfer-Protocol/Server/blob/main/docs/spec/12-authenticated-handshake.md).

## 🚀 Installation & Build

**Prerequisites:**
*   CMake (optional) or GCC/Clang
*   OpenSSL (`libssl-dev` or `openssl@3`)

**Compiling with GCC:**

```bash
# Example compile command for macOS (Homebrew OpenSSL)
gcc -I include -I/opt/homebrew/include -I/usr/local/include \
    src/client.c src/packet.c src/crypto.c example.c \
    -L/opt/homebrew/lib -L/usr/local/lib -lssl -lcrypto -o adatp_chat
```

## 🛠️ Usage

### 1. Basic Chat Client

```c
#include "adatp.h"

int main() {
    // 1. Create Handle
    adatp_client_t* client = adatp_client_create("127.0.0.1", 3000);
    
    // 2. Connect
    if (adatp_client_connect(client) != 0) {
        printf("Connection Failed\n");
        return 1;
    }

    // 3. Authenticate
    adatp_client_authenticate(client, "user", "pass");

    // 4. Send Message
    adatp_client_send_text(client, "Hello from C!");

    // 5. Read Packet
    adatp_packet_t pkt;
    if (adatp_client_read_packet(client, &pkt) == 0) {
        if (pkt.header.msg_type == ADATP_MSG_TEXT_MESSAGE) {
            uint8_t buffer[1024];
            int len = adatp_client_decrypt_packet(client, &pkt, buffer);
            if(len > 0) {
                buffer[len] = 0;
                printf("Received: %s\n", buffer);
            }
        }
    }

    // 6. Cleanup
    adatp_client_destroy(client);
    return 0;
}
```

### 2. File Transfer

File transfers in C require manual construction of the protocol payloads (`INIT`, `CHUNK`, `COMPLETE`) if not using high-level helpers.

The typical flow:
1.  **FILE_INIT:** Send JSON metadata.
2.  **FILE_CHUNK:** Send UUID (16 bytes) + Data Chunk.
3.  **FILE_COMPLETE:** Send UUID (16 bytes).

See `filetransfer_example.c` for a raw implementation of this packet construction.

## 📂 Examples

*   **Chat CLI:** `example.c`
    *   Implements `select()` to multiplex `stdin` (user input) and the WebSocket file descriptor for real-time chat.
*   **File Sender:** `filetransfer_example.c`
    *   Demonstrates manually constructing the binary payloads required to upload a file to the room.

## 🔧 API Reference

*   `adatp_client_create(host, port)`: Allocate client context.
*   `adatp_client_connect(client)`: Connect over WebSocket (/ws) + crypto handshake.
*   `adatp_client_authenticate(client, user, pass)`: Send auth packet.
*   `adatp_client_send_text(client, msg)`: Helper for text messages.
*   `adatp_client_send(client, type, payload, len)`: Send raw encrypted packet.

## Language / locale

Set the SDK language for user-facing strings (client-side metadata — the
wire protocol is language-neutral). Default `en`; supported:
`en tr it fr de zh ja hi ar`.

```c
adatp_client_t* client = adatp_client_create("127.0.0.1", 3000);
adatp_client_set_locale(client, "tr");
const char* lang = adatp_client_get_locale(client);
```
