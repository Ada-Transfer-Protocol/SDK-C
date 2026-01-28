# AdaTP C SDK

A high-performance C11 client library for the **Ada Transfer Protocol (AdaTP)**. Designed for embedded systems and performant native applications, this SDK provides direct access to the binary protocol with full encryption support.

## 📦 Features
*   **Performance:** written in pure C11 with minimal overhead.
*   **Security:** Uses OpenSSL `libcrypto` and `libssl` for X25519/AES-GCM.
*   **Portability:** Tested on macOS (Clang) and Linux (GCC).

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
    adatp_client_t* client = adatp_client_create("127.0.0.1", 8444);
    
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
    *   Implements `select()` to multiplex `stdin` (user input) and the TCP socket for real-time chat.
*   **File Sender:** `filetransfer_example.c`
    *   Demonstrates manually constructing the binary payloads required to upload a file to the room.

## 🔧 API Reference

*   `adatp_client_create(host, port)`: Allocate client context.
*   `adatp_client_connect(client)`: Perform TCP handshake + Crypto handshake.
*   `adatp_client_authenticate(client, user, pass)`: Send auth packet.
*   `adatp_client_send_text(client, msg)`: Helper for text messages.
*   `adatp_client_send(client, type, payload, len)`: Send raw encrypted packet.
