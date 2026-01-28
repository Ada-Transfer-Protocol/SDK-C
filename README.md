# AdaTP C SDK

A high-performance, lightweight C client for the Ada Transport Protocol (AdaTP), utilizing OpenSSL for cryptographic primitives.

## Features

- **Native Performance**: Written in pure C99 for maximum efficiency.
- **Secure by Default**: Uses OpenSSL's EVP API for X25519, HKDF, and AES-256-GCM.
- **Low Footprint**: Minimal dependency tree (only OpenSSL required).
- **Portable**: Can be compiled on Linux, macOS, and Windows (with MSVC/MinGW).
- **Protocol Compliant**: Fully compatible with the official AdaTP Rust server.

## Requirements

- C Compiler (GCC, Clang, MSVC)
- CMake (3.10+) or Make
- OpenSSL Development Libraries (3.0+ recommended)
  - Ubuntu: `libssl-dev`
  - macOS: `openssl@3` (via Homebrew)
  - Fedora: `openssl-devel`

## Building

### Using CMake

```bash
mkdir build
cd build
cmake ..
make
```

### Manual Compilation

```bash
gcc -o adatp_client \
    examples/example.c \
    src/client.c \
    src/packet.c \
    src/crypto.c \
    -I include -I src \
    -lssl -lcrypto
```

*Note: On macOS with Homebrew, you may need to specify include/lib paths:*

```bash
gcc -o adatp_client ... \
    -I /opt/homebrew/opt/openssl@3/include \
    -L /opt/homebrew/opt/openssl@3/lib \
    -lssl -lcrypto
```

## Usage

```c
#include "adatp.h"
#include <stdio.h>

int main() {
    // Create client instance for localhost:8443
    adatp_client_t* client = adatp_client_create("127.0.0.1", 8443);
    
    // Connect and perform Handshake
    if (adatp_client_connect(client) == 0) {
        printf("Secure connection established!\n");
        
        // Send encrypted message and wait for echo
        adatp_client_send_text(client, "Hello from C!");
        
        // Disconnect
        adatp_client_disconnect(client);
    } else {
        printf("Connection failed.\n");
    }
    
    // Cleanup
    adatp_client_destroy(client);
    return 0;
}
```

## API Reference

### Management

- `adatp_client_create(host, port)`: Allocates a new client.
- `adatp_client_destroy(client)`: Frees the client resources.

### Connection

- `adatp_client_connect(client)`: Connects via TCP and executes the X25519/HKDF handshake. Returns 0 on success.
- `adatp_client_disconnect(client)`: Sends a DISCONNECT packet and closes the socket.

### Messaging

- `adatp_client_send_text(client, text)`: Encrypts and sends a text message. Blocks until sent.
- `adatp_client_join_room(client, room)`: Encrypts and sends a join room command. (0x00A0).

### Multi-Room Support

```c
adatp_client_join_room(client, "meeting_room");
```
## Protocol Support

| Feature | Status |
|---------|--------|
| Handshake (X25519) | ✅ |
| Encryption (AES-GCM) | ✅ |
| Text Messages | ✅ |
| Multi-Room Chat | ✅ |
| File Transfer | ✅ (Implemented) |
| Voice/Video | 🚧 (Planned) |

## License

MIT
# SDK-C
