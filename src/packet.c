#include "adatp.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h> // htonl etc

// Helper for 64-bit endian conversion if not present
#ifndef htonll
#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#endif
#ifndef ntohll
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif

void adatp_packet_encode(const adatp_packet_t* packet, uint8_t* buffer, size_t* len) {
    size_t offset = 0;
    
    // Header
    uint32_t magic = htonl(packet->header.magic);
    // Actually Protocol uses Little Endian. htonl is Big Endian usually (unless system is BE).
    // Spec says Little Endian.
    // If we assume running on x86/ARM (LE), then htonl converts to BE. We don't want that if protocol is LE.
    // We want host_to_le32.
    // On LE system, host_to_le32 is data. On BE system, it swaps.
    // Let's implement manual LE serialization to be safe.
}

static void put_u32_le(uint8_t* buf, uint32_t val) {
    buf[0] = val & 0xFF;
    buf[1] = (val >> 8) & 0xFF;
    buf[2] = (val >> 16) & 0xFF;
    buf[3] = (val >> 24) & 0xFF;
}

static void put_u16_le(uint8_t* buf, uint16_t val) {
    buf[0] = val & 0xFF;
    buf[1] = (val >> 8) & 0xFF;
}

static void put_u64_le(uint8_t* buf, uint64_t val) {
    put_u32_le(buf, val & 0xFFFFFFFF);
    put_u32_le(buf + 4, val >> 32);
}

// ... Getters similarly

size_t adatp_packet_serialized_size(const adatp_packet_t* packet) {
    size_t size = ADATP_HEADER_SIZE + packet->header.length;
    if (packet->header.flags & ADATP_FLAG_ENCRYPTED) {
        size += 16;
    }
    return size;
}

void adatp_packet_serialize(const adatp_packet_t* packet, uint8_t* buf) {
    put_u32_le(buf + 0, packet->header.magic);
    buf[4] = packet->header.version;
    put_u16_le(buf + 5, packet->header.flags);
    put_u32_le(buf + 7, packet->header.length);
    put_u64_le(buf + 11, packet->header.sequence);
    put_u16_le(buf + 19, packet->header.msg_type);
    put_u64_le(buf + 21, packet->header.timestamp);
    memcpy(buf + 29, packet->header.session_id, 16);
    
    memcpy(buf + 45, packet->payload, packet->header.length);
    
    if (packet->header.flags & ADATP_FLAG_ENCRYPTED) {
        memcpy(buf + 45 + packet->header.length, packet->auth_tag, 16);
    }
}
