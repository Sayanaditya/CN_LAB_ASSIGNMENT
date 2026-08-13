#ifndef FRAME_H
#define FRAME_H

#include <stdint.h>

/* ---------- Frame layout constants ---------- */

#define MAC_LEN         6
#define PAYLOAD_SIZE    44
#define HEADER_SIZE     (MAC_LEN + MAC_LEN + 2 + 2) /* 16 bytes header */
#define FCS_SIZE        4
#define FRAME_SIZE      (HEADER_SIZE + PAYLOAD_SIZE + FCS_SIZE) /* total 64 bytes */

#define PORT            5050

/* ---------- Frame structure (64 bytes, packed) ---------- */

#pragma pack(push, 1)
typedef struct {
    uint8_t  dest_mac[MAC_LEN];
    uint8_t  src_mac[MAC_LEN];
    uint16_t payload_len;   /* actual data length before padding */
    uint16_t frame_no;
    uint8_t  payload[PAYLOAD_SIZE];
    uint8_t  fcs[FCS_SIZE]; /* fcs[0..1] = checksum, fcs[2..3] = CRC */
} frame_t;
#pragma pack(pop)

/* ---------- 16-bit Internet Checksum (RFC 1071) ---------- */

static inline uint16_t calc_checksum(uint8_t *data, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len; i += 2) {
        uint16_t word = (data[i] << 8) + (i < len - 1 ? data[i + 1] : 0);
        sum += word;
        while (sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

/* ---------- CRC-16 (x^16 + x^15 + x^2 + 1, poly 0x8005) ---------- */

static inline uint16_t calc_crc(uint8_t *data, int len) {
    uint16_t crc = 0;
    for (int p = 0; p < len; p++) {
        crc ^= (uint16_t)data[p] << 8;
        for (int i = 0; i < 8; i++) {
            crc = (crc & 0x8000) ? (crc << 1) ^ 0x8005 : (crc << 1);
        }
    }
    return crc;
}

#endif