#ifndef ERROR_H
#define ERROR_H

#include <stdlib.h>
#include <stdint.h>
#include "frame.h"

// error types

#define ERR_NONE       0   // no error 
#define ERR_SINGLE     1   // single bit flip
#define ERR_TWO_ISOL   2   // two isolated single bit flips
#define ERR_ODD        3   // odd number of bit flips
#define ERR_BURST      4   // burst error
#define ERR_CS_FALSE   5   // checksum stays same, CRC catches (word swap)
#define ERR_CRC_FALSE  6   // CRC stays same, checksum catches

// Deterministic error injection
static inline void inject_error(frame_t *f, int type) {
    uint8_t tmp;
    switch (type) {
        case ERR_SINGLE:
            f->payload[5] ^= (1 << 3);
            break;
        case ERR_TWO_ISOL:
            f->payload[3]  ^= (1 << 2);
            f->payload[25] ^= (1 << 6);
            break;
        case ERR_ODD:
            f->payload[1]  ^= (1 << 0);
            f->payload[15] ^= (1 << 4);
            f->payload[35] ^= (1 << 7);
            break;
        case ERR_BURST:
            f->payload[10] = (uint8_t)~f->payload[10];
            break;
        case ERR_CS_FALSE:
            // swap two adjacent 16-bit words , checksum will still be evaluated to the same value
            tmp = f->payload[0]; f->payload[0] = f->payload[2]; f->payload[2] = tmp;
            tmp = f->payload[1]; f->payload[1] = f->payload[3]; f->payload[3] = tmp;
            break;
        case ERR_CRC_FALSE:
            // XOR with G(x) = x^16+x^15+x^2+1 across 3 bytes. CRC remainder stays 0 (ACCEPT), but checksum changes (REJECT)
            f->payload[10] ^= 0xC0;
            f->payload[11] ^= 0x02;
            f->payload[12] ^= 0x80;
            break;
    }
}

// Randomised error injection
static inline void inject_random_error(frame_t *f, int type) {
    uint8_t tmp;
    int x, y, idx, len, bit;

    switch (type) {
        case ERR_SINGLE:
            /* flip exactly one random bit in a random payload byte */
            idx = rand() % PAYLOAD_SIZE;
            bit = rand() % 8;
            f->payload[idx] ^= (1 << bit);
            break;

        case ERR_TWO_ISOL:
            /* flip one random bit in each of two distinct bytes */
            x = rand() % PAYLOAD_SIZE;
            y = rand() % PAYLOAD_SIZE;
            if (x == y) y = (x + 1 + rand() % (PAYLOAD_SIZE - 1)) % PAYLOAD_SIZE;
            f->payload[x] ^= (1 << (rand() % 8));
            f->payload[y] ^= (1 << (rand() % 8));
            break;

        case ERR_ODD:
            /* flip exactly 3 bits in three distinct bytes */
            f->payload[rand() % PAYLOAD_SIZE] ^= (1 << (rand() % 8));
            f->payload[rand() % PAYLOAD_SIZE] ^= (1 << (rand() % 8));
            f->payload[rand() % PAYLOAD_SIZE] ^= (1 << (rand() % 8));
            break;

        case ERR_BURST:
            /* flip a contiguous run of 1..8 bytes */
            idx = rand() % PAYLOAD_SIZE;
            len = 1 + rand() % 8;
            if (idx + len > PAYLOAD_SIZE) len = PAYLOAD_SIZE - idx;
            for (int i = 0; i < len; i++)
                f->payload[idx + i] ^= (1 + rand() % 255); /* never XOR 0 */
            break;

        case ERR_CS_FALSE:
            /* swap two distinct payload bytes (preserves checksum word-sum) */
            x = rand() % (PAYLOAD_SIZE - 1);   /* even-aligned index */
            x = x & ~1;                         /* force even */
            y = x + 2;
            if (y + 1 >= PAYLOAD_SIZE) y = 0;
            /* swap the 16-bit word at x with the 16-bit word at y */
            tmp = f->payload[x];   f->payload[x]   = f->payload[y];   f->payload[y]   = tmp;
            tmp = f->payload[x+1]; f->payload[x+1] = f->payload[y+1]; f->payload[y+1] = tmp;
            break;

        case ERR_CRC_FALSE:
            /* XOR with the generator polynomial — CRC stays unchanged */
            idx = rand() % (PAYLOAD_SIZE - 3);
            f->payload[idx]     ^= 0xC0;
            f->payload[idx + 1] ^= 0x02;
            f->payload[idx + 2] ^= 0x80;
            break;
    }
}


static inline const char *err_name(int t) {
    switch (t) {
        case ERR_NONE:      return "NONE (clean)";
        case ERR_SINGLE:    return "SINGLE-BIT";
        case ERR_TWO_ISOL:  return "TWO ISOLATED";
        case ERR_ODD:       return "ODD (3 bits)";
        case ERR_BURST:     return "BURST (8 bits)";
        case ERR_CS_FALSE:  return "WORD-SWAP (CS blind)";
        case ERR_CRC_FALSE: return "CRC FALSE";
        default:            return "UNKNOWN";
    }
}

#endif
