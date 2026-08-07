#ifndef SHA512_H
#define SHA512_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t state[8];
    uint64_t bitlen_hi;
    uint64_t bitlen_lo;
    uint8_t  buffer[128];
    int      finalized;
} sha512_ctx;

void sha512_hash(const uint8_t *in, size_t len, uint8_t out[64]);

int sha512_init(sha512_ctx *ctx);
int sha512_update(sha512_ctx *ctx, const uint8_t *in, size_t len);
int sha512_final(sha512_ctx *ctx, uint8_t out[64]);

#endif
