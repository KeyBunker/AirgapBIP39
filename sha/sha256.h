#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

void sha256_hash(const uint8_t *in, size_t len, uint8_t out[32]);

#endif
