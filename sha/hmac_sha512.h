#ifndef HMAC_SHA512_H
#define HMAC_SHA512_H

#include <stdint.h>
#include <stddef.h>

void hmac_sha512(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[64]);

#endif
