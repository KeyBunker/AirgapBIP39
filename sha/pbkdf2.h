#ifndef PBKDF2_H
#define PBKDF2_H

#include <stdint.h>
#include <stddef.h>

int pbkdf2_hmac_sha512(const uint8_t *password, size_t pass_len,
                       const uint8_t *salt, size_t salt_len,
                       uint32_t iterations,
                       uint8_t *out, size_t dk_len);

#endif
