#include "pbkdf2.h"
#include "hmac_sha512.h"

#include <string.h>
#include <stdlib.h>

static void secure_wipe(void *v, size_t n) {
    volatile unsigned char *p = (volatile unsigned char *)v;
    while (n--) *p++ = 0;
}

int pbkdf2_hmac_sha512(const uint8_t *password, size_t pass_len,
                       const uint8_t *salt, size_t salt_len,
                       uint32_t iterations,
                       uint8_t *out, size_t dk_len)
{
    if (!out || dk_len == 0) return -1;
    if (iterations == 0) return -1;

    uint32_t block_index = 1;
    size_t remaining = dk_len;

    uint8_t U[64];
    uint8_t T[64];

    while (remaining > 0) {
        size_t sbuf_len = salt_len + 4;
        uint8_t *sbuf = malloc(sbuf_len);
        if (!sbuf) exit(1); 

        if (salt_len && salt)
            memcpy(sbuf, salt, salt_len);
        else if (salt_len)
            memset(sbuf, 0, salt_len);

        sbuf[salt_len + 0] = (uint8_t)(block_index >> 24);
        sbuf[salt_len + 1] = (uint8_t)(block_index >> 16);
        sbuf[salt_len + 2] = (uint8_t)(block_index >> 8);
        sbuf[salt_len + 3] = (uint8_t)(block_index);

        hmac_sha512(password, pass_len, sbuf, sbuf_len, U);
        memcpy(T, U, 64);

        for (uint32_t i = 2; i <= iterations; i++) {
            hmac_sha512(password, pass_len, U, 64, U);

            for (int j = 0; j < 64; j++) {
                T[j] ^= U[j];
            }
        }

        size_t to_write = (remaining > 64) ? 64 : remaining;
        memcpy(out, T, to_write);

        out       += to_write;
        remaining -= to_write;
        block_index++;

        secure_wipe(sbuf, sbuf_len);
        free(sbuf);
    }

    secure_wipe(U, sizeof(U));
    secure_wipe(T, sizeof(T));

    return 0;
}
