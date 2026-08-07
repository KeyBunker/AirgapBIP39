#include "hmac_sha512.h"
#include "sha512.h"

#include <string.h>
#include <stdlib.h>

static void secure_wipe(void *v, size_t n) {
    volatile unsigned char *p = (volatile unsigned char *)v;
    while (n--) *p++ = 0;
}

void hmac_sha512(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out[64])
{
    if (!out) {
        return; 
    }

    const size_t block_size = 128;

    uint8_t key_block[128];
    uint8_t key_hash[64];
    size_t use_len;

    if (key_len > block_size) {
        sha512_hash((key ? key : (const uint8_t *)""), key_len, key_hash);
        use_len = 64;
        memset(key_block, 0, block_size);
        memcpy(key_block, key_hash, use_len);
        secure_wipe(key_hash, sizeof(key_hash));
    } else {
        memset(key_block, 0, block_size);
        if (key_len && key) {
            memcpy(key_block, key, key_len);
        }
        use_len = key_len;
        (void)use_len; 
    }


    uint8_t ipad[128];
    uint8_t opad[128];

    for (size_t i = 0; i < block_size; i++) {
        uint8_t kb = key_block[i];
        ipad[i] = (uint8_t)(kb ^ 0x36);
        opad[i] = (uint8_t)(kb ^ 0x5c);
    }

    uint8_t inner[64];
    sha512_ctx ctx;

    sha512_init(&ctx);
    sha512_update(&ctx, ipad, block_size);
    if (data_len && data) {
        sha512_update(&ctx, data, data_len);
    }
    sha512_final(&ctx, inner);

    sha512_init(&ctx);
    sha512_update(&ctx, opad, block_size);
    sha512_update(&ctx, inner, sizeof(inner));
    sha512_final(&ctx, out);

    secure_wipe(key_block, sizeof(key_block));
    secure_wipe(key_hash, sizeof(key_hash));
    secure_wipe(ipad, sizeof(ipad));
    secure_wipe(opad, sizeof(opad));
    secure_wipe(inner, sizeof(inner));
}
