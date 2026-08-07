#include <stdint.h>
#include <string.h>
#include "ripemd160.h"

typedef struct {
    uint32_t h[5];
    uint32_t length;
    uint32_t curlen;
    uint8_t buf[64];
} RIPEMD160_CTX;

#define F1(x,y,z)  ( (x) ^ (y) ^ (z) )
#define F2(x,y,z)  ( ((x)&(y)) | (~(x)&(z)) )
#define F3(x,y,z)  ( ((x)|~(y)) ^ (z) )
#define F4(x,y,z)  ( ((x)&(z)) | ((y)&~(z)) )
#define F5(x,y,z)  ( (x) ^ ((y) | ~(z)) )

#define ROL(x,n)   (((x)<<(n)) | ((x)>>(32-(n))))

static const uint32_t K[5]  = { 0x00000000UL, 0x5A827999UL, 0x6ED9EBA1UL,
                                0x8F1BBCDCUL, 0xA953FD4EUL };
static const uint32_t KK[5] = { 0x50A28BE6UL, 0x5C4DD124UL, 0x6D703EF3UL,
                                0x7A6D76E9UL, 0x00000000UL };

static const uint8_t R[80] = {
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
     7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
     3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
     1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
     4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13
};

static const uint8_t RR[80] = {
     5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
     6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
    15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
     8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
    12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11
};

static const uint8_t S[80] = {
    11,14,15,12, 5, 8, 7, 9,11,13,14,15, 6, 7, 9, 8,
     7, 6, 8,13,11, 9, 7,15, 7,12,15, 9,11, 7,13,12,
    11,13, 6, 7,14, 9,13,15,14, 8,13, 6, 5,12, 7, 5,
    11,12,14,15,14,15, 9, 8, 9,14, 5, 6, 8, 6, 5,12,
     9,15, 5,11, 6, 8,13,12, 5,12,13,14,11, 8, 5, 6
};

static const uint8_t SS[80] = {
     8, 9, 9,11,13,15,15, 5, 7, 7, 8,11,14,14,12, 6,
     9,13,15, 7,12, 8, 9,11, 7, 7,12, 7, 6,15,13,11,
     9, 7,15,11, 8, 6, 6,14,12,13, 5,14,13,13, 7, 5,
    15, 5, 8,11,14,14, 6,14, 6, 9,12, 9,12, 5,15, 8,
     8, 5,12, 9,12, 5,14, 6, 8,13, 6, 5,15,13,11,11
};

static void ripemd160_compress(RIPEMD160_CTX *ctx, const uint8_t *buf)
{
    uint32_t a,b,c,d,e,aa,bb,cc,dd,ee,t;
    uint32_t X[16];

    for (int i = 0; i < 16; i++) {
        X[i] =  (uint32_t)buf[i*4 + 0]
              | ((uint32_t)buf[i*4 + 1] << 8)
              | ((uint32_t)buf[i*4 + 2] << 16)
              | ((uint32_t)buf[i*4 + 3] << 24);
    }

    a = aa = ctx->h[0];
    b = bb = ctx->h[1];
    c = cc = ctx->h[2];
    d = dd = ctx->h[3];
    e = ee = ctx->h[4];

    for (int i = 0; i < 80; i++) {
        uint32_t f, k, s, r, temp;

        /* left branch */
        if (i < 16)      f = F1(b,c,d), k = K[0];
        else if (i < 32) f = F2(b,c,d), k = K[1];
        else if (i < 48) f = F3(b,c,d), k = K[2];
        else if (i < 64) f = F4(b,c,d), k = K[3];
        else             f = F5(b,c,d), k = K[4];

        r = R[i];
        s = S[i];

        temp = ROL(a + f + X[r] + k, s) + e;
        a = e; e = d; d = ROL(c,10); c = b; b = temp;

        /* right branch */
        if (i < 16)      f = F5(bb,cc,dd), k = KK[0];
        else if (i < 32) f = F4(bb,cc,dd), k = KK[1];
        else if (i < 48) f = F3(bb,cc,dd), k = KK[2];
        else if (i < 64) f = F2(bb,cc,dd), k = KK[3];
        else             f = F1(bb,cc,dd), k = KK[4];

        r = RR[i];
        s = SS[i];

        temp = ROL(aa + f + X[r] + k, s) + ee;
        aa = ee; ee = dd; dd = ROL(cc,10); cc = bb; bb = temp;
    }

    t = ctx->h[1] + c + dd;
    ctx->h[1] = ctx->h[2] + d + ee;
    ctx->h[2] = ctx->h[3] + e + aa;
    ctx->h[3] = ctx->h[4] + a + bb;
    ctx->h[4] = ctx->h[0] + b + cc;
    ctx->h[0] = t;
}

static void ripemd160_init(RIPEMD160_CTX *ctx)
{
    ctx->length = 0;
    ctx->curlen = 0;
    ctx->h[0] = 0x67452301UL;
    ctx->h[1] = 0xefcdab89UL;
    ctx->h[2] = 0x98badcfeUL;
    ctx->h[3] = 0x10325476UL;
    ctx->h[4] = 0xc3d2e1f0UL;
}

static void ripemd160_update(RIPEMD160_CTX *ctx, const uint8_t *buf, size_t len)
{
    while (len > 0) {
        size_t n = (len < (64 - ctx->curlen)) ? len : (64 - ctx->curlen);
        memcpy(ctx->buf + ctx->curlen, buf, n);
        ctx->curlen += n;
        buf += n;
        len -= n;

        if (ctx->curlen == 64) {
            ripemd160_compress(ctx, ctx->buf);
            ctx->length += 512;
            ctx->curlen = 0;
        }
    }
}

static void ripemd160_final(RIPEMD160_CTX *ctx, uint8_t *out)
{
    ctx->length += ctx->curlen * 8;

    ctx->buf[ctx->curlen++] = 0x80;

    if (ctx->curlen > 56) {
        while (ctx->curlen < 64)
            ctx->buf[ctx->curlen++] = 0;
        ripemd160_compress(ctx, ctx->buf);
        ctx->curlen = 0;
    }

    while (ctx->curlen < 56)
        ctx->buf[ctx->curlen++] = 0;

    for (int i = 0; i < 8; i++)
        ctx->buf[56 + i] = (ctx->length >> (8 * i)) & 0xff;

    ripemd160_compress(ctx, ctx->buf);

    for (int i = 0; i < 5; i++) {
        out[i*4+0] = (ctx->h[i]      ) & 0xff;
        out[i*4+1] = (ctx->h[i] >>  8) & 0xff;
        out[i*4+2] = (ctx->h[i] >> 16) & 0xff;
        out[i*4+3] = (ctx->h[i] >> 24) & 0xff;
    }
}

void ripemd160_hash(const uint8_t *msg, size_t msg_len, uint8_t out[20])
{
    RIPEMD160_CTX ctx;
    ripemd160_init(&ctx);
    ripemd160_update(&ctx, msg, msg_len);
    ripemd160_final(&ctx, out);
}
