#include "sha256.h"
#include <string.h>

static void secure_wipe(void *v, size_t n) {
    volatile uint8_t *p = (volatile uint8_t*)v;
    while (n--) *p++ = 0;
}

typedef struct {
    uint32_t s[8];
    uint64_t bits;
    uint8_t  buf[64];
} sha256_ctx;

#define ROR(x,n) ((x >> n) | (x << (32-n)))
#define SHR(x,n) (x >> n)

#define CH(x,y,z)  ((x & y) ^ ((~x) & z))
#define MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define EP0(x) (ROR(x,2)^ROR(x,13)^ROR(x,22))
#define EP1(x) (ROR(x,6)^ROR(x,11)^ROR(x,25))
#define S0(x)  (ROR(x,7)^ROR(x,18)^SHR(x,3))
#define S1(x)  (ROR(x,17)^ROR(x,19)^SHR(x,10))

static const uint32_t K[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
  0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
  0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
  0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
  0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
  0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
  0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
  0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
  0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(sha256_ctx *c, const uint8_t b[64]) {
    uint32_t w[64], a, b0, c0, d, e, f, g, h;

    for(int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)b[i*4] << 24) |
               ((uint32_t)b[i*4+1] << 16) |
               ((uint32_t)b[i*4+2] << 8) |
               (uint32_t)b[i*4+3];
    }
    for(int i = 16; i < 64; i++)
        w[i] = S1(w[i-2]) + w[i-7] + S0(w[i-15]) + w[i-16];

    a=c->s[0]; b0=c->s[1]; c0=c->s[2]; d=c->s[3];
    e=c->s[4]; f=c->s[5]; g=c->s[6]; h=c->s[7];

    for(int i=0;i<64;i++){
        uint32_t t1 = h + EP1(e) + CH(e,f,g) + K[i] + w[i];
        uint32_t t2 = EP0(a) + MAJ(a,b0,c0);
        h = g; g = f; f = e; e = d + t1;
        d = c0; c0 = b0; b0 = a; a = t1 + t2;
    }

    c->s[0]+=a; c->s[1]+=b0; c->s[2]+=c0; c->s[3]+=d;
    c->s[4]+=e; c->s[5]+=f;  c->s[6]+=g; c->s[7]+=h;

    secure_wipe(w, sizeof(w));
}

static void sha256_init(sha256_ctx *c){
    c->bits=0;
    c->s[0]=0x6a09e667; c->s[1]=0xbb67ae85;
    c->s[2]=0x3c6ef372; c->s[3]=0xa54ff53a;
    c->s[4]=0x510e527f; c->s[5]=0x9b05688c;
    c->s[6]=0x1f83d9ab; c->s[7]=0x5be0cd19;
}

static void sha256_update(sha256_ctx *c,const uint8_t *in,size_t len){
    size_t i = c->bits/8 % 64;
    c->bits += (uint64_t)len * 8;

    size_t fill = 64 - i;
    if(i && len >= fill){
        memcpy(c->buf+i, in, fill);
        sha256_transform(c, c->buf);
        in  += fill;
        len -= fill;
        i = 0;
    }
    while(len >= 64){
        sha256_transform(c, in);
        in  += 64;
        len -= 64;
    }
    if(len) memcpy(c->buf+i, in, len);
}

static void sha256_final(sha256_ctx *c,uint8_t out[32]){
    size_t i = c->bits/8 % 64;

    c->buf[i++] = 0x80;
    if(i > 56){
        memset(c->buf+i,0,64-i);
        sha256_transform(c,c->buf);
        i = 0;
    }
    memset(c->buf+i,0,56-i);

    uint64_t b = c->bits;
    for(int k=0;k<8;k++)
        c->buf[56+k] = b >> (56 - k*8);

    sha256_transform(c,c->buf);

    for(int k=0;k<8;k++){
        out[k*4+0] = c->s[k] >> 24;
        out[k*4+1] = c->s[k] >> 16;
        out[k*4+2] = c->s[k] >>  8;
        out[k*4+3] = c->s[k];
    }

    secure_wipe(c,sizeof(*c));
}

void sha256_hash(const uint8_t *in, size_t len, uint8_t out[32]){
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, in, len);
    sha256_final(&c, out);
}
