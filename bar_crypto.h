/* bar_crypto.h - AES-128 (AES-NI on x86, portable software fallback),
 * SHA-256 and HMAC-SHA256, plus CBC decrypt/encrypt and the SCECAF
 * ciphertext-stealing tail. Lifted verbatim from the original p4br tools so
 * the crypto stays bit-exact; the only change is that the x86 AES-NI path is
 * guarded so the file also compiles on ARM (e.g. Apple Silicon), where the
 * software path is used.
 *
 * Everything here is `static` so each tool compiles its own copy; there is no
 * separate crypto translation unit to link. */
#ifndef BAR_CRYPTO_H
#define BAR_CRYPTO_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
  #define BAR_X86 1
#else
  #define BAR_X86 0
#endif

#if BAR_X86
  #include <wmmintrin.h>
  #include <emmintrin.h>
  #if !defined(_MSC_VER)
    #include <cpuid.h>
  #endif
#endif

static int g_aesni = 0;

typedef struct {
#if BAR_X86
    __m128i ni_enc[11];
    __m128i ni_dec[11];
#endif
    uint8_t sw[176];                 /* software round keys */
} aes_ctx;

/* ---- AES-NI (x86 only) ---- */
#if BAR_X86
static __m128i ni_expand_step(__m128i key, __m128i gen)
{
    gen = _mm_shuffle_epi32(gen, _MM_SHUFFLE(3, 3, 3, 3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, gen);
}
static void ni_key_setup(aes_ctx *c, const uint8_t key[16])
{
    __m128i *e = c->ni_enc, *d = c->ni_dec;
    e[0] = _mm_loadu_si128((const __m128i *)key);
    e[1] = ni_expand_step(e[0], _mm_aeskeygenassist_si128(e[0], 0x01));
    e[2] = ni_expand_step(e[1], _mm_aeskeygenassist_si128(e[1], 0x02));
    e[3] = ni_expand_step(e[2], _mm_aeskeygenassist_si128(e[2], 0x04));
    e[4] = ni_expand_step(e[3], _mm_aeskeygenassist_si128(e[3], 0x08));
    e[5] = ni_expand_step(e[4], _mm_aeskeygenassist_si128(e[4], 0x10));
    e[6] = ni_expand_step(e[5], _mm_aeskeygenassist_si128(e[5], 0x20));
    e[7] = ni_expand_step(e[6], _mm_aeskeygenassist_si128(e[6], 0x40));
    e[8] = ni_expand_step(e[7], _mm_aeskeygenassist_si128(e[7], 0x80));
    e[9] = ni_expand_step(e[8], _mm_aeskeygenassist_si128(e[8], 0x1B));
    e[10] = ni_expand_step(e[9], _mm_aeskeygenassist_si128(e[9], 0x36));
    d[0] = e[10];
    for (int i = 1; i < 10; i++) d[i] = _mm_aesimc_si128(e[10 - i]);
    d[10] = e[0];
}
static inline __m128i ni_enc_block(const aes_ctx *c, __m128i m)
{
    const __m128i *e = c->ni_enc;
    m = _mm_xor_si128(m, e[0]);
    m = _mm_aesenc_si128(m, e[1]);  m = _mm_aesenc_si128(m, e[2]);
    m = _mm_aesenc_si128(m, e[3]);  m = _mm_aesenc_si128(m, e[4]);
    m = _mm_aesenc_si128(m, e[5]);  m = _mm_aesenc_si128(m, e[6]);
    m = _mm_aesenc_si128(m, e[7]);  m = _mm_aesenc_si128(m, e[8]);
    m = _mm_aesenc_si128(m, e[9]);
    return _mm_aesenclast_si128(m, e[10]);
}
static inline __m128i ni_dec_block(const aes_ctx *c, __m128i m)
{
    const __m128i *d = c->ni_dec;
    m = _mm_xor_si128(m, d[0]);
    m = _mm_aesdec_si128(m, d[1]);  m = _mm_aesdec_si128(m, d[2]);
    m = _mm_aesdec_si128(m, d[3]);  m = _mm_aesdec_si128(m, d[4]);
    m = _mm_aesdec_si128(m, d[5]);  m = _mm_aesdec_si128(m, d[6]);
    m = _mm_aesdec_si128(m, d[7]);  m = _mm_aesdec_si128(m, d[8]);
    m = _mm_aesdec_si128(m, d[9]);
    return _mm_aesdeclast_si128(m, d[10]);
}
#endif /* BAR_X86 */

/* ---- software AES (fallback, always compiled) ---- */
static const uint8_t SBOX[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16 };

static uint8_t RSBOX[256];
static void build_rsbox(void){ for (int i=0;i<256;i++) RSBOX[SBOX[i]]=(uint8_t)i; }

static const uint8_t RCON[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static void sw_key_setup(aes_ctx *c, const uint8_t key[16])
{
    uint8_t *rk = c->sw;
    memcpy(rk, key, 16);
    for (int i = 4; i < 44; i++) {
        uint8_t t[4];
        memcpy(t, rk + (i - 1) * 4, 4);
        if (i % 4 == 0) {
            uint8_t tmp = t[0];
            t[0] = (uint8_t)(SBOX[t[1]] ^ RCON[i / 4]);
            t[1] = SBOX[t[2]];
            t[2] = SBOX[t[3]];
            t[3] = SBOX[tmp];
        }
        for (int j = 0; j < 4; j++)
            rk[i * 4 + j] = rk[(i - 4) * 4 + j] ^ t[j];
    }
}
static inline uint8_t xtime(uint8_t x){ return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b)); }
static inline uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1; if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}
static void sw_enc_block(const aes_ctx *c, const uint8_t in[16], uint8_t out[16])
{
    const uint8_t *rk = c->sw;
    uint8_t s[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ rk[i];
    for (int round = 1; round <= 10; round++) {
        uint8_t t[16];
        for (int i = 0; i < 16; i++) t[i] = SBOX[s[i]];
        uint8_t a[16];
        a[0]=t[0];  a[4]=t[4];  a[8]=t[8];   a[12]=t[12];
        a[1]=t[5];  a[5]=t[9];  a[9]=t[13];  a[13]=t[1];
        a[2]=t[10]; a[6]=t[14]; a[10]=t[2];  a[14]=t[6];
        a[3]=t[15]; a[7]=t[3];  a[11]=t[7];  a[15]=t[11];
        if (round != 10) {
            for (int col = 0; col < 4; col++) {
                uint8_t *p = a + col * 4;
                uint8_t c0=p[0],c1=p[1],c2=p[2],c3=p[3];
                p[0]=(uint8_t)(xtime(c0)^(xtime(c1)^c1)^c2^c3);
                p[1]=(uint8_t)(c0^xtime(c1)^(xtime(c2)^c2)^c3);
                p[2]=(uint8_t)(c0^c1^xtime(c2)^(xtime(c3)^c3));
                p[3]=(uint8_t)((xtime(c0)^c0)^c1^c2^xtime(c3));
            }
        }
        for (int i = 0; i < 16; i++) s[i] = a[i] ^ rk[round * 16 + i];
    }
    memcpy(out, s, 16);
}
static void sw_dec_block(const aes_ctx *c, const uint8_t in[16], uint8_t out[16])
{
    const uint8_t *rk = c->sw;
    uint8_t s[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ rk[10 * 16 + i];
    for (int round = 9; round >= 0; round--) {
        uint8_t a[16];
        a[0]=s[0];  a[4]=s[4];  a[8]=s[8];   a[12]=s[12];
        a[1]=s[13]; a[5]=s[1];  a[9]=s[5];   a[13]=s[9];
        a[2]=s[10]; a[6]=s[14]; a[10]=s[2];  a[14]=s[6];
        a[3]=s[7];  a[7]=s[11]; a[11]=s[15]; a[15]=s[3];
        uint8_t t[16];
        for (int i = 0; i < 16; i++) t[i] = RSBOX[a[i]];
        for (int i = 0; i < 16; i++) t[i] ^= rk[round * 16 + i];
        if (round != 0) {
            for (int col = 0; col < 4; col++) {
                uint8_t *p = t + col * 4;
                uint8_t c0=p[0],c1=p[1],c2=p[2],c3=p[3];
                p[0]=(uint8_t)(gmul(c0,14)^gmul(c1,11)^gmul(c2,13)^gmul(c3,9));
                p[1]=(uint8_t)(gmul(c0,9)^gmul(c1,14)^gmul(c2,11)^gmul(c3,13));
                p[2]=(uint8_t)(gmul(c0,13)^gmul(c1,9)^gmul(c2,14)^gmul(c3,11));
                p[3]=(uint8_t)(gmul(c0,11)^gmul(c1,13)^gmul(c2,9)^gmul(c3,14));
            }
        }
        memcpy(s, t, 16);
    }
    memcpy(out, s, 16);
}

static void aes_setup(aes_ctx *c, const uint8_t key[16])
{
#if BAR_X86
    if (g_aesni) { ni_key_setup(c, key); return; }
#endif
    sw_key_setup(c, key);
}
static inline void aes_enc_block(const aes_ctx *c, const uint8_t in[16], uint8_t out[16])
{
#if BAR_X86
    if (g_aesni) { _mm_storeu_si128((__m128i *)out, ni_enc_block(c, _mm_loadu_si128((const __m128i *)in))); return; }
#endif
    sw_enc_block(c, in, out);
}
static inline void aes_dec_block(const aes_ctx *c, const uint8_t in[16], uint8_t out[16])
{
#if BAR_X86
    if (g_aesni) { _mm_storeu_si128((__m128i *)out, ni_dec_block(c, _mm_loadu_si128((const __m128i *)in))); return; }
#endif
    sw_dec_block(c, in, out);
}

/* Decrypt `nblocks` consecutive CBC blocks from `ct` into `out`, chaining from
 * iv[16]; iv is updated to the last ciphertext block. */
static void cbc_dec_blocks(const aes_ctx *c, const uint8_t *ct, size_t nblocks,
                           uint8_t iv[16], uint8_t *out)
{
#if BAR_X86
    if (g_aesni) {
        __m128i prev = _mm_loadu_si128((const __m128i *)iv);
        for (size_t i = 0; i < nblocks; i++) {
            __m128i cb = _mm_loadu_si128((const __m128i *)(ct + i * 16));
            __m128i pb = _mm_xor_si128(ni_dec_block(c, cb), prev);
            _mm_storeu_si128((__m128i *)(out + i * 16), pb);
            prev = cb;
        }
        _mm_storeu_si128((__m128i *)iv, prev);
        return;
    }
#endif
    {
        uint8_t prev[16]; memcpy(prev, iv, 16);
        for (size_t i = 0; i < nblocks; i++) {
            const uint8_t *cb = ct + i * 16;
            uint8_t db[16];
            sw_dec_block(c, cb, db);
            for (int j = 0; j < 16; j++) out[i * 16 + j] = db[j] ^ prev[j];
            memcpy(prev, cb, 16);
        }
        memcpy(iv, prev, 16);
    }
}

/* Encrypt `nblocks` CBC blocks from `pt` into `out`, chaining from iv[16];
 * iv is updated to the last ciphertext block. (Used by the creator.) */
static void cbc_enc_blocks(const aes_ctx *c, const uint8_t *pt, size_t nblocks,
                           uint8_t iv[16], uint8_t *out)
{
    uint8_t prev[16]; memcpy(prev, iv, 16);
    for (size_t i = 0; i < nblocks; i++) {
        uint8_t blk[16];
        for (int j = 0; j < 16; j++) blk[j] = pt[i * 16 + j] ^ prev[j];
        uint8_t cb[16];
        aes_enc_block(c, blk, cb);
        memcpy(out + i * 16, cb, 16);
        memcpy(prev, cb, 16);
    }
    memcpy(iv, prev, 16);
}

/* ---- SHA-256 + HMAC-SHA256 ---- */
typedef struct { uint32_t h[8]; uint64_t bits; uint8_t buf[64]; size_t n; } sha256_t;

static const uint32_t SHA_K[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };

#define BAR_SHR(x,n)  ((x) >> (n))
#define BAR_ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_blk(sha256_t *c, const uint8_t *p)
{
    uint32_t w[64], a,b,cc,d,e,f,g,h,t1,t2;
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4]<<24)|((uint32_t)p[i*4+1]<<16)|((uint32_t)p[i*4+2]<<8)|p[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = BAR_ROTR(w[i-15],7) ^ BAR_ROTR(w[i-15],18) ^ BAR_SHR(w[i-15],3);
        uint32_t s1 = BAR_ROTR(w[i-2],17) ^ BAR_ROTR(w[i-2],19) ^ BAR_SHR(w[i-2],10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=c->h[0];b=c->h[1];cc=c->h[2];d=c->h[3];e=c->h[4];f=c->h[5];g=c->h[6];h=c->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = BAR_ROTR(e,6) ^ BAR_ROTR(e,11) ^ BAR_ROTR(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        t1 = h + S1 + ch + SHA_K[i] + w[i];
        uint32_t S0 = BAR_ROTR(a,2) ^ BAR_ROTR(a,13) ^ BAR_ROTR(a,22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        t2 = S0 + maj;
        h=g;g=f;f=e;e=d+t1;d=cc;cc=b;b=a;a=t1+t2;
    }
    c->h[0]+=a;c->h[1]+=b;c->h[2]+=cc;c->h[3]+=d;c->h[4]+=e;c->h[5]+=f;c->h[6]+=g;c->h[7]+=h;
}
static void sha256_init(sha256_t *c)
{
    c->h[0]=0x6a09e667;c->h[1]=0xbb67ae85;c->h[2]=0x3c6ef372;c->h[3]=0xa54ff53a;
    c->h[4]=0x510e527f;c->h[5]=0x9b05688c;c->h[6]=0x1f83d9ab;c->h[7]=0x5be0cd19;
    c->bits=0;c->n=0;
}
static void sha256_update(sha256_t *c, const uint8_t *p, size_t len)
{
    c->bits += (uint64_t)len * 8;
    while (len) {
        size_t take = 64 - c->n; if (take > len) take = len;
        memcpy(c->buf + c->n, p, take);
        c->n += take; p += take; len -= take;
        if (c->n == 64) { sha256_blk(c, c->buf); c->n = 0; }
    }
}
static void sha256_final(sha256_t *c, uint8_t out[32])
{
    uint64_t bits = c->bits;
    uint8_t pad = 0x80;
    sha256_update(c, &pad, 1);
    uint8_t z = 0;
    while (c->n != 56) sha256_update(c, &z, 1);
    uint8_t lb[8];
    for (int i = 0; i < 8; i++) lb[i] = (uint8_t)(bits >> (56 - i*8));
    sha256_update(c, lb, 8);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(c->h[i] >> 24);
        out[i*4+1] = (uint8_t)(c->h[i] >> 16);
        out[i*4+2] = (uint8_t)(c->h[i] >> 8);
        out[i*4+3] = (uint8_t)(c->h[i]);
    }
}
typedef struct { sha256_t in, out; } hmac256_t;
static void hmac256_init(hmac256_t *h, const uint8_t *key, size_t klen)
{
    uint8_t k[64], ki[64], ko[64], kh[32];
    if (klen > 64) { sha256_t t; sha256_init(&t); sha256_update(&t,key,klen); sha256_final(&t,kh); key=kh; klen=32; }
    memset(k, 0, 64); memcpy(k, key, klen);
    for (int i = 0; i < 64; i++) { ki[i] = k[i]^0x36; ko[i] = k[i]^0x5c; }
    sha256_init(&h->in);  sha256_update(&h->in, ki, 64);
    sha256_init(&h->out); sha256_update(&h->out, ko, 64);
}
static void hmac256_update(hmac256_t *h, const uint8_t *p, size_t len)
{ sha256_update(&h->in, p, len); }
static void hmac256_final(hmac256_t *h, uint8_t out[32])
{
    uint8_t ih[32];
    sha256_final(&h->in, ih);
    sha256_update(&h->out, ih, 32);
    sha256_final(&h->out, out);
}

/* detect AES-NI (x86); always build the inverse sbox for the software path */
static void detect_aesni(void)
{
#if BAR_X86
  #if defined(_MSC_VER)
    int regs[4]; __cpuid(regs, 1);
    g_aesni = (regs[2] & (1 << 25)) ? 1 : 0;   /* ECX bit 25 = AES */
  #else
    unsigned a, b, c, d;
    if (__get_cpuid(1, &a, &b, &c, &d)) g_aesni = (c & bit_AES) ? 1 : 0;
  #endif
#else
    g_aesni = 0;
#endif
    build_rsbox();
}

static int hex2bin(const char *hex, uint8_t *out, int n)
{
    for (int i = 0; i < n; i++) {
        int hi, lo;
        char a = hex[2*i], b = hex[2*i+1];
        if (!a || !b) return -1;
        hi = (a<='9')?a-'0':(a|32)-'a'+10;
        lo = (b<='9')?b-'0':(b|32)-'a'+10;
        if (hi<0||hi>15||lo<0||lo>15) return -1;
        out[i] = (uint8_t)((hi<<4)|lo);
    }
    return 0;
}

#endif /* BAR_CRYPTO_H */
