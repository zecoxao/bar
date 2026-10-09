/*
 * p4br_extract.c  --  PS4 "Back Up PS4" (SCECAF / P4BR) restore extractor.
 *
 * Multithreaded native-Windows C port of p4br_extract.py.
 *
 * Build (mingw64 -> native .exe):
 *   x86_64-w64-mingw32-gcc -O3 -maes -msse4.1 p4br_extract.c -o p4br_extract.exe
 *
 * HMAC-SHA256 verification of the header and every segment runs before
 * extraction by default (obligatory); disable it with --verify false.
 *
 * Differences from the Python reference (all improvements, output identical):
 *   - Segments are decrypted with CBC random-access, a bounded window at a
 *     time, instead of materializing a whole segment in RAM.  This matters:
 *     individual segments in a real backup reach ~65 GB, which the Python
 *     PayloadReader would have tried to hold in memory all at once.
 *   - File extraction is fanned out across worker threads, each owning a
 *     contiguous (payload-order) slice of the catalog, its own archive file
 *     handles, and its own segment window.  Threads write disjoint files, so
 *     no write locking is needed.
 *   - AES-128 uses AES-NI when the CPU advertises it, with a portable software
 *     fallback.  Both paths produce identical plaintext.
 *
 * Container layout and record formats are exactly as documented in the Python
 * source; see that file's header comment for the on-disk spec.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>
#include <cpuid.h>
#include <wmmintrin.h>
#include <emmintrin.h>

#define MAX_SEG   0xFFFF0000ULL      /* per-archive split size            */
#define CHUNK     0x10000UL          /* file write chunk                  */
#define REC       0x458UL            /* catalog record size               */
#define BUFCAP    (1u << 20)         /* per-thread crypto window (mult 16) */

static const char CAF_MAGIC[8]  = { 'S','C','E','C','A','F',0,0 };
static const char P4BR_MAGIC[4] = { 'P','4','B','R' };
static const char *DEFAULT_KEY  = "101851B22B669178970C5459B3CB8D45";
/* HMAC-SHA256 key for the per-segment / header signatures (new keyset). */
static const char *DEFAULT_HASH_KEY =
    "184FBFBB6DC61433C7A5BD8259C1C21FFEC0ECBEC4319805EE0693869152EB52";

/* ===================================================================== */
/* AES-128 : AES-NI primary, software fallback                           */
/* ===================================================================== */

static int g_aesni = 0;

typedef struct {
    __m128i ni_enc[11];
    __m128i ni_dec[11];
    uint8_t sw[176];                 /* software round keys */
} aes_ctx;

/* ---- AES-NI ---- */
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
    m = _mm_aesenc_si128(m, e[1]);
    m = _mm_aesenc_si128(m, e[2]);
    m = _mm_aesenc_si128(m, e[3]);
    m = _mm_aesenc_si128(m, e[4]);
    m = _mm_aesenc_si128(m, e[5]);
    m = _mm_aesenc_si128(m, e[6]);
    m = _mm_aesenc_si128(m, e[7]);
    m = _mm_aesenc_si128(m, e[8]);
    m = _mm_aesenc_si128(m, e[9]);
    return _mm_aesenclast_si128(m, e[10]);
}

static inline __m128i ni_dec_block(const aes_ctx *c, __m128i m)
{
    const __m128i *d = c->ni_dec;
    m = _mm_xor_si128(m, d[0]);
    m = _mm_aesdec_si128(m, d[1]);
    m = _mm_aesdec_si128(m, d[2]);
    m = _mm_aesdec_si128(m, d[3]);
    m = _mm_aesdec_si128(m, d[4]);
    m = _mm_aesdec_si128(m, d[5]);
    m = _mm_aesdec_si128(m, d[6]);
    m = _mm_aesdec_si128(m, d[7]);
    m = _mm_aesdec_si128(m, d[8]);
    m = _mm_aesdec_si128(m, d[9]);
    return _mm_aesdeclast_si128(m, d[10]);
}

/* ---- software AES (fallback) ---- */
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

#define SW_RCON_N 10
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
        /* ShiftRows */
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
        /* InvShiftRows */
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
    if (g_aesni) ni_key_setup(c, key);
    else         sw_key_setup(c, key);
}

static inline void aes_enc_block(const aes_ctx *c, const uint8_t in[16], uint8_t out[16])
{
    if (g_aesni) _mm_storeu_si128((__m128i *)out, ni_enc_block(c, _mm_loadu_si128((const __m128i *)in)));
    else         sw_enc_block(c, in, out);
}

/* Decrypt `nblocks` consecutive CBC blocks of ciphertext `ct` into `out`,
 * chaining from iv[16]; iv is updated to the last ciphertext block. */
static void cbc_dec_blocks(const aes_ctx *c, const uint8_t *ct, size_t nblocks,
                           uint8_t iv[16], uint8_t *out)
{
    if (g_aesni) {
        __m128i prev = _mm_loadu_si128((const __m128i *)iv);
        for (size_t i = 0; i < nblocks; i++) {
            __m128i cb = _mm_loadu_si128((const __m128i *)(ct + i * 16));
            __m128i pb = _mm_xor_si128(ni_dec_block(c, cb), prev);
            _mm_storeu_si128((__m128i *)(out + i * 16), pb);
            prev = cb;
        }
        _mm_storeu_si128((__m128i *)iv, prev);
    } else {
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

/* ===================================================================== */
/* SHA-256 + HMAC-SHA256 (self-contained, used by --verify)              */
/* ===================================================================== */

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

#define SHR(x,n)  ((x) >> (n))
#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_blk(sha256_t *c, const uint8_t *p)
{
    uint32_t w[64], a,b,cc,d,e,f,g,h,t1,t2;
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4]<<24)|((uint32_t)p[i*4+1]<<16)|((uint32_t)p[i*4+2]<<8)|p[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROTR(w[i-15],7) ^ ROTR(w[i-15],18) ^ SHR(w[i-15],3);
        uint32_t s1 = ROTR(w[i-2],17) ^ ROTR(w[i-2],19) ^ SHR(w[i-2],10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=c->h[0];b=c->h[1];cc=c->h[2];d=c->h[3];e=c->h[4];f=c->h[5];g=c->h[6];h=c->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        t1 = h + S1 + ch + SHA_K[i] + w[i];
        uint32_t S0 = ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22);
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

/* ===================================================================== */
/* split-archive random-access reader                                    */
/* ===================================================================== */

typedef struct {
    const wchar_t *dir;
    HANDLE h;
    long long n;        /* currently-open archive index, -1 = none */
} archive_t;

static void archive_init(archive_t *a, const wchar_t *dir)
{
    a->dir = dir; a->h = INVALID_HANDLE_VALUE; a->n = -1;
}

static void archive_close(archive_t *a)
{
    if (a->h != INVALID_HANDLE_VALUE) { CloseHandle(a->h); a->h = INVALID_HANDLE_VALUE; }
    a->n = -1;
}

static HANDLE archive_open(const wchar_t *dir, long long n)
{
    wchar_t path[MAX_PATH * 2];
    if (n == 0) _snwprintf(path, MAX_PATH * 2, L"%s\\archive.dat", dir);
    else        _snwprintf(path, MAX_PATH * 2, L"%s\\archive%04lld.dat", dir, n);
    return CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
}

/* read `size` bytes from global offset `off`; returns bytes actually read */
static uint64_t archive_read(archive_t *a, uint64_t off, uint64_t size, uint8_t *buf)
{
    uint8_t *p = buf;
    while (size > 0) {
        long long n = (long long)(off / MAX_SEG);
        uint64_t within = off % MAX_SEG;
        if (a->n != n) {
            if (a->h != INVALID_HANDLE_VALUE) CloseHandle(a->h);
            a->h = archive_open(a->dir, n);
            a->n = n;
            if (a->h == INVALID_HANDLE_VALUE) { a->n = -1; break; }
        }
        LARGE_INTEGER li; li.QuadPart = (LONGLONG)within;
        if (!SetFilePointerEx(a->h, li, NULL, FILE_BEGIN)) break;
        uint64_t want = MAX_SEG - within;
        if (want > size) want = size;
        DWORD got = 0;
        DWORD req = (DWORD)(want > 0x40000000UL ? 0x40000000UL : want);
        if (!ReadFile(a->h, p, req, &got, NULL) || got == 0) break;
        p += got; off += got; size -= got;
    }
    return (uint64_t)(p - buf);
}

/* ===================================================================== */
/* segment table / catalog                                               */
/* ===================================================================== */

typedef struct {
    uint64_t index, off, pad, algo, key_idx;
    uint8_t  seed[16];
    uint64_t nopad;
} segment_t;

typedef struct {
    char    *path;      /* UTF-8 bytes, NUL-terminated */
    uint64_t size;
    uint32_t mode;
    uint32_t mtime;
} record_t;

static uint64_t rd_u64(const uint8_t *p){ uint64_t v; memcpy(&v,p,8); return v; }
static uint32_t rd_u32(const uint8_t *p){ uint32_t v; memcpy(&v,p,4); return v; }

/* decrypt plaintext sub-range [so, so+len) of a segment into out.
 * Streams ciphertext through a bounded window; never allocates the segment. */
static void seg_read_plain(archive_t *ar, const aes_ctx *c, const segment_t *seg,
                           uint64_t so, uint64_t len, uint8_t *out,
                           uint8_t *rbuf, uint8_t *pbuf /* each BUFCAP, 16-aligned */)
{
    uint64_t L = seg->nopad;
    uint64_t full = L - (L % 16);
    uint64_t end = so + len;

    if (so < full) {
        uint64_t region_end = end < full ? end : full;
        uint64_t b0 = so / 16;
        uint64_t first = b0 * 16;
        uint8_t iv[16];
        if (b0 == 0) memcpy(iv, seg->seed, 16);
        else         archive_read(ar, seg->off + first - 16, 16, iv);

        uint64_t cpos = first;
        while (cpos < region_end) {
            uint64_t want = region_end - cpos;
            if (want > BUFCAP) want = BUFCAP;         /* multiple of 16 */
            archive_read(ar, seg->off + cpos, want, rbuf);
            cbc_dec_blocks(c, rbuf, (size_t)(want / 16), iv, pbuf);
            uint64_t cstart = cpos > so ? cpos : so;
            uint64_t cendv  = (cpos + want < region_end) ? (cpos + want) : region_end;
            if (cendv > cstart)
                memcpy(out + (cstart - so), pbuf + (cstart - cpos), (size_t)(cendv - cstart));
            cpos += want;
        }
    }

    if (end > full) {                                  /* ciphertext-stealing tail */
        uint64_t tstart = so > full ? so : full;
        uint8_t prev[16], ks[16], ctb[16];
        if (full >= 16) archive_read(ar, seg->off + full - 16, 16, prev);
        else            memcpy(prev, seg->seed, 16);
        aes_enc_block(c, prev, ks);
        uint64_t r = L - full;
        archive_read(ar, seg->off + full, r, ctb);
        for (uint64_t j = tstart; j < end; j++)
            out[j - so] = ctb[j - full] ^ ks[j - full];
    }
}

/* ===================================================================== */
/* payload reader (payload = concatenated plaintext of segs[seg_start:])  */
/* ===================================================================== */

typedef struct {
    archive_t      ar;
    const aes_ctx *c;
    const segment_t *segs;   /* full array */
    const uint64_t  *prefix; /* prefix[i] = payload offset at segs[seg_start+i] */
    int   nseg;              /* count from seg_start */
    int   seg_start;
    uint8_t *rbuf, *pbuf;
} payload_t;

static int pr_locate(const payload_t *p, uint64_t pos)
{
    int lo = 0, hi = p->nseg - 1;
    while (lo < hi) {
        int mid = (lo + hi + 1) / 2;
        if (p->prefix[mid] <= pos) lo = mid; else hi = mid - 1;
    }
    return lo;
}

static uint64_t pr_read(payload_t *p, uint64_t pos, uint64_t n, uint8_t *out)
{
    uint8_t *o = out;
    int i = pr_locate(p, pos);
    while (n > 0 && i < p->nseg) {
        const segment_t *seg = &p->segs[p->seg_start + i];
        uint64_t seg_off = pos - p->prefix[i];
        uint64_t avail = seg->nopad - seg_off;
        if ((int64_t)avail <= 0) { i++; continue; }
        uint64_t take = n < avail ? n : avail;
        seg_read_plain(&p->ar, p->c, seg, seg_off, take, o, p->rbuf, p->pbuf);
        o += take; pos += take; n -= take; i++;
    }
    return (uint64_t)(o - out);
}

/* ===================================================================== */
/* path helpers                                                          */
/* ===================================================================== */

static wchar_t *utf8_to_wide(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, NULL, 0);
    UINT cp = CP_UTF8;
    if (n == 0) { cp = CP_ACP; n = MultiByteToWideChar(cp, 0, s, -1, NULL, 0); }
    if (n == 0) return NULL;
    wchar_t *w = malloc((size_t)n * sizeof(wchar_t));
    if (!w) return NULL;
    MultiByteToWideChar(cp, 0, s, -1, w, n);
    return w;
}

/* Build outdir-relative dest (UTF-8) for an absolute POSIX catalog path.
 * Returns 0 and fills dst on success, -1 if the path is unsafe. */
static int safe_join(const char *outdir, const char *path, char *dst, size_t cap)
{
    size_t len = strlen(outdir);
    if (len + 1 >= cap) return -1;
    memcpy(dst, outdir, len);
    size_t w = len;
    const char *p = path;
    while (*p == '/') p++;
    while (*p) {
        const char *seg = p;
        while (*p && *p != '/') p++;
        size_t sl = (size_t)(p - seg);
        while (*p == '/') p++;
        if (sl == 0) continue;
        if (sl == 1 && seg[0] == '.') continue;
        if (sl == 2 && seg[0] == '.' && seg[1] == '.') return -1;
        if (w + 1 + sl >= cap) return -1;
        dst[w++] = '\\';
        memcpy(dst + w, seg, sl);
        w += sl;
    }
    dst[w] = 0;
    return 0;
}

/* recursively create all directory components of a wide path */
static void mkdirs_w(const wchar_t *full)
{
    wchar_t tmp[MAX_PATH * 2];
    size_t n = wcslen(full);
    if (n >= MAX_PATH * 2) return;
    wcscpy(tmp, full);
    for (size_t i = 1; i < n; i++) {
        if (tmp[i] == L'\\') {
            tmp[i] = 0;
            if (!(i == 2 && tmp[1] == L':'))
                CreateDirectoryW(tmp, NULL);
            tmp[i] = L'\\';
        }
    }
    CreateDirectoryW(tmp, NULL);
}

static void mkdirs_parent_w(const wchar_t *full)
{
    wchar_t tmp[MAX_PATH * 2];
    size_t n = wcslen(full);
    if (n >= MAX_PATH * 2) return;
    wcscpy(tmp, full);
    for (long i = (long)n - 1; i >= 0; i--) {
        if (tmp[i] == L'\\') { tmp[i] = 0; mkdirs_w(tmp); return; }
    }
}

static void human(uint64_t n, char *out)
{
    const char *u[] = { "B","KB","MB","GB","TB","PB" };
    double d = (double)n; int i = 0;
    while (d >= 1024.0 && i < 5) { d /= 1024.0; i++; }
    sprintf(out, "%.1f%s", d, u[i]);
}

/* ===================================================================== */
/* catalog parsing                                                       */
/* ===================================================================== */

static record_t *parse_catalog(const uint8_t *blob, uint64_t blen, int *count)
{
    uint64_t nmax = blen / REC;
    record_t *recs = malloc((size_t)(nmax ? nmax : 1) * sizeof(record_t));
    int n = 0;
    for (uint64_t i = 0; i < nmax; i++) {
        const uint8_t *r = blob + i * REC;
        uint64_t size  = rd_u64(r + 0x30);
        uint32_t mode  = rd_u32(r + 0x50);
        uint32_t mtime = rd_u32(r + 0x10);
        const char *ps = (const char *)(r + 0x54);
        size_t maxlen = REC - 0x54;
        size_t pl = strnlen(ps, maxlen);
        if (mode == 0 && pl == 0) break;
        char *path = malloc(pl + 1);
        memcpy(path, ps, pl); path[pl] = 0;
        recs[n].path = path; recs[n].size = size;
        recs[n].mode = mode; recs[n].mtime = mtime;
        n++;
    }
    *count = n;
    return recs;
}

/* ===================================================================== */
/* filters                                                               */
/* ===================================================================== */

typedef struct { char **inc; int ninc; char **exc; int nexc; } filter_t;

static int starts_with(const char *s, const char *pre)
{
    size_t l = strlen(pre);
    return strncmp(s, pre, l) == 0;
}

static int wanted(const filter_t *f, const char *path)
{
    if (f->ninc) {
        int any = 0;
        for (int i = 0; i < f->ninc; i++) if (starts_with(path, f->inc[i])) { any = 1; break; }
        if (!any) return 0;
    }
    for (int i = 0; i < f->nexc; i++) if (starts_with(path, f->exc[i])) return 0;
    return 1;
}

/* ===================================================================== */
/* worker threads                                                        */
/* ===================================================================== */

static volatile LONG64 g_done = 0;
static volatile LONG64 g_extracted = 0;
static volatile LONG64 g_skipped = 0;

typedef struct {
    const wchar_t  *dir;
    const aes_ctx  *c;
    const segment_t *segs;
    const uint64_t  *prefix;
    int    nseg, seg_start;
    const record_t *files;
    const uint64_t *cums;        /* payload offset of each file */
    const filter_t *filt;
    const char     *outdir;
    int    from, to;             /* [from, to) file indices this thread owns */
    uint64_t max_bytes;          /* 0 = unlimited (global budget, shared read only) */
    int    tid;
} worker_t;

static void unix_to_filetime(uint32_t t, FILETIME *ft)
{
    ULONGLONG ll = ((ULONGLONG)t + 11644473600ULL) * 10000000ULL;
    ft->dwLowDateTime  = (DWORD)(ll & 0xFFFFFFFFULL);
    ft->dwHighDateTime = (DWORD)(ll >> 32);
}

static DWORD WINAPI worker_main(LPVOID arg)
{
    worker_t *w = (worker_t *)arg;
    payload_t pr;
    archive_init(&pr.ar, w->dir);
    pr.c = w->c; pr.segs = w->segs; pr.prefix = w->prefix;
    pr.nseg = w->nseg; pr.seg_start = w->seg_start;
    pr.rbuf = _aligned_malloc(BUFCAP, 16);
    pr.pbuf = _aligned_malloc(BUFCAP, 16);
    uint8_t *fbuf = malloc(CHUNK);
    char dst[MAX_PATH * 2];

    for (int idx = w->from; idx < w->to; idx++) {
        if (w->max_bytes && g_done >= (LONG64)w->max_bytes) break;
        const record_t *rec = &w->files[idx];
        if (!wanted(w->filt, rec->path)) { InterlockedIncrement64(&g_skipped); continue; }
        if (safe_join(w->outdir, rec->path, dst, sizeof dst) != 0) {
            fprintf(stderr, "  !! unsafe path skipped: %s\n", rec->path);
            continue;
        }
        wchar_t *wdst = utf8_to_wide(dst);
        if (!wdst) { fprintf(stderr, "  !! bad path: %s\n", rec->path); continue; }
        mkdirs_parent_w(wdst);

        /* resume: a complete file already present is left alone */
        WIN32_FILE_ATTRIBUTE_DATA fad;
        if (GetFileAttributesExW(wdst, GetFileExInfoStandard, &fad)) {
            ULONGLONG cur = ((ULONGLONG)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
            if (cur == rec->size) {
                InterlockedAdd64(&g_done, (LONG64)rec->size);
                InterlockedIncrement64(&g_skipped);
                free(wdst); continue;
            }
        }

        HANDLE out = CreateFileW(wdst, GENERIC_WRITE, 0, NULL,
                                 CREATE_ALWAYS, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (out == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "  !! cannot create: %s\n", rec->path);
            free(wdst); continue;
        }
        uint64_t pos = w->cums[idx];
        uint64_t remaining = rec->size;
        int ok = 1;
        while (remaining > 0) {
            uint64_t want = remaining < CHUNK ? remaining : CHUNK;
            uint64_t got = pr_read(&pr, pos, want, fbuf);
            if (got == 0) { fprintf(stderr, "  !! short read on %s\n", rec->path); ok = 0; break; }
            DWORD wr = 0;
            if (!WriteFile(out, fbuf, (DWORD)got, &wr, NULL) || wr != got) {
                fprintf(stderr, "  !! write error on %s\n", rec->path); ok = 0; break;
            }
            pos += got; remaining -= got;
            InterlockedAdd64(&g_done, (LONG64)got);
        }
        if (ok) {
            FILETIME ft; unix_to_filetime(rec->mtime, &ft);
            SetFileTime(out, &ft, &ft, &ft);
        }
        CloseHandle(out);
        free(wdst);
        if (ok) InterlockedIncrement64(&g_extracted);
    }

    archive_close(&pr.ar);
    _aligned_free(pr.rbuf); _aligned_free(pr.pbuf); free(fbuf);
    return 0;
}

/* ===================================================================== */
/* main                                                                  */
/* ===================================================================== */

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

static void detect_aesni(void)
{
    unsigned a, b, c, d;
    if (__get_cpuid(1, &a, &b, &c, &d)) g_aesni = (c & bit_AES) ? 1 : 0;
    build_rsbox();   /* always, in case fallback is used */
}

/* ===================================================================== */
/* --verify : per-segment + header HMAC-SHA256                           */
/* ===================================================================== */

/* HMAC-SHA256 over a segment's raw ciphertext (data_size_without_padding
 * bytes at seg->off), streamed through a bounded window. `base` is an
 * hmac256_t whose key has already been absorbed. */
static void hmac_segment_ct(archive_t *ar, const hmac256_t *base,
                            const segment_t *seg, uint8_t *rbuf, uint8_t out[32])
{
    hmac256_t h = *base;
    uint64_t left = seg->nopad, pos = seg->off;
    while (left) {
        uint64_t want = left < BUFCAP ? left : BUFCAP;
        uint64_t got = archive_read(ar, pos, want, rbuf);
        if (got == 0) break;
        hmac256_update(&h, rbuf, (size_t)got);
        pos += got; left -= got;
    }
    hmac256_final(&h, out);
}

/* HMAC-SHA256 over the plaintext header region file[0:hsize]. */
static void hmac_header(archive_t *ar, const hmac256_t *base,
                        uint64_t hsize, uint8_t *rbuf, uint8_t out[32])
{
    hmac256_t h = *base;
    uint64_t left = hsize, pos = 0;
    while (left) {
        uint64_t want = left < BUFCAP ? left : BUFCAP;
        uint64_t got = archive_read(ar, pos, want, rbuf);
        if (got == 0) break;
        hmac256_update(&h, rbuf, (size_t)got);
        pos += got; left -= got;
    }
    hmac256_final(&h, out);
}

int main(int argc, char **argv)
{
    const char *backup = NULL, *outdir = "restore", *keyhex = DEFAULT_KEY;
    const char *hashhex = DEFAULT_HASH_KEY;
    const char *manifest = NULL;
    char *inc[64]; int ninc = 0;
    char *exc[64]; int nexc = 0;
    int do_list = 0;
    int verify = 1;              /* obligatory by default; --verify false disables */
    uint64_t max_bytes = 0;
    int nthreads = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a,"-o")||!strcmp(a,"--out"))        outdir   = argv[++i];
        else if (!strcmp(a,"-k")||!strcmp(a,"--key"))   keyhex   = argv[++i];
        else if (!strcmp(a,"-H")||!strcmp(a,"--hash-key")) hashhex = argv[++i];
        else if (!strcmp(a,"--include"))                { if (ninc<64) inc[ninc++]=argv[++i]; else i++; }
        else if (!strcmp(a,"--exclude"))                { if (nexc<64) exc[nexc++]=argv[++i]; else i++; }
        else if (!strcmp(a,"--list"))                   do_list = 1;
        else if (!strcmp(a,"--manifest"))               manifest = argv[++i];
        else if (!strcmp(a,"--max-bytes"))              max_bytes = strtoull(argv[++i],NULL,0);
        else if (!strcmp(a,"-j")||!strcmp(a,"--threads")) nthreads = atoi(argv[++i]);
        else if (!strcmp(a,"--verify")) {
            /* optional boolean argument; default true */
            const char *v = (i+1 < argc) ? argv[i+1] : NULL;
            if (v && (!strcmp(v,"false")||!strcmp(v,"0")||!strcmp(v,"no")||!strcmp(v,"off")))  { verify = 0; i++; }
            else if (v && (!strcmp(v,"true")||!strcmp(v,"1")||!strcmp(v,"yes")||!strcmp(v,"on"))) { verify = 1; i++; }
            else verify = 1;
        }
        else if (a[0]=='-') { fprintf(stderr,"unknown option: %s\n",a); return 2; }
        else backup = a;
    }
    if (!backup) { fprintf(stderr,
        "usage: p4br_extract <backup_dir> [-o out] [-k hexkey] [-H hashkey]\n"
        "                    [--include P]... [--exclude P]... [--list]\n"
        "                    [--verify true|false] [--manifest F] [--max-bytes N] [-j threads]\n"
        "\n"
        "HMAC-SHA256 verification of the header and every segment runs before\n"
        "extraction by default (obligatory); disable it with --verify false.\n"); return 2; }

    uint8_t key[16];
    if (strlen(keyhex) != 32 || hex2bin(keyhex, key, 16) != 0) {
        fprintf(stderr, "key must be 16 bytes (32 hex chars)\n"); return 2;
    }
    uint8_t hkey[32];
    if (strlen(hashhex) != 64 || hex2bin(hashhex, hkey, 32) != 0) {
        fprintf(stderr, "hash key must be 32 bytes (64 hex chars)\n"); return 2;
    }

    detect_aesni();
    aes_ctx ctx;
    aes_setup(&ctx, key);

    wchar_t *wdir = utf8_to_wide(backup);
    if (!wdir) { fprintf(stderr,"bad backup path\n"); return 2; }

    archive_t ar; archive_init(&ar, wdir);
    uint8_t hdr[0x30];
    if (archive_read(&ar, 0, 0x30, hdr) != 0x30 || memcmp(hdr, CAF_MAGIC, 8) != 0) {
        fprintf(stderr, "not a SCECAF container\n"); return 1;
    }
    uint64_t version  = rd_u64(hdr + 0x08);
    uint64_t nseg     = rd_u64(hdr + 0x18);
    uint64_t file_size= rd_u64(hdr + 0x28);

    uint8_t *tbl = malloc((size_t)(0x40 * nseg));
    archive_read(&ar, 0x30, 0x40 * nseg, tbl);
    segment_t *segs = malloc((size_t)nseg * sizeof(segment_t));
    for (uint64_t i = 0; i < nseg; i++) {
        const uint8_t *r = tbl + 0x40 * i;
        segs[i].index   = rd_u64(r + 0x00);
        segs[i].off     = rd_u64(r + 0x08);
        segs[i].pad     = rd_u64(r + 0x10);
        segs[i].algo    = rd_u64(r + 0x18);
        segs[i].key_idx = rd_u64(r + 0x20);
        memcpy(segs[i].seed, r + 0x28, 16);
        segs[i].nopad   = rd_u64(r + 0x38);
    }
    free(tbl);

    char hbuf[32];
    human(file_size, hbuf);
    printf("[+] SCECAF v%llu  segments=%llu  total=%s (0x%llx)%s\n",
           (unsigned long long)version, (unsigned long long)nseg, hbuf,
           (unsigned long long)file_size, g_aesni ? "  [AES-NI]" : "  [SW-AES]");

    uint8_t *rbuf = _aligned_malloc(BUFCAP, 16);
    uint8_t *pbuf = _aligned_malloc(BUFCAP, 16);

    /* seg0: P4BR header */
    uint8_t *p4 = malloc((size_t)segs[0].nopad);
    seg_read_plain(&ar, &ctx, &segs[0], 0, segs[0].nopad, p4, rbuf, pbuf);
    if (memcmp(p4, P4BR_MAGIC, 4) != 0) {
        fprintf(stderr, "decrypt failed: expected P4BR, got %02x%02x%02x%02x -- wrong key?\n",
                p4[0],p4[1],p4[2],p4[3]);
        return 1;
    }
    uint32_t ndirs  = rd_u32(p4 + 0x10);
    uint32_t nfiles = rd_u32(p4 + 0x14);
    char name[256]={0}, title[256]={0};
    strncpy(name, (char*)p4 + 0x34, 255);
    strncpy(title, (char*)p4 + 0x80, 255);
    printf("[+] P4BR  '%s'  label='%s'  dirs=%u files=%u\n", name, title, ndirs, nfiles);
    free(p4);

    /* seg1 dirs, seg2 files */
    uint8_t *dblob = malloc((size_t)segs[1].nopad);
    seg_read_plain(&ar, &ctx, &segs[1], 0, segs[1].nopad, dblob, rbuf, pbuf);
    uint8_t *fblob = malloc((size_t)segs[2].nopad);
    seg_read_plain(&ar, &ctx, &segs[2], 0, segs[2].nopad, fblob, rbuf, pbuf);
    int ndir_rec, nfile_rec;
    record_t *dirs  = parse_catalog(dblob, segs[1].nopad, &ndir_rec);
    record_t *files = parse_catalog(fblob, segs[2].nopad, &nfile_rec);
    free(dblob); free(fblob);
    printf("[+] catalog: %d dirs, %d files\n", ndir_rec, nfile_rec);

    /* locate payload start segment */
    uint64_t sum_files = 0;
    for (int i = 0; i < nfile_rec; i++) sum_files += files[i].size;
    uint64_t data_from3 = 0;
    for (uint64_t i = 3; i < nseg; i++) data_from3 += segs[i].nopad;
    if (data_from3 < sum_files) { fprintf(stderr,"catalog/segment size mismatch; refusing\n"); return 1; }
    uint64_t aux = data_from3 - sum_files;
    int seg_start = 3; uint64_t acc = 0;
    while (seg_start < (int)nseg && acc + segs[seg_start].nopad <= aux) { acc += segs[seg_start].nopad; seg_start++; }
    if (acc != aux) { fprintf(stderr,"aux prefix 0x%llx not on segment boundary (acc=0x%llx)\n",
                              (unsigned long long)aux,(unsigned long long)acc); return 1; }
    human(aux, hbuf);
    printf("[+] payload begins at segment index %d (aux metadata = %s)\n", seg_start, hbuf);

    /* prefix offsets over segs[seg_start:] */
    int npseg = (int)nseg - seg_start;
    uint64_t *prefix = malloc((size_t)(npseg + 1) * sizeof(uint64_t));
    prefix[0] = 0;
    for (int i = 0; i < npseg; i++) prefix[i+1] = prefix[i] + segs[seg_start + i].nopad;
    uint64_t pr_total = prefix[npseg];

    /* cumulative payload offset of each file */
    uint64_t *cums = malloc((size_t)nfile_rec * sizeof(uint64_t));
    uint64_t cum = 0;
    for (int i = 0; i < nfile_rec; i++) { cums[i] = cum; cum += files[i].size; }
    if (cum != pr_total)
        printf("[!] warning: catalog payload 0x%llx != segment payload 0x%llx\n",
               (unsigned long long)cum, (unsigned long long)pr_total);

    /* ----- obligatory HMAC-SHA256 verification (header + every segment) ----- */
    if (verify && !do_list) {
        hmac256_t base; hmac256_init(&base, hkey, 32);
        uint64_t hsize    = 0x30 + 0x40 * nseg + 0x30 * nseg;
        uint64_t sig_base = 0x30 + 0x40 * nseg;
        uint8_t calc[32], want[32];

        archive_read(&ar, hsize, 0x20, want);
        hmac_header(&ar, &base, hsize, rbuf, calc);
        int hdr_ok = (memcmp(calc, want, 32) == 0);
        printf("[+] HMAC header signature: %s\n", hdr_ok ? "OK" : "MISMATCH");

        int bad = 0, empty = 0, checked = 0;
        for (uint64_t i = 0; i < nseg; i++) {
            if (segs[i].nopad == 0) { empty++; continue; }  /* empty seg: placeholder sig */
            uint8_t sig[48];
            archive_read(&ar, sig_base + 48 * i, 48, sig);
            hmac_segment_ct(&ar, &base, &segs[i], rbuf, calc);
            checked++;
            if (memcmp(calc, sig + 8, 32) != 0) {
                bad++;
                const char *label = "?";
                char lbuf[300];
                if ((int)i < seg_start) {
                    const char *names[3] = { "P4BR header", "dir catalog", "file catalog" };
                    label = (i < 3) ? names[i] : "aux metadata";
                } else {
                    uint64_t p0 = prefix[i - (uint64_t)seg_start];
                    uint64_t p1 = p0 + segs[i].nopad;
                    int first = -1, hits = 0;
                    for (int f = 0; f < nfile_rec; f++) {
                        uint64_t a0 = cums[f], a1 = cums[f] + files[f].size;
                        if (a0 < p1 && a1 > p0) { if (first < 0) first = f; hits++; }
                    }
                    if (first >= 0) {
                        if (hits > 1) { snprintf(lbuf, sizeof lbuf, "%s (+%d more)", files[first].path, hits - 1); label = lbuf; }
                        else label = files[first].path;
                    }
                }
                printf("  BAD  seg[%llu] index=%llu nopad=0x%llx -> %s\n",
                       (unsigned long long)i, (unsigned long long)segs[i].index,
                       (unsigned long long)segs[i].nopad, label);
            }
        }
        printf("[+] segment HMAC: %d/%d OK, %d bad, %d empty (placeholder)\n",
               checked - bad, checked, bad, empty);
        int ok = hdr_ok && !bad;
        printf("%s\n", ok ? "[+] verification PASSED"
                          : "[!] verification FAILED -- extracting anyway (data may be corrupt)");
    }

    filter_t filt = { inc, ninc, exc, nexc };

    /* roots summary */
    {
        printf("[+] roots:");
        /* simple top-level aggregation */
        char seen[32][64]; uint64_t cnt[32]; uint64_t sz[32]; int ns = 0;
        for (int i = 0; i < nfile_rec; i++) {
            const char *p = files[i].path; while (*p=='/') p++;
            char top[64]; int k=0; while (p[k] && p[k]!='/' && k<63){ top[k]=p[k]; k++; } top[k]=0;
            if (k==0) strcpy(top,"?");
            int j; for (j=0;j<ns;j++) if (!strcmp(seen[j],top)) break;
            if (j==ns && ns<32){ strcpy(seen[ns],top); cnt[ns]=0; sz[ns]=0; ns++; }
            if (j<32){ cnt[j]++; sz[j]+=files[i].size; }
        }
        for (int j=0;j<ns;j++){ char hb[32]; human(sz[j],hb);
            printf(" %s(%llu files, %s)%s", seen[j], (unsigned long long)cnt[j], hb, j<ns-1?",":""); }
        printf("\n");
    }

    if (manifest) {
        FILE *mf = fopen(manifest, "w");
        if (mf) {
            fputs("path\tsize\tmode\tmtime\n", mf);
            for (int i = 0; i < nfile_rec; i++)
                fprintf(mf, "%s\t%llu\t%o\t%u\n", files[i].path,
                        (unsigned long long)files[i].size, files[i].mode, files[i].mtime);
            fclose(mf);
            printf("[+] manifest written: %s\n", manifest);
        }
    }

    if (do_list) {
        for (int i = 0; i < nfile_rec; i++)
            if (wanted(&filt, files[i].path))
                printf("  %06o %12llu %s\n", files[i].mode,
                       (unsigned long long)files[i].size, files[i].path);
        return 0;
    }

    /* pre-create directories (single-threaded, avoids mkdir races) */
    char djoin[MAX_PATH*2];
    for (int i = 0; i < ndir_rec; i++) {
        if (!wanted(&filt, dirs[i].path)) continue;
        if (safe_join(outdir, dirs[i].path, djoin, sizeof djoin) == 0) {
            wchar_t *wd = utf8_to_wide(djoin);
            if (wd) { mkdirs_w(wd); free(wd); }
        }
    }
    for (int i = 0; i < nfile_rec; i++) {
        if (!wanted(&filt, files[i].path)) continue;
        if (safe_join(outdir, files[i].path, djoin, sizeof djoin) == 0) {
            wchar_t *wd = utf8_to_wide(djoin);
            if (wd) { mkdirs_parent_w(wd); free(wd); }
        }
    }
    { wchar_t *wo = utf8_to_wide(outdir); if (wo) { mkdirs_w(wo); free(wo); } }

    /* last wanted index + selected total */
    int last_wanted = -1; uint64_t sel_total = 0;
    for (int i = 0; i < nfile_rec; i++)
        if (wanted(&filt, files[i].path)) { last_wanted = i; sel_total += files[i].size; }
    if (last_wanted < 0) { printf("[!] nothing matches the include/exclude filters\n"); return 0; }

    if (nthreads <= 0) {
        SYSTEM_INFO si; GetSystemInfo(&si);
        nthreads = (int)si.dwNumberOfProcessors;
        if (nthreads < 1) nthreads = 1;
        if (nthreads > 32) nthreads = 32;
    }
    int lim = last_wanted + 1;
    if (nthreads > lim) nthreads = lim ? lim : 1;

    human(sel_total, hbuf);
    printf("[+] extracting %s selected payload with %d threads to %s\n", hbuf, nthreads, outdir);

    /* Partition [0, lim) into contiguous ranges balanced by wanted bytes. */
    worker_t *wk = calloc((size_t)nthreads, sizeof(worker_t));
    HANDLE   *th = calloc((size_t)nthreads, sizeof(HANDLE));
    uint64_t per = sel_total / (uint64_t)nthreads;
    int t = 0, start = 0; uint64_t acc_b = 0;
    for (int i = 0; i < lim && t < nthreads; i++) {
        if (wanted(&filt, files[i].path)) acc_b += files[i].size;
        int last_thread = (t == nthreads - 1);
        if (!last_thread && acc_b >= per * (uint64_t)(t + 1) && i + 1 < lim) {
            wk[t].from = start; wk[t].to = i + 1; start = i + 1; t++;
        }
    }
    wk[t].from = start; wk[t].to = lim; t++;
    int actual = t;

    LARGE_INTEGER freq, t0; QueryPerformanceFrequency(&freq); QueryPerformanceCounter(&t0);

    for (int i = 0; i < actual; i++) {
        wk[i].dir = wdir; wk[i].c = &ctx; wk[i].segs = segs; wk[i].prefix = prefix;
        wk[i].nseg = npseg; wk[i].seg_start = seg_start; wk[i].files = files;
        wk[i].cums = cums; wk[i].filt = &filt; wk[i].outdir = outdir;
        wk[i].max_bytes = max_bytes; wk[i].tid = i;
        th[i] = CreateThread(NULL, 0, worker_main, &wk[i], 0, NULL);
    }

    /* progress loop */
    for (;;) {
        DWORD r = WaitForMultipleObjects(actual, th, TRUE, 2000);
        LARGE_INTEGER now; QueryPerformanceCounter(&now);
        double el = (double)(now.QuadPart - t0.QuadPart) / (double)freq.QuadPart;
        LONG64 done = g_done;
        char hb1[32], hb2[32], hr[32];
        human((uint64_t)done, hb1); human(sel_total, hb2);
        human((uint64_t)(done / (el > 1e-6 ? el : 1e-6)), hr);
        printf("\r  %s/%s @ %s/s  (%llds)      ", hb1, hb2, hr, (long long)el);
        fflush(stdout);
        if (r == WAIT_OBJECT_0) break;
        if (max_bytes && done >= (LONG64)max_bytes) {
            /* budget reached; let threads finish their current file then stop.
               (Threads honor max_bytes implicitly via the global counter below.) */
        }
    }
    printf("\n");

    for (int i = 0; i < actual; i++) CloseHandle(th[i]);

    LARGE_INTEGER end; QueryPerformanceCounter(&end);
    double el = (double)(end.QuadPart - t0.QuadPart) / (double)freq.QuadPart;
    char hb3[32]; human((uint64_t)g_done, hb3);
    printf("[+] done: %lld extracted, %lld skipped, %s written in %.0fs -> %s\n",
           (long long)g_extracted, (long long)g_skipped, hb3, el, outdir);

    archive_close(&ar);
    _aligned_free(rbuf); _aligned_free(pbuf);
    return 0;
}
