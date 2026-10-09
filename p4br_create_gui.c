/*
 * p4br_create_gui.c  --  PS4 "Back Up PS4" (SCECAF / P4BR) backup CREATOR,
 *                        Win32 GUI (also runs as a CLI when given arguments).
 *
 * Inverse of p4br_extract: packs a folder tree into a SCECAF/P4BR container
 * (archive.dat [+ archiveNNNN.dat ...]) with the documented layout,
 * AES-128-CBC (+ ciphertext-stealing tail) segment encryption and valid
 * HMAC-SHA256 per-segment and header signatures.
 *
 * Build (mingw64 -> native .exe):
 *   x86_64-w64-mingw32-gcc -O3 -maes -msse4.1 -mwindows \
 *       p4br_create_gui.c -o p4br_create_gui.exe -lshell32 -lole32 -luuid
 *
 * SCOPE / CAVEAT
 *   The container produced here round-trips through p4br_extract (and passes
 *   its --verify): the catalog, encryption and signatures are correct.  It is
 *   NOT guaranteed to be restorable by a real PS4, because the "aux metadata"
 *   segments (seg3..5 in a Sony backup -- a large structured table) are not
 *   reverse-engineered.  This tool emits no aux segments: payload starts right
 *   after the catalogs (the extractor handles aux = 0).
 *
 * Layout written (mirrors the format documented in p4br_extract):
 *   SCECAF header (0x30) | segment table (0x40*nseg) | segment signatures
 *   (0x30*nseg) | header HMAC (0x20) | zero pad to file_offset |
 *   seg data (each padded to CHUNK) ...
 *     seg0  = P4BR header
 *     seg1  = directory records (0x458 each)
 *     seg2  = file records      (0x458 each)
 *     seg3+ = one segment per file, payload in catalog order
 */

#include <windows.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>
#include <time.h>
#include <cpuid.h>
#include <wmmintrin.h>
#include <emmintrin.h>

#define MAX_SEG   0xFFFF0000ULL      /* per-archive split size            */
#define CHUNK     0x10000ULL         /* segment in-file alignment / pad    */
#define REC       0x458ULL           /* catalog record size                */
#define P4BR_LEN  0x300ULL           /* P4BR header segment size           */
#define BUFCAP    (1u << 20)         /* crypto window (multiple of 16)     */

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
    uint8_t sw[176];
} aes_ctx;

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
    __m128i *e = c->ni_enc;
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

static const uint8_t RCON[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static void sw_key_setup(aes_ctx *c, const uint8_t key[16])
{
    uint8_t *rk = c->sw;
    memcpy(rk, key, 16);
    for (int i = 4; i < 44; i++) {
        uint8_t t[4];
        memcpy(t, rk + 4*(i-1), 4);
        if (i % 4 == 0) {
            uint8_t tmp = t[0];
            t[0] = SBOX[t[1]] ^ RCON[i/4];
            t[1] = SBOX[t[2]];
            t[2] = SBOX[t[3]];
            t[3] = SBOX[tmp];
        }
        for (int j = 0; j < 4; j++) rk[4*i+j] = rk[4*(i-4)+j] ^ t[j];
    }
}

static inline uint8_t xtime(uint8_t x){ return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b)); }

static void sw_enc_block(const aes_ctx *c, const uint8_t in[16], uint8_t out[16])
{
    const uint8_t *rk = c->sw;
    uint8_t s[16];
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ rk[i];
    for (int round = 1; round <= 10; round++) {
        uint8_t t[16];
        for (int i = 0; i < 16; i++) t[i] = SBOX[s[i]];
        /* ShiftRows */
        uint8_t r[16] = {
            t[0], t[5], t[10], t[15],
            t[4], t[9], t[14], t[3],
            t[8], t[13], t[2], t[7],
            t[12], t[1], t[6], t[11] };
        if (round < 10) {
            for (int col = 0; col < 4; col++) {
                uint8_t *p = r + 4*col;
                uint8_t a0=p[0],a1=p[1],a2=p[2],a3=p[3];
                p[0]=(uint8_t)(xtime(a0)^(xtime(a1)^a1)^a2^a3);
                p[1]=(uint8_t)(a0^xtime(a1)^(xtime(a2)^a2)^a3);
                p[2]=(uint8_t)(a0^a1^xtime(a2)^(xtime(a3)^a3));
                p[3]=(uint8_t)((xtime(a0)^a0)^a1^a2^xtime(a3));
            }
        }
        for (int i = 0; i < 16; i++) s[i] = r[i] ^ rk[16*round + i];
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

/* CBC-encrypt nblocks blocks of pt into ct, chaining from iv[16];
 * iv is updated to the last ciphertext block. */
static void cbc_enc_blocks(const aes_ctx *c, const uint8_t *pt, size_t nblocks,
                           uint8_t iv[16], uint8_t *ct)
{
    uint8_t prev[16]; memcpy(prev, iv, 16);
    for (size_t i = 0; i < nblocks; i++) {
        uint8_t x[16];
        for (int j = 0; j < 16; j++) x[j] = pt[i*16+j] ^ prev[j];
        aes_enc_block(c, x, ct + i*16);
        memcpy(prev, ct + i*16, 16);
    }
    memcpy(iv, prev, 16);
}

/* ===================================================================== */
/* SHA-256 + HMAC-SHA256                                                 */
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
/* split-archive sequential writer                                       */
/* ===================================================================== */

typedef struct {
    const wchar_t *dir;
    HANDLE h;
    long long n;        /* currently-open archive index, -1 = none */
} writer_t;

static void writer_init(writer_t *w, const wchar_t *dir){ w->dir=dir; w->h=INVALID_HANDLE_VALUE; w->n=-1; }
static void writer_close(writer_t *w){ if(w->h!=INVALID_HANDLE_VALUE){CloseHandle(w->h);w->h=INVALID_HANDLE_VALUE;} w->n=-1; }

static HANDLE writer_open(const wchar_t *dir, long long n)
{
    wchar_t path[MAX_PATH*2];
    if (n == 0) _snwprintf(path, MAX_PATH*2, L"%s\\archive.dat", dir);
    else        _snwprintf(path, MAX_PATH*2, L"%s\\archive%04lld.dat", dir, n);
    return CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL,
                       OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

/* write `size` bytes to global offset `off`; returns bytes written */
static uint64_t writer_write(writer_t *w, uint64_t off, const uint8_t *buf, uint64_t size)
{
    const uint8_t *p = buf;
    while (size > 0) {
        long long n = (long long)(off / MAX_SEG);
        uint64_t within = off % MAX_SEG;
        if (w->n != n) {
            if (w->h != INVALID_HANDLE_VALUE) CloseHandle(w->h);
            w->h = writer_open(w->dir, n);
            w->n = n;
            if (w->h == INVALID_HANDLE_VALUE) { w->n = -1; break; }
        }
        LARGE_INTEGER li; li.QuadPart = (LONGLONG)within;
        if (!SetFilePointerEx(w->h, li, NULL, FILE_BEGIN)) break;
        uint64_t want = MAX_SEG - within;
        if (want > size) want = size;
        DWORD wr = 0;
        DWORD req = (DWORD)(want > 0x40000000UL ? 0x40000000UL : want);
        if (!WriteFile(w->h, p, req, &wr, NULL) || wr == 0) break;
        p += wr; off += wr; size -= wr;
    }
    return (uint64_t)(p - buf);
}

/* read back `size` bytes from global offset `off` (used for the header HMAC) */
static uint64_t writer_readback(writer_t *w, uint64_t off, uint64_t size, uint8_t *buf)
{
    uint8_t *p = buf;
    while (size > 0) {
        long long n = (long long)(off / MAX_SEG);
        uint64_t within = off % MAX_SEG;
        if (w->n != n) {
            if (w->h != INVALID_HANDLE_VALUE) CloseHandle(w->h);
            w->h = writer_open(w->dir, n);
            w->n = n;
            if (w->h == INVALID_HANDLE_VALUE) { w->n = -1; break; }
        }
        LARGE_INTEGER li; li.QuadPart = (LONGLONG)within;
        if (!SetFilePointerEx(w->h, li, NULL, FILE_BEGIN)) break;
        uint64_t want = MAX_SEG - within;
        if (want > size) want = size;
        DWORD got = 0;
        DWORD req = (DWORD)(want > 0x40000000UL ? 0x40000000UL : want);
        if (!ReadFile(w->h, p, req, &got, NULL) || got == 0) break;
        p += got; off += got; size -= got;
    }
    return (uint64_t)(p - buf);
}

/* ===================================================================== */
/* catalog model                                                         */
/* ===================================================================== */

typedef struct {
    char    *path;      /* UTF-8, absolute POSIX, e.g. /user/home/x       */
    wchar_t *wfull;     /* full on-disk path (files only; NULL for dirs)  */
    uint64_t size;      /* 0 for dirs (stored as 512 in the record)       */
    uint32_t mode;      /* unix mode (0x4xxx dir / 0x8xxx file)           */
    uint32_t ctime, mtime, atime;
    int      is_dir;
} entry_t;

typedef struct {
    entry_t *v; int n, cap;
} vec_t;

static void vec_push(vec_t *a, entry_t e)
{
    if (a->n == a->cap) { a->cap = a->cap ? a->cap*2 : 256; a->v = realloc(a->v, (size_t)a->cap*sizeof(entry_t)); }
    a->v[a->n++] = e;
}

static uint32_t ft_to_unix(FILETIME ft)
{
    ULARGE_INTEGER u; u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
    if (u.QuadPart < 116444736000000000ULL) return 0;
    return (uint32_t)((u.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

static char *utf8_dup(const wchar_t *w)
{
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (n <= 0) return NULL;
    char *s = malloc((size_t)n);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s, n, NULL, NULL);
    return s;
}

static wchar_t *utf8_to_wide(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) return NULL;
    wchar_t *w = malloc((size_t)n * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

/* recursive directory walk; rel is the POSIX path so far ("" at root). */
static void walk(const wchar_t *base, const char *rel, vec_t *dirs, vec_t *files)
{
    wchar_t pat[MAX_PATH*2];
    _snwprintf(pat, MAX_PATH*2, L"%s\\*", base);
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
        char *namu = utf8_dup(fd.cFileName);
        if (!namu) continue;
        size_t rl = strlen(rel), nl = strlen(namu);
        char *posix = malloc(rl + 1 + nl + 1);
        memcpy(posix, rel, rl); posix[rl] = '/'; memcpy(posix + rl + 1, namu, nl + 1);
        free(namu);

        wchar_t sub[MAX_PATH*2];
        _snwprintf(sub, MAX_PATH*2, L"%s\\%s", base, fd.cFileName);

        entry_t e; memset(&e, 0, sizeof e);
        e.path  = posix;
        e.ctime = ft_to_unix(fd.ftCreationTime);
        e.mtime = ft_to_unix(fd.ftLastWriteTime);
        e.atime = ft_to_unix(fd.ftLastAccessTime);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            e.is_dir = 1; e.size = 0; e.mode = 0x41F8;      /* 040770 */
            vec_push(dirs, e);
            walk(sub, posix, dirs, files);
        } else {
            e.is_dir = 0;
            e.size = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            e.mode = 0x81C0;                                 /* 0100700 */
            e.wfull = _wcsdup(sub);
            vec_push(files, e);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

/* write one 0x458 catalog record for e into rec (zeroed). */
static void fill_record(uint8_t rec[REC], const entry_t *e)
{
    memset(rec, 0, REC);
    uint32_t ct = e->ctime, mt = e->mtime, at = e->atime;
    memcpy(rec + 0x00, &ct, 4);
    memcpy(rec + 0x10, &mt, 4);
    memcpy(rec + 0x20, &at, 4);
    uint64_t sz = e->is_dir ? 512 : e->size;
    memcpy(rec + 0x30, &sz, 8);
    memcpy(rec + 0x38, &ct, 4);          /* 4th timestamp (as seen in dumps) */
    uint32_t mode = e->mode;
    memcpy(rec + 0x50, &mode, 4);
    size_t pl = strlen(e->path);
    if (pl > REC - 0x54 - 1) pl = REC - 0x54 - 1;
    memcpy(rec + 0x54, e->path, pl);     /* NUL already present */
}

/* ===================================================================== */
/* segment sealing : encrypt (CBC + CTS tail) + HMAC, write to archive    */
/* ===================================================================== */

typedef struct { uint64_t index, off, pad, nopad; uint8_t seed[16], sig[32]; } seg_out_t;

static void rand_seed(uint8_t s[16])
{
    static uint64_t x = 0;
    if (!x) { LARGE_INTEGER c; QueryPerformanceCounter(&c); x = (uint64_t)c.QuadPart ^ 0x9e3779b97f4a7c15ULL ^ (uint64_t)GetCurrentProcessId(); }
    for (int i = 0; i < 16; i++) { x ^= x<<13; x ^= x>>7; x ^= x<<17; s[i] = (uint8_t)(x >> ((i&7)*8)); }
}

/* source abstraction: in-memory buffer OR an open file, read sequentially */
typedef struct { const uint8_t *mem; HANDLE fh; uint64_t left; } src_t;

static uint64_t src_read(src_t *s, uint8_t *dst, uint64_t n)
{
    if (n > s->left) n = s->left;
    uint64_t done = 0;
    if (s->mem) { memcpy(dst, s->mem, (size_t)n); s->mem += n; done = n; }
    else {
        while (done < n) {
            DWORD got = 0;
            DWORD req = (DWORD)((n - done) > 0x40000000UL ? 0x40000000UL : (n - done));
            if (!ReadFile(s->fh, dst + done, req, &got, NULL) || got == 0) break;
            done += got;
        }
    }
    s->left -= done;
    return done;
}

/* Encrypt `L` plaintext bytes from src with IV=seed, write ciphertext at
 * archive offset `off`, zero-pad the segment to `pad`, and HMAC the
 * ciphertext (nopad bytes). Fills seg->sig. */
static int seal_segment(writer_t *w, const aes_ctx *c, const hmac256_t *hbase,
                        src_t *src, seg_out_t *seg,
                        uint8_t *inbuf, uint8_t *outbuf)
{
    uint64_t L = seg->nopad;
    uint64_t full = L - (L % 16);
    uint8_t iv[16]; memcpy(iv, seg->seed, 16);
    uint8_t lastct[16]; memcpy(lastct, seg->seed, 16);
    hmac256_t hm = *hbase;
    uint64_t wpos = seg->off;

    uint64_t done = 0;
    while (done < full) {
        uint64_t want = full - done; if (want > BUFCAP) want = BUFCAP;   /* multiple of 16 */
        if (src_read(src, inbuf, want) != want) return -1;
        cbc_enc_blocks(c, inbuf, (size_t)(want/16), iv, outbuf);          /* iv chains */
        memcpy(lastct, outbuf + want - 16, 16);
        hmac256_update(&hm, outbuf, (size_t)want);
        writer_write(w, wpos, outbuf, want);
        wpos += want; done += want;
    }
    uint64_t r = L - full;
    if (r) {                                                              /* CTS tail */
        uint8_t ptb[16] = {0}, ks[16], ctb[16];
        if (src_read(src, ptb, r) != r) return -1;
        aes_enc_block(c, (full >= 16) ? lastct : seg->seed, ks);
        for (uint64_t i = 0; i < r; i++) ctb[i] = ptb[i] ^ ks[i];
        hmac256_update(&hm, ctb, (size_t)r);
        writer_write(w, wpos, ctb, r);
        wpos += r;
    }
    hmac256_final(&hm, seg->sig);

    /* zero-pad to pad */
    uint64_t padbytes = seg->pad - L;
    if (padbytes) {
        memset(outbuf, 0, BUFCAP);
        while (padbytes) {
            uint64_t want = padbytes > BUFCAP ? BUFCAP : padbytes;
            writer_write(w, wpos, outbuf, want);
            wpos += want; padbytes -= want;
        }
    }
    return 0;
}

/* ===================================================================== */
/* create job                                                            */
/* ===================================================================== */

typedef struct {
    char  source[1024];
    char  outdir[1024];
    char  keyhex[72];
    char  hashhex[72];
    char  name[128];
    char  label[128];
    int   verify_after;
} create_job_t;

static int hex2bin(const char *hex, uint8_t *out, int n)
{
    for (int i = 0; i < n; i++) {
        char a = hex[2*i], b = hex[2*i+1];
        if (!a || !b) return -1;
        int hi = (a<='9')?a-'0':(a|32)-'a'+10;
        int lo = (b<='9')?b-'0':(b|32)-'a'+10;
        if (hi<0||hi>15||lo<0||lo>15) return -1;
        out[i] = (uint8_t)((hi<<4)|lo);
    }
    return 0;
}

static void detect_aesni(void)
{
    unsigned a,b,c,d;
    if (__get_cpuid(1,&a,&b,&c,&d)) g_aesni = (c & bit_AES) ? 1 : 0;
}

static uint64_t pad_of(uint64_t nopad){ return nopad ? ((nopad + CHUNK - 1) / CHUNK) * CHUNK : 0; }

static void human(uint64_t n, char *out)
{
    const char *u[] = {"B","KB","MB","GB","TB","PB"}; double v = (double)n; int i=0;
    while (v >= 1024.0 && i < 5) { v /= 1024.0; i++; }
    sprintf(out, "%.1f%s", v, u[i]);
}

static int run_create(const create_job_t *J)
{
    const char *keyhex  = J->keyhex[0]  ? J->keyhex  : DEFAULT_KEY;
    const char *hashhex = J->hashhex[0] ? J->hashhex : DEFAULT_HASH_KEY;

    uint8_t key[16], hkey[32];
    if (strlen(keyhex) != 32 || hex2bin(keyhex, key, 16) != 0) { fprintf(stderr,"key must be 32 hex chars\n"); return 2; }
    if (strlen(hashhex) != 64 || hex2bin(hashhex, hkey, 32) != 0) { fprintf(stderr,"hash key must be 64 hex chars\n"); return 2; }

    detect_aesni();
    aes_ctx ctx; aes_setup(&ctx, key);
    hmac256_t hbase; hmac256_init(&hbase, hkey, 32);

    wchar_t *wsrc = utf8_to_wide(J->source);
    wchar_t *wout = utf8_to_wide(J->outdir[0] ? J->outdir : "backup_out");
    if (!wsrc || !wout) { fprintf(stderr,"bad path\n"); return 2; }
    CreateDirectoryW(wout, NULL);

    printf("[+] scanning %s%s\n", J->source, g_aesni ? "  [AES-NI]" : "  [SW-AES]");
    vec_t dirs = {0}, files = {0};
    walk(wsrc, "", &dirs, &files);
    printf("[+] catalog: %d dirs, %d files\n", dirs.n, files.n);
    if (files.n == 0 && dirs.n == 0) { fprintf(stderr,"source is empty\n"); return 1; }

    uint64_t total_payload = 0;
    for (int i = 0; i < files.n; i++) total_payload += files.v[i].size;

    /* segment plan: seg0 P4BR, seg1 dirs, seg2 files, seg3+ one per file */
    uint64_t nseg = 3 + (uint64_t)files.n;
    seg_out_t *segs = calloc((size_t)nseg, sizeof(seg_out_t));

    uint64_t header_size = 0x30 + 0x40*nseg + 0x30*nseg;
    uint64_t file_offset = ((header_size + 0x20 + CHUNK - 1) / CHUNK) * CHUNK;  /* room for hdr HMAC too */
    if (file_offset < CHUNK) file_offset = CHUNK;

    /* nopad sizes */
    segs[0].nopad = P4BR_LEN;
    segs[1].nopad = (uint64_t)dirs.n  * REC;
    segs[2].nopad = (uint64_t)files.n * REC;
    for (int i = 0; i < files.n; i++) segs[3+i].nopad = files.v[i].size;

    /* offsets + pads + segment index values */
    uint64_t off = file_offset;
    for (uint64_t i = 0; i < nseg; i++) {
        segs[i].pad = pad_of(segs[i].nopad);
        segs[i].off = off;
        off += segs[i].pad;
        segs[i].index = (i < 3) ? (i + 1) : (0x10000 + (i - 3));  /* mirror observed scheme */
        rand_seed(segs[i].seed);
    }
    uint64_t file_size = 0; for (uint64_t i=0;i<nseg;i++) file_size += segs[i].nopad;

    writer_t w; writer_init(&w, wout);

    /* ---- seg0: P4BR header ---- */
    {
        uint8_t *p4 = calloc(1, P4BR_LEN);
        memcpy(p4, P4BR_MAGIC, 4);
        uint32_t ver = 2;         memcpy(p4 + 0x04, &ver, 4);
        uint32_t nd = (uint32_t)dirs.n, nf = (uint32_t)files.n;
        memcpy(p4 + 0x10, &nd, 4);
        memcpy(p4 + 0x14, &nf, 4);
        strncpy((char*)p4 + 0x34, J->name[0]  ? J->name  : "PS4", 0x4B);
        strncpy((char*)p4 + 0x80, J->label[0] ? J->label : (J->name[0]?J->name:"PS4 backup"), 0x7F);
        src_t s = { p4, NULL, P4BR_LEN };
        uint8_t *ib = _aligned_malloc(BUFCAP,16), *ob = _aligned_malloc(BUFCAP,16);
        seal_segment(&w, &ctx, &hbase, &s, &segs[0], ib, ob);
        _aligned_free(ib); _aligned_free(ob); free(p4);
    }

    /* ---- seg1 dirs, seg2 files : catalog blobs ---- */
    {
        uint8_t *ib = _aligned_malloc(BUFCAP,16), *ob = _aligned_malloc(BUFCAP,16);
        uint8_t *db = calloc(1, segs[1].nopad ? (size_t)segs[1].nopad : 1);
        for (int i = 0; i < dirs.n; i++) fill_record(db + (size_t)i*REC, &dirs.v[i]);
        src_t sd = { db, NULL, segs[1].nopad };
        seal_segment(&w, &ctx, &hbase, &sd, &segs[1], ib, ob);
        free(db);

        uint8_t *fb = calloc(1, segs[2].nopad ? (size_t)segs[2].nopad : 1);
        for (int i = 0; i < files.n; i++) fill_record(fb + (size_t)i*REC, &files.v[i]);
        src_t sf = { fb, NULL, segs[2].nopad };
        seal_segment(&w, &ctx, &hbase, &sf, &segs[2], ib, ob);
        free(fb);
        _aligned_free(ib); _aligned_free(ob);
    }

    /* ---- seg3+ : payload, one segment per file ---- */
    {
        uint8_t *ib = _aligned_malloc(BUFCAP,16), *ob = _aligned_malloc(BUFCAP,16);
        uint64_t doneb = 0; char hb[32], hb2[32]; human(total_payload, hb2);
        DWORD t0 = GetTickCount(), tlast = t0;
        for (int i = 0; i < files.n; i++) {
            seg_out_t *sg = &segs[3 + i];
            HANDLE fh = INVALID_HANDLE_VALUE;
            if (sg->nopad) {
                fh = CreateFileW(files.v[i].wfull, GENERIC_READ, FILE_SHARE_READ, NULL,
                                 OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
                if (fh == INVALID_HANDLE_VALUE) { fprintf(stderr,"cannot open %s\n", files.v[i].path); return 1; }
            }
            src_t s = { NULL, fh, sg->nopad };
            if (seal_segment(&w, &ctx, &hbase, &s, sg, ib, ob) != 0) {
                fprintf(stderr,"short read on %s\n", files.v[i].path);
                if (fh != INVALID_HANDLE_VALUE) CloseHandle(fh);
                return 1;
            }
            if (fh != INVALID_HANDLE_VALUE) CloseHandle(fh);
            doneb += sg->nopad;
            DWORD now = GetTickCount();
            if (now - tlast > 500 || i == files.n - 1) {
                human(doneb, hb);
                printf("  [%d/%d] %s/%s  %s\n", i+1, files.n, hb, hb2, files.v[i].path);
                fflush(stdout);
                tlast = now;
            }
        }
        _aligned_free(ib); _aligned_free(ob);
    }

    /* ---- header + segment table + signatures ---- */
    {
        uint8_t *hdrbuf = calloc(1, (size_t)header_size);
        memcpy(hdrbuf, CAF_MAGIC, 8);
        uint64_t version = 2, hki = 0x200000001ULL;
        memcpy(hdrbuf + 0x08, &version, 8);
        memcpy(hdrbuf + 0x10, &hki, 8);
        memcpy(hdrbuf + 0x18, &nseg, 8);
        memcpy(hdrbuf + 0x20, &file_offset, 8);
        memcpy(hdrbuf + 0x28, &file_size, 8);

        uint8_t *tbl = hdrbuf + 0x30;
        for (uint64_t i = 0; i < nseg; i++) {
            uint8_t *r = tbl + 0x40*i;
            uint64_t algo = 2, kidx = 0x200000001ULL;
            memcpy(r + 0x00, &segs[i].index, 8);
            memcpy(r + 0x08, &segs[i].off, 8);
            memcpy(r + 0x10, &segs[i].pad, 8);
            memcpy(r + 0x18, &algo, 8);
            memcpy(r + 0x20, &kidx, 8);
            memcpy(r + 0x28, segs[i].seed, 16);
            memcpy(r + 0x38, &segs[i].nopad, 8);
        }
        uint8_t *sigtbl = tbl + 0x40*nseg;
        for (uint64_t i = 0; i < nseg; i++) {
            uint8_t *e = sigtbl + 0x30*i;
            memcpy(e + 0x00, &i, 8);             /* signature index (0-based) */
            memcpy(e + 0x08, segs[i].sig, 32);
            /* +0x28 u64 pad = 0 */
        }
        writer_write(&w, 0, hdrbuf, header_size);

        /* header HMAC over file[0:header_size], stored right after */
        uint8_t hh[32];
        hmac256_t hm = hbase;
        hmac256_update(&hm, hdrbuf, (size_t)header_size);
        hmac256_final(&hm, hh);
        writer_write(&w, header_size, hh, 32);

        /* zero the gap between header+hmac and file_offset */
        uint64_t gap_start = header_size + 32;
        if (file_offset > gap_start) {
            uint64_t g = file_offset - gap_start;
            uint8_t *z = calloc(1, (size_t)(g > BUFCAP ? BUFCAP : g));
            uint64_t pos = gap_start;
            while (g) { uint64_t wn = g > BUFCAP ? BUFCAP : g; writer_write(&w, pos, z, wn); pos += wn; g -= wn; }
            free(z);
        }
        free(hdrbuf);
    }

    writer_close(&w);
    char hbt[32]; human(file_size, hbt);
    printf("[+] wrote SCECAF v2  segments=%llu  content=%s  file_offset=0x%llx -> %s\n",
           (unsigned long long)nseg, hbt, (unsigned long long)file_offset,
           J->outdir[0] ? J->outdir : "backup_out");

    /* optional immediate verification (re-reads the archive we just wrote) */
    if (J->verify_after) {
        writer_t r; writer_init(&r, wout);
        uint8_t stored[32], calc[32];
        /* header */
        uint8_t *hb = malloc((size_t)header_size);
        writer_readback(&r, 0, header_size, hb);
        hmac256_t hm = hbase; hmac256_update(&hm, hb, (size_t)header_size); hmac256_final(&hm, calc);
        free(hb);
        writer_readback(&r, header_size, 32, stored);
        int hdr_ok = (memcmp(calc, stored, 32) == 0);
        printf("[+] re-verify header HMAC: %s\n", hdr_ok ? "OK" : "MISMATCH");
        int bad = 0, empty = 0;
        uint8_t *buf = _aligned_malloc(BUFCAP, 16);
        for (uint64_t i = 0; i < nseg; i++) {
            if (segs[i].nopad == 0) { empty++; continue; }
            hmac256_t hs = hbase;
            uint64_t left = segs[i].nopad, pos = segs[i].off;
            while (left) { uint64_t want = left < BUFCAP ? left : BUFCAP;
                uint64_t got = writer_readback(&r, pos, want, buf); if (!got) break;
                hmac256_update(&hs, buf, (size_t)got); pos += got; left -= got; }
            hmac256_final(&hs, calc);
            if (memcmp(calc, segs[i].sig, 32) != 0) { bad++; printf("  BAD seg[%llu]\n",(unsigned long long)i); }
        }
        _aligned_free(buf); writer_close(&r);
        printf("[+] re-verify segments: %llu/%llu OK, %d bad, %d empty\n",
               (unsigned long long)(nseg - bad - empty), (unsigned long long)(nseg - empty), bad, empty);
        printf("%s\n", (hdr_ok && !bad) ? "[+] self-check PASSED" : "[!] self-check FAILED");
    }

    for (int i=0;i<dirs.n;i++)  { free(dirs.v[i].path);  free(dirs.v[i].wfull); }
    for (int i=0;i<files.n;i++) { free(files.v[i].path); free(files.v[i].wfull); }
    free(dirs.v); free(files.v); free(segs); free(wsrc); free(wout);
    return 0;
}

/* ===================================================================== */
/* command-line front end                                                */
/* ===================================================================== */

static int parse_args(int argc, char **argv, create_job_t *J)
{
    const char *source = NULL;
    J->verify_after = 1;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a,"-o")||!strcmp(a,"--out"))        { if(++i<argc) strncpy(J->outdir,argv[i],sizeof J->outdir-1); }
        else if (!strcmp(a,"-k")||!strcmp(a,"--key"))   { if(++i<argc) strncpy(J->keyhex,argv[i],sizeof J->keyhex-1); }
        else if (!strcmp(a,"-H")||!strcmp(a,"--hash-key")) { if(++i<argc) strncpy(J->hashhex,argv[i],sizeof J->hashhex-1); }
        else if (!strcmp(a,"-n")||!strcmp(a,"--name"))  { if(++i<argc) strncpy(J->name,argv[i],sizeof J->name-1); }
        else if (!strcmp(a,"-l")||!strcmp(a,"--label")) { if(++i<argc) strncpy(J->label,argv[i],sizeof J->label-1); }
        else if (!strcmp(a,"--gui"))                    { /* handled in main */ }
        else if (!strcmp(a,"--verify")) {
            const char *v = (i+1 < argc) ? argv[i+1] : NULL;
            if (v && (!strcmp(v,"false")||!strcmp(v,"0")||!strcmp(v,"no")||!strcmp(v,"off")))  { J->verify_after = 0; i++; }
            else if (v && (!strcmp(v,"true")||!strcmp(v,"1")||!strcmp(v,"yes")||!strcmp(v,"on"))) { J->verify_after = 1; i++; }
            else J->verify_after = 1;
        }
        else if (a[0]=='-') { fprintf(stderr,"unknown option: %s\n",a); return 2; }
        else source = a;
    }
    if (!source) { fprintf(stderr,
        "usage: p4br_create <source_folder> [-o out] [-k hexkey] [-H hashkey]\n"
        "                   [-n name] [-l label] [--verify true|false]\n"
        "       p4br_create            (no args -> graphical mode)\n"
        "\n"
        "Packs <source_folder> into a SCECAF/P4BR container (archive.dat ...).\n"
        "Round-trips through p4br_extract; not a PS4-restorable backup (the aux\n"
        "metadata segments are not reverse-engineered).\n"); return 2; }
    strncpy(J->source, source, sizeof J->source - 1);
    return 0;
}

/* ===================================================================== */
/* graphical front end (Win32)                                           */
/* ===================================================================== */

#define IDC_SRC_EDIT   2001
#define IDC_SRC_BROWSE 2002
#define IDC_OUT_EDIT   2003
#define IDC_OUT_BROWSE 2004
#define IDC_NAME       2005
#define IDC_LABEL      2006
#define IDC_VERIFY     2007
#define IDC_GO         2008
#define IDC_STATUS     2009
#define WM_JOB_DONE    (WM_APP + 1)

static HWND g_main, g_src, g_out, g_name, g_label, g_verify, g_go, g_status;
static HFONT g_font;
static volatile LONG g_running = 0;
static create_job_t g_job;

static void ensure_console(void)
{
    if (!GetConsoleWindow()) AllocConsole();
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
    SetConsoleTitleA("p4br_create - log");
    HWND c = GetConsoleWindow();
    if (c) ShowWindow(c, SW_SHOW);
}

static int browse_folder(HWND owner, const char *title, char *out, int cap)
{
    wchar_t wtitle[128];
    MultiByteToWideChar(CP_UTF8, 0, title, -1, wtitle, 128);
    BROWSEINFOW bi; memset(&bi, 0, sizeof bi);
    bi.hwndOwner = owner; bi.lpszTitle = wtitle;
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (!pidl) return 0;
    wchar_t wpath[MAX_PATH];
    int ok = SHGetPathFromIDListW(pidl, wpath);
    CoTaskMemFree(pidl);
    if (!ok) return 0;
    WideCharToMultiByte(CP_UTF8, 0, wpath, -1, out, cap, NULL, NULL);
    return 1;
}

static DWORD WINAPI gui_worker(LPVOID arg)
{
    (void)arg;
    printf("\n========================================================\n");
    printf("[*] creating backup\n"); fflush(stdout);
    int rc = run_create(&g_job);
    printf("[*] done (code %d)\n", rc); fflush(stdout);
    PostMessageW(g_main, WM_JOB_DONE, (WPARAM)rc, 0);
    return 0;
}

static void start_job(void)
{
    if (InterlockedExchange(&g_running, 1)) return;
    memset(&g_job, 0, sizeof g_job);
    GetWindowTextA(g_src,   g_job.source, sizeof g_job.source);
    GetWindowTextA(g_out,   g_job.outdir, sizeof g_job.outdir);
    GetWindowTextA(g_name,  g_job.name,   sizeof g_job.name);
    GetWindowTextA(g_label, g_job.label,  sizeof g_job.label);
    g_job.verify_after = (SendMessageW(g_verify, BM_GETCHECK, 0, 0) == BST_CHECKED) ? 1 : 0;

    if (!g_job.source[0]) {
        MessageBoxW(g_main, L"Choose the source folder to back up first.", L"p4br_create", MB_ICONWARNING);
        InterlockedExchange(&g_running, 0); return;
    }
    if (!g_job.outdir[0]) {
        MessageBoxW(g_main, L"Choose an (empty) output folder for the archive.", L"p4br_create", MB_ICONWARNING);
        InterlockedExchange(&g_running, 0); return;
    }
    ensure_console();
    EnableWindow(g_go, FALSE);
    SetWindowTextW(g_go, L"Working...");
    SetWindowTextW(g_status, L"Creating - see the log window.");
    HANDLE h = CreateThread(NULL, 0, gui_worker, NULL, 0, NULL);
    if (h) CloseHandle(h);
    else { InterlockedExchange(&g_running, 0); EnableWindow(g_go, TRUE); }
}

static LRESULT CALLBACK wndproc(HWND hw, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_SRC_BROWSE: {
            char p[1024];
            if (browse_folder(hw, "Select the folder to back up", p, sizeof p)) {
                SetWindowTextA(g_src, p);
                char cur[1024]; GetWindowTextA(g_out, cur, sizeof cur);
                if (!cur[0]) { char o[1100]; _snprintf(o, sizeof o, "%s_bar", p); SetWindowTextA(g_out, o); }
            }
            return 0;
        }
        case IDC_OUT_BROWSE: {
            char p[1024];
            if (browse_folder(hw, "Select the output folder (for archive.dat)", p, sizeof p))
                SetWindowTextA(g_out, p);
            return 0;
        }
        case IDC_GO: start_job(); return 0;
        }
        break;
    case WM_JOB_DONE: {
        InterlockedExchange(&g_running, 0);
        EnableWindow(g_go, TRUE);
        SetWindowTextW(g_go, L"Create");
        wchar_t s[64]; _snwprintf(s, 64, L"Done (code %ld). See the log window.", (long)wp);
        SetWindowTextW(g_status, s);
        return 0;
    }
    case WM_CLOSE:
        if (g_running && MessageBoxW(hw, L"A job is still running. Quit anyway?",
                L"p4br_create", MB_YESNO | MB_ICONQUESTION) != IDYES) return 0;
        DestroyWindow(hw); return 0;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hw, msg, wp, lp);
}

static HWND mk(const wchar_t *cls, const wchar_t *txt, DWORD style,
               int x, int y, int w, int h, HWND parent, int id)
{
    HWND c = CreateWindowW(cls, txt, WS_CHILD | WS_VISIBLE | style,
                           x, y, w, h, parent, (HMENU)(INT_PTR)id, GetModuleHandleW(NULL), NULL);
    if (g_font) SendMessageW(c, WM_SETFONT, (WPARAM)g_font, TRUE);
    return c;
}

static int gui_run(void)
{
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    g_font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    WNDCLASSW wc; memset(&wc, 0, sizeof wc);
    wc.lpfnWndProc = wndproc; wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"p4br_create"; wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClassW(&wc);

    int W = 560, H = 290;
    g_main = CreateWindowW(L"p4br_create", L"PS4 backup creator (P4BR / SCECAF)",
                           WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                           CW_USEDEFAULT, CW_USEDEFAULT, W, H, NULL, NULL, GetModuleHandleW(NULL), NULL);

    mk(L"STATIC", L"Source folder to back up:", 0, 15, 12, 360, 18, g_main, 0);
    g_src = mk(L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL, 15, 32, 430, 24, g_main, IDC_SRC_EDIT);
    mk(L"BUTTON", L"Browse...", 0, 455, 32, 85, 24, g_main, IDC_SRC_BROWSE);

    mk(L"STATIC", L"Output folder (archive.dat is written here):", 0, 15, 66, 400, 18, g_main, 0);
    g_out = mk(L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL, 15, 84, 430, 24, g_main, IDC_OUT_EDIT);
    mk(L"BUTTON", L"Browse...", 0, 455, 84, 85, 24, g_main, IDC_OUT_BROWSE);

    mk(L"STATIC", L"Name:", 0, 15, 120, 45, 18, g_main, 0);
    g_name = mk(L"EDIT", L"PS4", WS_BORDER | ES_AUTOHSCROLL, 60, 117, 150, 24, g_main, IDC_NAME);
    mk(L"STATIC", L"Label:", 0, 225, 120, 45, 18, g_main, 0);
    g_label = mk(L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL, 275, 117, 265, 24, g_main, IDC_LABEL);

    g_verify = mk(L"BUTTON", L"Verify after creating (recommended)", BS_AUTOCHECKBOX, 15, 152, 300, 20, g_main, IDC_VERIFY);
    SendMessageW(g_verify, BM_SETCHECK, BST_CHECKED, 0);

    g_go = mk(L"BUTTON", L"Create", BS_DEFPUSHBUTTON, 455, 150, 85, 28, g_main, IDC_GO);

    g_status = mk(L"STATIC",
                  L"Packs a folder into a SCECAF/P4BR archive. Round-trips with the "
                  L"extractor; not a PS4-restorable backup.",
                  0, 15, 192, 525, 36, g_main, IDC_STATUS);

    ShowWindow(g_main, SW_SHOW); UpdateWindow(g_main);
    MSG m;
    while (GetMessageW(&m, NULL, 0, 0) > 0) {
        if (!IsDialogMessageW(g_main, &m)) { TranslateMessage(&m); DispatchMessageW(&m); }
    }
    return 0;
}

int main(int argc, char **argv)
{
    int gui = (argc < 2) || (argc == 2 && !strcmp(argv[1], "--gui"));
    if (gui) return gui_run();
    create_job_t J; memset(&J, 0, sizeof J);
    int rc = parse_args(argc, argv, &J);
    if (rc) return rc;
    return run_create(&J);
}
