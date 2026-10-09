/*
 * p4br_extract.c  --  PS4 "Back Up PS4" (SCECAF / P4BR) restore extractor.
 *
 * Multithreaded native-Windows C port of p4br_extract.py.
 *
 * Build (from WSL, mingw64 cross compiler -> native .exe):
 *   x86_64-w64-mingw32-gcc -O3 -maes -msse4.1 -municode \
 *       p4br_extract.c -o p4br_extract.exe
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
#include <shlobj.h>
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

typedef struct {
    char  backup[1024];
    char  outdir[1024];
    char  keyhex[64];
    char  manifest[1024];
    char *inc[64]; int ninc;
    char *exc[64]; int nexc;
    int   do_list;
    uint64_t max_bytes;
    int   nthreads;
} job_t;

static int run_job(const job_t *J)
{
    const char *backup   = J->backup;
    const char *outdir   = J->outdir[0]   ? J->outdir   : "restore";
    const char *keyhex   = J->keyhex[0]   ? J->keyhex   : DEFAULT_KEY;
    const char *manifest = J->manifest[0] ? J->manifest : NULL;
    char **inc = (char **)J->inc; int ninc = J->ninc;
    char **exc = (char **)J->exc; int nexc = J->nexc;
    int do_list = J->do_list;
    uint64_t max_bytes = J->max_bytes;
    int nthreads = J->nthreads;

    g_done = g_extracted = g_skipped = 0;

    uint8_t key[16];
    if (strlen(keyhex) != 32 || hex2bin(keyhex, key, 16) != 0) {
        fprintf(stderr, "key must be 16 bytes (32 hex chars)\n"); return 2;
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

/* ===================================================================== */
/* command-line front end                                                */
/* ===================================================================== */

static int parse_args(int argc, char **argv, job_t *J)
{
    const char *backup = NULL;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a,"-o")||!strcmp(a,"--out"))        { if(++i<argc) strncpy(J->outdir,argv[i],sizeof J->outdir-1); }
        else if (!strcmp(a,"-k")||!strcmp(a,"--key"))   { if(++i<argc) strncpy(J->keyhex,argv[i],sizeof J->keyhex-1); }
        else if (!strcmp(a,"--include"))                { if(++i<argc && J->ninc<64) J->inc[J->ninc++]=argv[i]; }
        else if (!strcmp(a,"--exclude"))                { if(++i<argc && J->nexc<64) J->exc[J->nexc++]=argv[i]; }
        else if (!strcmp(a,"--list"))                   J->do_list = 1;
        else if (!strcmp(a,"--manifest"))               { if(++i<argc) strncpy(J->manifest,argv[i],sizeof J->manifest-1); }
        else if (!strcmp(a,"--max-bytes"))              { if(++i<argc) J->max_bytes = strtoull(argv[i],NULL,0); }
        else if (!strcmp(a,"-j")||!strcmp(a,"--threads")){ if(++i<argc) J->nthreads = atoi(argv[i]); }
        else if (!strcmp(a,"--gui"))                    { /* handled in main */ }
        else if (!strcmp(a,"--verify")) { fprintf(stderr,"--verify is not ported to the C tool\n"); return 2; }
        else if (a[0]=='-') { fprintf(stderr,"unknown option: %s\n",a); return 2; }
        else backup = a;
    }
    if (!backup) { fprintf(stderr,
        "usage: p4br_extract <backup_dir> [-o out] [-k hexkey] [--include P]...\n"
        "                    [--exclude P]... [--list] [--manifest F]\n"
        "                    [--max-bytes N] [-j threads]\n"
        "       p4br_extract            (no args -> graphical mode)\n"); return 2; }
    strncpy(J->backup, backup, sizeof J->backup - 1);
    return 0;
}

/* ===================================================================== */
/* graphical front end (Win32)                                           */
/* ===================================================================== */

#define IDC_BK_EDIT   1001
#define IDC_BK_BROWSE 1002
#define IDC_OUT_EDIT  1003
#define IDC_OUT_BROWSE 1004
#define IDC_THREADS   1005
#define IDC_LISTONLY  1006
#define IDC_GO        1007
#define IDC_STATUS    1008
#define WM_JOB_DONE   (WM_APP + 1)

static HWND g_main, g_bk, g_out, g_threads, g_listonly, g_go, g_status;
static HFONT g_font;
static volatile LONG g_running = 0;

static void ensure_console(void)
{
    if (!GetConsoleWindow()) AllocConsole();
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
    SetConsoleTitleA("p4br_extract - verbose log");
    HWND c = GetConsoleWindow();
    if (c) ShowWindow(c, SW_SHOW);
}

static int browse_folder(HWND owner, const char *title, char *out, int cap)
{
    wchar_t wtitle[128];
    MultiByteToWideChar(CP_UTF8, 0, title, -1, wtitle, 128);
    BROWSEINFOW bi; memset(&bi, 0, sizeof bi);
    bi.hwndOwner = owner;
    bi.lpszTitle = wtitle;
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

static job_t g_job;

static DWORD WINAPI gui_worker(LPVOID arg)
{
    (void)arg;
    printf("\n========================================================\n");
    printf("[*] starting job\n");
    fflush(stdout);
    int rc = run_job(&g_job);
    printf("[*] job finished (code %d)\n", rc);
    fflush(stdout);
    PostMessageW(g_main, WM_JOB_DONE, (WPARAM)rc, 0);
    return 0;
}

static void start_job(void)
{
    if (InterlockedExchange(&g_running, 1)) return;   /* already running */

    memset(&g_job, 0, sizeof g_job);
    GetWindowTextA(g_bk,  g_job.backup, sizeof g_job.backup);
    GetWindowTextA(g_out, g_job.outdir, sizeof g_job.outdir);
    char tb[16]; GetWindowTextA(g_threads, tb, sizeof tb);
    g_job.nthreads = atoi(tb);
    if (SendMessageW(g_listonly, BM_GETCHECK, 0, 0) == BST_CHECKED)
        g_job.do_list = 1;

    if (!g_job.backup[0]) {
        MessageBoxW(g_main, L"Choose the backup folder first (the one containing archive.dat).",
                    L"p4br_extract", MB_ICONWARNING);
        InterlockedExchange(&g_running, 0);
        return;
    }

    ensure_console();
    EnableWindow(g_go, FALSE);
    SetWindowTextW(g_go, L"Working...");
    SetWindowTextW(g_status, L"Running - see the log window.");

    HANDLE h = CreateThread(NULL, 0, gui_worker, NULL, 0, NULL);
    if (h) CloseHandle(h);
    else { InterlockedExchange(&g_running, 0); EnableWindow(g_go, TRUE); }
}

static LRESULT CALLBACK wndproc(HWND hw, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_BK_BROWSE: {
            char p[1024];
            if (browse_folder(hw, "Select the PS4 backup folder (contains archive.dat)", p, sizeof p)) {
                SetWindowTextA(g_bk, p);
                char cur[1024]; GetWindowTextA(g_out, cur, sizeof cur);
                if (!cur[0]) {   /* auto-suggest an output folder next to the backup */
                    char o[1100]; _snprintf(o, sizeof o, "%s_restore", p);
                    SetWindowTextA(g_out, o);
                }
            }
            return 0;
        }
        case IDC_OUT_BROWSE: {
            char p[1024];
            if (browse_folder(hw, "Select the output (restore) folder", p, sizeof p))
                SetWindowTextA(g_out, p);
            return 0;
        }
        case IDC_GO:
            start_job();
            return 0;
        }
        break;

    case WM_JOB_DONE: {
        InterlockedExchange(&g_running, 0);
        EnableWindow(g_go, TRUE);
        SetWindowTextW(g_go, L"Extract");
        wchar_t s[64];
        _snwprintf(s, 64, L"Done (code %ld). See the log window.", (long)wp);
        SetWindowTextW(g_status, s);
        return 0;
    }

    case WM_CLOSE:
        if (g_running) {
            if (MessageBoxW(hw, L"A job is still running. Quit anyway?",
                            L"p4br_extract", MB_YESNO | MB_ICONQUESTION) != IDYES)
                return 0;
        }
        DestroyWindow(hw);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hw, msg, wp, lp);
}

static HWND mk(const wchar_t *cls, const wchar_t *txt, DWORD style,
               int x, int y, int w, int h, HWND parent, int id)
{
    HWND c = CreateWindowW(cls, txt, WS_CHILD | WS_VISIBLE | style,
                           x, y, w, h, parent, (HMENU)(INT_PTR)id,
                           GetModuleHandleW(NULL), NULL);
    if (g_font) SendMessageW(c, WM_SETFONT, (WPARAM)g_font, TRUE);
    return c;
}

static int gui_run(void)
{
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    g_font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    WNDCLASSW wc; memset(&wc, 0, sizeof wc);
    wc.lpfnWndProc   = wndproc;
    wc.hInstance     = GetModuleHandleW(NULL);
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"p4br_gui";
    wc.hIcon         = LoadIcon(NULL, IDI_APPLICATION);
    RegisterClassW(&wc);

    int W = 560, H = 230;
    g_main = CreateWindowW(L"p4br_gui", L"PS4 backup extractor (P4BR / SCECAF)",
                           WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                           CW_USEDEFAULT, CW_USEDEFAULT, W, H,
                           NULL, NULL, GetModuleHandleW(NULL), NULL);

    mk(L"STATIC", L"Backup folder (contains archive.dat):", 0, 15, 12, 360, 18, g_main, 0);
    g_bk = mk(L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL, 15, 32, 430, 24, g_main, IDC_BK_EDIT);
    mk(L"BUTTON", L"Browse...", 0, 455, 32, 85, 24, g_main, IDC_BK_BROWSE);

    mk(L"STATIC", L"Output folder:", 0, 15, 66, 360, 18, g_main, 0);
    g_out = mk(L"EDIT", L"", WS_BORDER | ES_AUTOHSCROLL, 15, 84, 430, 24, g_main, IDC_OUT_EDIT);
    mk(L"BUTTON", L"Browse...", 0, 455, 84, 85, 24, g_main, IDC_OUT_BROWSE);

    mk(L"STATIC", L"Threads (0 = auto):", 0, 15, 120, 120, 18, g_main, 0);
    g_threads = mk(L"EDIT", L"0", WS_BORDER | ES_NUMBER, 140, 117, 50, 24, g_main, IDC_THREADS);
    g_listonly = mk(L"BUTTON", L"List only (no extract)", BS_AUTOCHECKBOX,
                    210, 120, 180, 20, g_main, IDC_LISTONLY);

    g_go = mk(L"BUTTON", L"Extract", BS_DEFPUSHBUTTON, 455, 116, 85, 28, g_main, IDC_GO);

    g_status = mk(L"STATIC", L"Pick a backup folder, then press Extract. Log opens in a separate window.",
                  0, 15, 155, 525, 18, g_main, IDC_STATUS);

    ShowWindow(g_main, SW_SHOW);
    UpdateWindow(g_main);

    MSG m;
    while (GetMessageW(&m, NULL, 0, 0) > 0) {
        if (!IsDialogMessageW(g_main, &m)) {
            TranslateMessage(&m);
            DispatchMessageW(&m);
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    int gui = (argc < 2) || (argc == 2 && !strcmp(argv[1], "--gui"));
    if (gui) return gui_run();

    job_t J; memset(&J, 0, sizeof J);
    int rc = parse_args(argc, argv, &J);
    if (rc) return rc;
    return run_job(&J);
}
