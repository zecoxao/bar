/*
 * p4br_create.c  --  PS4 "Back Up PS4" (SCECAF / P4BR) backup CREATOR.
 *
 * Portable C (Windows / Linux / macOS, incl. Apple Silicon). The crypto, the
 * seg3 registry codec, the segment sealing, the catalog/record building and
 * the keyset logic are unchanged from the original native-Windows creator; the
 * Win32 file I/O, wide paths, FILETIME, directory walking and AES-NI gating
 * have been replaced by the portable layers in bar_crypto.h / bar_platform.h.
 *
 * The work is exposed as p4br_create_run() (+ p4br_create_autofill()) so a GUI
 * can drive it with log / progress / cancel callbacks; the CLI main() (unless
 * P4BR_CREATE_GUI is defined) parses argv and calls it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

#include "bar_crypto.h"
#include "bar_platform.h"

#define MAX_SEG   0xFFFF0000ULL
#define CHUNK     0x10000ULL
#define REC       0x458ULL
#define P4BR_LEN  0x300ULL
#define BUFCAP    (1u << 20)
#define RG_BLOB   0x64600ULL
#define MAX_SETS  32
#define RK_USER_NAME 0x07800200u
#define RK_HOSTNAME  0x02050000u

static const char CAF_MAGIC[8]  = { 'S','C','E','C','A','F',0,0 };
static const char P4BR_MAGIC[4] = { 'P','4','B','R' };
static const char *DEFAULT_KEY      = "101851B22B669178970C5459B3CB8D45";
static const char *DEFAULT_HASH_KEY = "184FBFBB6DC61433C7A5BD8259C1C21FFEC0ECBEC4319805EE0693869152EB52";
static const char *OLD_KEY_HEX      = "79C8CCC889A1540D4F2E27BB614FD653";
static const char *OLD_HASH_KEY_HEX = "1F18C970D000AC7E6FCC1A8CDD89B4FECDA133A10EC8F525982223F5861F0200";

/* ===================== log / progress / cancel ======================= */
typedef struct {
    void (*log)(const char *line, void *ud);
    void (*progress)(long long done, long long total, void *ud);
    volatile int *cancel;
    void *ud;
} p4br_cbs;
static p4br_cbs g_cbs;
static void p4br_log(const char *fmt, ...)
{
    char line[2048];
    va_list ap; va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (g_cbs.log) g_cbs.log(line, g_cbs.ud);
    else { fputs(line, stdout); fputc('\n', stdout); }
}
static int cancelled(void) { return g_cbs.cancel && *g_cbs.cancel; }

/* ===================== CBC + CTS tail ================================ */
static void cbc_dec_cts(const aes_ctx *c, const uint8_t seed[16],
                        const uint8_t *ct, uint64_t len, uint8_t *pt)
{
    uint64_t full = len - (len % 16);
    uint8_t prev[16]; memcpy(prev, seed, 16);
    for (uint64_t i = 0; i < full; i += 16) {
        uint8_t dec[16];
        aes_dec_block(c, ct + i, dec);
        for (int j = 0; j < 16; j++) pt[i+j] = dec[j] ^ prev[j];
        memcpy(prev, ct + i, 16);
    }
    uint64_t r = len - full;
    if (r) {
        uint8_t ks[16];
        aes_enc_block(c, (full >= 16) ? (ct + full - 16) : seed, ks);
        for (uint64_t i = 0; i < r; i++) pt[full+i] = ct[full+i] ^ ks[i];
    }
}
static void cbc_enc_cts(const aes_ctx *c, const uint8_t seed[16],
                        const uint8_t *pt, uint64_t len, uint8_t *ct)
{
    uint64_t full = len - (len % 16);
    uint8_t iv[16]; memcpy(iv, seed, 16);
    if (full) cbc_enc_blocks(c, pt, (size_t)(full/16), iv, ct);
    uint64_t r = len - full;
    if (r) {
        uint8_t ks[16];
        aes_enc_block(c, (full >= 16) ? (ct + full - 16) : seed, ks);
        for (uint64_t i = 0; i < r; i++) ct[full+i] = pt[full+i] ^ ks[i];
    }
}

/* ===================== seg3 registry codec ========================== */
static const uint8_t RG_OBF[31] = {
0x41,0x89,0x85,0x63,0x8c,0xc3,0x97,0x2f,0xd8,0x8d,0x9c,0xe6,0xd7,0xe1,0xd5,0x30,
0x8a,0x84,0xa5,0x34,0xb8,0x44,0x75,0x4e,0xf3,0x41,0xc5,0x57,0xfa,0x2b,0xd0 };
static const uint8_t RG_KID[16] = {
0x1f,0x26,0xfd,0x8d,0xbf,0x0a,0x8d,0x92,0x7f,0x6b,0xa0,0x12,0xb4,0x0e,0x8f,0xb1 };
static const uint8_t RG_HASH[8] = { 0x72,0x02,0x85,0x61,0xe0,0x1c,0xbb,0x89 };
static const uint8_t RG_T3[8]   = { 0x23,0x58,0xb7,0xac,0x94,0x24,0x94,0xb9 };

static void rg_obf(uint8_t *buf, uint32_t len, uint32_t key)
{
    uint64_t v3 = (17ULL*len + ((17u*((key) + ((key>>16)&0xffff))) & 0xffff));
    uint32_t v5 = (uint32_t)(v3 % 7);
    int m = (int)(((32 - 3*v5) & 0xFFFFFFFE) - 1);
    for (uint32_t i = 0; i < len; i++) buf[i] ^= RG_OBF[v5 + (i % m)];
}
static void rg_chk(const uint8_t *data, uint32_t len, uint8_t *out, int outlen)
{
    uint64_t acc; memcpy(&acc, RG_HASH, 8);
    uint32_t v8 = 0, v9 = 0;
    for (;;) {
        v9 = v8;
        if (v8 < len) {
            uint64_t v10 = acc; int sh = 0, k = 0, last = 1;
            for (;;) {
                uint8_t b = data[v9];
                v10 = v10 + ((uint64_t)((b ^ RG_HASH[k]) & 0xff) << sh);
                v10 = v10 * (b ? b : 3);
                last = k + 1; v9 = v8 + k + 1;
                if (v9 >= len) break;
                sh += 8;
                if (!(k < 7)) break;
                k++;
            }
            v8 += last; acc = v10;
        }
        if (v9 >= len) break;
    }
    uint8_t ab[8]; memcpy(ab, &acc, 8);
    for (int i = 0; i < outlen; i++) out[i] = ab[7 - i];
}
static uint32_t rg_kidmask(uint32_t v138, uint8_t out[4])
{
    uint32_t v63 = v138 % 13;
    uint8_t b[4] = { (uint8_t)(v138>>24),(uint8_t)(v138>>16),(uint8_t)(v138>>8),(uint8_t)v138 };
    uint8_t d[4]; for (int j = 0; j < 4; j++) d[j] = b[j] ^ RG_KID[v63 + j];
    out[0]=d[3]; out[1]=d[2]; out[2]=d[1]; out[3]=d[0];
    return v63;
}
static uint32_t rg_roundblk(uint32_t size){ return size ? ((size + 7) & 0xFFFFFFFC) : 0; }
static void rg_xor_hdr(uint8_t *h){ for (int i = 0; i < 80; i++) h[i] ^= RG_T3[i % 8]; }

typedef struct {
    uint32_t v138; uint16_t type; uint16_t size;
    uint32_t inl; uint8_t *val; uint32_t vlen;
} rg_entry;
typedef struct { uint8_t hdr[80]; uint32_t total; rg_entry *e; int n, cap; } rg_reg;

static void rg_push(rg_reg *R, rg_entry x)
{
    if (R->n == R->cap) { R->cap = R->cap ? R->cap*2 : 1024; R->e = (rg_entry*)realloc(R->e, (size_t)R->cap*sizeof(rg_entry)); }
    R->e[R->n++] = x;
}
static void rg_free(rg_reg *R){ for (int i=0;i<R->n;i++) free(R->e[i].val); free(R->e); R->e=NULL; R->n=R->cap=0; }

static int rg_decode(const uint8_t *seg3, uint32_t len, rg_reg *R)
{
    memset(R, 0, sizeof *R);
    if (len < 0x50) return -1;
    memcpy(R->hdr, seg3, 80); rg_xor_hdr(R->hdr);
    uint16_t total; memcpy(&total, R->hdr + 4, 2); R->total = total;
    uint32_t data_start = 0x50 + 16u*total;
    for (uint32_t i = 0; i < total; i++) {
        uint8_t d[16]; memcpy(d, seg3 + 0x50 + 16*i, 16); rg_obf(d, 16, i);
        int filler = 1; for (int j=0;j<16;j++) if (d[j]!=0x17){ filler=0; break; }
        if (filler) continue;
        uint16_t v57; memcpy(&v57, d+8, 2);
        if (v57 > 12) continue;
        uint16_t type, size; memcpy(&type, d+4, 2); memcpy(&size, d+6, 2);
        uint32_t off, enc; memcpy(&off, d+12, 4); memcpy(&enc, d+0, 4);
        uint8_t b[4] = { (uint8_t)(enc>>24),(uint8_t)(enc>>16),(uint8_t)(enc>>8),(uint8_t)enc };
        uint8_t dd[4]; for (int j=0;j<4;j++) dd[j]=b[j]^RG_KID[v57+j];
        uint32_t v138 = ((uint32_t)dd[0]<<24)|((uint32_t)dd[1]<<16)|((uint32_t)dd[2]<<8)|dd[3];
        rg_entry ent; memset(&ent, 0, sizeof ent);
        ent.v138=v138; ent.type=type; ent.size=size;
        if (type == 0) { ent.inl = off; }
        else {
            uint32_t blen = rg_roundblk(size);
            if (data_start + off + blen > len) return -2;
            uint8_t *blk = (uint8_t*)malloc(blen ? blen : 1);
            memcpy(blk, seg3 + data_start + off, blen);
            rg_obf(blk, blen, v138);
            ent.vlen = size; ent.val = (uint8_t*)malloc(size ? size : 1);
            memcpy(ent.val, blk + 4, size); free(blk);
        }
        rg_push(R, ent);
    }
    return 0;
}
static void rg_encode(const rg_reg *R, uint8_t *out, uint32_t len)
{
    memset(out, 0, len);
    uint32_t total = R->total, emitted = (uint32_t)R->n;
    uint32_t v45 = 0x50 + 16u*total;
    uint32_t datalen = 0;
    for (uint32_t i = 0; i < emitted; i++) {
        const rg_entry *e = &R->e[i];
        uint8_t desc[16]; memset(desc, 0, 16);
        uint8_t km[4]; uint32_t v63 = rg_kidmask(e->v138, km);
        memcpy(desc+0, km, 4);
        memcpy(desc+4, &e->type, 2);
        memcpy(desc+6, &e->size, 2);
        uint16_t v57w = (uint16_t)v63; memcpy(desc+8, &v57w, 2);
        if (e->type == 0) { memcpy(desc+12, &e->inl, 4); }
        else {
            memcpy(desc+12, &datalen, 4);
            uint32_t blen = rg_roundblk(e->size);
            uint8_t *blk = (uint8_t*)malloc(blen ? blen : 1);
            memset(blk, 0x22, blen);
            rg_chk(e->val, e->size, blk, 4);
            if (e->size) memcpy(blk+4, e->val, e->size);
            rg_obf(blk, blen, e->v138);
            memcpy(out + v45 + datalen, blk, blen); free(blk);
            datalen += blen;
        }
        uint8_t dc[2]; rg_chk(desc, 16, dc, 2); memcpy(desc+10, dc, 2);
        rg_obf(desc, 16, i);
        memcpy(out + 0x50 + 16*i, desc, 16);
    }
    for (uint32_t i = emitted; i < total; i++) {
        uint8_t desc[16]; memset(desc, 0x17, 16);
        rg_obf(desc, 16, i);
        memcpy(out + 0x50 + 16*i, desc, 16);
    }
    uint32_t pstart = v45 + datalen;
    for (uint32_t j = pstart; j < len; j++) out[j] = 0xE5;
    uint32_t off = 0, rem = len - pstart;
    while (rem > 0) {
        uint32_t clen = rem > 0xE8 ? 233 : rem;
        rg_obf(out + pstart + off, clen, off);
        off += clen; rem -= clen;
    }
    uint8_t h[80]; memset(h, 0, 80);
    memcpy(h+0,  R->hdr+0,  4);
    uint16_t tw=(uint16_t)total, ew=(uint16_t)emitted; memcpy(h+4,&tw,2); memcpy(h+6,&ew,2);
    memcpy(h+8, &datalen, 4);
    memcpy(h+16, R->hdr+16, 16);
    memcpy(h+32, R->hdr+32, 4);
    memcpy(h+40, R->hdr+40, 7);
    h[56] = R->hdr[56];
    { uint8_t t[2]; rg_chk(h+32, 4, t, 2); memcpy(h+36, t, 2); }
    { uint8_t v151[4] = { h[0x2B],h[0x2A],h[0x29],h[0x28] }, t[2]; rg_chk(v151, 4, t, 2); memcpy(h+38, t, 2); }
    { uint8_t t[4]; rg_chk(h, 80, t, 4); memcpy(h+12, t, 4); }
    rg_xor_hdr(h);
    memcpy(out, h, 80);
}
static int rg_set_str(rg_reg *R, uint32_t keyid, const char *s)
{
    for (int i = 0; i < R->n; i++) {
        rg_entry *e = &R->e[i];
        if (e->v138 == keyid && e->type != 0) {
            uint32_t sz = e->size, sl = (uint32_t)strlen(s);
            if (sl > sz - 1) sl = sz ? sz - 1 : 0;
            memset(e->val, 0, sz);
            memcpy(e->val, s, sl);
            return 1;
        }
    }
    return 0;
}
/* read a string registry value (for GUI autofill); returns 1 if found */
static int rg_get_str(rg_reg *R, uint32_t keyid, char *out, int cap)
{
    for (int i = 0; i < R->n; i++) {
        rg_entry *e = &R->e[i];
        if (e->v138 == keyid && e->type != 0 && e->val) {
            int n = (int)e->vlen; if (n >= cap) n = cap - 1;
            memcpy(out, e->val, n); out[n] = 0;
            return 1;
        }
    }
    return 0;
}

/* ===================== split-archive reader (per-call) =============== */
static int caf_pread(const char *dir, uint64_t off, uint64_t size, uint8_t *buf)
{
    uint8_t *p = buf;
    while (size > 0) {
        long long n = (long long)(off / MAX_SEG);
        uint64_t within = off % MAX_SEG;
        char path[4096];
        if (n == 0) snprintf(path, sizeof path, "%s/archive.dat", dir);
        else        snprintf(path, sizeof path, "%s/archive%04lld.dat", dir, n);
        FILE *f = bar_fopen(path, "rb");
        if (!f) return -1;
        bar_fseek64(f, (long long)within, SEEK_SET);
        uint64_t want = MAX_SEG - within; if (want > size) want = size;
        size_t got = fread(p, 1, (size_t)want, f);
        fclose(f);
        if (got != (size_t)want) return -1;
        p += want; off += want; size -= want;
    }
    return 0;
}

static void dir_of_archive(const char *archive_path, char *out, int cap)
{
    if (bar_is_dir(archive_path)) { snprintf(out, cap, "%s", archive_path); return; }
    snprintf(out, cap, "%s", archive_path);
    for (long i = (long)strlen(out) - 1; i >= 0; i--)
        if (out[i] == '/' || out[i] == '\\') { out[i] = 0; return; }
    snprintf(out, cap, ".");
}

static int caf_read_seg(const char *dir, uint32_t want_index, uint8_t **out, uint64_t *outlen,
                        int *keyset_out, uint64_t *hki_out)
{
    uint8_t hdr[0x30];
    if (caf_pread(dir, 0, 0x30, hdr) != 0) return -1;
    if (memcmp(hdr, CAF_MAGIC, 6) != 0) return -2;
    uint64_t nseg; memcpy(&nseg, hdr + 0x18, 8);
    if (nseg == 0 || nseg > 2000000) return -3;
    if (hki_out) memcpy(hki_out, hdr + 0x10, 8);
    uint8_t *tbl = (uint8_t*)malloc((size_t)(0x40*nseg));
    if (caf_pread(dir, 0x30, 0x40*nseg, tbl) != 0) { free(tbl); return -1; }

    uint8_t nkey[16], okey[16]; hex2bin(DEFAULT_KEY, nkey, 16); hex2bin(OLD_KEY_HEX, okey, 16);
    detect_aesni();
    aes_ctx kc; const uint8_t *chosen = NULL;
    for (uint64_t i = 0; i < nseg; i++) {
        uint8_t *r = tbl + 0x40*i; uint64_t idx; memcpy(&idx, r, 8);
        if (idx != 1) continue;
        uint64_t off, nopad; memcpy(&off, r+8, 8); memcpy(&nopad, r+0x38, 8);
        uint8_t seed[16]; memcpy(seed, r+0x28, 16);
        if (nopad < 4 || nopad > 0x4000) break;
        uint8_t *ct = (uint8_t*)malloc((size_t)nopad);
        if (caf_pread(dir, off, nopad, ct) != 0) { free(ct); break; }
        for (int t = 0; t < 2; t++) {
            aes_setup(&kc, t ? okey : nkey);
            uint8_t head[16]; cbc_dec_cts(&kc, seed, ct, (nopad<16?nopad:16), head);
            if (memcmp(head, P4BR_MAGIC, 4) == 0) { chosen = (t ? okey : nkey); if (keyset_out) *keyset_out = t ? 0 : 1; break; }
        }
        free(ct);
        break;
    }
    if (!chosen) { free(tbl); return -4; }
    aes_setup(&kc, chosen);

    int rc = -5;
    for (uint64_t i = 0; i < nseg; i++) {
        uint8_t *r = tbl + 0x40*i; uint64_t idx; memcpy(&idx, r, 8);
        if (idx != want_index) continue;
        uint64_t off, nopad; memcpy(&off, r+8, 8); memcpy(&nopad, r+0x38, 8);
        uint8_t seed[16]; memcpy(seed, r+0x28, 16);
        uint8_t *ct = (uint8_t*)malloc((size_t)(nopad?nopad:1));
        if (caf_pread(dir, off, nopad, ct) != 0) { free(ct); break; }
        uint8_t *pt = (uint8_t*)malloc((size_t)(nopad?nopad:1));
        cbc_dec_cts(&kc, seed, ct, nopad, pt);
        free(ct);
        *out = pt; *outlen = nopad; rc = 0; break;
    }
    free(tbl);
    return rc;
}

static int caf_empty_sig(const char *dir, uint8_t out[32])
{
    uint8_t hdr[0x30];
    if (caf_pread(dir, 0, 0x30, hdr) != 0) return -1;
    if (memcmp(hdr, CAF_MAGIC, 6) != 0) return -2;
    uint64_t nseg; memcpy(&nseg, hdr + 0x18, 8);
    if (nseg == 0 || nseg > 2000000) return -3;
    uint8_t *tbl = (uint8_t*)malloc((size_t)(0x40*nseg));
    if (caf_pread(dir, 0x30, 0x40*nseg, tbl) != 0) { free(tbl); return -1; }
    uint64_t sigbase = 0x30 + 0x40*nseg;
    int rc = -4;
    for (uint64_t i = 0; i < nseg; i++) {
        uint64_t nopad; memcpy(&nopad, tbl + 0x40*i + 0x38, 8);
        if (nopad == 0) {
            uint8_t ent[0x30];
            if (caf_pread(dir, sigbase + 0x30*i, 0x30, ent) == 0) { memcpy(out, ent + 8, 32); rc = 0; }
            break;
        }
    }
    free(tbl);
    return rc;
}

/* ===================== split-archive writer ========================= */
typedef struct { char dir[4096]; FILE *f; long long n; } writer_t;
static void writer_init(writer_t *w, const char *dir){ snprintf(w->dir,sizeof w->dir,"%s",dir); w->f=NULL; w->n=-1; }
static void writer_close(writer_t *w){ if(w->f){fclose(w->f);w->f=NULL;} w->n=-1; }
static FILE *writer_open(const char *dir, long long n)
{
    char path[4096];
    if (n == 0) snprintf(path, sizeof path, "%s/archive.dat", dir);
    else        snprintf(path, sizeof path, "%s/archive%04lld.dat", dir, n);
    FILE *f = bar_fopen(path, "r+b");
    if (!f) f = bar_fopen(path, "w+b");
    return f;
}
static uint64_t writer_write(writer_t *w, uint64_t off, const uint8_t *buf, uint64_t size)
{
    const uint8_t *p = buf;
    while (size > 0) {
        long long n = (long long)(off / MAX_SEG);
        uint64_t within = off % MAX_SEG;
        if (w->n != n) { if (w->f) fclose(w->f); w->f = writer_open(w->dir, n); w->n = n; if (!w->f) { w->n=-1; break; } }
        if (bar_fseek64(w->f, (long long)within, SEEK_SET) != 0) break;
        uint64_t want = MAX_SEG - within; if (want > size) want = size;
        size_t wr = fwrite(p, 1, (size_t)want, w->f);
        if (wr == 0) break;
        p += wr; off += wr; size -= wr;
    }
    return (uint64_t)(p - buf);
}
static uint64_t writer_readback(writer_t *w, uint64_t off, uint64_t size, uint8_t *buf)
{
    uint8_t *p = buf;
    while (size > 0) {
        long long n = (long long)(off / MAX_SEG);
        uint64_t within = off % MAX_SEG;
        if (w->n != n) { if (w->f) fclose(w->f); w->f = writer_open(w->dir, n); w->n = n; if (!w->f) { w->n=-1; break; } }
        if (bar_fseek64(w->f, (long long)within, SEEK_SET) != 0) break;
        uint64_t want = MAX_SEG - within; if (want > size) want = size;
        size_t got = fread(p, 1, (size_t)want, w->f);
        if (got == 0) break;
        p += got; off += got; size -= got;
    }
    return (uint64_t)(p - buf);
}

/* ===================== catalog model ================================ */
typedef struct {
    char    *path;      /* UTF-8 absolute POSIX  */
    char    *full;      /* on-disk UTF-8 path (files only) */
    uint64_t size;
    uint32_t mode;
    uint32_t ctime, mtime, atime;
    int      is_dir;
} entry_t;
typedef struct { entry_t *v; int n, cap; } vec_t;
static void vec_push(vec_t *a, entry_t e)
{
    if (a->n == a->cap) { a->cap = a->cap ? a->cap*2 : 256; a->v = (entry_t*)realloc(a->v, (size_t)a->cap*sizeof(entry_t)); }
    a->v[a->n++] = e;
}

/* recursive directory walk (mirrors the Win32 original, incl. skipping the
 * depth-0 roots as dir records). */
typedef struct { const char *base; const char *rel; vec_t *dirs; vec_t *files; } walk_ctx;
static void walk_rec(const char *base, const char *rel, vec_t *dirs, vec_t *files);
static int walk_cb(const bar_dirent *de, void *ud)
{
    walk_ctx *w = (walk_ctx *)ud;
    char posix[4096]; snprintf(posix, sizeof posix, "%s/%s", w->rel, de->name);
    char full[4096];  snprintf(full,  sizeof full,  "%s/%s", w->base, de->name);
    entry_t e; memset(&e, 0, sizeof e);
    e.ctime = de->ctime; e.mtime = de->mtime; e.atime = de->atime;
    if (de->is_dir) {
        e.is_dir = 1; e.size = 0; e.mode = 0x41F8;
        if (w->rel[0]) { e.path = strdup(posix); vec_push(w->dirs, e); }
        walk_rec(full, posix, w->dirs, w->files);
    } else {
        e.is_dir = 0; e.size = de->size; e.mode = 0x81C0;
        e.path = strdup(posix); e.full = strdup(full);
        vec_push(w->files, e);
    }
    return 0;
}
static void walk_rec(const char *base, const char *rel, vec_t *dirs, vec_t *files)
{
    walk_ctx w = { base, rel, dirs, files };
    bar_enum_dir(base, walk_cb, &w);
}

static void fill_record(uint8_t rec[REC], const entry_t *e)
{
    memset(rec, 0, REC);
    uint32_t ct = e->ctime, mt = e->mtime, at = e->atime;
    memcpy(rec + 0x00, &ct, 4);
    memcpy(rec + 0x10, &mt, 4);
    memcpy(rec + 0x20, &at, 4);
    uint64_t sz = e->is_dir ? 512 : e->size;
    memcpy(rec + 0x30, &sz, 8);
    memcpy(rec + 0x38, &ct, 4);
    uint32_t mode = e->mode;
    memcpy(rec + 0x50, &mode, 4);
    size_t pl = strlen(e->path);
    if (pl > REC - 0x54 - 1) pl = REC - 0x54 - 1;
    memcpy(rec + 0x54, e->path, pl);
}
static const uint8_t *tmpl_rec(const uint8_t *blob, uint64_t blob_len, const char *path)
{
    if (!blob || !path) return NULL;
    uint64_t n = blob_len / REC;
    for (uint64_t i = 0; i < n; i++) {
        const uint8_t *r = blob + i*REC;
        if (!strncmp((const char *)r + 0x54, path, REC - 0x54)) return r;
    }
    return NULL;
}
static void fill_record_tmpl(uint8_t rec[REC], const entry_t *e, const uint8_t *tblob, uint64_t tlen)
{
    const uint8_t *tr = tmpl_rec(tblob, tlen, e->path);
    if (!tr) { fill_record(rec, e); return; }
    memcpy(rec, tr, REC);
    if (!e->is_dir) { uint64_t sz = e->size; memcpy(rec + 0x30, &sz, 8); }
}

/* ===================== segment sealing ============================== */
typedef struct { uint64_t index, off, pad, nopad; uint8_t seed[16], sig[32]; } seg_out_t;
static uint64_t pad_of(uint64_t nopad){ return nopad ? ((nopad + CHUNK - 1) / CHUNK) * CHUNK : 0; }

static void rand_seed(uint8_t s[16])
{
    static uint64_t x = 0;
    if (!x) x = bar_rand64();
    for (int i = 0; i < 16; i++) { x ^= x<<13; x ^= x>>7; x ^= x<<17; s[i] = (uint8_t)(x >> ((i&7)*8)); }
}

typedef struct { const uint8_t *mem; FILE *fh; uint64_t left; } src_t;
static uint64_t src_read(src_t *s, uint8_t *dst, uint64_t n)
{
    if (n > s->left) n = s->left;
    uint64_t done = 0;
    if (s->mem) { memcpy(dst, s->mem, (size_t)n); s->mem += n; done = n; }
    else if (s->fh) { done = fread(dst, 1, (size_t)n, s->fh); }
    s->left -= done;
    return done;
}

static uint8_t g_empty_sig[32];
static int     g_have_empty_sig = 0;

static int seal_segment(writer_t *w, const aes_ctx *c, const hmac256_t *hbase,
                        src_t *src, seg_out_t *seg, uint8_t *inbuf, uint8_t *outbuf)
{
    uint64_t L = seg->nopad;
    if (L == 0) {
        if (g_have_empty_sig) memcpy(seg->sig, g_empty_sig, 32);
        else { hmac256_t hm = *hbase; hmac256_final(&hm, seg->sig); }
        return 0;
    }
    uint64_t full = L - (L % 16);
    uint8_t iv[16]; memcpy(iv, seg->seed, 16);
    uint8_t lastct[16]; memcpy(lastct, seg->seed, 16);
    hmac256_t hm = *hbase;
    uint64_t wpos = seg->off;

    uint64_t done = 0;
    while (done < full) {
        uint64_t want = full - done; if (want > BUFCAP) want = BUFCAP;
        if (src_read(src, inbuf, want) != want) return -1;
        cbc_enc_blocks(c, inbuf, (size_t)(want/16), iv, outbuf);
        memcpy(lastct, outbuf + want - 16, 16);
        hmac256_update(&hm, outbuf, (size_t)want);
        writer_write(w, wpos, outbuf, want);
        wpos += want; done += want;
    }
    uint64_t r = L - full;
    if (r) {
        uint8_t ptb[16] = {0}, ks[16], ctb[16];
        if (src_read(src, ptb, r) != r) return -1;
        aes_enc_block(c, (full >= 16) ? lastct : seg->seed, ks);
        for (uint64_t i = 0; i < r; i++) ctb[i] = ptb[i] ^ ks[i];
        hmac256_update(&hm, ctb, (size_t)r);
        writer_write(w, wpos, ctb, r);
        wpos += r;
    }
    hmac256_final(&hm, seg->sig);

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

/* ===================== skeleton / helpers =========================== */
static void human(uint64_t n, char *out)
{
    const char *u[] = {"B","KB","MB","GB","TB","PB"}; double v = (double)n; int i=0;
    while (v >= 1024.0 && i < 5) { v /= 1024.0; i++; }
    sprintf(out, "%.1f%s", v, u[i]);
}
static void clear_output(const char *dir)
{
    char path[4096];
    snprintf(path, sizeof path, "%s/archive.dat", dir); bar_remove(path);
    for (int n = 1; n < 100000; n++) {
        snprintf(path, sizeof path, "%s/archive%04d.dat", dir, n);
        uint64_t sz; if (bar_file_size(path, &sz) != 0) break;
        bar_remove(path);
    }
}
static void skeleton_path(char *out, int cap)
{
    char dir[4096]; bar_exe_dir(dir, sizeof dir);
    snprintf(out, cap, "%s/p4br_skeleton/archive.dat", dir[0] ? dir : ".");
}

static int run_make_skeleton(const char *backup, const char *outskel_opt)
{
    detect_aesni();
    char tdir[4096]; dir_of_archive(backup, tdir, sizeof tdir);
    uint8_t h0[0x30];
    if (caf_pread(tdir, 0, 0x30, h0) != 0 || memcmp(h0, CAF_MAGIC, 6) != 0) { p4br_log("skeleton: not a SCECAF backup"); return 1; }
    uint64_t nseg; memcpy(&nseg, h0 + 0x18, 8);
    uint64_t foff; memcpy(&foff, h0 + 0x20, 8);
    if (!nseg || nseg > 2000000) { p4br_log("skeleton: bad nseg"); return 1; }
    uint8_t *tbl = (uint8_t*)malloc((size_t)(0x40*nseg));
    if (caf_pread(tdir, 0x30, 0x40*nseg, tbl) != 0) { free(tbl); p4br_log("skeleton: read table"); return 1; }
    uint64_t aux_end = foff;
    for (uint64_t i = 0; i < nseg; i++) {
        uint8_t *r = tbl + 0x40*i; uint64_t idx; memcpy(&idx, r, 8);
        if (idx >= 1 && idx <= 6) {
            uint64_t off,pad,nop; memcpy(&off,r+8,8); memcpy(&pad,r+0x10,8); memcpy(&nop,r+0x38,8);
            if (nop && off >= foff && off + pad > aux_end) aux_end = off + pad;
        }
    }
    free(tbl);

    char skp[4096];
    if (outskel_opt && outskel_opt[0]) snprintf(skp, sizeof skp, "%s", outskel_opt);
    else skeleton_path(skp, sizeof skp);
    bar_mkdirs_parent(skp);
    FILE *oh = bar_fopen(skp, "wb");
    if (!oh) { p4br_log("skeleton: cannot write output (%s)", skp); return 1; }
    uint8_t *buf = (uint8_t*)malloc(BUFCAP); uint64_t pos = 0; int ok = 1;
    while (pos < aux_end) {
        uint64_t n = aux_end - pos; if (n > BUFCAP) n = BUFCAP;
        if (caf_pread(tdir, pos, n, buf) != 0) { ok = 0; break; }
        if (fwrite(buf, 1, (size_t)n, oh) != (size_t)n) { ok = 0; break; }
        pos += n;
    }
    free(buf); fclose(oh);
    if (!ok) { p4br_log("skeleton: copy failed"); return 1; }
    p4br_log("[+] skeleton saved: %s (%llu bytes)", skp, (unsigned long long)aux_end);
    p4br_log("[+] now create backups from files only (no template).");
    return 0;
}

static void posix_to_full(const char *root, const char *posix, char *out, int cap)
{
    snprintf(out, cap, "%s%s", root, posix);
}
static void rmtree_cb_fwd(const char *dir);
static int rmtree_cb(const bar_dirent *de, void *ud)
{
    const char *dir = (const char *)ud;
    char sub[4096]; snprintf(sub, sizeof sub, "%s/%s", dir, de->name);
    if (de->is_dir) { rmtree_cb_fwd(sub); }
    else bar_remove(sub);
    return 0;
}
static void rmtree_cb_fwd(const char *dir)
{
    bar_enum_dir(dir, rmtree_cb, (void*)dir);
#if defined(_WIN32)
    { wchar_t *w = bar_utf8_to_wide(dir); if (w) { _wrmdir(w); free(w); } }
#else
    rmdir(dir);
#endif
}

static int source_is_backup(const char *src, char *bdir_out, int cap)
{
    char arcu[4096];
    if (bar_is_dir(src)) snprintf(arcu, sizeof arcu, "%s/archive.dat", src);
    else snprintf(arcu, sizeof arcu, "%s", src);
    char bdir[4096]; dir_of_archive(arcu, bdir, sizeof bdir);
    uint8_t h[0x30];
    if (caf_pread(bdir, 0, 0x30, h) != 0 || memcmp(h, CAF_MAGIC, 6) != 0) return 0;
    snprintf(bdir_out, cap, "%s", bdir);
    return 1;
}
static int extract_backup_to_tree(const char *bdir, const char *destroot)
{
    bar_mkdirs(destroot);
    uint8_t *dcat=NULL,*fcat=NULL; uint64_t dl=0,fl=0;
    caf_read_seg(bdir, 2, &dcat, &dl, NULL, NULL);
    if (caf_read_seg(bdir, 3, &fcat, &fl, NULL, NULL) != 0) { p4br_log("[!] backup source has no file catalog"); free(dcat); return 1; }
    int ndir=0, nfile=0, ok=1;
    if (dcat) for (uint64_t o=0; o+REC<=dl; o+=REC) {
        const char *path=(const char*)dcat+o+0x54; if (!path[0]) continue;
        char full[4096]; posix_to_full(destroot, path, full, sizeof full);
        bar_mkdirs(full); ndir++;
    }
    int rec=0;
    for (uint64_t o=0; o+REC<=fl; o+=REC, rec++) {
        const char *path=(const char*)fcat+o+0x54;
        uint8_t *pl=NULL; uint64_t pll=0;
        int r = caf_read_seg(bdir, 10000+rec, &pl, &pll, NULL, NULL);
        if (!path[0]) { if (pl) free(pl); continue; }
        char full[4096]; posix_to_full(destroot, path, full, sizeof full);
        bar_mkdirs_parent(full);
        FILE *oh = bar_fopen(full, "wb");
        if (!oh) { p4br_log("[!] cannot write %s", full); ok=0; if(pl)free(pl); continue; }
        if (r==0 && pl && pll) fwrite(pl, 1, (size_t)pll, oh);
        fclose(oh); if (pl) free(pl); nfile++;
    }
    free(dcat); free(fcat);
    p4br_log("[+] extracted backup source: %d dirs, %d files", ndir, nfile);
    return ok?0:1;
}

static void reorder_by_template(vec_t *v, const uint8_t *tcat, uint64_t tlen)
{
    if (!tcat || tlen < REC || v->n <= 1) return;
    int tn = (int)(tlen / REC), k = 0;
    entry_t *nv = (entry_t*)malloc((size_t)v->n * sizeof(entry_t));
    char *placed = (char*)calloc((size_t)v->n, 1);
    for (int t = 0; t < tn && k < v->n; t++) {
        const char *tp = (const char *)tcat + (uint64_t)t*REC + 0x54;
        if (!tp[0]) continue;
        for (int i = 0; i < v->n; i++)
            if (!placed[i] && !strcmp(v->v[i].path, tp)) { nv[k++] = v->v[i]; placed[i] = 1; break; }
    }
    int matched = k;
    for (int i = 0; i < v->n; i++) if (!placed[i]) nv[k++] = v->v[i];
    memcpy(v->v, nv, (size_t)v->n * sizeof(entry_t));
    free(nv); free(placed);
    if (matched < v->n) p4br_log("  [order] %d/%d match template order, %d new kept last", matched, v->n, v->n - matched);
}

/* ===================== options + run ================================ */
typedef struct {
    const char *source;
    const char *outdir;
    const char *keyhex;
    const char *hashhex;
    const char *name;
    const char *label;
    int   verify_after;
    const char *tmpl;
    const char *set_user;
    const char *set_host;
    const char *openpsid;
    const char *sets[MAX_SETS];
    int   nsets;
    const char *keyset;     /* "old" | "new" | NULL */
    int   clone;
    int   make_skeleton;
} p4br_create_opts;

static const char *S(const char *p) { return p ? p : ""; }

static int run_clone(const p4br_create_opts *J)
{
    detect_aesni();
    char tdir[4096]; dir_of_archive(J->tmpl, tdir, sizeof tdir);
    uint8_t h0[0x30];
    if (caf_pread(tdir, 0, 0x30, h0) != 0 || memcmp(h0, CAF_MAGIC, 6) != 0) { p4br_log("clone: bad template"); return 1; }
    uint64_t nseg; memcpy(&nseg, h0 + 0x18, 8);
    uint64_t foff; memcpy(&foff, h0 + 0x20, 8);
    if (!nseg || nseg > 2000000) { p4br_log("clone: bad nseg"); return 1; }
    uint8_t *tbl = (uint8_t*)malloc((size_t)(0x40*nseg));
    uint64_t hdr_size = 0x30 + 0x40*nseg + 0x30*nseg;
    if (caf_pread(tdir, 0x30, 0x40*nseg, tbl) != 0) { free(tbl); p4br_log("clone: short read"); return 1; }

    uint8_t nkey[16], okey[16]; hex2bin(DEFAULT_KEY, nkey, 16); hex2bin(OLD_KEY_HEX, okey, 16);
    uint8_t nhk[32], ohk[32]; hex2bin(DEFAULT_HASH_KEY, nhk, 32); hex2bin(OLD_HASH_KEY_HEX, ohk, 32);
    aes_ctx kc; const uint8_t *ck=NULL, *hk=NULL;
    for (uint64_t i = 0; i < nseg; i++) {
        uint8_t *r = tbl + 0x40*i; uint64_t idx; memcpy(&idx, r, 8); if (idx != 1) continue;
        uint64_t off,nop; memcpy(&off,r+8,8); memcpy(&nop,r+0x38,8); uint8_t seed[16]; memcpy(seed,r+0x28,16);
        if (!nop || nop > 0x4000) break;
        uint8_t *ct = (uint8_t*)malloc((size_t)nop), head[16];
        if (caf_pread(tdir, off, nop, ct) == 0) {
            for (int t=0;t<2;t++){ aes_setup(&kc, t?okey:nkey); cbc_dec_cts(&kc,seed,ct,(nop<16?nop:16),head);
                if (memcmp(head,P4BR_MAGIC,4)==0){ ck=t?okey:nkey; hk=t?ohk:nhk; break; } }
        }
        free(ct); break;
    }
    if (!ck) { free(tbl); p4br_log("clone: could not detect keyset"); return 1; }
    aes_setup(&kc, ck);
    hmac256_t hbase; hmac256_init(&hbase, hk, 32);
    g_have_empty_sig = (caf_empty_sig(tdir, g_empty_sig) == 0);

    const char *outdir = (J->outdir && J->outdir[0]) ? J->outdir : "clone_out";
    bar_mkdirs(outdir);
    clear_output(outdir);
    writer_t w; writer_init(&w, outdir);
    p4br_log("[+] clone %s : nseg=%llu keyset=%s%s", J->tmpl, (unsigned long long)nseg,
             ck==nkey?"new":"old", g_aesni?"  [AES-NI]":"");

    uint8_t *hdrbuf = (uint8_t*)malloc((size_t)foff);
    if (caf_pread(tdir, 0, foff, hdrbuf) != 0) { p4br_log("clone: header read"); free(tbl); free(hdrbuf); return 1; }
    uint8_t *osig = hdrbuf + 0x30 + 0x40*nseg;
    uint8_t *cbuf = (uint8_t*)bar_aligned_alloc(BUFCAP);
    int nchanged = 0;

    for (uint64_t i = 0; i < nseg; i++) {
        uint8_t *r = tbl + 0x40*i;
        uint64_t off,pad,nop; memcpy(&off,r+8,8); memcpy(&pad,r+0x10,8); memcpy(&nop,r+0x38,8);
        uint8_t seed[16]; memcpy(seed,r+0x28,16);
        uint64_t idx; memcpy(&idx, r, 8);
        int candidate = nop &&
            ((idx==4 && nop==RG_BLOB && (S(J->set_user)[0]||S(J->set_host)[0]||S(J->openpsid)[0]||J->nsets)) ||
             (idx==1 && nop>=0x100 && (S(J->name)[0]||S(J->label)[0]||S(J->openpsid)[0]||S(J->set_host)[0])));
        if (!candidate) {
            uint64_t p=off, rem=pad; while (rem){ uint64_t n=rem>BUFCAP?BUFCAP:rem; if(caf_pread(tdir,p,n,cbuf)!=0)break; writer_write(&w,p,cbuf,n); p+=n; rem-=n; }
            continue;
        }
        uint8_t *buf = (uint8_t*)malloc((size_t)pad);
        if (caf_pread(tdir, off, pad, buf)!=0){ p4br_log("clone: read seg %llu",(unsigned long long)i); free(buf); break; }
        uint8_t *pt = (uint8_t*)malloc((size_t)nop), *op = (uint8_t*)malloc((size_t)nop);
        cbc_dec_cts(&kc, seed, buf, nop, pt); memcpy(op, pt, (size_t)nop);
        if (idx == 4) {
            rg_reg R;
            if (rg_decode(pt, (uint32_t)nop, &R) == 0) {
                if (S(J->set_user)[0]) p4br_log("  [reg] user -> %s (%s)", J->set_user, rg_set_str(&R,RK_USER_NAME,J->set_user)?"ok":"absent");
                if (S(J->set_host)[0]) p4br_log("  [reg] host -> %s (%s)", J->set_host, rg_set_str(&R,RK_HOSTNAME,J->set_host)?"ok":"absent");
                if (S(J->openpsid)[0] && strlen(J->openpsid)==32) { uint8_t o[16]; if(hex2bin(J->openpsid,o,16)==0){ memcpy(R.hdr+16,o,16); p4br_log("  [reg] seg3 OpenPSID overridden"); } }
                for (int si=0; si<J->nsets; si++){ char t[160]; strncpy(t,J->sets[si],159); t[159]=0; char *eq=strchr(t,'='); if(!eq)continue; *eq=0; uint32_t kid=(uint32_t)strtoul(t,NULL,16); p4br_log("  [reg] %08x -> \"%s\" (%s)",kid,eq+1, rg_set_str(&R,kid,eq+1)?"ok":"absent"); }
                rg_encode(&R, pt, (uint32_t)nop); rg_free(&R);
            }
        } else {
            const char *cn = S(J->name)[0] ? J->name : (S(J->set_host)[0] ? J->set_host : NULL);
            if (cn && strncmp((char*)pt+0x34, cn, 0x40)) { memset(pt+0x34,0,0x40); strncpy((char*)pt+0x34, cn, 0x3F); p4br_log("  [p4br] name -> %s", cn); }
            if (S(J->label)[0] && strncmp((char*)pt+0x80, J->label, 0x78)) { memset(pt+0x80,0,0x78); strncpy((char*)pt+0x80, J->label, 0x77); p4br_log("  [p4br] label -> %s", J->label); }
            if (S(J->openpsid)[0] && strlen(J->openpsid)==32) { uint8_t o[16]; if(hex2bin(J->openpsid,o,16)==0) memcpy(pt+0x18,o,16); }
        }
        if (memcmp(pt, op, (size_t)nop) != 0) {
            cbc_enc_cts(&kc, seed, pt, nop, buf);
            hmac256_t hm=hbase; hmac256_update(&hm, buf, (size_t)nop); hmac256_final(&hm, osig + 0x30*i + 8);
            nchanged++;
        }
        writer_write(&w, off, buf, pad);
        free(buf); free(pt); free(op);
    }

    uint8_t hh[32]; hmac256_t hm=hbase; hmac256_update(&hm, hdrbuf, (size_t)hdr_size); hmac256_final(&hm, hh);
    memcpy(hdrbuf + hdr_size, hh, 32);
    writer_write(&w, 0, hdrbuf, foff);

    bar_aligned_free(cbuf); free(hdrbuf); free(tbl);
    writer_close(&w);
    p4br_log("[+] clone done (%d segment%s changed) -> %s", nchanged, nchanged==1?"":"s", outdir);
    return 0;
}

static int run_create_main(const p4br_create_opts *J)
{
    if (J->clone) {
        if (!J->tmpl || !J->tmpl[0]) { p4br_log("--clone needs -t <template archive.dat>"); return 2; }
        return run_clone(J);
    }
    if (J->make_skeleton) return run_make_skeleton(J->source, J->outdir);

    const char *keyhex  = (J->keyhex && J->keyhex[0])  ? J->keyhex  : DEFAULT_KEY;
    const char *hashhex = (J->hashhex && J->hashhex[0]) ? J->hashhex : DEFAULT_HASH_KEY;
    uint8_t key[16], hkey[32];
    if (strlen(keyhex) != 32 || hex2bin(keyhex, key, 16) != 0) { p4br_log("key must be 32 hex chars"); return 2; }
    if (strlen(hashhex) != 64 || hex2bin(hashhex, hkey, 32) != 0) { p4br_log("hash key must be 64 hex chars"); return 2; }

    detect_aesni();
    aes_ctx ctx; aes_setup(&ctx, key);
    hmac256_t hbase; hmac256_init(&hbase, hkey, 32);
    int user_key = (J->keyhex && J->keyhex[0]), user_hash = (J->hashhex && J->hashhex[0]);
    uint64_t hki_used = 0x200000001ULL;
    int tkeyset = -1; uint64_t thki = 0;

    char tmpl[1024]; snprintf(tmpl, sizeof tmpl, "%s", S(J->tmpl));
    if (!tmpl[0]) {
        char skp[4096]; skeleton_path(skp, sizeof skp);
        uint64_t sz;
        if (bar_file_size(skp, &sz) == 0) { snprintf(tmpl, sizeof tmpl, "%s", skp); p4br_log("[+] using bundled skeleton for aux (registry/reboot/sparse/identity)"); }
    }

    const char *outdir = (J->outdir && J->outdir[0]) ? J->outdir : "backup_out";
    bar_mkdirs(outdir);
    clear_output(outdir);

    char srcdir[4096]; snprintf(srcdir, sizeof srcdir, "%s", J->source);
    char srctree[4096]; srctree[0] = 0;
    {
        char bdir[4096];
        if (source_is_backup(J->source, bdir, sizeof bdir)) {
            snprintf(srctree, sizeof srctree, "%s/_p4br_srctree", outdir);
            rmtree_cb_fwd(srctree);
            p4br_log("[+] source is a PS4 backup -> extracting its file tree to rebuild from");
            if (extract_backup_to_tree(bdir, srctree) != 0) { p4br_log("[!] could not extract backup source"); return 1; }
            snprintf(srcdir, sizeof srcdir, "%s", srctree);
        }
    }

    p4br_log("[+] scanning %s%s", srcdir, g_aesni ? "  [AES-NI]" : "  [SW-AES]");
    vec_t dirs = {0}, files = {0};
    walk_rec(srcdir, "", &dirs, &files);
    p4br_log("[+] catalog: %d dirs, %d files", dirs.n, files.n);
    if (files.n == 0 && dirs.n == 0) { p4br_log("source is empty"); return 1; }

    { int good=0, stray=0;
      for (int i=0;i<files.n;i++) if (!strncmp(files.v[i].path,"/user/",6)||!strncmp(files.v[i].path,"/system_data/",13)) good++; else stray++;
      if (stray) { p4br_log("[!] WARNING: %d file(s) are NOT under /user or /system_data; a PS4 backup only restores files inside those roots.", stray);
                   if (!good) p4br_log("[!] NONE of the files are under a valid root -- this backup will not restore."); }
    }

    uint64_t total_payload = 0;
    for (int i = 0; i < files.n; i++) total_payload += files.v[i].size;

    int have_aux = 0;
    uint8_t *reg_blob=NULL,*seg4buf=NULL,*seg5buf=NULL,*p4tmpl=NULL;
    uint64_t seg4len=0, seg5len=0, p4tmpllen=0;
    uint8_t *tcat_d=NULL,*tcat_f=NULL; uint64_t tcat_dl=0, tcat_fl=0;
    if (tmpl[0]) {
        char tdir[4096]; dir_of_archive(tmpl, tdir, sizeof tdir);
        uint8_t *s3=NULL,*s4=NULL,*s5=NULL,*s0=NULL; uint64_t l3=0,l4=0,l5=0,l0=0;
        int r3 = caf_read_seg(tdir, 4, &s3, &l3, &tkeyset, &thki);
        int r4 = caf_read_seg(tdir, 5, &s4, &l4, NULL, NULL);
        int r5 = caf_read_seg(tdir, 6, &s5, &l5, NULL, NULL);
        int r0 = caf_read_seg(tdir, 1, &s0, &l0, NULL, NULL);
        if (caf_read_seg(tdir, 2, &tcat_d, &tcat_dl, NULL, NULL) != 0) { tcat_d=NULL; tcat_dl=0; }
        if (caf_read_seg(tdir, 3, &tcat_f, &tcat_fl, NULL, NULL) != 0) { tcat_f=NULL; tcat_fl=0; }
        if (r3==0 && l3==RG_BLOB && r4==0 && r5==0 && r0==0) {
            rg_reg R;
            if (rg_decode(s3, (uint32_t)l3, &R) == 0) {
                if (S(J->set_user)[0]) p4br_log("  [reg] user  -> %s (%s)", J->set_user, rg_set_str(&R,RK_USER_NAME,J->set_user)?"ok":"key not present");
                if (S(J->set_host)[0]) p4br_log("  [reg] host  -> %s (%s)", J->set_host, rg_set_str(&R,RK_HOSTNAME,J->set_host)?"ok":"key not present");
                if (S(J->openpsid)[0] && strlen(J->openpsid)==32) {
                    uint8_t ops[16];
                    if (hex2bin(J->openpsid, ops, 16)==0) { memcpy(R.hdr+16, ops, 16); if (s0 && l0>=0x28) memcpy(s0+0x18, ops, 16); p4br_log("  [reg] OpenPSID overridden"); }
                }
                for (int si=0; si<J->nsets; si++) {
                    char tmp[160]; strncpy(tmp, J->sets[si], 159); tmp[159]=0;
                    char *eq = strchr(tmp, '='); if (!eq) continue; *eq = 0;
                    uint32_t kid = (uint32_t)strtoul(tmp, NULL, 16);
                    p4br_log("  [reg] %08x -> \"%s\" (%s)", kid, eq+1, rg_set_str(&R, kid, eq+1)?"ok":"key not present");
                }
                reg_blob = (uint8_t*)malloc(RG_BLOB); rg_encode(&R, reg_blob, RG_BLOB);
                rg_free(&R);
                seg4buf=s4; seg4len=l4; seg5buf=s5; seg5len=l5; p4tmpl=s0; p4tmpllen=l0;
                have_aux = 1;
                g_have_empty_sig = (caf_empty_sig(tdir, g_empty_sig) == 0);
                p4br_log("[+] aux from template %s : seg3=0x%llx seg4=0x%llx seg5=0x%llx (template keyset=%s)",
                         tmpl, (unsigned long long)RG_BLOB, (unsigned long long)seg4len, (unsigned long long)seg5len, tkeyset ? "new" : "old");
            } else free(s3);
        }
        if (!have_aux) { free(s3); free(s4); free(s5); free(s0);
            p4br_log("[!] template unusable (r3=%d l3=0x%llx r4=%d r5=%d r0=%d); creating WITHOUT aux (not PS4-restorable)",
                     r3, (unsigned long long)l3, r4, r5, r0); }
        if (have_aux) free(s3);
        reorder_by_template(&dirs,  tcat_d, tcat_dl);
        reorder_by_template(&files, tcat_f, tcat_fl);
    }

    { int want = -1;
      if (J->keyset && J->keyset[0]) want = (J->keyset[0]=='o'||J->keyset[0]=='O') ? 0 : 1;
      else if (tkeyset >= 0) want = tkeyset;
      if (want < 0) want = 1;
      hki_used = (have_aux && !(J->keyset && J->keyset[0]) && thki) ? thki : (want ? 0x200000001ULL : 0x200000000ULL);
      if (!user_key && !user_hash) {
          if (want == 0) { hex2bin(OLD_KEY_HEX, key, 16); hex2bin(OLD_HASH_KEY_HEX, hkey, 32); }
          else           { hex2bin(DEFAULT_KEY, key, 16); hex2bin(DEFAULT_HASH_KEY, hkey, 32); }
          aes_setup(&ctx, key); hmac256_init(&hbase, hkey, 32);
      }
      p4br_log("[+] keyset=%s  key-index=0x%llx%s", want ? "new" : "old", (unsigned long long)hki_used,
               (user_key||user_hash) ? "  (cipher/hash overridden by -k/-H)" : "");
    }

    uint64_t naux = have_aux ? 6 : 3;
    uint64_t nseg = naux + (uint64_t)files.n;
    seg_out_t *segs = (seg_out_t*)calloc((size_t)nseg, sizeof(seg_out_t));
    uint64_t header_size = 0x30 + 0x40*nseg + 0x30*nseg;
    uint64_t file_offset = ((header_size + 0x20 + CHUNK - 1) / CHUNK) * CHUNK;
    if (file_offset < CHUNK) file_offset = CHUNK;

    segs[0].nopad = have_aux ? p4tmpllen : P4BR_LEN;
    segs[1].nopad = (uint64_t)dirs.n  * REC;
    segs[2].nopad = (uint64_t)files.n * REC;
    if (have_aux) { segs[3].nopad = RG_BLOB; segs[4].nopad = seg4len; segs[5].nopad = seg5len; }
    for (int i = 0; i < files.n; i++) segs[naux+i].nopad = files.v[i].size;

    uint64_t off = file_offset;
    for (uint64_t i = 0; i < nseg; i++) {
        segs[i].pad = pad_of(segs[i].nopad);
        segs[i].off = segs[i].nopad ? off : 0x200000;
        off += segs[i].pad;
        segs[i].index = (i < naux) ? (i + 1) : (10000 + (i - naux));
        rand_seed(segs[i].seed);
    }
    uint64_t file_size = 0; for (uint64_t i=0;i<nseg;i++) file_size += segs[i].pad;

    writer_t w; writer_init(&w, outdir);

    /* seg0 P4BR */
    {
        uint64_t p4len = segs[0].nopad;
        uint8_t *p4 = (uint8_t*)calloc(1, (size_t)p4len);
        if (have_aux && p4tmpl) memcpy(p4, p4tmpl, (size_t)p4len);
        else { memcpy(p4, P4BR_MAGIC, 4); uint32_t ver = 2; memcpy(p4 + 0x04, &ver, 4); }
        uint32_t nd = (uint32_t)dirs.n, nf = (uint32_t)files.n;
        memcpy(p4 + 0x10, &nd, 4); memcpy(p4 + 0x14, &nf, 4);
        const char *cn = S(J->name)[0] ? J->name : (S(J->set_host)[0] ? J->set_host : NULL);
        if (cn)          { memset(p4 + 0x34, 0, 0x40); strncpy((char*)p4 + 0x34, cn, 0x3F); }
        else if (!have_aux) strncpy((char*)p4 + 0x34, "PS4", 0x3F);
        if (S(J->openpsid)[0] && strlen(J->openpsid)==32) { uint8_t o[16]; if(hex2bin(J->openpsid,o,16)==0) memcpy(p4+0x18,o,16); }
        if (S(J->label)[0]) { memset(p4 + 0x80, 0, 0x78); strncpy((char*)p4 + 0x80, J->label, 0x77); }
        else if (!have_aux) strncpy((char*)p4 + 0x80, S(J->name)[0]?J->name:"PS4 backup", 0x77);
        src_t s = { p4, NULL, p4len };
        uint8_t *ib = (uint8_t*)bar_aligned_alloc(BUFCAP), *ob = (uint8_t*)bar_aligned_alloc(BUFCAP);
        seal_segment(&w, &ctx, &hbase, &s, &segs[0], ib, ob);
        bar_aligned_free(ib); bar_aligned_free(ob); free(p4);
    }
    /* seg1 dirs, seg2 files */
    {
        uint8_t *ib = (uint8_t*)bar_aligned_alloc(BUFCAP), *ob = (uint8_t*)bar_aligned_alloc(BUFCAP);
        int inh_d = 0, inh_f = 0;
        uint8_t *db = (uint8_t*)calloc(1, segs[1].nopad ? (size_t)segs[1].nopad : 1);
        for (int i = 0; i < dirs.n; i++) { fill_record_tmpl(db + (size_t)i*REC, &dirs.v[i], tcat_d, tcat_dl); if (tcat_d && tmpl_rec(tcat_d, tcat_dl, dirs.v[i].path)) inh_d++; }
        src_t sd = { db, NULL, segs[1].nopad }; seal_segment(&w, &ctx, &hbase, &sd, &segs[1], ib, ob); free(db);
        uint8_t *fb = (uint8_t*)calloc(1, segs[2].nopad ? (size_t)segs[2].nopad : 1);
        for (int i = 0; i < files.n; i++) { fill_record_tmpl(fb + (size_t)i*REC, &files.v[i], tcat_f, tcat_fl); if (tcat_f && tmpl_rec(tcat_f, tcat_fl, files.v[i].path)) inh_f++; }
        if (tcat_d || tcat_f) p4br_log("[+] catalog fields inherited from template: %d/%d dirs, %d/%d files", inh_d, dirs.n, inh_f, files.n);
        src_t sf = { fb, NULL, segs[2].nopad }; seal_segment(&w, &ctx, &hbase, &sf, &segs[2], ib, ob); free(fb);
        bar_aligned_free(ib); bar_aligned_free(ob);
    }
    /* seg3/4/5 aux */
    if (have_aux) {
        uint8_t *ib = (uint8_t*)bar_aligned_alloc(BUFCAP), *ob = (uint8_t*)bar_aligned_alloc(BUFCAP);
        src_t s3 = { reg_blob, NULL, segs[3].nopad }; seal_segment(&w, &ctx, &hbase, &s3, &segs[3], ib, ob);
        src_t s4 = { seg4buf,  NULL, segs[4].nopad }; seal_segment(&w, &ctx, &hbase, &s4, &segs[4], ib, ob);
        src_t s5 = { seg5buf,  NULL, segs[5].nopad }; seal_segment(&w, &ctx, &hbase, &s5, &segs[5], ib, ob);
        bar_aligned_free(ib); bar_aligned_free(ob);
    }
    /* payload */
    int rc_fail = 0;
    {
        uint8_t *ib = (uint8_t*)bar_aligned_alloc(BUFCAP), *ob = (uint8_t*)bar_aligned_alloc(BUFCAP);
        uint64_t doneb = 0; char hb[32], hb2[32]; human(total_payload, hb2);
        double tlast = bar_monotonic();
        for (int i = 0; i < files.n && !rc_fail; i++) {
            if (cancelled()) { rc_fail = 1; break; }
            seg_out_t *sg = &segs[naux + i];
            FILE *fh = NULL;
            if (sg->nopad) {
                fh = bar_fopen(files.v[i].full, "rb");
                if (!fh) { p4br_log("cannot open %s", files.v[i].path); rc_fail = 1; break; }
            }
            src_t s = { NULL, fh, sg->nopad };
            if (seal_segment(&w, &ctx, &hbase, &s, sg, ib, ob) != 0) { p4br_log("short read on %s", files.v[i].path); if (fh) fclose(fh); rc_fail = 1; break; }
            if (fh) fclose(fh);
            doneb += sg->nopad;
            if (g_cbs.progress) g_cbs.progress((long long)doneb, (long long)total_payload, g_cbs.ud);
            double now = bar_monotonic();
            if (now - tlast > 0.5 || i == files.n - 1) { human(doneb, hb); p4br_log("  [%d/%d] %s/%s  %s", i+1, files.n, hb, hb2, files.v[i].path); tlast = now; }
        }
        bar_aligned_free(ib); bar_aligned_free(ob);
    }
    /* header + tables + signatures */
    if (!rc_fail) {
        uint8_t *hdrbuf = (uint8_t*)calloc(1, (size_t)header_size);
        memcpy(hdrbuf, CAF_MAGIC, 8);
        uint64_t version = 2, hki = hki_used;
        memcpy(hdrbuf + 0x08, &version, 8); memcpy(hdrbuf + 0x10, &hki, 8);
        memcpy(hdrbuf + 0x18, &nseg, 8); memcpy(hdrbuf + 0x20, &file_offset, 8); memcpy(hdrbuf + 0x28, &file_size, 8);
        uint8_t *tbl = hdrbuf + 0x30;
        for (uint64_t i = 0; i < nseg; i++) {
            uint8_t *r = tbl + 0x40*i; uint64_t algo = 2, kidx = hki_used;
            memcpy(r+0x00,&segs[i].index,8); memcpy(r+0x08,&segs[i].off,8); memcpy(r+0x10,&segs[i].pad,8);
            memcpy(r+0x18,&algo,8); memcpy(r+0x20,&kidx,8); memcpy(r+0x28,segs[i].seed,16); memcpy(r+0x38,&segs[i].nopad,8);
        }
        uint8_t *sigtbl = tbl + 0x40*nseg;
        for (uint64_t i = 0; i < nseg; i++) { uint8_t *e = sigtbl + 0x30*i; memcpy(e+0x00,&i,8); memcpy(e+0x08,segs[i].sig,32); }
        writer_write(&w, 0, hdrbuf, header_size);
        uint8_t hh[32]; hmac256_t hm = hbase; hmac256_update(&hm, hdrbuf, (size_t)header_size); hmac256_final(&hm, hh);
        writer_write(&w, header_size, hh, 32);
        uint64_t gap_start = header_size + 32;
        if (file_offset > gap_start) {
            uint64_t g = file_offset - gap_start;
            uint8_t *z = (uint8_t*)calloc(1, (size_t)(g > BUFCAP ? BUFCAP : g));
            uint64_t pos = gap_start;
            while (g) { uint64_t wn = g > BUFCAP ? BUFCAP : g; writer_write(&w, pos, z, wn); pos += wn; g -= wn; }
            free(z);
        }
        free(hdrbuf);
    }
    writer_close(&w);

    if (!rc_fail) {
        char hbt[32]; human(file_size, hbt);
        p4br_log("[+] wrote SCECAF v2  segments=%llu  content=%s  file_offset=0x%llx -> %s",
                 (unsigned long long)nseg, hbt, (unsigned long long)file_offset, outdir);
    }

    if (!rc_fail && J->verify_after) {
        writer_t r; writer_init(&r, outdir);
        uint8_t stored[32], calc[32];
        uint8_t *hb = (uint8_t*)malloc((size_t)header_size);
        writer_readback(&r, 0, header_size, hb);
        hmac256_t hm = hbase; hmac256_update(&hm, hb, (size_t)header_size); hmac256_final(&hm, calc); free(hb);
        writer_readback(&r, header_size, 32, stored);
        int hdr_ok = (memcmp(calc, stored, 32) == 0);
        p4br_log("[+] re-verify header HMAC: %s", hdr_ok ? "OK" : "MISMATCH");
        int bad = 0, empty = 0;
        uint8_t *buf = (uint8_t*)bar_aligned_alloc(BUFCAP);
        for (uint64_t i = 0; i < nseg; i++) {
            if (segs[i].nopad == 0) { empty++; continue; }
            hmac256_t hs = hbase; uint64_t left = segs[i].nopad, pos = segs[i].off;
            while (left) { uint64_t want = left < BUFCAP ? left : BUFCAP; uint64_t got = writer_readback(&r, pos, want, buf); if (!got) break; hmac256_update(&hs, buf, (size_t)got); pos += got; left -= got; }
            hmac256_final(&hs, calc);
            if (memcmp(calc, segs[i].sig, 32) != 0) { bad++; p4br_log("  BAD seg[%llu]", (unsigned long long)i); }
        }
        bar_aligned_free(buf); writer_close(&r);
        p4br_log("[+] re-verify segments: %llu/%llu OK, %d bad, %d empty",
                 (unsigned long long)(nseg - bad - empty), (unsigned long long)(nseg - empty), bad, empty);
        p4br_log("%s", (hdr_ok && !bad) ? "[+] self-check PASSED" : "[!] self-check FAILED");
    }

    for (int i=0;i<dirs.n;i++)  { free(dirs.v[i].path);  free(dirs.v[i].full); }
    for (int i=0;i<files.n;i++) { free(files.v[i].path); free(files.v[i].full); }
    free(dirs.v); free(files.v); free(segs);
    free(reg_blob); free(seg4buf); free(seg5buf); free(p4tmpl);
    free(tcat_d); free(tcat_f);
    (void)srctree;
    return rc_fail ? 1 : 0;
}

/* public entry for the GUI */
static int p4br_create_run(const p4br_create_opts *o, const p4br_cbs *cbs)
{
    g_cbs = cbs ? *cbs : (p4br_cbs){0};
    return run_create_main(o);
}

/* read identity fields from a template/skeleton for GUI autofill */
static int p4br_create_autofill(const char *tmpl,
                                char *label, int labsz, char *openpsid, int opsz,
                                char *user, int usz, char *host, int hsz)
{
    if (label && labsz) label[0] = 0;
    if (openpsid && opsz) openpsid[0] = 0;
    if (user && usz) user[0] = 0;
    if (host && hsz) host[0] = 0;
    char tdir[4096]; dir_of_archive(tmpl, tdir, sizeof tdir);
    uint8_t *s0=NULL, *s3=NULL; uint64_t l0=0, l3=0;
    int ok = 0;
    if (caf_read_seg(tdir, 1, &s0, &l0, NULL, NULL) == 0 && s0) {
        if (label && labsz && l0 >= 0x80) { snprintf(label, labsz, "%.*s", 0x77, (char*)s0 + 0x80); }
        if (openpsid && opsz >= 33 && l0 >= 0x28) {
            for (int i=0;i<16;i++) snprintf(openpsid + i*2, 3, "%02x", s0[0x18+i]);
        }
        ok = 1;
    }
    if (caf_read_seg(tdir, 4, &s3, &l3, NULL, NULL) == 0 && s3 && l3 == RG_BLOB) {
        rg_reg R;
        if (rg_decode(s3, (uint32_t)l3, &R) == 0) {
            if (user && usz) rg_get_str(&R, RK_USER_NAME, user, usz);
            if (host && hsz) rg_get_str(&R, RK_HOSTNAME, host, hsz);
            rg_free(&R);
            ok = 1;
        }
    }
    free(s0); free(s3);
    return ok ? 0 : -1;
}

/* ===================== CLI ========================================== */
#ifndef P4BR_CREATE_GUI
int main(int argc, char **argv)
{
    p4br_create_opts J; memset(&J, 0, sizeof J);
    J.verify_after = 1;
    const char *source = NULL;
    static char setbuf[MAX_SETS][160];
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a,"-o")||!strcmp(a,"--out"))        { if(++i<argc) J.outdir=argv[i]; }
        else if (!strcmp(a,"-k")||!strcmp(a,"--key"))   { if(++i<argc) J.keyhex=argv[i]; }
        else if (!strcmp(a,"-H")||!strcmp(a,"--hash-key")) { if(++i<argc) J.hashhex=argv[i]; }
        else if (!strcmp(a,"-n")||!strcmp(a,"--name"))  { if(++i<argc) J.name=argv[i]; }
        else if (!strcmp(a,"-l")||!strcmp(a,"--label")) { if(++i<argc) J.label=argv[i]; }
        else if (!strcmp(a,"-t")||!strcmp(a,"--template")) { if(++i<argc) J.tmpl=argv[i]; }
        else if (!strcmp(a,"--set-user"))               { if(++i<argc) J.set_user=argv[i]; }
        else if (!strcmp(a,"--set-hostname"))           { if(++i<argc) J.set_host=argv[i]; }
        else if (!strcmp(a,"--openpsid"))               { if(++i<argc) J.openpsid=argv[i]; }
        else if (!strcmp(a,"--set"))                    { if(++i<argc && J.nsets<MAX_SETS){ strncpy(setbuf[J.nsets],argv[i],159); J.sets[J.nsets]=setbuf[J.nsets]; J.nsets++; } }
        else if (!strcmp(a,"--keyset"))                 { if(++i<argc) J.keyset=argv[i]; }
        else if (!strcmp(a,"--clone"))                  { J.clone = 1; }
        else if (!strcmp(a,"--make-skeleton"))          { J.make_skeleton = 1; }
        else if (!strcmp(a,"--verify")) {
            const char *v = (i+1 < argc) ? argv[i+1] : NULL;
            if (v && (!strcmp(v,"false")||!strcmp(v,"0")||!strcmp(v,"no")||!strcmp(v,"off")))  { J.verify_after = 0; i++; }
            else if (v && (!strcmp(v,"true")||!strcmp(v,"1")||!strcmp(v,"yes")||!strcmp(v,"on"))) { J.verify_after = 1; i++; }
            else J.verify_after = 1;
        }
        else if (a[0]=='-') { fprintf(stderr,"unknown option: %s\n",a); return 2; }
        else source = a;
    }
    J.source = source;
    if (!J.clone && !J.make_skeleton && !source) {
        fprintf(stderr,
        "usage: p4br_create <source_folder> [-o out] [-k hexkey] [-H hashkey]\n"
        "                   [-n name] [-l label] [--verify true|false]\n"
        "                   [-t template_archive.dat]\n"
        "                   [--set-user NAME] [--set-hostname NAME]\n"
        "                   [--openpsid 32HEX] [--set KEYIDHEX=STRING] ...\n"
        "                   [--keyset old|new]\n"
        "       p4br_create --clone -t template.dat -o out\n"
        "       p4br_create --make-skeleton <backup/archive.dat> [-o out/archive.dat]\n");
        return 2;
    }
    if (J.make_skeleton && !source) { fprintf(stderr,"--make-skeleton needs a backup archive.dat argument\n"); return 2; }
    return p4br_create_run(&J, NULL);
}
#endif
