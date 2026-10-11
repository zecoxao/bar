/*
 * p4br_extract.c  --  PS4 "Back Up PS4" (SCECAF / P4BR) restore extractor.
 *
 * Portable C (Windows / Linux / macOS, incl. Apple Silicon). The crypto, HMAC
 * verification, segment/catalog parsing and payload math are unchanged from
 * the original native-Windows port; the Win32 file I/O, wide paths, FILETIME,
 * thread pool and AES-NI gating have been replaced by the portable layers in
 * bar_crypto.h / bar_platform.h.
 *
 * The extraction work is exposed as p4br_extract_run() so a GUI can drive it
 * with log / progress / cancel callbacks; the CLI main() (compiled unless
 * P4BR_EXTRACT_GUI is defined) just parses argv and calls it.
 *
 * Container layout and record formats are exactly as documented in
 * p4br_extract.py; see that file's header comment for the on-disk spec.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "bar_crypto.h"
#include "bar_platform.h"

#define MAX_SEG   0xFFFF0000ULL      /* per-archive split size            */
#define CHUNK     0x10000UL          /* file write chunk                  */
#define REC       0x458UL            /* catalog record size               */
#define BUFCAP    (1u << 20)         /* per-thread crypto window (mult 16) */

static const char CAF_MAGIC[8]  = { 'S','C','E','C','A','F',0,0 };
static const char P4BR_MAGIC[4] = { 'P','4','B','R' };
static const char *DEFAULT_KEY  = "101851B22B669178970C5459B3CB8D45";
static const char *DEFAULT_HASH_KEY =
    "184FBFBB6DC61433C7A5BD8259C1C21FFEC0ECBEC4319805EE0693869152EB52";

/* ===================== log / progress / cancel ======================= */
typedef struct {
    void (*log)(const char *line, void *ud);
    void (*progress)(long long done, long long total, void *ud);
    volatile int *cancel;        /* may be NULL */
    void *ud;
} p4br_cbs;

static p4br_cbs g_cbs;            /* active callbacks for this run */

static void p4br_log(const char *fmt, ...)
{
    char line[2048];
    va_list ap; va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (g_cbs.log) g_cbs.log(line, g_cbs.ud);
    else { fputs(line, stdout); fputc('\n', stdout); }
}

/* ===================== split-archive reader ========================== */
typedef struct {
    const char *dir;   /* UTF-8 backup directory (holds archive*.dat) */
    FILE *f;
    long long n;       /* currently-open archive index, -1 = none */
} archive_t;

static void archive_init(archive_t *a, const char *dir) { a->dir = dir; a->f = NULL; a->n = -1; }
static void archive_close(archive_t *a) { if (a->f) { fclose(a->f); a->f = NULL; } a->n = -1; }

static FILE *archive_open(const char *dir, long long n)
{
    char path[4096];
    if (n == 0) snprintf(path, sizeof path, "%s/archive.dat", dir);
    else        snprintf(path, sizeof path, "%s/archive%04lld.dat", dir, n);
    return bar_fopen(path, "rb");
}

/* read `size` bytes from global offset `off`; returns bytes actually read */
static uint64_t archive_read(archive_t *a, uint64_t off, uint64_t size, uint8_t *buf)
{
    uint8_t *p = buf;
    while (size > 0) {
        long long n = (long long)(off / MAX_SEG);
        uint64_t within = off % MAX_SEG;
        if (a->n != n) {
            if (a->f) fclose(a->f);
            a->f = archive_open(a->dir, n);
            a->n = n;
            if (!a->f) { a->n = -1; break; }
        }
        if (bar_fseek64(a->f, (long long)within, SEEK_SET) != 0) break;
        uint64_t want = MAX_SEG - within;
        if (want > size) want = size;
        size_t req = (size_t)(want > 0x40000000ULL ? 0x40000000ULL : want);
        size_t got = fread(p, 1, req, a->f);
        if (got == 0) break;
        p += got; off += got; size -= got;
    }
    return (uint64_t)(p - buf);
}

/* ===================== segment table / catalog ======================= */
typedef struct {
    uint64_t index, off, pad, algo, key_idx;
    uint8_t  seed[16];
    uint64_t nopad;
} segment_t;

typedef struct { char *path; uint64_t size; uint32_t mode; uint32_t mtime; } record_t;

static uint64_t rd_u64(const uint8_t *p){ uint64_t v; memcpy(&v,p,8); return v; }
static uint32_t rd_u32(const uint8_t *p){ uint32_t v; memcpy(&v,p,4); return v; }

/* decrypt plaintext sub-range [so, so+len) of a segment into out. */
static void seg_read_plain(archive_t *ar, const aes_ctx *c, const segment_t *seg,
                           uint64_t so, uint64_t len, uint8_t *out,
                           uint8_t *rbuf, uint8_t *pbuf)
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
            if (want > BUFCAP) want = BUFCAP;
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

/* ===================== payload reader ================================ */
typedef struct {
    archive_t      ar;
    const aes_ctx *c;
    const segment_t *segs;
    const uint64_t  *prefix;
    int   nseg, seg_start;
    uint8_t *rbuf, *pbuf;
} payload_t;

static int pr_locate(const payload_t *p, uint64_t pos)
{
    int lo = 0, hi = p->nseg - 1;
    while (lo < hi) { int mid = (lo + hi + 1) / 2; if (p->prefix[mid] <= pos) lo = mid; else hi = mid - 1; }
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

/* ===================== path / catalog helpers ======================== */
/* Build outdir-relative dest (UTF-8) for an absolute POSIX catalog path,
 * using '/' separators (portable). 0 ok, -1 if unsafe. */
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
        dst[w++] = '/';
        memcpy(dst + w, seg, sl);
        w += sl;
    }
    dst[w] = 0;
    return 0;
}

static void human(uint64_t n, char *out)
{
    const char *u[] = { "B","KB","MB","GB","TB","PB" };
    double d = (double)n; int i = 0;
    while (d >= 1024.0 && i < 5) { d /= 1024.0; i++; }
    sprintf(out, "%.1f%s", d, u[i]);
}

static record_t *parse_catalog(const uint8_t *blob, uint64_t blen, int *count)
{
    uint64_t nmax = blen / REC;
    record_t *recs = (record_t *)malloc((size_t)(nmax ? nmax : 1) * sizeof(record_t));
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
        char *path = (char *)malloc(pl + 1);
        memcpy(path, ps, pl); path[pl] = 0;
        recs[n].path = path; recs[n].size = size; recs[n].mode = mode; recs[n].mtime = mtime;
        n++;
    }
    *count = n;
    return recs;
}

/* ===================== filters ======================================= */
typedef struct { const char **inc; int ninc; const char **exc; int nexc; } filter_t;
static int starts_with(const char *s, const char *pre){ size_t l=strlen(pre); return strncmp(s,pre,l)==0; }
static int wanted(const filter_t *f, const char *path)
{
    if (f->ninc) { int any=0; for (int i=0;i<f->ninc;i++) if (starts_with(path,f->inc[i])){any=1;break;} if (!any) return 0; }
    for (int i=0;i<f->nexc;i++) if (starts_with(path,f->exc[i])) return 0;
    return 1;
}

/* ===================== worker threads ================================ */
static bar_atomic64 g_done, g_extracted, g_skipped;
static volatile int *g_cancel;   /* set from cbs->cancel; may be NULL */

typedef struct {
    const char     *dir;
    const aes_ctx  *c;
    const segment_t *segs;
    const uint64_t  *prefix;
    int    nseg, seg_start;
    const record_t *files;
    const uint64_t *cums;
    const filter_t *filt;
    const char     *outdir;
    int    from, to;
    uint64_t max_bytes;
    bar_atomic64 *finished;
} worker_t;

static int cancelled(void) { return g_cancel && *g_cancel; }

static void *worker_main(void *arg)
{
    worker_t *w = (worker_t *)arg;
    payload_t pr;
    archive_init(&pr.ar, w->dir);
    pr.c = w->c; pr.segs = w->segs; pr.prefix = w->prefix;
    pr.nseg = w->nseg; pr.seg_start = w->seg_start;
    pr.rbuf = (uint8_t *)bar_aligned_alloc(BUFCAP);
    pr.pbuf = (uint8_t *)bar_aligned_alloc(BUFCAP);
    uint8_t *fbuf = (uint8_t *)malloc(CHUNK);
    char dst[4096];

    for (int idx = w->from; idx < w->to; idx++) {
        if (cancelled()) break;
        if (w->max_bytes && BAR_LOAD64(&g_done) >= (long long)w->max_bytes) break;
        const record_t *rec = &w->files[idx];
        if (!wanted(w->filt, rec->path)) { BAR_INC64(&g_skipped); continue; }
        if (safe_join(w->outdir, rec->path, dst, sizeof dst) != 0) {
            p4br_log("  !! unsafe path skipped: %s", rec->path); continue;
        }
        bar_mkdirs_parent(dst);

        /* resume: a complete file already present is left alone */
        uint64_t cur;
        if (bar_file_size(dst, &cur) == 0 && cur == rec->size) {
            BAR_ADD64(&g_done, (long long)rec->size);
            BAR_INC64(&g_skipped);
            continue;
        }

        FILE *out = bar_fopen(dst, "wb");
        if (!out) { p4br_log("  !! cannot create: %s", rec->path); continue; }
        uint64_t pos = w->cums[idx];
        uint64_t remaining = rec->size;
        int ok = 1;
        while (remaining > 0) {
            if (cancelled()) { ok = 0; break; }
            uint64_t want = remaining < CHUNK ? remaining : CHUNK;
            uint64_t got = pr_read(&pr, pos, want, fbuf);
            if (got == 0) { p4br_log("  !! short read on %s", rec->path); ok = 0; break; }
            if (fwrite(fbuf, 1, (size_t)got, out) != got) {
                p4br_log("  !! write error on %s", rec->path); ok = 0; break;
            }
            pos += got; remaining -= got;
            BAR_ADD64(&g_done, (long long)got);
        }
        fclose(out);
        if (ok) { bar_set_mtime(dst, rec->mtime); BAR_INC64(&g_extracted); }
        else if (cancelled()) bar_remove(dst);
    }

    archive_close(&pr.ar);
    bar_aligned_free(pr.rbuf); bar_aligned_free(pr.pbuf); free(fbuf);
    BAR_INC64(w->finished);
    return NULL;
}

/* ===================== verify (header + segments) ==================== */
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

/* ===================== options + run ================================= */
typedef struct {
    const char *backup;          /* dir containing archive.dat (or archive.dat itself) */
    const char *outdir;
    const char *keyhex;          /* NULL -> default */
    const char *hashhex;         /* NULL -> default */
    const char **inc; int ninc;
    const char **exc; int nexc;
    int do_list;
    int verify;
    uint64_t max_bytes;
    int nthreads;
    const char *manifest;
} p4br_extract_opts;

/* derive the backup directory from a path that may be a dir or an archive.dat */
static void derive_dir(const char *in, char *out, size_t cap)
{
    if (bar_is_dir(in)) { snprintf(out, cap, "%s", in); return; }
    /* strip trailing filename */
    snprintf(out, cap, "%s", in);
    for (long i = (long)strlen(out) - 1; i >= 0; i--)
        if (out[i] == '/' || out[i] == '\\') { out[i] = 0; return; }
    snprintf(out, cap, ".");
}

static int p4br_extract_run(const p4br_extract_opts *o, const p4br_cbs *cbs)
{
    g_cbs = cbs ? *cbs : (p4br_cbs){0};
    g_cancel = cbs ? cbs->cancel : NULL;
    BAR_STORE64(&g_done, 0); BAR_STORE64(&g_extracted, 0); BAR_STORE64(&g_skipped, 0);

    const char *keyhex  = o->keyhex  ? o->keyhex  : DEFAULT_KEY;
    const char *hashhex = o->hashhex ? o->hashhex : DEFAULT_HASH_KEY;
    const char *outdir  = o->outdir  ? o->outdir  : "restore";

    uint8_t key[16];
    if (strlen(keyhex) != 32 || hex2bin(keyhex, key, 16) != 0) { p4br_log("key must be 16 bytes (32 hex chars)"); return 2; }
    uint8_t hkey[32];
    if (strlen(hashhex) != 64 || hex2bin(hashhex, hkey, 32) != 0) { p4br_log("hash key must be 32 bytes (64 hex chars)"); return 2; }

    detect_aesni();
    aes_ctx ctx; aes_setup(&ctx, key);

    char dir[4096]; derive_dir(o->backup, dir, sizeof dir);
    archive_t ar; archive_init(&ar, dir);

    uint8_t hdr[0x30];
    if (archive_read(&ar, 0, 0x30, hdr) != 0x30 || memcmp(hdr, CAF_MAGIC, 8) != 0) {
        p4br_log("not a SCECAF container (looked in %s)", dir); archive_close(&ar); return 1;
    }
    uint64_t version   = rd_u64(hdr + 0x08);
    uint64_t nseg      = rd_u64(hdr + 0x18);
    uint64_t file_size = rd_u64(hdr + 0x28);

    uint8_t *tbl = (uint8_t *)malloc((size_t)(0x40 * nseg));
    archive_read(&ar, 0x30, 0x40 * nseg, tbl);
    segment_t *segs = (segment_t *)malloc((size_t)nseg * sizeof(segment_t));
    for (uint64_t i = 0; i < nseg; i++) {
        const uint8_t *r = tbl + 0x40 * i;
        segs[i].index=rd_u64(r+0x00); segs[i].off=rd_u64(r+0x08); segs[i].pad=rd_u64(r+0x10);
        segs[i].algo=rd_u64(r+0x18); segs[i].key_idx=rd_u64(r+0x20);
        memcpy(segs[i].seed, r+0x28, 16); segs[i].nopad=rd_u64(r+0x38);
    }
    free(tbl);

    char hbuf[32]; human(file_size, hbuf);
    p4br_log("[+] SCECAF v%llu  segments=%llu  total=%s (0x%llx)%s",
             (unsigned long long)version, (unsigned long long)nseg, hbuf,
             (unsigned long long)file_size, g_aesni ? "  [AES-NI]" : "  [SW-AES]");

    uint8_t *rbuf = (uint8_t *)bar_aligned_alloc(BUFCAP);
    uint8_t *pbuf = (uint8_t *)bar_aligned_alloc(BUFCAP);

    uint8_t *p4 = (uint8_t *)malloc((size_t)segs[0].nopad);
    seg_read_plain(&ar, &ctx, &segs[0], 0, segs[0].nopad, p4, rbuf, pbuf);
    if (memcmp(p4, P4BR_MAGIC, 4) != 0) {
        p4br_log("decrypt failed: expected P4BR, got %02x%02x%02x%02x -- wrong key?",
                 p4[0],p4[1],p4[2],p4[3]);
        free(p4); free(segs); bar_aligned_free(rbuf); bar_aligned_free(pbuf); archive_close(&ar); return 1;
    }
    uint32_t ndirs = rd_u32(p4+0x10), nfiles = rd_u32(p4+0x14);
    char name[256]={0}, title[256]={0};
    strncpy(name,(char*)p4+0x34,255); strncpy(title,(char*)p4+0x80,255);
    p4br_log("[+] P4BR  '%s'  label='%s'  dirs=%u files=%u", name, title, ndirs, nfiles);
    free(p4);

    uint8_t *dblob = (uint8_t *)malloc((size_t)segs[1].nopad);
    seg_read_plain(&ar,&ctx,&segs[1],0,segs[1].nopad,dblob,rbuf,pbuf);
    uint8_t *fblob = (uint8_t *)malloc((size_t)segs[2].nopad);
    seg_read_plain(&ar,&ctx,&segs[2],0,segs[2].nopad,fblob,rbuf,pbuf);
    int ndir_rec, nfile_rec;
    record_t *dirs  = parse_catalog(dblob, segs[1].nopad, &ndir_rec);
    record_t *files = parse_catalog(fblob, segs[2].nopad, &nfile_rec);
    free(dblob); free(fblob);
    p4br_log("[+] catalog: %d dirs, %d files", ndir_rec, nfile_rec);

    uint64_t sum_files = 0; for (int i=0;i<nfile_rec;i++) sum_files += files[i].size;
    uint64_t data_from3 = 0; for (uint64_t i=3;i<nseg;i++) data_from3 += segs[i].nopad;
    int rc_err = 0;
    if (data_from3 < sum_files) { p4br_log("catalog/segment size mismatch; refusing"); rc_err = 1; }
    uint64_t aux = rc_err ? 0 : data_from3 - sum_files;
    int seg_start = 3; uint64_t acc = 0;
    if (!rc_err) {
        while (seg_start < (int)nseg && acc + segs[seg_start].nopad <= aux) { acc += segs[seg_start].nopad; seg_start++; }
        if (acc != aux) { p4br_log("aux prefix 0x%llx not on segment boundary (acc=0x%llx)",
                          (unsigned long long)aux,(unsigned long long)acc); rc_err = 1; }
    }
    if (rc_err) {
        for (int i=0;i<ndir_rec;i++) free(dirs[i].path);
        for (int i=0;i<nfile_rec;i++) free(files[i].path);
        free(dirs); free(files); free(segs);
        bar_aligned_free(rbuf); bar_aligned_free(pbuf); archive_close(&ar); return 1;
    }
    human(aux, hbuf);
    p4br_log("[+] payload begins at segment index %d (aux metadata = %s)", seg_start, hbuf);

    int npseg = (int)nseg - seg_start;
    uint64_t *prefix = (uint64_t *)malloc((size_t)(npseg + 1) * sizeof(uint64_t));
    prefix[0] = 0;
    for (int i = 0; i < npseg; i++) prefix[i+1] = prefix[i] + segs[seg_start + i].nopad;
    uint64_t pr_total = prefix[npseg];

    uint64_t *cums = (uint64_t *)malloc((size_t)nfile_rec * sizeof(uint64_t));
    uint64_t cum = 0; for (int i=0;i<nfile_rec;i++){ cums[i]=cum; cum+=files[i].size; }
    if (cum != pr_total)
        p4br_log("[!] warning: catalog payload 0x%llx != segment payload 0x%llx",
                 (unsigned long long)cum, (unsigned long long)pr_total);

    if (o->verify && !o->do_list) {
        hmac256_t base; hmac256_init(&base, hkey, 32);
        uint64_t hsize = 0x30 + 0x40*nseg + 0x30*nseg;
        uint64_t sig_base = 0x30 + 0x40*nseg;
        uint8_t calc[32], want[32];
        archive_read(&ar, hsize, 0x20, want);
        hmac_header(&ar, &base, hsize, rbuf, calc);
        int hdr_ok = (memcmp(calc, want, 32) == 0);
        p4br_log("[+] HMAC header signature: %s", hdr_ok ? "OK" : "MISMATCH");
        int bad=0, empty=0, checked=0;
        for (uint64_t i=0;i<nseg && !cancelled();i++) {
            if (segs[i].nopad == 0) { empty++; continue; }
            uint8_t sig[48];
            archive_read(&ar, sig_base + 48*i, 48, sig);
            hmac_segment_ct(&ar, &base, &segs[i], rbuf, calc);
            checked++;
            if (memcmp(calc, sig+8, 32) != 0) {
                bad++;
                char lbuf[300]; const char *label = "?";
                if ((int)i < seg_start) { const char *names[3]={"P4BR header","dir catalog","file catalog"}; label=(i<3)?names[i]:"aux metadata"; }
                else {
                    uint64_t p0 = prefix[i-(uint64_t)seg_start], p1 = p0 + segs[i].nopad;
                    int first=-1, hits=0;
                    for (int f=0; f<nfile_rec; f++){ uint64_t a0=cums[f],a1=cums[f]+files[f].size; if (a0<p1 && a1>p0){ if(first<0)first=f; hits++; } }
                    if (first>=0){ if (hits>1){ snprintf(lbuf,sizeof lbuf,"%s (+%d more)",files[first].path,hits-1); label=lbuf; } else label=files[first].path; }
                }
                p4br_log("  BAD  seg[%llu] index=%llu nopad=0x%llx -> %s",
                         (unsigned long long)i,(unsigned long long)segs[i].index,(unsigned long long)segs[i].nopad,label);
            }
        }
        p4br_log("[+] segment HMAC: %d/%d OK, %d bad, %d empty (placeholder)", checked-bad, checked, bad, empty);
        p4br_log("%s", (hdr_ok && !bad) ? "[+] verification PASSED"
                                        : "[!] verification FAILED -- extracting anyway (data may be corrupt)");
    }

    filter_t filt = { o->inc, o->ninc, o->exc, o->nexc };

    if (o->manifest) {
        FILE *mf = bar_fopen(o->manifest, "w");
        if (mf) {
            fputs("path\tsize\tmode\tmtime\n", mf);
            for (int i=0;i<nfile_rec;i++)
                fprintf(mf,"%s\t%llu\t%o\t%u\n",files[i].path,(unsigned long long)files[i].size,files[i].mode,files[i].mtime);
            fclose(mf);
            p4br_log("[+] manifest written: %s", o->manifest);
        }
    }

    if (o->do_list) {
        for (int i=0;i<nfile_rec;i++)
            if (wanted(&filt, files[i].path))
                p4br_log("  %06o %12llu %s", files[i].mode,(unsigned long long)files[i].size,files[i].path);
        for (int i=0;i<ndir_rec;i++) free(dirs[i].path);
        for (int i=0;i<nfile_rec;i++) free(files[i].path);
        free(dirs); free(files); free(segs); free(prefix); free(cums);
        bar_aligned_free(rbuf); bar_aligned_free(pbuf); archive_close(&ar);
        return 0;
    }

    /* pre-create directories */
    char djoin[4096];
    for (int i=0;i<ndir_rec;i++) if (wanted(&filt,dirs[i].path) && safe_join(outdir,dirs[i].path,djoin,sizeof djoin)==0) bar_mkdirs(djoin);
    for (int i=0;i<nfile_rec;i++) if (wanted(&filt,files[i].path) && safe_join(outdir,files[i].path,djoin,sizeof djoin)==0) bar_mkdirs_parent(djoin);
    bar_mkdirs(outdir);

    int last_wanted=-1; uint64_t sel_total=0;
    for (int i=0;i<nfile_rec;i++) if (wanted(&filt,files[i].path)){ last_wanted=i; sel_total+=files[i].size; }
    if (last_wanted < 0) {
        p4br_log("[!] nothing matches the include/exclude filters");
        for (int i=0;i<ndir_rec;i++) free(dirs[i].path);
        for (int i=0;i<nfile_rec;i++) free(files[i].path);
        free(dirs); free(files); free(segs); free(prefix); free(cums);
        bar_aligned_free(rbuf); bar_aligned_free(pbuf); archive_close(&ar);
        return 0;
    }

    int nthreads = o->nthreads;
    if (nthreads <= 0) { nthreads = bar_cpu_count(); if (nthreads<1) nthreads=1; if (nthreads>32) nthreads=32; }
    int lim = last_wanted + 1;
    if (nthreads > lim) nthreads = lim ? lim : 1;

    human(sel_total, hbuf);
    p4br_log("[+] extracting %s selected payload with %d threads to %s", hbuf, nthreads, outdir);

    worker_t *wk = (worker_t *)calloc((size_t)nthreads, sizeof(worker_t));
    bar_thread *th = (bar_thread *)calloc((size_t)nthreads, sizeof(bar_thread));
    bar_atomic64 finished; BAR_STORE64(&finished, 0);
    uint64_t per = sel_total / (uint64_t)nthreads;
    int t=0, start=0; uint64_t acc_b=0;
    for (int i=0;i<lim && t<nthreads;i++) {
        if (wanted(&filt,files[i].path)) acc_b += files[i].size;
        int last_thread = (t == nthreads-1);
        if (!last_thread && acc_b >= per*(uint64_t)(t+1) && i+1<lim) { wk[t].from=start; wk[t].to=i+1; start=i+1; t++; }
    }
    wk[t].from=start; wk[t].to=lim; t++;
    int actual = t;

    double t0 = bar_monotonic();
    for (int i=0;i<actual;i++) {
        wk[i].dir=dir; wk[i].c=&ctx; wk[i].segs=segs; wk[i].prefix=prefix;
        wk[i].nseg=npseg; wk[i].seg_start=seg_start; wk[i].files=files; wk[i].cums=cums;
        wk[i].filt=&filt; wk[i].outdir=outdir; wk[i].max_bytes=o->max_bytes; wk[i].finished=&finished;
        bar_thread_create(&th[i], worker_main, &wk[i]);
    }

    /* progress loop */
    while (BAR_LOAD64(&finished) < actual) {
        bar_sleep_ms(400);
        long long done = BAR_LOAD64(&g_done);
        if (g_cbs.progress) g_cbs.progress(done, (long long)sel_total, g_cbs.ud);
        else {
            double el = bar_monotonic() - t0;
            char hb1[32],hb2[32],hr[32];
            human((uint64_t)done,hb1); human(sel_total,hb2);
            human((uint64_t)(done/(el>1e-6?el:1e-6)),hr);
            printf("\r  %s/%s @ %s/s  (%llds)      ", hb1,hb2,hr,(long long)el); fflush(stdout);
        }
    }
    for (int i=0;i<actual;i++) bar_thread_join(&th[i]);
    if (!g_cbs.progress) printf("\n");

    double el = bar_monotonic() - t0;
    char hb3[32]; human((uint64_t)BAR_LOAD64(&g_done), hb3);
    p4br_log("[+] done: %lld extracted, %lld skipped, %s written in %.0fs -> %s",
             (long long)BAR_LOAD64(&g_extracted), (long long)BAR_LOAD64(&g_skipped), hb3, el, outdir);

    for (int i=0;i<ndir_rec;i++) free(dirs[i].path);
    for (int i=0;i<nfile_rec;i++) free(files[i].path);
    free(dirs); free(files); free(segs); free(prefix); free(cums);
    free(wk); free(th);
    bar_aligned_free(rbuf); bar_aligned_free(pbuf); archive_close(&ar);
    return cancelled() ? 1 : 0;
}

/* ===================== CLI ========================================== */
#ifndef P4BR_EXTRACT_GUI
int main(int argc, char **argv)
{
    p4br_extract_opts o; memset(&o, 0, sizeof o);
    o.outdir = "restore"; o.verify = 1;
    const char *inc[64]; const char *exc[64];
    o.inc = inc; o.exc = exc;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a,"-o")||!strcmp(a,"--out"))        o.outdir = argv[++i];
        else if (!strcmp(a,"-k")||!strcmp(a,"--key"))   o.keyhex = argv[++i];
        else if (!strcmp(a,"-H")||!strcmp(a,"--hash-key")) o.hashhex = argv[++i];
        else if (!strcmp(a,"--include"))                { if (o.ninc<64) inc[o.ninc++]=argv[++i]; else i++; }
        else if (!strcmp(a,"--exclude"))                { if (o.nexc<64) exc[o.nexc++]=argv[++i]; else i++; }
        else if (!strcmp(a,"--list"))                   o.do_list = 1;
        else if (!strcmp(a,"--manifest"))               o.manifest = argv[++i];
        else if (!strcmp(a,"--max-bytes"))              o.max_bytes = strtoull(argv[++i],NULL,0);
        else if (!strcmp(a,"-j")||!strcmp(a,"--threads")) o.nthreads = atoi(argv[++i]);
        else if (!strcmp(a,"--verify")) {
            const char *v = (i+1 < argc) ? argv[i+1] : NULL;
            if (v && (!strcmp(v,"false")||!strcmp(v,"0")||!strcmp(v,"no")||!strcmp(v,"off")))  { o.verify = 0; i++; }
            else if (v && (!strcmp(v,"true")||!strcmp(v,"1")||!strcmp(v,"yes")||!strcmp(v,"on"))) { o.verify = 1; i++; }
            else o.verify = 1;
        }
        else if (a[0]=='-') { fprintf(stderr,"unknown option: %s\n",a); return 2; }
        else o.backup = a;
    }
    if (!o.backup) {
        fprintf(stderr,
        "usage: p4br_extract <backup_dir> [-o out] [-k hexkey] [-H hashkey]\n"
        "                    [--include P]... [--exclude P]... [--list]\n"
        "                    [--verify true|false] [--manifest F] [--max-bytes N] [-j threads]\n"
        "\n"
        "HMAC-SHA256 verification of the header and every segment runs before\n"
        "extraction by default (obligatory); disable it with --verify false.\n");
        return 2;
    }
    return p4br_extract_run(&o, NULL);
}
#endif
