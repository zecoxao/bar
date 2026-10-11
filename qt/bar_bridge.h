/* bar_bridge.h - clean C API the Qt front-end calls. extract_bridge.c and
 * create_bridge.c each compile one portable core (p4br_extract.c /
 * p4br_create.c) with its *_GUI macro and implement these wrappers. */
#ifndef BAR_BRIDGE_H
#define BAR_BRIDGE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*bar_log_fn)(const char *line, void *ud);
typedef void (*bar_prog_fn)(long long done, long long total, void *ud);

/* ---------------- extractor ---------------- */
typedef struct {
    const char *backup;          /* dir containing archive.dat (or the file) */
    const char *outdir;
    const char *keyhex;          /* "" / NULL -> default */
    const char *hashhex;
    const char *const *inc; int ninc;
    const char *const *exc; int nexc;
    const char *manifest;        /* "" / NULL -> none */
    int do_list;
    int verify;
    int nthreads;                /* 0 = auto */
} barx_opts;

int barx_extract(const barx_opts *o, bar_log_fn log, bar_prog_fn prog,
                 volatile int *cancel, void *ud);

/* ---------------- creator ------------------ */
typedef struct {
    const char *source;
    const char *outdir;
    const char *name;
    const char *label;
    const char *keyhex;
    const char *hashhex;
    const char *tmpl;
    const char *set_user;
    const char *set_host;
    const char *openpsid;
    const char *const *sets; int nsets;   /* "KEYIDHEX=STRING" */
    const char *keyset;          /* "old" | "new" | NULL */
    int verify;
    int clone;
    int make_skeleton;
} barc_opts;

int  barc_create(const barc_opts *o, bar_log_fn log, bar_prog_fn prog,
                 volatile int *cancel, void *ud);

/* fill identity fields from a template/skeleton (for the Create tab). 0 ok. */
int  barc_autofill(const char *tmpl, char *label, int labsz, char *openpsid,
                   int opsz, char *user, int usz, char *host, int hsz);

#ifdef __cplusplus
}
#endif
#endif
