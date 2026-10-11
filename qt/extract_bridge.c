/* extract_bridge.c - compiles the portable extractor core and exposes the
 * barx_* C API used by the Qt front-end. */
#define P4BR_EXTRACT_GUI 1
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#include "../p4br_extract.c"
#include "bar_bridge.h"

int barx_extract(const barx_opts *o, bar_log_fn log, bar_prog_fn prog,
                 volatile int *cancel, void *ud)
{
    p4br_extract_opts e;
    memset(&e, 0, sizeof e);
    e.backup   = o->backup;
    e.outdir   = (o->outdir && o->outdir[0]) ? o->outdir : "restore";
    e.keyhex   = (o->keyhex && o->keyhex[0]) ? o->keyhex : NULL;
    e.hashhex  = (o->hashhex && o->hashhex[0]) ? o->hashhex : NULL;
    e.inc      = o->inc; e.ninc = o->ninc;
    e.exc      = o->exc; e.nexc = o->nexc;
    e.manifest = (o->manifest && o->manifest[0]) ? o->manifest : NULL;
    e.do_list  = o->do_list;
    e.verify   = o->verify;
    e.nthreads = o->nthreads;

    p4br_cbs cbs;
    cbs.log = log; cbs.progress = prog; cbs.cancel = cancel; cbs.ud = ud;
    return p4br_extract_run(&e, &cbs);
}
