/* create_bridge.c - compiles the portable creator core and exposes the barc_*
 * C API used by the Qt front-end. */
#define P4BR_CREATE_GUI 1
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#include "../p4br_create.c"
#include "bar_bridge.h"

int barc_create(const barc_opts *o, bar_log_fn log, bar_prog_fn prog,
                volatile int *cancel, void *ud)
{
    p4br_create_opts c;
    memset(&c, 0, sizeof c);
    c.source   = o->source;
    c.outdir   = o->outdir;
    c.name     = o->name;
    c.label    = o->label;
    c.keyhex   = o->keyhex;
    c.hashhex  = o->hashhex;
    c.tmpl     = o->tmpl;
    c.set_user = o->set_user;
    c.set_host = o->set_host;
    c.openpsid = o->openpsid;
    for (int i = 0; i < o->nsets && i < MAX_SETS; i++) c.sets[i] = o->sets[i];
    c.nsets    = o->nsets < MAX_SETS ? o->nsets : MAX_SETS;
    c.keyset   = o->keyset;
    c.verify_after = o->verify;
    c.clone        = o->clone;
    c.make_skeleton= o->make_skeleton;

    p4br_cbs cbs;
    cbs.log = log; cbs.progress = prog; cbs.cancel = cancel; cbs.ud = ud;
    return p4br_create_run(&c, &cbs);
}

int barc_autofill(const char *tmpl, char *label, int labsz, char *openpsid,
                  int opsz, char *user, int usz, char *host, int hsz)
{
    return p4br_create_autofill(tmpl, label, labsz, openpsid, opsz, user, usz, host, hsz);
}
