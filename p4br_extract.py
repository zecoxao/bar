#!/usr/bin/env python3
"""
p4br_extract.py  --  PS4 "Back Up PS4" (SCECAF / P4BR) restore extractor.

Port of BAR-master (bar.c) for the 202610021241_00 style USB backup, updated
for the new SBL BAR cipher key and taught to reconstruct the real directory
tree (user/ and system_data/) instead of dumping opaque per-segment blobs.

Container layout (reverse-engineered & verified against this backup):

  archive.dat, archive0001.dat ...   split at MAX_SEG (0xFFFF0000) bytes each
  +--------------------------------------------------------------------------+
  | SCECAF header (0x30)                                                      |
  | segment table : num_segments * 0x40                                      |
  | (optional) per-segment HMAC-SHA256 signatures (skipped - may be bad)     |
  | segment data @ file_offset, each AES-128-CBC with its own cipher_seed IV |
  +--------------------------------------------------------------------------+

  Decrypted segment stream (segments concatenated, nopad bytes, table order):

    seg0  : "P4BR" header (console/backup name, user list, total size)
    seg1  : N_dirs  directory records  (0x458 bytes each)
    seg2  : N_files file      records  (0x458 bytes each)
    seg3..5: auxiliary metadata (not referenced by the file catalog)
    seg6..: file payload, tight-packed, in catalog order

  Catalog record (0x458 bytes):
    +0x00 u32 ctime      +0x10 u32 mtime   +0x20 u32 atime
    +0x30 u64 size       +0x50 u32 mode (octal unix; 0x4xxx dir, 0x8xxx file)
    +0x54 char path[]    (NUL-terminated, absolute, e.g. /user/home/..)

Everything after seg6 is the payload region, addressed by the cumulative sum
of the file sizes from the file catalog.
"""
import os, sys, struct, argparse, time
from Crypto.Cipher import AES

MAX_SEG   = 4294901760          # 0xFFFF0000  per-archive split size
CHUNK     = 0x10000             # streaming chunk / segment padding unit
REC       = 0x458               # catalog record size
CAF_MAGIC = b"SCECAF\x00\x00"
P4BR_MAGIC= b"P4BR"

# --- NEW SBL BAR cipher key (replaces the old 79c8ccc8... key in bar.c) ---
DEFAULT_KEY = "101851B22B669178970C5459B3CB8D45"

# HMAC-SHA256 key for the per-segment / header signatures (new keyset).
DEFAULT_HASH_KEY = "184FBFBB6DC61433C7A5BD8259C1C21FFEC0ECBEC4319805EE0693869152EB52"


class Archive:
    """Random-access reader over the split archive*.dat files."""
    def __init__(self, bkdir):
        self.dir = bkdir
        self._cache_n = -1
        self._cache_f = None

    def _path(self, n):
        return os.path.join(self.dir, "archive.dat" if n == 0 else f"archive{n:04d}.dat")

    def _f(self, n):
        if n != self._cache_n:
            if self._cache_f:
                self._cache_f.close()
            self._cache_f = open(self._path(n), "rb")
            self._cache_n = n
        return self._cache_f

    def read(self, off, size):
        out = bytearray()
        while size > 0:
            n = off // MAX_SEG
            within = off % MAX_SEG
            f = self._f(n)
            f.seek(within)
            d = f.read(min(size, MAX_SEG - within))
            if not d:
                break
            out += d
            off += len(d)
            size -= len(d)
        return bytes(out)

    def close(self):
        if self._cache_f:
            self._cache_f.close()
            self._cache_f = None
            self._cache_n = -1


def cbc_dec(key, iv, data):
    """flatz's algo from bar.c: AES-128-CBC; final partial block via
    keystream = AES_ENC(previous ciphertext block) (ciphertext stealing tail)."""
    n = len(data)
    full = n - (n % 16)
    out = bytearray()
    if full:
        out += AES.new(key, AES.MODE_CBC, iv).decrypt(data[:full])
    r = n - full
    if r:
        prev = data[full - 16:full] if full >= 16 else iv
        ks = AES.new(key, AES.MODE_ECB).encrypt(prev)
        out += bytes(data[full + i] ^ ks[i] for i in range(r))
    return bytes(out)


class Segment:
    __slots__ = ("index", "off", "pad", "algo", "key_idx", "seed", "nopad")
    def __init__(self, raw):
        (self.index, self.off, self.pad, self.algo, self.key_idx) = struct.unpack("<QQQQQ", raw[:40])
        self.seed = raw[40:56]
        self.nopad = struct.unpack("<Q", raw[56:64])[0]


def parse_container(ar):
    hdr = ar.read(0, 0x30)
    if hdr[:8] != CAF_MAGIC:
        sys.exit(f"not a SCECAF container (magic={hdr[:8]!r})")
    magic, version, hasher_key_index, num_segments, file_offset, file_size = struct.unpack("<8sQQQQQ", hdr)
    tbl = ar.read(0x30, 0x40 * num_segments)
    segs = [Segment(tbl[0x40 * i:0x40 * i + 0x40]) for i in range(num_segments)]
    return dict(version=version, num_segments=num_segments, file_offset=file_offset,
                file_size=file_size, segs=segs)


def decrypt_segment(ar, key, seg):
    return cbc_dec(key, seg.seed, ar.read(seg.off, seg.nopad))


def read_segment_signatures(ar, num_segments):
    """Per-segment HMAC-SHA256 signatures follow the segment table.
    Layout caf_segment_signature_t: u64 index, u8 sig[0x20], u64 pad (48 bytes)."""
    base = 0x30 + 0x40 * num_segments
    raw = ar.read(base, 48 * num_segments)
    sigs = []
    for i in range(num_segments):
        e = raw[48 * i:48 * i + 48]
        sigs.append(e[8:40])
    return sigs


def parse_catalog(blob):
    """Return list of (path, size, mode, mtime) from a records blob."""
    recs = []
    for i in range(len(blob) // REC):
        r = blob[i * REC:(i + 1) * REC]
        size  = struct.unpack("<Q", r[0x30:0x38])[0]
        mode  = struct.unpack("<I", r[0x50:0x54])[0]
        mtime = struct.unpack("<I", r[0x10:0x14])[0]
        path  = r[0x54:].split(b"\x00")[0].decode("latin1", "replace")
        if mode == 0 and not path:
            break
        recs.append((path, size, mode, mtime))
    return recs


class PayloadReader:
    """Random-access reader over the decrypted payload region.

    The payload is the concatenation of segs[seg_start:] nopad plaintext.
    read(pos,n) decrypts only the segment(s) covering [pos,pos+n); skipping a
    region costs nothing because nothing is decrypted for bytes never read.
    A one-segment plaintext cache keeps sequential reads fast."""
    def __init__(self, ar, key, segs, seg_start):
        self.ar, self.key = ar, key
        self.segs = segs[seg_start:]
        # prefix[i] = payload offset at start of self.segs[i]
        self.prefix = [0]
        for s in self.segs:
            self.prefix.append(self.prefix[-1] + s.nopad)
        self.total = self.prefix[-1]
        self._ci = -1          # cached segment index
        self._cbuf = b""

    def _seg_plain(self, i):
        if i != self._ci:
            self._cbuf = decrypt_segment(self.ar, self.key, self.segs[i])
            self._ci = i
        return self._cbuf

    def _locate(self, pos):
        # binary search: largest i with prefix[i] <= pos
        lo, hi = 0, len(self.segs) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.prefix[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo

    def read(self, pos, n):
        out = bytearray()
        i = self._locate(pos)
        while n > 0 and i < len(self.segs):
            seg_off = pos - self.prefix[i]
            plain = self._seg_plain(i)
            take = min(n, len(plain) - seg_off)
            if take <= 0:
                i += 1
                continue
            out += plain[seg_off:seg_off + take]
            pos += take
            n -= take
            i += 1
        return bytes(out)


def safe_join(outdir, path):
    # path is absolute POSIX like /user/home/..  -> join under outdir, block traversal
    rel = path.lstrip("/")
    parts = []
    for p in rel.split("/"):
        if p in ("", "."):
            continue
        if p == "..":
            return None
        parts.append(p)
    dest = os.path.join(outdir, *parts)
    if not os.path.abspath(dest).startswith(os.path.abspath(outdir)):
        return None
    return dest


def human(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}PB"


def main():
    ap = argparse.ArgumentParser(description="Extract a PS4 SCECAF/P4BR USB backup.")
    ap.add_argument("backup", help="path to backup folder containing archive.dat")
    ap.add_argument("-o", "--out", default="restore", help="output directory (default: ./restore)")
    ap.add_argument("-k", "--key", default=DEFAULT_KEY, help="AES-128 cipher key (hex)")
    ap.add_argument("-H", "--hash-key", default=DEFAULT_HASH_KEY, help="HMAC-SHA256 hash key (hex)")
    ap.add_argument("--include", action="append", default=[],
                    help="only extract paths starting with this prefix (repeatable), e.g. /system_data /user/home")
    ap.add_argument("--exclude", action="append", default=[],
                    help="skip paths starting with this prefix (repeatable), e.g. /user/app /user/patch")
    ap.add_argument("--list", action="store_true", help="list catalog only, extract nothing")
    ap.add_argument("--verify", action="store_true",
                    help="check every segment's HMAC-SHA256 and report bad (corrupt) segments "
                         "and the files they affect; extracts nothing")
    ap.add_argument("--manifest", help="write a TSV manifest (path, size, mode, mtime) to this file")
    ap.add_argument("--max-bytes", type=int, default=0,
                    help="stop after extracting approximately this many payload bytes (0 = no limit)")
    args = ap.parse_args()

    key = bytes.fromhex(args.key)
    if len(key) != 16:
        sys.exit("key must be 16 bytes (AES-128)")

    ar = Archive(args.backup)
    meta = parse_container(ar)
    segs = meta["segs"]
    print(f"[+] SCECAF v{meta['version']}  segments={meta['num_segments']}  "
          f"total={human(meta['file_size'])} ({meta['file_size']:#x})")

    # seg0 P4BR header
    p4 = decrypt_segment(ar, key, segs[0])
    if p4[:4] != P4BR_MAGIC:
        sys.exit(f"decrypt failed: expected P4BR, got {p4[:4]!r} -- wrong key?")
    ndirs  = struct.unpack("<I", p4[0x10:0x14])[0]
    nfiles = struct.unpack("<I", p4[0x14:0x18])[0]
    name   = p4[0x34:].split(b"\x00")[0].decode("latin1", "replace")
    title  = p4[0x80:].split(b"\x00")[0].decode("latin1", "replace")
    print(f"[+] P4BR  '{name}'  label='{title}'  dirs={ndirs} files={nfiles}")

    dir_blob  = decrypt_segment(ar, key, segs[1])
    file_blob = decrypt_segment(ar, key, segs[2])
    dirs  = parse_catalog(dir_blob)
    files = parse_catalog(file_blob)
    print(f"[+] catalog: {len(dirs)} dirs, {len(files)} files")

    # payload starts at the segment AFTER (P4BR + dir + file + aux) sections.
    # aux prefix bytes = sum(nopad[3:]) - sum(file sizes). Advance seg index past it.
    sum_files = sum(f[1] for f in files)
    data_nopad_from3 = sum(s.nopad for s in segs[3:])
    aux = data_nopad_from3 - sum_files
    if aux < 0:
        sys.exit(f"catalog/segment size mismatch (aux={aux}); refusing to extract")
    seg_start = 3
    acc = 0
    while seg_start < len(segs) and acc + segs[seg_start].nopad <= aux:
        acc += segs[seg_start].nopad
        seg_start += 1
    if acc != aux:
        sys.exit(f"aux prefix {aux:#x} not on a segment boundary (acc={acc:#x}) -- unexpected layout")
    print(f"[+] payload begins at segment index {seg_start} (aux metadata = {human(aux)})")

    if args.manifest:
        with open(args.manifest, "w", encoding="utf-8") as mf:
            mf.write("path\tsize\tmode\tmtime\n")
            for p, s, m, t in files:
                mf.write(f"{p}\t{s}\t{m:o}\t{t}\n")
        print(f"[+] manifest written: {args.manifest}")

    def wanted(path):
        if args.include and not any(path.startswith(x) for x in args.include):
            return False
        if any(path.startswith(x) for x in args.exclude):
            return False
        return True

    # roots summary
    roots = {}
    for p, s, m, t in files:
        top = p.strip("/").split("/")[0] if p.strip("/") else "?"
        roots.setdefault(top, [0, 0])
        roots[top][0] += 1
        roots[top][1] += s
    print("[+] roots: " + ", ".join(f"{k}({v[0]} files, {human(v[1])})" for k, v in sorted(roots.items())))

    if args.list:
        for p, s, m, t in files:
            if wanted(p):
                print(f"  {m:06o} {s:>12} {p}")
        ar.close()
        return

    if args.verify:
        import hmac, hashlib
        hkey = bytes.fromhex(args.hash_key)
        if len(hkey) != 32:
            sys.exit("hash key must be 32 bytes (AES/HMAC-SHA256)")
        ns = meta["num_segments"]
        sigs = read_segment_signatures(ar, ns)

        # header signature: HMAC-SHA256 over file[0:header_size], stored right after
        header_size = 0x30 + 0x40 * ns + 0x30 * ns
        stored = ar.read(header_size, 0x20)
        calc = hmac.new(hkey, ar.read(0, header_size), hashlib.sha256).digest()
        hdr_ok = (calc == stored)
        print(f"[+] HMAC header signature: {'OK' if hdr_ok else 'MISMATCH'}")

        # per-segment: HMAC-SHA256 over the raw ciphertext (nopad bytes)
        cum = 0
        franges = []
        for p, s, m, t in files:
            franges.append((cum, cum + s, p)); cum += s
        payload_base = sum(s.nopad for s in segs[:seg_start])
        bad = empty = checked = 0
        t0 = time.time()
        for i, seg in enumerate(segs):
            if seg.nopad == 0:
                empty += 1          # empty segment carries a constant placeholder sig
                continue
            ct = ar.read(seg.off, seg.nopad)
            checked += 1
            if hmac.new(hkey, ct, hashlib.sha256).digest() != sigs[i]:
                bad += 1
                if i >= seg_start:
                    p0 = sum(s.nopad for s in segs[seg_start:i])
                    hit = [fp for (a, b, fp) in franges if a < p0 + seg.nopad and b > p0]
                    label = (hit[0] + (f" (+{len(hit)-1} more)" if len(hit) > 1 else "")) if hit else "?"
                else:
                    label = ["P4BR header", "dir catalog", "file catalog"][i] if i < 3 else "aux metadata"
                print(f"  BAD  seg[{i}] index={seg.index} nopad={seg.nopad:#x} -> {label}")
        ar.close()
        print(f"[+] segment HMAC: {checked-bad}/{checked} OK, {bad} bad, {empty} empty (placeholder)")
        ok = hdr_ok and not bad
        print(f"[+] verification {'PASSED' if ok else 'FAILED'} in {time.time()-t0:.0f}s")
        sys.exit(0 if ok else 1)

    outdir = os.path.abspath(args.out)
    os.makedirs(outdir, exist_ok=True)

    # pre-create directories (so empty dirs also appear)
    for p, s, m, t in dirs:
        if not wanted(p):
            continue
        d = safe_join(outdir, p)
        if d:
            os.makedirs(d, exist_ok=True)

    pr = PayloadReader(ar, key, segs, seg_start)

    # cumulative payload offset of each file (catalog order = storage order)
    cum = 0
    cums = []
    for p, s, m, t in files:
        cums.append(cum)
        cum += s
    if cum != pr.total:
        print(f"[!] warning: catalog payload {cum:#x} != segment payload {pr.total:#x}")

    # stop after the last wanted file so selective runs don't walk the whole archive
    last_wanted = -1
    for i, (p, s, m, t) in enumerate(files):
        if wanted(p):
            last_wanted = i
    if last_wanted < 0:
        print("[!] nothing matches the include/exclude filters")
        ar.close()
        return

    done_bytes = 0
    extracted = skipped = 0
    t0 = time.time()
    tlast = t0
    sel_total = sum(s for p, s, m, t in files if wanted(p))
    print(f"[+] extracting {human(sel_total)} selected payload to {outdir}")

    for idx in range(last_wanted + 1):
        path, size, mode, mtime = files[idx]
        if not wanted(path):
            skipped += 1
            continue
        dest = safe_join(outdir, path)
        if dest is None:
            print(f"  !! unsafe path skipped: {path}")
            continue
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        # resume: a complete file already present is left alone
        if os.path.exists(dest) and os.path.getsize(dest) == size:
            done_bytes += size
            skipped += 1
            continue
        pos = cums[idx]
        with open(dest, "wb") as fo:
            remaining = size
            while remaining > 0:
                blk = pr.read(pos, min(CHUNK, remaining))
                if not blk:
                    print(f"  !! short read on {path} ({remaining} left)")
                    break
                fo.write(blk)
                pos += len(blk)
                remaining -= len(blk)
                done_bytes += len(blk)
        try:
            os.utime(dest, (mtime, mtime))
        except OSError:
            pass
        extracted += 1
        now = time.time()
        if now - tlast > 2 or done_bytes >= sel_total:
            rate = done_bytes / max(now - t0, 1e-6)
            print(f"  [{idx+1}/{len(files)}] {human(done_bytes)}/{human(sel_total)} "
                  f"@ {human(rate)}/s  {path}", flush=True)
            tlast = now
        if args.max_bytes and done_bytes >= args.max_bytes:
            print(f"[!] reached --max-bytes {human(args.max_bytes)}, stopping")
            break

    ar.close()
    print(f"[+] done: {extracted} extracted, {skipped} skipped, {human(done_bytes)} written "
          f"in {time.time()-t0:.0f}s -> {outdir}")


if __name__ == "__main__":
    main()
