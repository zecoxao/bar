# bar — PS4 "Back Up PS4" (SCECAF / P4BR) tools

Extract **and create** PS4 USB backups (`archive.dat [+ archiveNNNN.dat ...]`),
in C (with a Win32 GUI) and Python.

A PS4 backup is a **SCECAF** container wrapping a file-level **P4BR** archive
(not a disk image): a header + segment table, AES-128-CBC segment encryption
(with a ciphertext-stealing tail) and HMAC-SHA256 per-segment / header
signatures. Decrypted segment order:

```
seg0  P4BR header (names, dir/file counts, OpenPSID, hardware, version)
seg1  directory records (0x458 each)
seg2  file records      (0x458 each)
seg3  system registry   (0x64600)   ] aux metadata
seg4  reboot data                   ]
seg5  sparse count                  ]
seg6+ file payload, one segment per file, tight-packed in catalog order
```

## Tools

| file | what it does |
|------|--------------|
| `p4br_extract.c` / `.exe` | CLI extractor (HMAC-verify, `--list`, include/exclude, manifest) |
| `p4br_extract_gui.c`      | same, Win32 GUI |
| `p4br_extract.py`         | Python extractor |
| `p4br_create_gui.c` / `.exe` | **creator** (CLI + GUI): folder → restorable-shaped backup |
| `seg3_codec.py`           | standalone seg3 **registry** codec (decode + encode) + validator |

## seg3 = the PS4 system registry

seg3 is the output of the kernel registry backup (`sceRegMgrBackupPullData`,
regmgr syscall). It was fully reverse-engineered from the kernel: the 0x64600
blob is a plaintext registry (header + a 16-byte descriptor per key + a
value/data area + padding) transformed by a **deterministic** XOR obfuscation
and custom checksums with **no per-console or SAMU secret**. `seg3_codec.py`
reproduces it **byte-for-byte** (verified against real 5.05 and 9.x backups),
so registry values can be decoded, edited and re-encoded offline.

## Creating a backup

```
p4br_create <source_folder> [-o out] [-n name] [-l label] [--verify true|false]
            [-t template_archive.dat]
            [--set-user NAME] [--set-hostname NAME]
            [--openpsid 32HEX] [--set KEYIDHEX=STRING] ...
p4br_create            (no args → GUI)
```

### Files-only (recommended): capture a skeleton once

A backup's `seg3` is the **whole PS4 registry**, `seg0` holds the registered
**accounts** / **OpenPSID**, and `seg4` is reboot-state — all live console
state that isn't in firmware. Capture it **once** from any real backup of your
console, then create backups from **just the files**:

```
p4br_create --make-skeleton  "X:\PS4\EXPORT\BACKUP\…\archive.dat"
            -> writes  <exe dir>\p4br_skeleton\archive.dat

p4br_create  ./my_files  -o ./out  --set-user NAME --set-hostname NAME
            -> uses the bundled skeleton automatically; no template needed
```

In the GUI: click **Make skeleton from a backup…** once, then just pick a
**Source** folder and **Create** (identity fields auto-fill from the skeleton
and stay editable). The output keeps the skeleton console's OpenPSID /
hardware, so it restores to that console.

### What the Source must be

The **Source** is the **file tree** to back up — a folder holding `user/`
and/or `system_data/` subfolders. It is **not** a backup folder and **not** an
`archive.dat`. As a convenience, if you *do* point it at a backup (a folder
containing `archive.dat`, or an `archive.dat` itself), the tool detects it and
**auto-extracts that backup's real file tree first**, then rebuilds from it — so
re-packing a backup reproduces its exact catalog instead of packing one bogus
`/archive.dat`. To edit files, extract a backup (`p4br_extract <backup> -o work`),
change files under `work/user/` or `work/system_data/`, then Source = `work`.

Catalog **order** matters: when a template or the bundled skeleton is present,
dirs/files are emitted in the template's exact catalog order (payloads follow
file order), and new files you added are appended last. A re-pack of an
unchanged backup then comes out **plaintext-identical** to the original
(only the per-segment IVs differ), i.e. structurally a known-good backup.

### Explicit template / no aux

* **Without `-t` and no skeleton**: packs the folder into a valid SCECAF/P4BR
  container that round-trips through `p4br_extract` (no aux — not restorable).
* **With `-t <template archive.dat>`**: also writes the aux segments. seg3
  (registry), seg4 and seg5 are taken from the template, and the P4BR header
  (OpenPSID / hardware / version / GUID) is kept from it, producing a
  **restorable-shaped** backup. The registry in seg3 is decoded, your overrides
  are applied, and it is re-encoded:
  * `--set-user NAME`      → local user name  (registry key `0x07800200`)
  * `--set-hostname NAME`  → console name     (`0x02050000`)
  * `--openpsid 32HEX`     → P4BR header + registry header OpenPSID
  * `--set KEYIDHEX=STRING`→ any string registry key (repeatable)

> A real PS4 restore validates **OpenPSID**, so the template's registry /
> OpenPSID must match the **target** console. Make the template on that console,
> or override with `--openpsid`. Value sizes are fixed by the registry schema
> (a string can't exceed its key's slot size).
>
> The output is sealed with the **same keyset as the template** (auto-detected).
> A console can only validate its own keyset — e.g. a 5.05 unit uses the OLD
> keyset, and a mismatched keyset restores as **DATA_CORRUPTED (CE-33310-0 /
> 0x81300203)**. Force it with `--keyset old|new` if needed.

Example:

```
p4br_create ./my_user_tree -o ./out -t /path/CONSOLE/archive.dat \
    --set-user Alice --set-hostname PS4-ALICE
```

## Build

```
# extractor / creator, native Win32 .exe (mingw-w64)
gcc -O3 -maes -msse4.1 p4br_extract.c     -o p4br_extract.exe
gcc -O3 -maes -msse4.1 -mwindows p4br_create_gui.c -o p4br_create_gui.exe \
    -lshell32 -lole32 -luuid -lgdi32 -lcomdlg32
# (console build: drop -mwindows)
```

Python tools need `pycryptodome` (`py -m pip install pycryptodome`), e.g.
`python seg3_codec.py <archive.dat>` runs a decode→encode round-trip self-check.

## Keys

The AES cipher key and the HMAC key are built into the C sources and the Python
scripts (new and old keysets); pass `-k` / `-H` to override. They are not listed
here.
