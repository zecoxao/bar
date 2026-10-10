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

* **Without `-t`**: packs the folder into a valid SCECAF/P4BR container that
  round-trips through `p4br_extract` (no aux — not PS4-restorable).
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
