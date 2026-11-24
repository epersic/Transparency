# Transparency

A Windows app analyser for red-team recon: launch a target inside a sandboxed
job object, watch what it does, then turn the findings into attack surface —
which unsigned DLLs you can proxy, which PEs have code caves, and which data
files make good payload carriers.

Three capabilities, one run:

1. **Scan** — the full process tree, every loaded DLL, signature/RWX/cave
   analysis of every PE, and every file the tree touched (ETW).
2. **Proxy-DLL generation** — scaffold a proxy for any DLL the app loads,
   sized and styled to blend in, with your payload slot built in.
3. **Payload staging** — append an encrypted payload to a file the app
   already reads, and get an IAT-clean reader object to fetch it from your
   loader.

Python port of the original Go implementation (same layout).

## Quick start

```bash
python -m pip install -r requirements.txt

python childwatch.py                          # interactive menu
python childwatch.py -t C:\app\app.exe -w 15 -s shellcode.bin
```

Requires Python 3.10+ on Windows and the mingw-w64 cross toolchain
(`x86_64-w64-mingw32-gcc` / `i686-w64-mingw32-gcc` on PATH) for the
generated scaffolds. Run elevated — ETW file tracing needs it. Use a real
console (Windows Terminal / cmd / PowerShell); under mintty prefix with
`winpty` for the menu.

## Scanning

The target is created suspended, placed in a job object with
kill-on-close, then resumed. Every process that joins the job reports
through an I/O completion port — event-driven, so nothing is missed
between polls and no parent-PID spoofing helps. At the end of the watch
window each live process's modules are snapshotted.

Report sections (default: indicators + caves + files; tree/modules with
`-v`; or exactly what you name with the section flags):

| Section | What it shows |
|---|---|
| `--tree` | observed process tree |
| `--modules` | DLLs loaded by each process |
| `--unsigned` | PEs with no valid Authenticode signature (embedded **or** catalog) — the natural proxy/patch targets |
| `--rwx` | PEs with a writable+executable section — MockingJay-style injection surface |
| `--caves` | executable-section code caves big enough for the shellcode given with `-s` (VA, file offset, size, slack) |
| `--files` | every file the tree opened/read/wrote/deleted, PE files excluded — the staging menu |

Notes:

- Sections used as inputs still run when hidden (`--caves` computes the
  unsigned set silently). Any section flag shows *only* the named sections.
- If no unsigned PE has a fitting cave, the cave analysis retries over
  signed PEs behind a warning — patching those breaks their signature and
  may trip WFP/SFC.
- Flags are only recognised **before** the first positional argument; `--`
  ends parsing. Legacy form `childwatch.py path [seconds] [args...]` works.

## Proxy-DLL generation

Offered after any run that showed module data (`--modules`, `--unsigned`,
`--rwx`, `--caves`, or the default report) — or driven entirely by flags.
The picker lists **unsigned DLLs first, in green, tagged `(unsigned)`**;
they are the natural targets since proxying them breaks no signature.
The app's own files are never modified; everything lands in a fresh output
folder and `make` runs automatically (skip with `--no-build`).

Generated scaffold:

| file | purpose |
|---|---|
| `proxy.c` | `DllMain` with a `payload()` slot (your code or the linked loader object) |
| `proxy.def` | export mapping, name + ordinal; ordinal-only exports become NONAME entries |
| `Makefile` | mingw-w64 build, arch matched to the original |
| `README.txt` | deploy steps |
| `<orig>_orig.dll` | renamed copy of the legitimate DLL |

**Styles** (`--proxy-style`):

- `forward` (default) — .def forwarders pointing into the renamed original.
  Simplest; MSVC-compatible.
- `call` — real wrapper functions in `.text` that resolve the original at
  load time and **tail-jump** to it. No forwarder strings anywhere. The
  tail-jump is mandatory: a plain call would misalign the frame and corrupt
  register/stack argument passing (verified empirically — int, double and
  stack-passed args all forward bit-exact with the tail-jump form).

**Decoy code** (`--proxy-junk`): fills the proxy with thousands of
plausible functions — byte scans, state walks, matrix passes, dispatchers,
textbook utilities — sized to match the original DLL's **file size**, so
the thunks hide in a comparable mass of code. `DllMain` gates the entire
decoy init behind a never-true runtime check (system clock == FILETIME
epoch) the compiler cannot fold: none of it ever executes, only
`payload()` runs, and the decoy survives `-O2`. Seeded, reproducible.
Large originals take a minute or two to compile.

**Linked loader** (`--payload-obj PATH`): keep your loader a separate
project. The object's sole contract is `void invoke_payload(void)`
(extern "C" if C++, arch must match); the generated `payload()` calls it
at `DLL_PROCESS_ATTACH` and the Makefile links it in
(`make LOADER_OBJ=/other/path.o` to swap).

Deploy: build, name the proxy exactly like the original DLL, put it where
the app loads it from, keep the renamed original next to it. Every import
flows through the proxy; `payload()` runs inside the legitimate process.

## Payload staging

Offered after the file-access section, or driven by `--stage`. The picker
lists non-PE files the job accessed, **biggest first**. The original
carrier is **never modified**: childwatch stages the payload into a **test
mapping** — a copy of the carrier with the encrypted payload appended,
placed at the same path the app itself uses, relative to the app's folder
(e.g. the app reads `Lib\somefile.txt`, so the mapping gets
`<mapping root>\Lib\somefile.txt`). Put the app in the mapping root and
launch it from there to test the whole setup.

Interactive runs ask for the carrier's app-relative path (auto-computed
from the accessing process), then **where to store the reader `.c`, where
to store the `.h`, and where to root the test mapping**. Non-interactive
runs use `--stage-c DIR`, `--stage-h DIR`, `--stage-map DIR`
(`--stage-rel PATH` overrides the relative carrier path).

**Format.** RC4-encrypted payload, zero-interleaved (one zero byte between
every payload byte) so the blob reads as half-zeros and file entropy stays
flat, plus a 48-byte EOF footer (magic, mode, key, lengths, FNV-1a hash,
original size). childwatch verifies the staged copy round-trips
bit-identically before reporting success.

**The reader is IAT-clean** — freestanding C, zero imports, no CRT, no
cleartext API names: kernel32 is found via PEB walk, the five file APIs
are resolved by **salted** ROR13 hashing over the export table (a random
per-build seed accumulates into every hash, so no constant in the binary
matches a public API-hash database), the footer is parsed byte-wise, and
decryption runs from a small stack buffer.

```c
#include "payload_staged.h"

unsigned long n  = stg_payload_size();    /* 0 + stg_last_error() on failure */
unsigned char *b = loader_alloc(n);
if (stg_read_payload(b, n) != n) { /* stg_last_error() says why */ }
```

`stg_read_payload` opens the carrier by the **relative path embedded at
generation time** (resolved against the process working directory, just
like the app's own `./Lib/somefile.txt`), so the whole app folder can be
relocated without regenerating anything; `stg_read_payload_from(path,
out, cap)` takes any wide path.

## Flags

| Flag | Meaning |
|---|---|
| `-t, --target PATH` | application to analyse (bypasses the menu) |
| `-w, --watch N` | watch window in seconds (default 10) |
| `-s, --shellcode FILE` | size-check code caves against this shellcode |
| `-v, --verbose` | full process, module and file listings |
| `--tree` / `--processes` | section: process tree only |
| `--modules` | section: per-process DLL listing only |
| `--unsigned` | section: Unsigned PEs indicator only |
| `--rwx` | section: RWX PEs indicator only |
| `--caves` | section: code-cave targets only |
| `--files` | section: file-access staging listing only |
| `--proxy PATH` | generate a proxy scaffold for this DLL (no prompt) |
| `--proxy-dir DIR` | where to write the proxy scaffold (default cwd) |
| `--proxy-name NAME` | name for the renamed legit copy (default `<stem>_orig.dll`) |
| `--proxy-style forward\|call` | export style (default `forward`) |
| `--proxy-junk` | add size-matched decoy code to the proxy |
| `--payload-obj PATH` | loader object defining `invoke_payload()`, linked into the proxy |
| `--no-build` | leave the proxy scaffold uncompiled |
| `--stage PATH` | stage the payload inside this carrier (from the file report) |
| `--stage-c DIR` | folder for the generated `payload_staged.c` |
| `--stage-h DIR` | folder for the generated `payload_staged.h` |
| `--stage-map DIR` | root of the test mapping — carrier copy + payload lands there |
| `--stage-rel PATH` | carrier path relative to the app folder (default: auto-computed) |
| `-h, --help` | usage |

Non-interactive example exercising everything:

```bash
python childwatch.py --unsigned --caves --files -s payload.bin \
    --proxy "C:\app\python38.dll" --proxy-style call --proxy-junk \
    --payload-obj loader.o \
    --stage "C:\app\Lib\somefile.txt" --stage-c loader\src \
    --stage-h loader\include --stage-map testmapping \
    -t "C:\app\app.exe" -w 15 -- --arg-for-target
```

## Known limits

- Module attribution is a snapshot at the end of the window; a DLL loaded
  and freed earlier is missed. Manually mapped / reflective DLLs are
  invisible to the loader-based list.
- ETW file tracing requires an elevated prompt; without it the run
  continues without the file section.
