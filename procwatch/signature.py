"""is_signed: Authenticode verification via WinVerifyTrust, embedded signature
first with a security-catalog fallback (so catalog-signed system files are
correctly treated as signed)."""

import ctypes
import ctypes.wintypes as wt

from .job import INVALID_HANDLE_VALUE

wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# WinVerifyTrust / catalog constants (from wintrust.h, softpub.h).
WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_CHOICE_CATALOG = 2
WTD_STATE_ACTION_VERIFY = 1
WTD_STATE_ACTION_CLOSE = 2
WTD_REVOCATION_CHECK_NONE = 0x00000010

TRUST_E_NO_SIGNATURE = 0x800B0100  # no embedded signature; try catalogs

FILE_NOT_FOUND = 2  # winerror.ERROR_FILE_NOT_FOUND

# CreateFileW flags (ctypes.wintypes does not define these).
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wt.DWORD),
        ("Data2", wt.WORD),
        ("Data3", wt.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


# WINTRUST_ACTION_GENERIC_VERIFY_V2.
GENERIC_VERIFY_V2 = GUID(
    0x00AAC56B, 0xCD44, 0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wt.DWORD),
        ("pcwszFilePath", wt.LPCWSTR),
        ("hFile", wt.HANDLE),
        ("pgKnownSubject", ctypes.c_void_p),
    ]


class WINTRUST_CATALOG_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wt.DWORD),
        ("dwCatalogVersion", wt.DWORD),
        ("pcwszCatalogFilePath", wt.LPCWSTR),
        ("pcwszMemberTag", wt.LPCWSTR),
        ("pcwszMemberFilePath", wt.LPCWSTR),
        ("hMemberFile", wt.HANDLE),
        ("pbCalculatedFileHash", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbCalculatedFileHash", wt.DWORD),
        ("pcCatalogContext", ctypes.c_void_p),
        ("hCatAdmin", wt.HANDLE),
    ]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wt.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wt.DWORD),
        ("fdwRevocationChecks", wt.DWORD),
        ("dwUnionChoice", wt.DWORD),
        ("pInfo", ctypes.c_void_p),
        ("dwStateAction", wt.DWORD),
        ("hWVTStateData", wt.HANDLE),
        ("pwszURLReference", wt.LPCWSTR),
        ("dwProvFlags", wt.DWORD),
        ("dwUIContext", wt.DWORD),
    ]


class CATALOG_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wt.DWORD),
        ("wszCatalogFile", ctypes.c_wchar * wt.MAX_PATH),
    ]


# --- prototypes -----------------------------------------------------------

wintrust.WinVerifyTrust.restype = ctypes.c_long  # HRESULT, compared unsigned
wintrust.WinVerifyTrust.argtypes = [wt.HWND, ctypes.POINTER(GUID), ctypes.c_void_p]

wintrust.CryptCATAdminAcquireContext2.restype = wt.BOOL
wintrust.CryptCATAdminAcquireContext2.argtypes = [
    ctypes.POINTER(wt.HANDLE), ctypes.c_void_p, wt.LPCWSTR, ctypes.c_void_p, wt.DWORD]

wintrust.CryptCATAdminReleaseContext.restype = wt.BOOL
wintrust.CryptCATAdminReleaseContext.argtypes = [wt.HANDLE, wt.DWORD]

wintrust.CryptCATAdminCalcHashFromFileHandle2.restype = wt.BOOL
wintrust.CryptCATAdminCalcHashFromFileHandle2.argtypes = [
    wt.HANDLE, wt.HANDLE, ctypes.POINTER(wt.DWORD), ctypes.POINTER(ctypes.c_ubyte), wt.DWORD]

wintrust.CryptCATAdminEnumCatalogFromHash.restype = wt.HANDLE
wintrust.CryptCATAdminEnumCatalogFromHash.argtypes = [
    wt.HANDLE, ctypes.POINTER(ctypes.c_ubyte), wt.DWORD, wt.DWORD, ctypes.c_void_p]

wintrust.CryptCATAdminReleaseCatalogContext.restype = wt.BOOL
wintrust.CryptCATAdminReleaseCatalogContext.argtypes = [wt.HANDLE, wt.HANDLE, wt.DWORD]


def _proc(dll, *names):
    """Resolve the first exported name among aliases. Older SDKs document
    CryptCATAdminCatalogInfoFromContext while modern wintrust.dll exports it
    as CryptCATCatalogInfoFromContext; accept either."""
    for n in names:
        try:
            return getattr(dll, n)
        except AttributeError:
            continue
    raise AttributeError(f"none of {names!r} exported")


proc_catalog_info_from_context = _proc(
    wintrust, "CryptCATAdminCatalogInfoFromContext", "CryptCATCatalogInfoFromContext")
proc_catalog_info_from_context.restype = wt.BOOL
proc_catalog_info_from_context.argtypes = [
    wt.HANDLE, ctypes.POINTER(CATALOG_INFO), wt.DWORD]

kernel32.CreateFileW.restype = wt.HANDLE
kernel32.CreateFileW.argtypes = [
    wt.LPCWSTR, wt.DWORD, wt.DWORD,
    ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.HANDLE]


def is_signed(path: str):
    """Report whether the PE at path carries a valid, trusted Authenticode
    signature — either embedded in the file or via a Windows security catalog.

    Returns (signed, error): False with error None for files that have no
    signature at all AND for files whose signature is present but does not
    chain to a trusted root (expired, self-signed, tampered, revoked) — only a
    properly trusted signature counts as signed, which is the useful
    definition for triage. The error is non-None only when the file itself
    could not be examined (e.g. it no longer exists)."""
    if not path:
        return False, ctypes.WinError(FILE_NOT_FOUND)

    status = _verify_embedded(path)
    if status == 0:
        return True, None
    # Only "no embedded signature" warrants a catalog lookup; any other status
    # means a signature exists but did not verify, which is not "signed".
    if status != TRUST_E_NO_SIGNATURE:
        return False, None
    return _verify_catalog(path)


def _verify_embedded(path: str) -> int:
    """Run WinVerifyTrust against the file's embedded signature and return the
    raw LONG status (0 == trusted)."""
    wpath = ctypes.create_unicode_buffer(path)
    wpath_ptr = ctypes.cast(wpath, wt.LPCWSTR)  # keep wpath alive through the calls

    fi = WINTRUST_FILE_INFO(
        cbStruct=ctypes.sizeof(WINTRUST_FILE_INFO),
        pcwszFilePath=wpath_ptr,
    )
    data = WINTRUST_DATA(
        cbStruct=ctypes.sizeof(WINTRUST_DATA),
        dwUIChoice=WTD_UI_NONE,
        fdwRevocationChecks=WTD_REVOKE_NONE,
        dwUnionChoice=WTD_CHOICE_FILE,
        dwStateAction=WTD_STATE_ACTION_VERIFY,
        dwProvFlags=WTD_REVOCATION_CHECK_NONE,
        pInfo=ctypes.cast(ctypes.byref(fi), ctypes.c_void_p),
    )
    guid = GENERIC_VERIFY_V2
    r = wintrust.WinVerifyTrust(0, ctypes.byref(guid), ctypes.byref(data))

    data.dwStateAction = WTD_STATE_ACTION_CLOSE
    wintrust.WinVerifyTrust(0, ctypes.byref(guid), ctypes.byref(data))
    return r & 0xFFFFFFFF


def _verify_catalog(path: str):
    """Locate the security catalog that vouches for the file's hash and verify
    the file as a member of it."""
    wpath = ctypes.create_unicode_buffer(path)
    wpath_ptr = ctypes.cast(wpath, wt.LPCWSTR)  # keep wpath alive through the calls

    h = kernel32.CreateFileW(wpath, GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
    if h == INVALID_HANDLE_VALUE:
        return False, ctypes.WinError(ctypes.get_last_error())
    try:
        algo = ctypes.create_unicode_buffer("SHA256")
        hcat = wt.HANDLE()
        if not wintrust.CryptCATAdminAcquireContext2(
                ctypes.byref(hcat), None, algo, None, 0):
            return False, None  # cannot query catalogs; treat as unsigned
        try:
            # Two-call pattern: size the hash, then compute it.
            cb_hash = wt.DWORD(0)
            wintrust.CryptCATAdminCalcHashFromFileHandle2(
                hcat, h, ctypes.byref(cb_hash), None, 0)
            if cb_hash.value == 0:
                return False, None
            hash_buf = (ctypes.c_ubyte * cb_hash.value)()
            if not wintrust.CryptCATAdminCalcHashFromFileHandle2(
                    hcat, h, ctypes.byref(cb_hash), hash_buf, 0):
                return False, None

            hcatinfo = wintrust.CryptCATAdminEnumCatalogFromHash(
                hcat, hash_buf, cb_hash.value, 0, None)
            if not hcatinfo:
                return False, None  # hash not present in any catalog
            try:
                ci = CATALOG_INFO(cbStruct=ctypes.sizeof(CATALOG_INFO))
                if not proc_catalog_info_from_context(
                        hcatinfo, ctypes.byref(ci), 0):
                    return False, None

                cat_file = ctypes.create_unicode_buffer(ci.wszCatalogFile)
                tag = ctypes.create_unicode_buffer(
                    bytes(hash_buf).hex().upper())

                cat = WINTRUST_CATALOG_INFO(
                    cbStruct=ctypes.sizeof(WINTRUST_CATALOG_INFO),
                    pcwszCatalogFilePath=ctypes.cast(cat_file, wt.LPCWSTR),
                    pcwszMemberTag=ctypes.cast(tag, wt.LPCWSTR),
                    pcwszMemberFilePath=wpath_ptr,
                    hMemberFile=h,
                    pbCalculatedFileHash=hash_buf,
                    cbCalculatedFileHash=cb_hash.value,
                    hCatAdmin=hcat,
                )
                data = WINTRUST_DATA(
                    cbStruct=ctypes.sizeof(WINTRUST_DATA),
                    dwUIChoice=WTD_UI_NONE,
                    fdwRevocationChecks=WTD_REVOKE_NONE,
                    dwUnionChoice=WTD_CHOICE_CATALOG,
                    dwStateAction=WTD_STATE_ACTION_VERIFY,
                    dwProvFlags=WTD_REVOCATION_CHECK_NONE,
                    pInfo=ctypes.cast(ctypes.byref(cat), ctypes.c_void_p),
                )
                guid = GENERIC_VERIFY_V2
                r = wintrust.WinVerifyTrust(0, ctypes.byref(guid), ctypes.byref(data))

                data.dwStateAction = WTD_STATE_ACTION_CLOSE
                wintrust.WinVerifyTrust(0, ctypes.byref(guid), ctypes.byref(data))
                return (r & 0xFFFFFFFF) == 0, None
            finally:
                wintrust.CryptCATAdminReleaseCatalogContext(hcat, hcatinfo, 0)
        finally:
            wintrust.CryptCATAdminReleaseContext(hcat, 0)
    finally:
        kernel32.CloseHandle(h)
