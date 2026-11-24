"""ProcDLL, loaded_modules: the ToolHelp snapshot of each observed process's
loader-visible modules."""

import ctypes
import ctypes.wintypes as wt
import os
from dataclasses import dataclass

from .job import ERROR_BAD_LENGTH, INVALID_HANDLE_VALUE, kernel32

TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010


@dataclass
class ProcDLL:
    """One loaded DLL paired with the process that loaded it. A single result
    list from loaded_modules holds one ProcDLL per (process, DLL) pair,
    flattened across every process supplied."""
    proc_name: str  # base name of the process image, e.g. "cmd.exe"
    pid: int
    dll_name: str  # base name of the module, e.g. "kernel32.dll"
    dll_path: str  # full path of the module on disk


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("th32ModuleID", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("GlblcntUsage", wt.DWORD),
        ("ProccntUsage", wt.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wt.DWORD),
        ("hModule", wt.HMODULE),
        ("szModule", ctypes.c_wchar * 256),
        ("szExePath", ctypes.c_wchar * wt.MAX_PATH),
    ]


kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
kernel32.Module32FirstW.restype = wt.BOOL
kernel32.Module32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32NextW.restype = wt.BOOL
kernel32.Module32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32W)]


def loaded_modules(procs: list) -> list[ProcDLL]:
    """Every DLL currently loaded by each process in procs. Processes that have
    exited or cannot be inspected are silently skipped.

    Only loader-visible modules are reported. DLLs mapped manually or
    reflectively (never registered with the loader) do not appear; ETW
    ImageLoad events or a memory scan are required to see those."""
    out: list[ProcDLL] = []
    for p in procs:
        mods, exe_name = enum_modules(p.pid)

        proc_name = os.path.basename(p.path) if p.path else ""
        if not proc_name:
            proc_name = exe_name  # recovered from the process's own module entry
        if not proc_name:
            proc_name = f"pid {p.pid}"

        for name, path in mods:
            out.append(ProcDLL(proc_name=proc_name, pid=p.pid,
                               dll_name=name, dll_path=path))
    return out


def enum_modules(pid: int):
    """Snapshot the module list of pid via ToolHelp. Returns the loaded modules
    (excluding the process's own image) and the base name of that image. On any
    failure it returns empty results."""
    max_retry = 3

    snap = None
    err = None
    for _ in range(max_retry):
        snap = kernel32.CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
        if snap and snap != INVALID_HANDLE_VALUE:
            break
        # The process may still be loading its modules; ToolHelp reports this
        # as ERROR_BAD_LENGTH. Retry a couple of times before giving up.
        err = ctypes.get_last_error()
        if err == ERROR_BAD_LENGTH:
            continue
        return [], ""
    if snap is None or snap == INVALID_HANDLE_VALUE:
        return [], ""
    try:
        me = MODULEENTRY32W()
        me.dwSize = ctypes.sizeof(MODULEENTRY32W)
        if not kernel32.Module32FirstW(snap, ctypes.byref(me)):
            return [], ""

        mods = []
        exe_name = None
        while True:
            if exe_name is None:
                # The first entry is always the process's own executable image.
                exe_name = me.szModule
            else:
                mods.append((me.szModule, me.szExePath))
            if not kernel32.Module32NextW(snap, ctypes.byref(me)):
                break  # ERROR_NO_MORE_FILES at the end of the list
        return mods, exe_name or ""
    finally:
        kernel32.CloseHandle(snap)
