"""Job object + completion-port glue: the ctypes definitions and thin wrappers
that session.py builds on, plus the small process helpers shared by the package.
"""

import ctypes
import ctypes.wintypes as wt
import subprocess

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# Job information classes and flags (from winnt.h).
JOB_OBJECT_ASSOCIATE_COMPLETION_PORT_INFORMATION = 7
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

# Completion-port message identifiers; they arrive in the "bytes transferred"
# field of GetQueuedCompletionStatus.
JOB_OBJECT_MSG_NEW_PROCESS = 6
JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO = 4

CREATE_SUSPENDED = 0x00000004
CREATE_NEW_CONSOLE = 0x00000010
PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000
WAIT_TIMEOUT = 258
ERROR_BAD_LENGTH = 99
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wt.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wt.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wt.DWORD),
        ("SchedulingClass", wt.DWORD),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class JOBOBJECT_ASSOCIATE_COMPLETION_PORT_CLASS(ctypes.Structure):
    _fields_ = [
        ("CompletionKey", ctypes.c_size_t),
        ("CompletionPort", wt.HANDLE),
    ]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wt.DWORD),
        ("lpReserved", wt.LPWSTR),
        ("lpDesktop", wt.LPWSTR),
        ("lpTitle", wt.LPWSTR),
        ("dwX", wt.DWORD),
        ("dwY", wt.DWORD),
        ("dwXSize", wt.DWORD),
        ("dwYSize", wt.DWORD),
        ("dwXCountChars", wt.DWORD),
        ("dwYCountChars", wt.DWORD),
        ("dwFillAttribute", wt.DWORD),
        ("dwFlags", wt.DWORD),
        ("wShowWindow", wt.WORD),
        ("cbReserved2", wt.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wt.HANDLE),
        ("hStdOutput", wt.HANDLE),
        ("hStdError", wt.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wt.HANDLE),
        ("hThread", wt.HANDLE),
        ("dwProcessId", wt.DWORD),
        ("dwThreadId", wt.DWORD),
    ]


# --- prototypes -----------------------------------------------------------

kernel32.CloseHandle.restype = wt.BOOL
kernel32.CloseHandle.argtypes = [wt.HANDLE]

kernel32.CreateJobObjectW.restype = wt.HANDLE
kernel32.CreateJobObjectW.argtypes = [wt.LPVOID, wt.LPCWSTR]

kernel32.SetInformationJobObject.restype = wt.BOOL
kernel32.SetInformationJobObject.argtypes = [wt.HANDLE, wt.DWORD, wt.LPVOID, wt.DWORD]

kernel32.CreateIoCompletionPort.restype = wt.HANDLE
kernel32.CreateIoCompletionPort.argtypes = [wt.HANDLE, wt.HANDLE, ctypes.c_size_t, wt.DWORD]

kernel32.GetQueuedCompletionStatus.restype = wt.BOOL
kernel32.GetQueuedCompletionStatus.argtypes = [
    wt.HANDLE,
    ctypes.POINTER(wt.DWORD),        # lpNumberOfBytesTransferred (message id)
    ctypes.POINTER(ctypes.c_size_t),  # lpCompletionKey
    ctypes.POINTER(ctypes.c_void_p),  # lpOverlapped (carries the PID)
    wt.DWORD,                         # dwMilliseconds
]

kernel32.CreateProcessW.restype = wt.BOOL
kernel32.CreateProcessW.argtypes = [
    wt.LPCWSTR,
    wt.LPWSTR,
    wt.LPVOID,
    wt.LPVOID,
    wt.BOOL,
    wt.DWORD,
    wt.LPVOID,
    wt.LPCWSTR,
    ctypes.POINTER(STARTUPINFOW),
    ctypes.POINTER(PROCESS_INFORMATION),
]

kernel32.AssignProcessToJobObject.restype = wt.BOOL
kernel32.AssignProcessToJobObject.argtypes = [wt.HANDLE, wt.HANDLE]

kernel32.ResumeThread.restype = wt.DWORD
kernel32.ResumeThread.argtypes = [wt.HANDLE]

kernel32.TerminateProcess.restype = wt.BOOL
kernel32.TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]

kernel32.TerminateJobObject.restype = wt.BOOL
kernel32.TerminateJobObject.argtypes = [wt.HANDLE, wt.UINT]

kernel32.OpenProcess.restype = wt.HANDLE
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]

kernel32.QueryFullProcessImageNameW.restype = wt.BOOL
kernel32.QueryFullProcessImageNameW.argtypes = [
    wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)
]


def last_error() -> OSError:
    """The pending ctypes last-error as an OSError, for raise sites."""
    return ctypes.WinError(ctypes.get_last_error())


def resolve_image_path(pid: int) -> str:
    """The full image path for pid, or "" if the process has already exited or
    cannot be opened for query."""
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = wt.DWORD(len(buf))
        if not kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            buf = ctypes.create_unicode_buffer(32768)  # grow once for long paths
            size = wt.DWORD(len(buf))
            if not kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                return ""
        return buf.value
    finally:
        kernel32.CloseHandle(h)


def build_command_line(exe: str, args: list[str]) -> str:
    """Assemble a properly quoted CreateProcess command line whose first token
    is the executable itself. list2cmdline implements the same quoting rules
    the Go version's windows.EscapeArg does."""
    return subprocess.list2cmdline([exe, *args])
