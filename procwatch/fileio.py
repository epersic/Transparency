"""FileMonitor: consumes the Microsoft-Windows-Kernel-File ETW provider (via
the eztw library) and records every file the observed processes open, read,
write or delete."""

import ctypes
import ctypes.wintypes as wt
import dataclasses
import logging
import os
import stat as stat_module
import subprocess
import threading
import time

from eztw import EztwConsumer, EztwController, EztwProviderConfig, parse_event
from eztw.common import EztwException
from eztw.controller import EztwControllerException
from eztw.log import LOGGER as _eztw_logger
from eztw.trace_common import TRACE_LEVEL_INFORMATION

# The library logs session lifecycle chatter at INFO; childwatch prints its own
# report and stays silent like the Go original.
_eztw_logger.addHandler(logging.NullHandler())
_eztw_logger.propagate = False
_eztw_logger.setLevel(logging.WARNING)

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.QueryDosDeviceW.restype = wt.DWORD
kernel32.QueryDosDeviceW.argtypes = [wt.LPCWSTR, wt.LPWSTR, wt.DWORD]

# Microsoft-Windows-Kernel-File. This is an ordinary admin-level provider: it
# needs elevation to open a real-time trace session, but not a driver and not
# the PPL-gated Threat-Intelligence provider.
KERNEL_FILE_PROVIDER_GUID = "{edd08927-9cc4-4e65-b970-c2560fb5c289}"

# Provider keywords (see: logman query providers Microsoft-Windows-Kernel-File).
KW_FILE_NAME = 0x0000000000000010  # NameCreate/NameDelete: FileKey -> name
KW_CREATE = 0x0000000000000080     # file opens, carries the full name
KW_READ = 0x0000000000000100
KW_WRITE = 0x0000000000000200
KW_DELETE_PATH = 0x0000000000000400

# Event IDs emitted by the provider.
EV_NAME_CREATE = 10
EV_CREATE = 12
EV_READ = 15
EV_WRITE = 16
EV_DELETE_PATH = 26
EV_CREATE_NEW_FILE = 30

_RECORDED_EVENTS = {EV_NAME_CREATE, EV_CREATE, EV_CREATE_NEW_FILE,
                    EV_READ, EV_WRITE, EV_DELETE_PATH}

# Operations recorded per (process, file). Read and write events identify
# their target only by object handle, so the name comes from the
# create/name events.
OP_OPEN = 1
OP_READ = 1 << 1
OP_WRITE = 1 << 2
OP_DELETE = 1 << 3


class FileAccess:
    """One file touched by one process, with the set of operations observed
    against it."""
    __slots__ = ("proc_name", "pid", "path", "ops", "is_dir", "is_pe", "size")

    def __init__(self, proc_name: str, pid: int, path: str, ops: str,
                 is_dir: bool, is_pe: bool, size: int):
        self.proc_name = proc_name  # base name of the accessing process image
        self.pid = pid
        self.path = path  # full path, drive-letter normalised where possible
        self.ops = ops  # comma-separated: open, read, write, delete
        self.is_dir = is_dir  # the path is a directory, not a file
        self.is_pe = is_pe  # content-checked MZ + PE signature: the file is a
        # PE regardless of its extension. PEs are excluded from the staging
        # listing — payload staging only makes sense in non-PE files.
        self.size = size  # size on disk in bytes, or -1 if unknown: a
        # directory, or a file that could not be stat'd because it was deleted
        # or is unreadable. A deleted file is worth attention, so it is kept
        # rather than discarded.


class FileMonitor:
    """Records file activity system-wide from Microsoft-Windows-Kernel-File
    and can afterwards report what any given set of processes touched.

    Tracing must be running before the processes of interest do their I/O, so
    a FileMonitor should be started BEFORE launch_traced. Events are
    deduplicated per (pid, path) as they arrive, so memory stays bounded by
    the number of distinct files touched rather than the number of I/O
    operations."""

    def __init__(self):
        _sweep_stale_sessions()
        self._controller = None
        self._consumer = None
        self._worker = None
        self._stop = threading.Event()
        self.perr = None
        self._devices = _build_device_map()

        # tracked is the set of PIDs whose events are recorded. It is consulted
        # for every event before anything expensive happens, so it has its own
        # lock to keep the hot path off the recording mutex.
        self._tlock = threading.Lock()
        self._tracked: set[int] = set()

        self._lock = threading.Lock()
        # files maps pid -> normalised path -> operation bitmask.
        self._files: dict[int, dict[str, int]] = {}
        # names resolves a file object/key handle to the path it was opened as.
        self._names: dict[str, str] = {}

        # A session name must be unique machine-wide; key it to this process.
        name = f"childwatch-file-{os.getpid()}"
        config = EztwProviderConfig(
            guid=KERNEL_FILE_PROVIDER_GUID,
            keywords=KW_FILE_NAME | KW_CREATE | KW_READ | KW_WRITE | KW_DELETE_PATH,
            level=TRACE_LEVEL_INFORMATION,
        )
        controller = EztwController(name, config)
        try:
            controller.start()
        except EztwControllerException as e:
            # EztwController already stops and retries when a stale session of
            # the same name survived an earlier crash (they are machine-wide
            # and outlive the process that made them). Remaining failures are
            # real: elevation is required.
            if "with error 5" in str(e):
                raise PermissionError(
                    "Access is denied (opening a real-time trace session "
                    "requires an elevated prompt)") from e
            raise
        self._controller = controller

        consumer = EztwConsumer(name)
        consumer.start()  # spawns eztw's internal ProcessTrace thread + queue
        self._consumer = consumer

        # The consumer thread only queues raw records; the parsing and
        # recording happen on this worker so the ETW callback is never blocked.
        self._worker = threading.Thread(target=self._drain, daemon=True,
                                        name="childwatch-file")
        self._worker.start()

        # Give the subscription a moment to come up so activity that happens
        # immediately after this call is not missed.
        time.sleep(0.3)

    # -- recording ----------------------------------------------------------

    def track(self, pid: int) -> None:
        """Start recording file activity for pid. Events from processes that
        were never tracked are discarded, so a caller must register each
        process of interest — ideally before it runs, since activity before
        the call is not recorded."""
        with self._tlock:
            self._tracked.add(pid)

    def _is_tracked(self, pid: int) -> bool:
        with self._tlock:
            return pid in self._tracked

    def _drain(self) -> None:
        while not self._stop.is_set():
            record = self._consumer.get_event(timeout=0.2)
            if record is not None:
                self._handle(record)

    def _handle(self, record) -> None:
        # Cheapest possible rejection first. This provider is system-wide and
        # very high volume; parsing properties for every file operation on the
        # machine cannot keep up, which backs up the trace buffers until
        # events are dropped and the consumer stops draining. Everything below
        # this check runs only for the handful of processes in the observed
        # tree.
        if not self._is_tracked(record.process_id):
            return

        if record.id not in _RECORDED_EVENTS:
            return

        try:
            parsed = parse_event(record)
        except EztwException:
            return  # no schema (yet) for this event; nothing to record
        except Exception:
            return

        props = dataclasses.asdict(parsed)

        # Read/write events reference the file only by object handle; create
        # and name events carry the actual path, so they seed the map.
        key = _key_of(props)
        name = _name_of(props)

        with self._lock:
            if name and key:
                self._names[key] = name
            if not name and key:
                name = self._names.get(key)
            if not name:
                return  # an operation on a handle we never saw opened

            eid = record.id
            if eid == EV_READ:
                op = OP_READ
            elif eid == EV_WRITE:
                op = OP_WRITE
            elif eid == EV_DELETE_PATH:
                op = OP_DELETE
            else:
                op = OP_OPEN

            pid = record.process_id
            path = self._normalize(name)
            per_pid = self._files.setdefault(pid, {})
            per_pid[path] = per_pid.get(path, 0) | op

    # -- reporting ----------------------------------------------------------

    def settle(self, max_wait: float = 4.0, quiet: float = 1.2) -> None:
        """Wait for straggler events before taking a report snapshot.

        Real-time ETW flushes session buffers lazily (roughly once a second
        on a quiet machine), so the last moments of the watched processes'
        activity can still be in flight after collect() returns. Wait until
        the consumer queue has stayed empty for `quiet` seconds, bounded by
        `max_wait` in total."""
        deadline = time.monotonic() + max_wait
        last_busy = time.monotonic()
        while time.monotonic() < deadline:
            if self._consumer is not None and self._consumer.pending_events():
                last_busy = time.monotonic()
            elif time.monotonic() - last_busy >= quiet:
                break
            time.sleep(0.1)

    def accessed_by(self, procs) -> list[FileAccess]:
        """The files touched by the given processes, sorted by process then
        path. Processes that touched nothing are simply absent."""
        with self._lock:
            snapshot = {pid: dict(paths) for pid, paths in self._files.items()}

        out: list[FileAccess] = []
        for p in procs:
            proc_name = os.path.basename(p.path) if p.path else f"pid {p.pid}"
            for path, ops in snapshot.get(p.pid, {}).items():
                # A failed stat leaves size -1, is_dir and is_pe False: the
                # path is gone or unreadable, which is not the same as it
                # being a directory or a non-PE — a deleted file is worth
                # attention, so it stays visible.
                size, is_dir, is_pe = -1, False, False
                try:
                    st = os.stat(path)
                    is_dir = stat_module.S_ISDIR(st.st_mode)
                    if not is_dir:
                        size = st.st_size
                        is_pe = _looks_like_pe(path)
                except OSError:
                    pass
                out.append(FileAccess(proc_name, p.pid, path,
                                      _ops_string(ops), is_dir, is_pe, size))
        out.sort(key=lambda a: (a.pid, a.path))
        return out

    # -- teardown -----------------------------------------------------------

    def stop(self, stop_timeout: float = 5.0, drain_timeout: float = 3.0):
        """End the trace session and wait for event processing to finish.
        Recorded results remain available afterwards.

        Shutdown is bounded: ProcessTrace only returns once the trace buffers
        drain, so a burst of events arriving as the session closes can delay
        it. Rather than block the caller indefinitely the wait is abandoned
        after a few seconds — the results are already collected by then, and
        the process is normally exiting."""
        if self._consumer is None:
            return
        consumer, controller = self._consumer, self._controller
        self._consumer = self._controller = None
        self._stop.set()

        # End the session (bounded).
        if controller is not None:
            t = threading.Thread(target=controller.stop, daemon=True)
            t.start()
            t.join(stop_timeout)

        # CloseTrace unblocks eztw's consumer thread; join it bounded.
        consumer._stop()
        if consumer.consumer_thread is not None:
            consumer.consumer_thread.join(drain_timeout)
            consumer.consumer_thread = None

        if self._worker is not None:
            self._worker.join(drain_timeout)
            self._worker = None

    # -- path helpers -------------------------------------------------------

    def _normalize(self, p: str) -> str:
        """Rewrite an NT device path (\\Device\\HarddiskVolume3\\...) to its
        drive-letter form. Paths that are already normal are returned
        unchanged."""
        lower = p.lower()
        for dev, drive in self._devices.items():
            if lower.startswith(dev + "\\"):
                return _trim_trailing_sep(drive + p[len(dev):])
        return _trim_trailing_sep(p)


def _looks_like_pe(path: str) -> bool:
    """Content check for a PE file: DOS MZ magic plus a PE\\0\\0 signature at
    the e_lfanew offset. Extension is ignored on purpose — a PE renamed to
    look like data is still a PE, and staging there achieves nothing."""
    try:
        with open(path, "rb") as f:
            if f.read(2) != b"MZ":
                return False
            f.seek(0x3C)
            off_bytes = f.read(4)
            if len(off_bytes) < 4:
                return False
            f.seek(int.from_bytes(off_bytes, "little"))
            return f.read(4) == b"PE\x00\x00"
    except OSError:
        return False


def _trim_trailing_sep(p: str) -> str:
    """Drop trailing separators so that "C:\\dir" and "C:\\dir\\" are recorded
    as one entry rather than two. A drive root ("C:\\") is left alone."""
    while len(p) > 3 and p[-1] in "\\/":
        p = p[:-1]
    return p


def _sweep_stale_sessions() -> None:
    """Stop childwatch trace sessions left behind by crashed earlier runs.

    Session names carry the creating process's pid (see FileMonitor), so a
    leftover whose pid is gone can only be garbage — and a stale real-time
    session on this provider was observed to wedge event delivery for fresh
    sessions. Best effort: any failure is ignored, the monitor still starts.
    """
    import re

    try:
        out = subprocess.run(["logman", "query", "-ets"],
                             capture_output=True, text=True,
                             timeout=15).stdout
    except Exception:
        return

    alive = kernel32.OpenProcess  # presence check via OpenProcess
    alive.restype = wt.HANDLE
    alive.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]

    for name in re.findall(r"^childwatch-file-(\d+)", out, re.M):
        pid = int(name)
        if pid == os.getpid():
            continue
        h = alive(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if h:
            kernel32.CloseHandle(h)
            continue  # a sibling childwatch is running; leave it alone
        try:
            subprocess.run(["logman", "stop", f"childwatch-file-{pid}", "-ets"],
                           capture_output=True, timeout=15)
        except Exception:
            pass


def _build_device_map() -> dict[str, str]:
    """Map NT device names to drive letters, so ETW paths can be shown the way
    a user would write them."""
    m: dict[str, str] = {}
    buf = ctypes.create_unicode_buffer(1024)
    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        drive = f"{c}:"
        n = kernel32.QueryDosDeviceW(drive, buf, len(buf))
        if n == 0:
            continue
        target = ctypes.wstring_at(buf)  # first null-terminated mapping
        if target:
            m[target.lower()] = drive
    return m


def _key_of(props: dict) -> str:
    """The handle/object key an operation event refers to. Property naming
    varies slightly between provider versions, so every spelling is accepted;
    the value is whatever type the manifest gives it (usually a pointer)."""
    for k in ("FileObject", "FileKey", "Irp"):
        if props.get(k) is not None:
            return str(props[k])
    return ""


def _name_of(props: dict) -> str:
    """The first non-empty string value among the given path-ish properties."""
    for k in ("FileName", "OpenPath", "FilePath"):
        v = props.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


def _ops_string(ops: int) -> str:
    parts = []
    if ops & OP_OPEN:
        parts.append("open")
    if ops & OP_READ:
        parts.append("read")
    if ops & OP_WRITE:
        parts.append("write")
    if ops & OP_DELETE:
        parts.append("delete")
    return ",".join(parts)
