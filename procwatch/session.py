"""Traced launch, process collection and cleanup: the Session that owns the
target's job object and discovers every descendant it spawns."""

import ctypes
import ctypes.wintypes as wt
import os
import sys
import time
from dataclasses import dataclass

from .job import (
    CREATE_NEW_CONSOLE,
    CREATE_SUSPENDED,
    INVALID_HANDLE_VALUE,
    JOB_OBJECT_ASSOCIATE_COMPLETION_PORT_INFORMATION,
    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO,
    JOB_OBJECT_MSG_NEW_PROCESS,
    JOBOBJECT_ASSOCIATE_COMPLETION_PORT_CLASS,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    PROCESS_INFORMATION,
    STARTUPINFOW,
    WAIT_TIMEOUT,
    kernel32,
    last_error,
)
from .job import resolve_image_path, build_command_line


class ProcwatchError(Exception):
    """A launch or collection failure that aborts the analysis."""


@dataclass
class ChildProcess:
    """One process spawned beneath the target."""
    pid: int
    path: str = ""  # full image path; "" if it exited before the path could be read


class Session:
    """A running target contained in a job object. Its descendants stay alive
    until close() is called, which lets callers inspect them (for example via
    loaded_modules) after collect() returns."""

    def __init__(self, jh, port, proc, thread, root_pid, root_path, on_process):
        self._job = jh
        self._port = port
        self._proc = proc
        self._thread = thread
        self.root_pid = root_pid
        self._root_path = root_path
        self._seen: dict[int, ChildProcess] = {}
        self._on_process = on_process
        self._closed = False

    def collect(self, d: float) -> list[ChildProcess]:
        """Drain process-creation notifications for up to d seconds and return
        the descendants discovered so far (the target itself is excluded). It
        may be called repeatedly; each call blocks for up to d and merges new
        processes."""
        deadline = time.monotonic() + d
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            msg_id = wt.DWORD()
            key = ctypes.c_size_t()
            ov = ctypes.c_void_p()
            ok = kernel32.GetQueuedCompletionStatus(
                self._port, ctypes.byref(msg_id), ctypes.byref(key),
                ctypes.byref(ov), int(remaining * 1000))
            if not ok:
                err = ctypes.get_last_error()
                if err == WAIT_TIMEOUT:
                    break
                raise ProcwatchError(f"read job notification: {ctypes.WinError(err)}")

            # For job notifications the "overlapped" field carries the PID
            # rather than a real pointer.
            pid = (ov.value or 0) & 0xFFFFFFFF
            msg = msg_id.value

            if msg == JOB_OBJECT_MSG_NEW_PROCESS:
                if pid == 0 or pid == self.root_pid:
                    continue  # skip the target's own assignment message
                if pid in self._seen:
                    continue
                self._seen[pid] = ChildProcess(pid=pid)  # path filled in below
                hook = self._on_process

                # Announce before resolving the image path: that lookup opens
                # the process and is far slower than the child takes to start
                # doing I/O.
                if hook is not None:
                    hook(pid)
                self._seen[pid].path = resolve_image_path(pid)
            elif msg == JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO:
                return self.children()  # whole tree exited on its own
        return self.children()

    def root(self) -> ChildProcess:
        """The target process itself — the process childwatch launched, at the
        root of the tree. It is deliberately excluded from collect/children
        (which report only spawned descendants), but callers scanning the whole
        tree for signatures or modules will usually want to include it."""
        return ChildProcess(pid=self.root_pid, path=self._root_path)

    def children(self) -> list[ChildProcess]:
        """A snapshot of every descendant discovered so far, sorted by PID."""
        return sorted(self._seen.values(), key=lambda c: c.pid)

    def close(self) -> None:
        """Terminate the process tree and release all handles. Idempotent."""
        if self._closed:
            return
        self._closed = True
        kernel32.TerminateJobObject(self._job, 0)
        kernel32.CloseHandle(self._thread)
        kernel32.CloseHandle(self._proc)
        kernel32.CloseHandle(self._port)
        kernel32.CloseHandle(self._job)  # kill-on-close backstop


def launch_traced(on_process, app_path: str, args: list[str] | None = None) -> Session:
    """Start app_path suspended, place it in a fresh job object, and invoke
    on_process for the target and each descendant as soon as its PID is known.
    The returned Session must be closed to terminate the process tree and
    release its handles.

    The hook exists so an observer that filters by PID — a FileMonitor, say —
    can start recording a process before it executes its first instruction,
    rather than after launch returns and the target has already run."""
    args = list(args or [])
    app_path = os.path.abspath(app_path)
    if os.path.isdir(app_path):
        raise ProcwatchError(f"stat target: target is a directory, not an executable: {app_path}")
    if not os.path.exists(app_path):
        raise ProcwatchError(f"stat target: The system cannot find the file: {app_path}")

    jh = kernel32.CreateJobObjectW(None, None)
    if not jh:
        raise ProcwatchError(f"CreateJobObject: {last_error()}")
    ok = False
    try:
        # Killing the job when its last handle closes guarantees the tree is
        # torn down even if the caller forgets to close or the analyzer crashes.
        eli = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        eli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        try:
            kernel32.SetInformationJobObject(
                jh, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(eli), ctypes.sizeof(eli))
        except Exception as e:
            raise ProcwatchError(f"set kill-on-close: {e}")
        if ctypes.get_last_error():
            pass  # SetInformationJobObject failures raise via the wrappers below

        # Associate the completion port with the still-empty job so no
        # descendant notification can be missed between assignment and
        # association.
        port = kernel32.CreateIoCompletionPort(INVALID_HANDLE_VALUE, None, 0, 1)
        if not port:
            raise ProcwatchError(f"CreateIoCompletionPort: {last_error()}")
        try:
            assoc = JOBOBJECT_ASSOCIATE_COMPLETION_PORT_CLASS(
                CompletionKey=1, CompletionPort=port)
            if not kernel32.SetInformationJobObject(
                    jh, JOB_OBJECT_ASSOCIATE_COMPLETION_PORT_INFORMATION,
                    ctypes.byref(assoc), ctypes.sizeof(assoc)):
                raise ProcwatchError(f"associate completion port: {last_error()}")

            cmdline = ctypes.create_unicode_buffer(build_command_line(app_path, args))
            if os.environ.get("CW_DEBUG_CMDLINE"):
                print(f"[debug] CreateProcessW cmdline: {cmdline.value!r}",
                      file=sys.stderr)
            app_name = ctypes.create_unicode_buffer(app_path)
            work_dir = ctypes.create_unicode_buffer(os.path.dirname(app_path))

            si = STARTUPINFOW()
            si.cb = ctypes.sizeof(STARTUPINFOW)
            pi = PROCESS_INFORMATION()

            # Suspended: the target cannot spawn anything until it is inside
            # the job.
            if not kernel32.CreateProcessW(
                    app_name, cmdline, None, None, False,
                    CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
                    None, work_dir, ctypes.byref(si), ctypes.byref(pi)):
                raise ProcwatchError(f"CreateProcess: {last_error()}")

            try:
                if not kernel32.AssignProcessToJobObject(jh, pi.hProcess):
                    raise ProcwatchError(f"AssignProcessToJobObject: {last_error()}")

                # Announce the target while it is still suspended, so an
                # observer is in place before it runs.
                if on_process is not None:
                    on_process(pi.dwProcessId)

                if kernel32.ResumeThread(pi.hThread) == 0xFFFFFFFF:
                    raise ProcwatchError(f"ResumeThread: {last_error()}")
            except BaseException:
                kernel32.TerminateProcess(pi.hProcess, 1)
                kernel32.CloseHandle(pi.hThread)
                kernel32.CloseHandle(pi.hProcess)
                raise

            session = Session(jh, port, pi.hProcess, pi.hThread,
                              pi.dwProcessId, app_path, on_process)
            ok = True
            return session
        finally:
            if not ok:
                kernel32.CloseHandle(port)
    finally:
        if not ok:
            kernel32.CloseHandle(jh)
