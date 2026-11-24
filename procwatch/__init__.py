"""Package procwatch launches a target executable inside a Windows Job Object
and observes the process tree it creates: the descendant processes, and the DLL
modules each of those processes loads.

Process discovery is event-driven via a job object wired to an I/O completion
port, so short-lived and deeply nested descendants are captured without polling
and without trusting a (spoofable) parent-PID field.

The package is Windows-only; importing it on any other platform raises.
"""

import sys

if sys.platform != "win32":  # pragma: no cover
    raise ImportError("procwatch is Windows-only")

from .session import ChildProcess, Session, launch_traced, ProcwatchError
from .modules import ProcDLL, loaded_modules
from .signature import is_signed
from .rwx import has_rwx_section
from .fileio import FileAccess, FileMonitor

__all__ = [
    "ChildProcess",
    "Session",
    "launch_traced",
    "ProcwatchError",
    "ProcDLL",
    "loaded_modules",
    "is_signed",
    "has_rwx_section",
    "FileAccess",
    "FileMonitor",
]
