"""has_rwx_section: a static inspection of a PE's section table looking for any
section that is simultaneously writable and executable."""

import pefile

# Section characteristics (winnt.h).
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000


def has_rwx_section(path: str):
    """Report whether the PE at path contains any section that is
    simultaneously writable and executable (a W+X / "RWX" section).

    A file that ships with a writable-executable section is a classic malware
    indicator and the precondition for MockingJay-style injection: an attacker
    maps a benign DLL that already owns an RWX section and drops shellcode into
    it, so there is no VirtualAlloc/VirtualProtect call for an EDR to
    intercept.

    This is a static inspection of the on-disk section table, so it works
    whether or not the file is currently loaded. The error is non-None only
    when the file could not be parsed as a PE."""
    try:
        pe = pefile.PE(path, fast_load=True)
    except (pefile.PEFormatError, OSError) as e:
        return False, e
    try:
        for section in pe.sections:
            chars = section.Characteristics
            if chars & IMAGE_SCN_MEM_EXECUTE and chars & IMAGE_SCN_MEM_WRITE:
                return True, None
        return False, None
    finally:
        pe.close()
