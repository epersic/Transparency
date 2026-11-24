"""CLI: the code-cave finder. Goes through the unsigned PEs an analysis
flagged and searches their executable sections for caves — runs of filler
bytes (NUL / NOP / INT3 padding) — large enough to hold the shellcode."""

import re
from dataclasses import dataclass

import pefile
from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from procwatch.rwx import IMAGE_SCN_MEM_EXECUTE
from report import console

# Runs of filler shorter than this are not worth reporting even in verbose:
# every function boundary has a few bytes of alignment padding.
CAVE_BYTE_FLOOR = 8

# A cave is a contiguous run of any mix of these fillers. Alignment padding,
# int3 fences between functions and leftover buffers all qualify.
_FILLER = re.compile(rb"[\x00\x90\xcc]{%d,}" % CAVE_BYTE_FLOOR)


@dataclass
class Cave:
    """One contiguous filler region inside an executable section."""
    path: str
    section: str      # section name, e.g. ".text"
    va: int           # preferred load address of the cave (ImageBase + RVA)
    rva: int          # RVA of the cave within the image
    file_offset: int  # offset of the cave in the on-disk file
    size: int         # cave length in bytes


@dataclass
class FileCaves:
    """All caves found in one PE, with the numbers that decide target status."""
    path: str
    caves: list[Cave]

    @property
    def largest(self) -> int:
        return max((c.size for c in self.caves), default=0)

    @property
    def total(self) -> int:
        return sum(c.size for c in self.caves)

    def big_enough(self, shellcode_size: int) -> list[Cave]:
        """Caves that can hold the shellcode in one piece."""
        return [c for c in self.caves if c.size >= shellcode_size]


def find_caves(path: str):
    """Scan the executable sections of the PE at path for caves.

    Returns (FileCaves, error): error is non-None only when the file could
    not be parsed as a PE (it may have been deleted since the scan)."""
    try:
        pe = pefile.PE(path, fast_load=True)
    except (pefile.PEFormatError, OSError) as e:
        return None, e
    try:
        base = pe.OPTIONAL_HEADER.ImageBase
        caves: list[Cave] = []
        for s in pe.sections:
            if not s.Characteristics & IMAGE_SCN_MEM_EXECUTE:
                continue  # a cave in a non-executable section cannot host code
            if s.SizeOfRawData == 0:
                continue
            data = s.get_data()
            for m in _FILLER.finditer(data):
                off = m.start()
                size = m.end() - m.start()
                caves.append(Cave(
                    path=path,
                    section=s.Name.decode(errors="replace").rstrip("\x00"),
                    va=base + s.VirtualAddress + off,
                    rva=s.VirtualAddress + off,
                    file_offset=s.PointerToRawData + off,
                    size=size,
                ))
        caves.sort(key=lambda c: -c.size)
        return FileCaves(path=path, caves=caves), None
    finally:
        pe.close()


def print_cave_targets(paths: list[str], shellcode_size: int,
                       verbose: bool, fallback: bool = False) -> list:
    """Report which of the given PEs are viable injection targets: at least
    one cave able to hold the whole shellcode.

    Returns the list of qualifying FileCaves, so a caller can decide whether
    to try the signed-PE fallback. With fallback=True the paths are signed
    PEs and the report leads with the signature-breakage warning."""
    header = (f"CODE-CAVE TARGETS — shellcode is {shellcode_size} bytes")
    if fallback:
        console.print(Panel(
            "[yellow]No unsigned PE had a cave big enough, so the signed PEs "
            "are analysed too.[/yellow]\n"
            "[bold yellow]Patching a signed PE breaks its Authenticode "
            "signature:[/bold yellow] the file will fail signature validation "
            "from then on — exactly what the Unsigned indicator screens for. "
            "For catalog-signed OS files, hash mismatch also means WFP/SFC may "
            "restore or flag the modified file.",
            title=Text("SIGNED-PE FALLBACK", style="bold yellow"),
            expand=False))
        header = (f"CODE-CAVE TARGETS — signed PEs (patching breaks the "
                  f"signature) — shellcode is {shellcode_size} bytes")

    if not paths:
        console.print(header, style="bold")
        console.print("[green]✔ no unsigned PEs — nothing to search for caves[/green]")
        return []

    results = [find_caves(path) for path in paths]
    targets = [(fc, err) for fc, err in results if fc and fc.big_enough(shellcode_size)]
    others = [(fc, err) for fc, err in results if not (fc and fc.big_enough(shellcode_size))]

    if targets:
        table = Table(title=header, title_style="bold magenta",
                      box=box.ROUNDED, header_style="bold")
        table.add_column("File", overflow="fold", style="bold")
        table.add_column("Section", no_wrap=True)
        table.add_column("VA", justify="right", no_wrap=True)
        table.add_column("File offset", justify="right", no_wrap=True)
        table.add_column("Cave size", justify="right", no_wrap=True, style="green")
        table.add_column("Slack", justify="right", no_wrap=True)
        for fc, _ in targets:
            for c in fc.big_enough(shellcode_size):
                table.add_row(
                    fc.path,
                    c.section,
                    hex(c.va),
                    hex(c.file_offset),
                    human_bytes(c.size),
                    human_bytes(c.size - shellcode_size),
                )
        console.print(table)
    else:
        console.print(header, style="bold")
        console.print("[yellow]⨯ no single cave fits the whole shellcode "
                      "in any " + ("scanned PE" if fallback else "unsigned PE")
                      + "[/yellow]")
        # Say how close it was, so "doesn't fit" is actionable rather than
        # a dead end: the largest cave that exists anywhere in the scanned
        # files is the ceiling for the single-cave strategy.
        viable = [(fc.largest, fc.path) for fc, _ in results if fc and fc.caves]
        if viable:
            largest, where = max(viable)
            console.print(f"[dim]largest cave anywhere: "
                          f"{human_bytes(largest)} in {where}[/dim]")

    # Files that only make sense if the shellcode is split across caves —
    # see the README for the splitting vs staging discussion. In the signed
    # fallback this tail is usually dozens of system files, so it stays
    # hidden unless verbose.
    if others and (verbose or not fallback):
        console.print("[dim]not viable as a single-cave target:[/dim]")
        for fc, err in others:
            if fc is None:
                what = str(err) if verbose else "<unparsable PE>"
                console.print(f"    [red]✗ {what}[/red]")
                continue
            console.print(f"    [dim]✗ {fc.path} — largest cave "
                          f"{human_bytes(fc.largest)}, total "
                          f"{human_bytes(fc.total)} across "
                          f"{len(fc.caves)} cave(s)[/dim]")

    if verbose:
        # A full listing of every ≥8-byte run would be thousands of rows of
        # alignment padding; the detail table keeps the caves big enough to
        # possibly matter and summarises the rest.
        floor = max(64, min(shellcode_size, 1024))
        detail = Table(title=f"All caves ≥ {floor} B", title_style="dim",
                       box=box.SIMPLE, pad_edge=False)
        detail.add_column("File", overflow="fold")
        detail.add_column("Section", no_wrap=True)
        detail.add_column("RVA", justify="right", no_wrap=True)
        detail.add_column("Size", justify="right", no_wrap=True)
        small = 0
        for fc, _ in results:
            if fc is None:
                continue
            for c in fc.caves:
                if c.size >= floor:
                    detail.add_row(fc.path, c.section, hex(c.rva), human_bytes(c.size))
                else:
                    small += 1
        if detail.rows:
            console.print(detail)
        if small:
            console.print(f"[dim]... plus {small} smaller cave(s) below the "
                          f"{floor} B floor[/dim]")

    return [fc for fc, _ in targets]


def human_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    return f"{n / 1024:.1f} KB"
