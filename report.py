"""CLI: the indicator table and output formatting, rendered with rich."""

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from procwatch import ChildProcess, ProcDLL, is_signed, has_rwx_section

console = Console()
err_console = Console(stderr=True)


class Indicator:
    """One malware-indicator check applied to every PE in the observed process
    tree. flagged(path) reports whether a given PE exhibits the indicator; the
    remaining fields are the labels used when printing the result."""

    def __init__(self, title, exe_header, mod_header, none_msg, flagged):
        self.title = title        # table title when printing the result
        self.exe_header = exe_header  # column header for flagged process images
        self.mod_header = mod_header  # column header for flagged modules
        self.none_msg = none_msg  # printed when the indicator flags nothing
        self.flagged = flagged


def _unsigned(path):
    signed, err = is_signed(path)
    return not signed, err


# Indicators are run in order against every PE in the tree.
INDICATORS = [
    Indicator(
        title="Unsigned PEs",
        exe_header="Process image",
        mod_header="Module",
        none_msg="NO UNSIGNED PEs FOUND!!",
        flagged=_unsigned,
    ),
    Indicator(
        title="RWX PEs",
        exe_header="Process image",
        mod_header="Module",
        none_msg="NO RWX PEs FOUND!!",
        flagged=has_rwx_section,
    ),
]


class _PEFile:
    __slots__ = ("path", "processes", "is_module")

    def __init__(self, path):
        self.path = path
        self.processes: list[ChildProcess] = []
        self.is_module = False


class IndicatorResult:
    """What one indicator flagged over the whole tree."""
    __slots__ = ("exes", "mods", "checked", "paths")

    def __init__(self, exes: list[str], mods: set[str], checked: int,
                 paths: list[str]):
        self.exes = exes      # inventory keys of flagged process images
        self.mods = mods      # inventory keys of flagged modules
        self.checked = checked  # PEs successfully examined
        self.paths = paths    # full paths of every flagged PE, for follow-up
        # analysis such as the code-cave finder


class Scan:
    """The PE inventory of an observed process tree, indexed once so that
    every indicator can be evaluated without rebuilding it."""

    def __init__(self, procs: list[ChildProcess], mods: list[ProcDLL]):
        self.mods = mods
        self.files: dict[str, _PEFile] = {}  # keyed by lower-case path
        for p in procs:
            if not p.path:
                continue  # exited before its path could be read
            file = self._file(p.path.lower(), p.path)
            file.processes.append(p)
        for m in mods:
            if not m.dll_path:
                continue
            self._file(m.dll_path.lower(), m.dll_path).is_module = True

    def _file(self, key: str, path: str) -> _PEFile:
        file = self.files.get(key)
        if file is None:
            file = _PEFile(path)
            self.files[key] = file
        return file

    def paths(self) -> list[str]:
        return sorted(self.files)

    def evaluate(self, ind: Indicator, verbose: bool = False) -> IndicatorResult:
        """Evaluate one indicator over the whole tree and return what it
        flags, without printing anything. Evaluation and printing are split
        so a caller can compute a result it needs as input (the unsigned set
        feeds the cave finder) without having to display it."""
        flagged_mods: set[str] = set()
        flagged_exes: list[str] = []
        checked = 0

        for k in self.paths():
            file = self.files[k]
            try:
                hit, err = ind.flagged(file.path)
            except Exception as e:  # defensive: flagged returns (bool, err)
                hit, err = False, e
            if err is not None:
                if verbose:
                    err_console.print(f"  [skip] {file.path}: {err}")
                continue
            checked += 1
            if not hit:
                continue
            if file.processes:
                flagged_exes.append(k)
            if file.is_module:
                flagged_mods.add(k)

        return IndicatorResult(
            exes=flagged_exes, mods=flagged_mods, checked=checked,
            paths=[self.files[k].path
                   for k in sorted(set(flagged_exes) | flagged_mods)])

    def print_result(self, ind: Indicator, res: IndicatorResult,
                     verbose: bool) -> None:
        """Print an indicator's evaluated result."""
        if verbose:
            console.print(f"[dim]== {ind.title} "
                          f"({len(res.exes)} exe, {len(res.mods)} module, "
                          f"of {res.checked} checked) ==[/dim]")

        if not res.exes and not res.mods:
            console.print(f"[green]✔ {ind.none_msg}[/green]")
            return

        table = Table(
            title=ind.title,
            title_style="bold red",
            box=box.ROUNDED,
            header_style="bold",
        )
        table.add_column("Kind", no_wrap=True)
        table.add_column(ind.exe_header if res.exes else ind.mod_header,
                         style="bold", overflow="fold")
        table.add_column("Loaded by / instances", overflow="fold")

        if res.exes:
            for k in sorted(res.exes):
                file = self.files[k]
                insts = sorted(file.processes, key=lambda p: p.pid)
                pids = ", ".join(f"pid {p.pid}" for p in insts)
                table.add_row("[red]EXE[/red]", file.path, pids)
        if res.mods:
            grouped: dict[str, set[str]] = {}
            for m in self.mods:
                if not m.dll_path or m.dll_path.lower() not in res.mods:
                    continue
                grouped.setdefault(m.dll_path, set()).add(
                    f"{m.proc_name} (pid {m.pid})")
            for dll_path in sorted(grouped):
                loaded_by = ", ".join(sorted(grouped[dll_path]))
                table.add_row("[yellow]MODULE[/yellow]", dll_path, loaded_by)

        console.print(table)


# How many files each process reports without -v. A busy process touches
# hundreds of paths, so the default view keeps the largest few — the ones
# worth noticing when looking for staged or exfiltrated data.
FILE_ACCESS_TOP_N = 10


def print_file_access(monitor, mon_err: Exception | None,
                      procs: list[ChildProcess], mods: list[ProcDLL],
                      verbose: bool) -> None:
    """Report the non-PE files each process in the tree touched — the menu of
       payload staging candidates.

    PE files are removed entirely, by content rather than extension: the
    process's own image, its loaded modules, and any PE it merely opened.
    Staging inside another PE buys nothing — it inherits every detection
    surface this tool exists to sidestep — so those files belong to the
    module/cave analysis instead. Files that no longer exist cannot be
    content-checked and stay visible (a deleted file is itself interesting)."""
    if mon_err is not None:
        console.print(Panel(
            f"[yellow]⨯ {mon_err}[/yellow]\n"
            "[dim](an ETW trace session requires an elevated prompt)[/dim]",
            title=Text("FILE ACCESS UNAVAILABLE", style="bold yellow"),
            expand=False))
        return

    accesses = monitor.accessed_by(procs)

    pe_hidden = 0
    non_pe = []
    for a in accesses:
        if a.is_pe:
            pe_hidden += 1
        else:
            non_pe.append(a)
    accesses = non_pe

    grouped: dict[str, list] = {}
    order: list[str] = []
    total = 0
    for a in accesses:
        # Opening a directory is recorded like any other access, but it is
        # rarely what someone scanning for staging spots wants to see, and a
        # process that walks a tree buries its real file activity under them.
        if a.is_dir and not verbose:
            continue
        key = f"{a.proc_name} (pid {a.pid})"
        if key not in grouped:
            order.append(key)
            grouped[key] = []
        grouped[key].append(a)
        total += 1

    if total == 0:
        if pe_hidden:
            console.print(f"[green]✔ NO NON-PE FILE ACCESS RECORDED[/green] "
                          f"[dim]({pe_hidden} PE file(s) excluded)[/dim]")
        else:
            console.print("[green]✔ NO FILE ACCESS RECORDED.[/green]")
        return

    if verbose:
        console.print(f"[bold]FILES ACCESSED[/bold] "
                      f"[dim]({total} non-PE, including directories)[/dim]")
    else:
        console.print(f"[bold]FILES ACCESSED[/bold] "
                      f"[dim]({total} non-PE, largest {FILE_ACCESS_TOP_N} per "
                      f"process — use -v for all + directories)[/dim]")
    if pe_hidden:
        console.print(f"[dim]{pe_hidden} PE file(s) excluded — stage payloads "
                      f"in non-PE files[/dim]")

    for key in sorted(order):
        lst = grouped[key]
        # Largest first, so the interesting files lead. Directories and
        # unreadable paths carry -1 and sink to the bottom.
        lst.sort(key=lambda a: (-a.size, a.path))

        hidden = 0
        if not verbose and len(lst) > FILE_ACCESS_TOP_N:
            hidden = len(lst) - FILE_ACCESS_TOP_N
            lst = lst[:FILE_ACCESS_TOP_N]

        table = Table(title=key, title_style="bold cyan", box=box.SIMPLE,
                      pad_edge=False)
        table.add_column("Size", justify="right", no_wrap=True)
        table.add_column("Path", overflow="fold")
        table.add_column("Ops", no_wrap=True)
        for a in lst:
            table.add_row(_size_text(a), a.path, f"[dim]{a.ops}[/dim]")
        if hidden > 0:
            table.add_row("", f"[dim]... {hidden} more "
                              f"(use -v for all)[/dim]", "")
        console.print(table)


def _size_text(a):
    """The size column. Directories are marked as such, and a file with no
    size is one that could not be stat'd — deleted before the scan finished,
    or unreadable — which is itself worth noticing."""
    if a.is_dir:
        return Text("<DIR>", style="dim")
    if a.size < 0:
        return Text("?", style="yellow")
    return human_size(a.size)


def human_size(n: int) -> str:
    """Render a byte count compactly."""
    unit = 1024
    if n < unit:
        return f"{n} B"
    div, exp = unit, 0
    x = n // unit
    while x >= unit:
        x //= unit
        div *= unit
        exp += 1
    return f"{n / div:.1f} {'KMGTPE'[exp]}B"


def print_processes(secs: int, root: ChildProcess,
                    children: list[ChildProcess]) -> None:
    table = Table(title=f"Observed process tree — {secs}s watch window",
                  title_style="bold cyan", box=box.ROUNDED, header_style="bold")
    table.add_column("PID", justify="right", no_wrap=True)
    table.add_column("Role", no_wrap=True)
    table.add_column("Image", overflow="fold")

    table.add_row(str(root.pid), "[bold]target[/bold]", root.path)
    if not children:
        table.add_row("", "[dim]descendant[/dim]",
                      "[dim](none spawned in the window)[/dim]")
    for c in children:
        path = c.path if c.path else "[dim]<exited before path could be read>[/dim]"
        table.add_row(str(c.pid), "descendant", path)
    console.print(table)


def print_modules(mods: list[ProcDLL]) -> None:
    table = Table(
        title=f"DLLs loaded — target + descendants ({len(mods)} pairs)",
        title_style="bold cyan", box=box.ROUNDED, header_style="bold",
        show_lines=False)
    table.add_column("Process", no_wrap=True, style="bold")
    table.add_column("#", justify="right", no_wrap=True)
    table.add_column("Modules (alphabetical)", overflow="fold")

    if not mods:
        console.print(table)
        console.print("[dim]  (none still alive to inspect)[/dim]")
        return

    by_proc: dict[str, list[ProcDLL]] = {}
    order: list[str] = []
    for m in mods:
        key = f"{m.proc_name} (pid {m.pid})"
        if key not in by_proc:
            order.append(key)
            by_proc[key] = []
        by_proc[key].append(m)

    for key in sorted(order):
        lst = sorted(by_proc[key], key=lambda m: m.dll_name.lower())
        names = "\n".join(m.dll_name for m in lst)
        table.add_row(key, str(len(lst)), names)
    console.print(table)
