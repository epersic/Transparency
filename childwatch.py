"""Command childwatch launches a target executable, observes the processes it
spawns and the DLLs those processes load, then screens every PE involved —
the process images themselves and their loaded modules — for malware
indicators.

    python childwatch.py [-v] [-t PATH] [-w N] [-s FILE] [path-to-exe] [seconds] [args...]

Run with no path and childwatch shows an interactive menu that asks which
application to analyse, which shellcode to stage (optional), for how long,
and how verbose the report should be. Every input can also be passed as
flags — -t/--target, -w/--watch, -s/--shellcode, -v/--verbose — which
bypasses the menu entirely.

Each indicator prints the PEs it flags in its own table: process images and
modules grouped by the process that loaded them. An indicator that flags
nothing prints a "NO ... FOUND!!" line instead. With -v/--verbose the full
spawned-process list and per-process loaded-DLL breakdown are printed as well.

The launched target itself is included in the scan, in addition to every
process it spawns, so an unsigned or RWX sample is flagged on its own.
"""

import os
import sys
import threading
import time

from rich.progress import (BarColumn, Progress, TaskProgressColumn,
                           TextColumn, TimeElapsedColumn)

from caves import print_cave_targets
from prompt import ask_config, clean_path
from proxygen import run_proxy_flow
from staging import run_staging_flow
from procwatch import (
    FileMonitor,
    ProcwatchError,
    launch_traced,
    loaded_modules,
)
from report import INDICATORS, Scan, print_file_access, print_modules, print_processes
from report import console

DEFAULT_WATCH_SECONDS = 10

# Report sections selectable via flags. With none given, the default set is
# shown (everything, with tree/modules only in verbose); passing any section
# flag shows *only* the named sections.
SECTION_FLAGS = {
    "--tree": "tree",
    "--processes": "tree",
    "--modules": "modules",
    "--unsigned": "unsigned",
    "--rwx": "rwx",
    "--caves": "caves",
    "--files": "files",
}
SECTION_KEYS = ("tree", "modules", "unsigned", "rwx", "caves", "files")


def usage() -> None:
    name = "childwatch.py"
    print(f"usage: {name} [-v] [-t PATH] [-w N] [-s FILE] [--proxy ...] [SECTION ...] [path-to-exe] [seconds] [args...]\n",
          file=sys.stderr)
    print(f"Run with no path and {name} shows an interactive menu.\n",
          file=sys.stderr)
    print("  -v, --verbose            full process, module and file listings",
          file=sys.stderr)
    print("  -t, --target PATH        application to analyse (bypasses the menu)",
          file=sys.stderr)
    print("  -w, --watch N            watch window in seconds (default 10)",
          file=sys.stderr)
    print("  -s, --shellcode FILE     size-check code caves against this shellcode",
          file=sys.stderr)
    print("      --proxy PATH          generate a proxy-DLL scaffold for this DLL",
          file=sys.stderr)
    print("      --proxy-dir DIR        where to write the scaffold (default cwd)",
          file=sys.stderr)
    print("      --proxy-name NAME      renamed copy of the legit DLL "
          "(default <stem>_orig.dll)", file=sys.stderr)
    print("      --proxy-style STYLE    forward (default) or call — export "
          "forwarders vs real", file=sys.stderr)
    print("                             wrapper functions calling the original",
          file=sys.stderr)
    print("      --proxy-junk           add benign decoy code to the proxy",
          file=sys.stderr)
    print("      --payload-obj PATH     link this loader object into the proxy;",
          file=sys.stderr)
    print("                             it must define invoke_payload(), called",
          file=sys.stderr)
    print("                             from payload() at DLL_PROCESS_ATTACH",
          file=sys.stderr)
    print("      --no-build             leave the scaffold uncompiled (default:",
          file=sys.stderr)
    print("                             run make and print the DLL path)",
          file=sys.stderr)
    print("      --stage PATH           stage the payload inside this carrier",
          file=sys.stderr)
    print("                             file (from the file-access report)",
          file=sys.stderr)
    print("      --stage-c DIR          folder for the generated payload_staged.c", file=sys.stderr)
    print("      --stage-h DIR          folder for the generated payload_staged.h", file=sys.stderr)
    print("      --stage-map DIR        root of the test mapping (the app's", file=sys.stderr)
    print("                             folder; carrier copy + payload there)", file=sys.stderr)
    print("      --stage-rel PATH       carrier path relative to the app folder", file=sys.stderr)
    print("                             (default: auto-computed)", file=sys.stderr)
    print("  -h, --help               this message\n", file=sys.stderr)
    print("Sections — show only what you ask for:", file=sys.stderr)
    print("  --tree                   the observed process tree (aka --processes)",
          file=sys.stderr)
    print("  --modules                per-process DLL listing", file=sys.stderr)
    print("  --unsigned               the Unsigned PEs indicator", file=sys.stderr)
    print("  --rwx                    the RWX PEs indicator", file=sys.stderr)
    print("  --caves                  code-cave targets (needs -s)", file=sys.stderr)
    print("  --files                  the file-access staging listing\n",
          file=sys.stderr)
    print("With no section flags every section is shown (tree and modules only",
          file=sys.stderr)
    print("with -v); passing any of them shows only those sections.\n",
          file=sys.stderr)
    print("Everything can be flags: "
          f"{name} -t app.exe -w 15 -s sc.bin --unsigned --caves",
          file=sys.stderr)
    print("With -t every positional argument is passed to the target; "
          "without it the first", file=sys.stderr)
    print("positional is the target path and a following number is the watch "
          "window.", file=sys.stderr)


def parse_args(args: list[str]):
    """Split childwatch's own flags from the target and the arguments
    forwarded to it. Flags are only recognised before the first positional
    (or before a bare "--", which ends flag parsing); everything after the
    target belongs to the target.

    Every input can be passed as a flag — -t/-w/-s/-v — which bypasses the
    interactive menu entirely. With -t, every positional argument belongs to
    the target (no legacy positional-seconds parsing); -w always wins over a
    positional seconds value.

    Returns (verbose, target, secs, target_args, shellcode, watch_explicit,
    sections, proxy_cfg); target is empty when the caller should show the
    interactive menu, sections is None when the caller should use the default
    set, and proxy_cfg is (proxy, proxy_dir, proxy_name, proxy_style,
    proxy_junk, payload_obj, build, stage, stage_c,
                   stage_h, stage_map, stage_rel)."""
    verbose = False
    shellcode = ""
    target_flag = ""
    watch = None
    sections: set[str] | None = None
    proxy = proxy_dir = proxy_name = ""
    proxy_style = ""
    proxy_junk = False
    payload_obj = None
    build = True
    stage = stage_c = stage_h = stage_map = stage_rel = ""

    while args and args[0].startswith("-") and args[0] != "--":
        name = args[0]
        inline = None
        if name.startswith("--") and "=" in name:
            name, inline = name.split("=", 1)

        def take_value(what):
            """Consume this flag's value, honouring the --flag=value form."""
            if inline is not None:
                args.pop(0)
                return inline
            if len(args) < 2:
                print(f"{name}: missing {what}", file=sys.stderr)
                usage()
                sys.exit(2)
            value = args[1]
            del args[:2]
            return value

        if name in ("-v", "--verbose"):
            verbose = True
            args = args[1:]
        elif name in SECTION_FLAGS:
            if sections is None:
                sections = set()
            sections.add(SECTION_FLAGS[name])
            args = args[1:]
        elif name in ("--proxy", "--proxy-dir", "--proxy-name"):
            what = {"--proxy": "DLL path",
                    "--proxy-dir": "output folder",
                    "--proxy-name": "renamed DLL name"}[name]
            value = take_value(what)
            if name == "--proxy":
                proxy = clean_path(value)
            elif name == "--proxy-dir":
                proxy_dir = clean_path(value)
            else:
                proxy_name = clean_path(value)
        elif name == "--proxy-style":
            proxy_style = take_value("export style").strip().lower()
            if proxy_style not in ("forward", "call"):
                print(f"--proxy-style: expected 'forward' or 'call', "
                      f"got {proxy_style!r}", file=sys.stderr)
                sys.exit(2)
        elif name == "--proxy-junk":
            proxy_junk = True
            args = args[1:]
        elif name == "--payload-obj":
            payload_obj = clean_path(take_value("loader object path"))
        elif name == "--no-build":
            build = False
            args = args[1:]
        elif name == "--stage":
            stage = clean_path(take_value("carrier file path"))
        elif name == "--stage-c":
            stage_c = clean_path(take_value("payload_staged.c folder"))
        elif name == "--stage-h":
            stage_h = clean_path(take_value("payload_staged.h folder"))
        elif name == "--stage-map":
            stage_map = clean_path(take_value("test mapping root folder"))
        elif name == "--stage-rel":
            stage_rel = take_value("relative carrier path")
        elif name in ("-t", "--target"):
            target_flag = clean_path(take_value("target path"))
        elif name in ("-s", "--shellcode"):
            shellcode = clean_path(take_value("shellcode path"))
        elif name in ("-w", "--watch"):
            raw = take_value("watch window in seconds")
            try:
                watch = int(raw)
            except ValueError:
                print(f"-w/--watch: {raw!r} is not a number", file=sys.stderr)
                sys.exit(2)
            if watch <= 0:
                print("-w/--watch: the watch window must be at least 1 second",
                      file=sys.stderr)
                sys.exit(2)
        elif name in ("-h", "--help"):
            usage()
            sys.exit(0)
        else:
            print(f"unknown flag: {name}", file=sys.stderr)
            usage()
            sys.exit(2)
    if args and args[0] == "--":
        args = args[1:]  # everything after -- is positional, even flags

    watch_explicit = watch is not None
    secs = watch if watch is not None else DEFAULT_WATCH_SECONDS

    if target_flag:
        # Flag-driven run: no menu, and positionals are purely target args.
        return (verbose, target_flag, secs, list(args), shellcode,
                watch_explicit, sections,
                (proxy, proxy_dir, proxy_name, proxy_style, proxy_junk,
                 payload_obj, build, stage, stage_c, stage_h,
                 stage_map, stage_rel))

    if not args:
        # Nothing positional and no -t: show the interactive menu instead.
        return (verbose, "", secs, [], shellcode, watch_explicit, sections,
                (proxy, proxy_dir, proxy_name, proxy_style, proxy_junk,
                 payload_obj, build, stage, stage_c, stage_h,
                 stage_map, stage_rel))

    # Legacy positional form: [path-to-exe] [seconds] [args...].
    target = clean_path(args[0])
    target_args = args[1:]
    if target_args and watch is None:
        try:  # Atoi semantics: an optional sign then digits
            secs = int(target_args[0])
            target_args = target_args[1:]
        except ValueError:
            pass
    return (verbose, target, secs, target_args, shellcode, watch_explicit,
            sections, (proxy, proxy_dir, proxy_name, proxy_style, proxy_junk,
                       payload_obj, build, stage, stage_c, stage_h,
                       stage_map, stage_rel))


def collect_with_progress(session, secs: float, target: str):
    """Run the blocking collect on a worker thread while a progress bar marks
    the watch window; the bar's description counts the processes seen so far."""
    result = {}

    def worker():
        try:
            result["children"] = session.collect(secs)
        except BaseException as e:  # re-raised on the main thread below
            result["error"] = e

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

    with Progress(
        TextColumn("[bold blue]watching[/] {task.fields[name]}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        TextColumn("[dim]{task.fields[procs]} process(es)[/dim]"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("", total=float(secs),
                                 name=_short_name(target), procs=1)
        start = time.monotonic()
        while thread.is_alive():
            elapsed = min(time.monotonic() - start, secs)
            seen = 1 + len(session.children())
            progress.update(task, completed=elapsed, procs=seen)
            time.sleep(0.1)
        progress.update(task, completed=float(secs),
                        procs=1 + len(session.children()))

    if "error" in result:
        raise result["error"]
    return result["children"]


def _short_name(path: str) -> str:
    name = path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    return name if name else path


def main() -> int:
    (verbose, target, secs, target_args, shellcode, watch_explicit,
     sections, (proxy, proxy_dir, proxy_name, proxy_style,
                proxy_junk, payload_obj, build, stage, stage_c,
                stage_h, stage_map, stage_rel)) = parse_args(sys.argv[1:])

    # No path on the command line: show the interactive menu.
    if not target:
        try:
            target, menu_shellcode, menu_secs, menu_verbose = ask_config()
        except EOFError as e:
            if str(e):
                print("error:", e, file=sys.stderr)
            print("(no interactive terminal? pass the path directly: "
                  "childwatch.py <path-to-exe>)", file=sys.stderr)
            return 1
        except KeyboardInterrupt:
            return 130  # cancelled at the menu
        if target is None:
            return 130  # cancelled at a prompt
        shellcode = shellcode or menu_shellcode
        if not watch_explicit:
            secs = menu_secs  # an explicit -w outranks the menu answer
        verbose = verbose or menu_verbose

    # The shellcode's size is what decides which unsigned PEs are targets.
    shellcode_size = None
    if shellcode:
        try:
            shellcode_size = os.path.getsize(shellcode)
        except OSError as e:
            print(f"error: cannot read shellcode {shellcode}: {e}",
                  file=sys.stderr)
            return 1
        if shellcode_size == 0:
            print(f"error: shellcode {shellcode} is empty", file=sys.stderr)
            return 1

    # File tracing must be running before the target executes anything, so
    # the monitor is started first. It needs elevation; without it the run
    # simply continues without the file-access section.
    monitor = None
    mon_err = None
    try:
        monitor = FileMonitor()
    except Exception as e:  # PermissionError when not elevated, etw failures
        mon_err = e

    session = None
    try:
        track = monitor.track if monitor is not None else (lambda pid: None)

        # The monitor filters by PID, so every process in the tree is
        # registered as it appears — the target before it is resumed, children
        # as they spawn.
        try:
            session = launch_traced(track, target, target_args)
        except ProcwatchError as e:
            print("error:", e, file=sys.stderr)
            return 1

        try:
            children = collect_with_progress(session, float(secs), target)
        except ProcwatchError as e:
            print("error:", e, file=sys.stderr)
            return 1

        # Scan the whole tree: the launched target plus every descendant.
        # Modules must be read while those processes are still alive, i.e.
        # before close.
        root = session.root()
        procs = [root, *children]
        mods = loaded_modules(procs)
        scan = Scan(procs, mods)

        # Which report sections to show: the default set, or exactly what
        # the section flags asked for.
        if sections is None:
            show = {"unsigned", "rwx", "caves", "files"}
            if verbose:
                show |= {"tree", "modules"}
        else:
            show = sections

        printed = [False]

        def section():
            """Blank line between sections, none before the first."""
            if printed[0]:
                console.print()
            printed[0] = True

        if "tree" in show:
            section()
            print_processes(secs, root, children)
        if "modules" in show:
            section()
            print_modules(mods)

        # Indicators: evaluate only what is shown, plus the unsigned set when
        # the cave section needs it as input (without displaying it).
        unsigned_paths: list[str] = []
        unsigned_eval = False
        for ind in INDICATORS:
            key = "unsigned" if ind.title == "Unsigned PEs" else "rwx"
            visible = key in show
            needed = visible or (key == "unsigned" and "caves" in show)
            if not needed:
                continue
            res = scan.evaluate(ind, verbose)
            if key == "unsigned":
                unsigned_paths = res.paths
                unsigned_eval = True
            if visible:
                section()
                scan.print_result(ind, res, verbose)

        if "caves" in show:
            if shellcode_size is not None:
                # The unsigned PEs are the patchable ones — see which can
                # hide the shellcode in a code cave.
                section()
                unsigned_lower = {p.lower() for p in unsigned_paths}
                targets = print_cave_targets(unsigned_paths, shellcode_size,
                                             verbose)
                if not targets:
                    # No unsigned PE fits the shellcode: fall back to the
                    # signed PEs, with the signature-breakage warning.
                    signed_paths = [scan.files[k].path for k in scan.paths()
                                    if k not in unsigned_lower]
                    if signed_paths:
                        print_cave_targets(signed_paths, shellcode_size,
                                           verbose, fallback=True)
            else:
                section()
                console.print("[dim]code-cave analysis skipped — give a "
                              "shellcode (-s FILE, or answer the menu prompt) "
                              "to size-check caves in the unsigned PEs[/dim]")

        if "files" in show:
            section()
            if monitor is not None and mon_err is None:
                # Real-time ETW buffers flush lazily (~1 s), so the target's
                # final moments of file activity arrive after collect()
                # returns. Give them time to land before the report snapshot.
                monitor.settle()
            if os.environ.get("CW_DEBUG_FILES") and monitor is not None:
                with monitor._lock:
                    for p_, files_ in monitor._files.items():
                        print(f"[debug] pid {p_}: {len(files_)} rows",
                              file=sys.stderr)
                        for path_, ops_ in sorted(files_.items()):
                            print(f"[debug]   {ops_:#x} {path_}",
                                  file=sys.stderr)
            print_file_access(monitor, mon_err, procs, mods, verbose)
            # Payload staging: offered whenever the file report ran.  The
            # original carrier is never modified — childwatch writes the
            # staged copy into the test mapping itself.
            if monitor is not None and mon_err is None:
                if stage or sys.stdin.isatty():
                    run_staging_flow(monitor, procs, shellcode, stage,
                                     stage_c, stage_h, stage_map,
                                     stage_rel)

        # Proxy-DLL scaffold: driven by --proxy flags, or asked interactively
        # — but only when the run actually surfaced module-level data
        # (modules / unsigned / rwx / caves).  A pure tree/files run never
        # looked at DLLs, so asking which to proxy is noise.
        module_sections = show & {"modules", "unsigned", "rwx", "caves"}
        if proxy or (sys.stdin.isatty() and module_sections):
            run_proxy_flow(mods, proxy, proxy_dir, proxy_name,
                           proxy_style, proxy_junk, payload_obj, build,
                           unsigned_paths=set(unsigned_paths) if unsigned_eval
                           else None)
        return 0
    finally:
        if session is not None:
            session.close()
        if monitor is not None:
            monitor.stop()


if __name__ == "__main__":
    sys.exit(main())
