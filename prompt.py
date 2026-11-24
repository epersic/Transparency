"""CLI: the interactive menu, shown when no path was given on the command
line. questionary renders the prompts (with path completion for the target),
rich renders the banner."""

import os
import sys

import questionary
from rich.console import Console
from rich.panel import Panel
from rich.style import Style
from rich.text import Text

console = Console()

BANNER_STYLE = Style(color="#ff5fd7", bold=True)  # lipgloss color 212
SUBTLE_STYLE = Style(dim=True)


def ask_config():
    """The interactive menu: ask which executable to analyse, where the
    shellcode to stage lives (optional), for how long, and how verbose the
    report should be.

    Returns (target, shellcode, secs, verbose). Raises EOFError when there is
    no interactive terminal to prompt on; returns (None, None, 0, False) when
    the user cancels at a prompt (Esc / Ctrl+C)."""
    if not sys.stdin.isatty():
        raise EOFError("no interactive terminal to prompt on")
    banner()

    try:
        # 1. What to analyse. questionary's path question gives tab-completion,
        #    so typing a long Windows path stays painless.
        target = questionary.path(
            "Application to analyse",
            validate=lambda s: True if validate_target(s) is None else validate_target(s),
            qmark="❯",
        ).ask()
        if target is None:
            return None, None, 0, False  # cancelled
        target = clean_path(target)

        # 2. The shellcode to stage, if cave analysis is wanted. Its size is
        #    what decides which unsigned PEs count as targets.
        shellcode = questionary.text(
            "Shellcode to stage (leave empty to skip cave analysis)",
            validate=_shellcode_or_empty,
            qmark="❯",
        ).ask()
        if shellcode is None:
            return None, None, 0, False
        shellcode = clean_path(shellcode)

        # 3. How long to watch it.
        secs = questionary.text(
            "Watch window (seconds)",
            default="10",
            validate=_positive_int,
            qmark="❯",
        ).ask()
        if secs is None:
            return None, None, 0, False
        secs = int(secs)

        # 4. How much to print.
        verbose = questionary.confirm(
            "Verbose output? (full process, module and file listings)",
            default=False,
            qmark="❯",
        ).ask()
        if verbose is None:
            return None, None, 0, False
    except EOFError:
        raise
    except Exception as e:  # e.g. mintty/xterm: no Windows console to render on
        raise EOFError(
            f"cannot show the interactive menu in this terminal ({e}); "
            "run from cmd.exe / PowerShell / Windows Terminal, or pass the "
            "path directly") from e

    console.print()
    return target, shellcode, secs, bool(verbose)


def _shellcode_or_empty(s: str):
    s = s.strip()
    if not s:
        return True  # empty == skip cave analysis
    if not os.path.exists(s):
        return "no file at that path (or leave empty to skip)"
    if os.path.isdir(s):
        return "that is a directory, not a shellcode file"
    if os.path.getsize(s) == 0:
        return "that file is empty"
    return True


def _positive_int(s: str):
    s = s.strip()
    if not s:
        return "enter a number of seconds"
    try:
        n = int(s)
    except ValueError:
        return "that is not a number"
    if n <= 0:
        return "the watch window must be at least 1 second"
    return True


def banner() -> None:
    console.print(Text("childwatch", style=BANNER_STYLE))
    console.print(Text("launch a program, then watch what it spawns, loads and touches",
                       style=SUBTLE_STYLE))
    console.print()


def cancelled_panel(target: str) -> None:
    console.print(Panel(f"[dim]analysis of {target} cancelled at the prompt[/dim]"))


def clean_path(s: str) -> str:
    """Tolerate the shapes a Windows path arrives in: padded with whitespace,
    and wrapped in the quotes that "Copy as path" adds."""
    return s.strip().strip('"\'').strip()


def validate_target(s: str) -> str | None:
    """Check the path as it is typed, so a mistake is caught in the menu
    rather than after the analysis has already started. Returns None when the
    path is acceptable, else the problem."""
    s = clean_path(s)
    if not s:
        return "a path is required"
    if not os.path.exists(s):
        return "no file at that path"
    if os.path.isdir(s):
        return "that is a directory, not an executable"
    return None
