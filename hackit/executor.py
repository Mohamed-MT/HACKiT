"""
Command execution.

This is the only module that ever calls subprocess against a tool
command, and it refuses to do so unless hackit.safety has approved
the action first. Output streams live to the terminal so the user
can see exactly what's happening and interrupt (Ctrl+C) at any time.

Security notes:
- subprocess.Popen is always called with an argv list, never
  shell=True, so shell metacharacters in a user-supplied value
  (;, |, $(...), backticks, &&, ...) are passed as a single literal
  argument to the target tool, not interpreted by a shell. This is
  a deliberate, load-bearing safety property, not an oversight —
  don't "fix" it by switching to shell=True for convenience.
- Any dynamic (user- or tool-controlled) text that reaches
  console.print()/Panel() is escaped with rich.markup.escape()
  first. Rich interprets [tags] in printed strings by default;
  without escaping, a value typed into a command placeholder could
  inject terminal styling or a clickable [link=...] — not RCE, but
  real terminal-spoofing risk in a tool whose whole job is showing
  you exactly what's about to run.
"""
from __future__ import annotations

import shlex
import subprocess  # nosec B404 — required to run the pentest tools HACKiT recommends; see module docstring
import sys

from rich.console import Console
from rich.markup import escape as _esc

from hackit.knowledge import ToolInfo
from hackit.safety import confirm_command, log_action

console = Console()


def run_command(tool: ToolInfo, command: str) -> int | None:
    """
    Requests approval via hackit.safety, then runs the command with
    live output streaming. Returns the process return code, or None
    if the user declined, the command couldn't be parsed/started, or
    nothing was ever executed.
    """
    approved = confirm_command(tool, command)
    if not approved:
        console.print("[yellow]Not running that — staying in explanation-only mode for this command.[/]")
        log_action(tool.name, command, approved=False)
        return None

    try:
        args = shlex.split(command)
    except ValueError as e:
        console.print(f"[red]Couldn't parse that command ({_esc(str(e))}).[/]")
        log_action(tool.name, command, approved=True, output_summary="parse_error")
        return None

    if not args:
        console.print("[red]Empty command — nothing to run.[/]")
        log_action(tool.name, command, approved=True, output_summary="empty_command")
        return None

    console.print(f"\n[bold cyan]$ {_esc(command)}[/]\n")

    proc: subprocess.Popen | None = None
    try:
        proc = subprocess.Popen(  # nosec B603 — argv list from shlex.split, shell=True never used; see module docstring
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        if proc.stdout is None:
            # Can't happen with stdout=PIPE, but don't rely on assert
            # (stripped under python -O) for something that gates a
            # real code path.
            raise RuntimeError("subprocess started without a readable stdout pipe")
        for line in proc.stdout:
            sys.stdout.write(line)
        proc.wait()
    except FileNotFoundError:
        console.print(
            f"[red]'{_esc(args[0])}' isn't installed or not on PATH.[/] "
            f"Try: [bold]sudo apt install {_esc(tool.package)}[/]"
        )
        log_action(tool.name, command, approved=True, output_summary="not_found")
        return None
    except PermissionError:
        console.print(f"[red]Permission denied running '{_esc(args[0])}'.[/] Check the binary is executable.")
        log_action(tool.name, command, approved=True, output_summary="permission_denied")
        return None
    except KeyboardInterrupt:
        if proc is not None:
            proc.terminate()
        console.print("\n[yellow]Interrupted — process stopped.[/]")
        log_action(tool.name, command, approved=True, output_summary="interrupted")
        return None
    except OSError as e:
        console.print(f"[red]Couldn't start that command: {_esc(str(e))}[/]")
        log_action(tool.name, command, approved=True, output_summary="os_error")
        return None

    console.print(f"\n[dim]Process exited with code {proc.returncode}[/]")
    log_action(tool.name, command, approved=True, output_summary=f"exit={proc.returncode}")
    return proc.returncode
