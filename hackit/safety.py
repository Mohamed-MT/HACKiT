"""
Safety and authorization gating.

HACKiT must never run a scan, enumeration, or exploitation command on
the user's behalf without explicit, informed approval, and it must
help the user stay mindful of authorization/scope. This module is the
single place that logic lives, so every execution path goes through
it — hackit.executor refuses to run anything that didn't come through
here.

Two layers:
  1. Session-level scope acknowledgment: once per session, before the
     first command that touches a target, the user states they are
     authorized to test the scope they're about to work against.
  2. Per-command approval: every single command is shown in full,
     with its risk level, and must be explicitly approved — "run
     everything" / silent-approval modes do not exist.

Security note: any dynamic text (the built command, which may contain
user-typed placeholder values; a user-typed tool/category name from
elsewhere in the CLI) is passed through rich.markup.escape() before
being interpolated into an f-string handed to console.print()/Panel().
Rich treats [tags] in printed text as live markup, so unescaped
dynamic content could inject styling or a clickable [link=...] into
the terminal — not code execution, but real spoofing risk in a tool
whose entire job is showing you, trustworthily, what's about to run.
"""
from __future__ import annotations

import datetime as _dt
import os
import stat
from dataclasses import dataclass

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.markup import escape as _esc

from hackit.knowledge import RiskLevel, ToolInfo

console = Console()


@dataclass
class SessionScope:
    acknowledged: bool = False
    scope_statement: str = ""
    acknowledged_at: str | None = None


_session_scope = SessionScope()


SCOPE_NOTICE = (
    "HACKiT is a tool-selection and guidance assistant. Before it will help you "
    "stage a command that touches a network target (scanning, enumeration, "
    "exploitation, password attacks, or wireless attacks), it needs a quick "
    "acknowledgment that you are authorized to test that target — e.g. it's "
    "your own lab/system, or you have explicit written permission (a signed "
    "scope of work, bug-bounty program rules, CTF rules, etc.). Unauthorized "
    "access to systems you don't own or have permission to test is illegal in "
    "most jurisdictions."
)


def ensure_session_scope() -> bool:
    """
    Ensures the user has acknowledged authorization for this session.
    Returns True if acknowledged (now or previously), False if the
    user declines — callers must not proceed to execution if False.
    """
    if _session_scope.acknowledged:
        return True

    console.print(Panel(SCOPE_NOTICE, title="[bold yellow]Authorization check[/]", border_style="yellow"))
    confirmed = Confirm.ask(
        "[bold]Do you confirm you are authorized to test the target(s) you'll work with this session?[/]",
        default=False,
    )
    if not confirmed:
        console.print("[red]Understood — HACKiT will stay in explanation-only mode until you confirm authorization.[/]")
        return False

    statement = Prompt.ask(
        "[dim]Briefly describe the authorized scope (e.g. 'my home lab 10.10.10.0/24', "
        "'ACME engagement per signed SOW')[/]",
        default="unspecified",
    )
    _session_scope.acknowledged = True
    _session_scope.scope_statement = statement
    _session_scope.acknowledged_at = _dt.datetime.now().isoformat(timespec="seconds")
    console.print("[green]Thanks — logged for this session. You remain responsible for staying within that scope.[/]\n")
    return True


def current_scope() -> SessionScope:
    return _session_scope


def confirm_command(tool: ToolInfo, command: str) -> bool:
    """
    Per-command approval gate. Always shown, regardless of risk level
    — HIGH-risk tools (exploitation, brute force, wireless injection)
    get an extra explicit scope reminder and require typing the
    command's tool name back, not just Enter/'y', to reduce
    rubber-stamping dangerous actions.
    """
    style = {
        RiskLevel.PASSIVE: "green",
        RiskLevel.LOW: "cyan",
        RiskLevel.MEDIUM: "yellow",
        RiskLevel.HIGH: "red",
    }[tool.risk]

    console.print(
        Panel(
            f"[bold]{_esc(command)}[/]\n\n[dim]Risk: {_esc(tool.risk_label())}[/]",
            title=f"[bold]Ready to run: {_esc(tool.name)}[/]",
            border_style=style,
        )
    )

    if tool.requires_target_auth and not _session_scope.acknowledged:
        if not ensure_session_scope():
            return False

    if tool.risk == RiskLevel.HIGH:
        console.print(
            f"[bold red]{_esc(tool.name)} is HIGH risk (exploitation / brute-force / injection). "
            f"This can lock out accounts, crash services, or alter a target.[/]"
        )
        typed = Prompt.ask(f"Type the tool name [bold]{_esc(tool.name)}[/] to confirm you want to run this")
        return typed.strip().lower() == tool.name.lower()

    return Confirm.ask("Run this command now?", default=False)


def log_action(tool_name: str, command: str, approved: bool, output_summary: str = "") -> None:
    """
    Appends a local audit-trail line for an approved/declined action.

    Honors the user's log_sessions preference (default on). Note that
    `command` may contain values the user typed in — including, if
    they chose to type one inline rather than use a wordlist file, a
    literal password passed to a tool like hydra — so log files are
    created with owner-only permissions (0600) in a 0700 directory,
    and are never printed back to the screen or sent anywhere.
    """
    from hackit.config import LOG_DIR, ConfigPathError, ensure_dirs, load_config, reject_if_symlink

    cfg = load_config()
    if not cfg.log_sessions:
        return

    ensure_dirs()
    log_file = LOG_DIR / f"session_{_dt.date.today().isoformat()}.log"
    try:
        reject_if_symlink(log_file)
    except ConfigPathError:
        # Someone planted a symlink at a predictable log path — don't
        # write through it. Logging is best-effort, so just skip it.
        return

    ts = _dt.datetime.now().isoformat(timespec="seconds")
    scope = _session_scope.scope_statement or "unspecified"
    # tool_name and output_summary always come from HACKiT's own fixed
    # knowledge base / internal strings, never from free-typed user
    # input, so repr() on scope/command alone is enough to neutralize
    # newline-based log forging from anything the user did type.
    line = f"[{ts}] tool={tool_name} approved={approved} scope={scope!r} command={command!r} {output_summary}\n"

    # Create (or open) the log file with owner-only permissions from
    # the first byte, rather than writing then chmod'ing afterward —
    # avoids a brief window where a new log file is readable under
    # the process's default umask. O_NOFOLLOW refuses to follow a
    # symlink planted at this predictable path after the check above.
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(log_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND | nofollow, 0o600)
    try:
        os.chmod(log_file, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "a") as f:
            f.write(line)
    except OSError:
        os.close(fd)
        raise
