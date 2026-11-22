"""
HACKiT CLI entry point.

Running `hackit` with no arguments drops into an interactive,
natural-language chat loop. Subcommands (`hackit tools`, `hackit
status`, `hackit gui`, `hackit config`) are available for scripted or
one-shot use.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Optional

import typer
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from rich.console import Console
from rich.markup import escape as _esc
from rich.prompt import Confirm, Prompt

from hackit import __version__
from hackit.banner import print_banner
from hackit.config import (
    HISTORY_FILE,
    ConfigPathError,
    ensure_dirs,
    load_config,
    reject_if_symlink,
    running_as_root,
    save_config,
)
from hackit.executor import run_command
from hackit.intent import classify
from hackit.knowledge import CATEGORY_LABELS
from hackit.knowledge.registry import all_categories, get_tool, list_category
from hackit.llm import refine_explanation
from hackit.safety import ensure_session_scope
from hackit.session import Session
from hackit.system_check import installed_tools, missing_tools, rank_by_installed, scan_system
from hackit.ui import (
    build_command_interactively,
    find_tool_fuzzy,
    print_candidates,
    print_categories,
    print_help,
    print_tool_card,
    print_tool_list,
)

app = typer.Typer(
    name="hackit",
    help="AI-powered penetration testing assistant for Kali Linux.",
    add_completion=False,
    no_args_is_help=False,
)
console = Console()


# --------------------------------------------------------------------------
# Default command: interactive chat
# --------------------------------------------------------------------------
@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="Show version and exit."),
):
    if version:
        console.print(f"HACKiT v{__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        chat()


@app.command()
def chat() -> None:
    """Start the interactive natural-language HACKiT session (default)."""
    ensure_dirs()
    print_banner(console)
    _warn_if_root()
    _secure_history_file()
    cfg = load_config()
    session = Session()
    prompt_session: PromptSession = PromptSession(history=FileHistory(str(HISTORY_FILE)))

    if not cfg.first_run_complete:
        _first_run_wizard(cfg)

    while True:
        try:
            query = prompt_session.prompt("hackit> ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Goodbye.[/]")
            break

        if not query:
            continue

        try:
            handled = _handle_builtin(query, session, cfg)
            if handled == "exit":
                break
            if handled:
                continue

            _handle_objective(query, session, cfg)
        except (EOFError, KeyboardInterrupt):
            # Let Ctrl+C/Ctrl+D inside a sub-prompt (e.g. mid command
            # build) cancel just that action, not crash the session.
            console.print("\n[yellow]Cancelled.[/]")
        except Exception as e:  # noqa: BLE001 — last-resort guard so one bad turn can't kill the session
            console.print(f"[red]Something went wrong handling that ({type(e).__name__}): {_esc(str(e))}[/]")
            console.print("[dim]You can keep going — this didn't run anything.[/]")


def _warn_if_root() -> None:
    if not running_as_root():
        return
    console.print(
        "[yellow]Running as root.[/] HACKiT's config, history, and logs will be stored under "
        "root's home directory (not your normal user's), and any command you approve will also "
        "run as root. That's expected for tools that need raw sockets (e.g. nmap SYN scans), but "
        "worth knowing if things look different from your usual setup.\n"
    )


def _secure_history_file() -> None:
    """
    Ensures the REPL history file exists with owner-only permissions
    before prompt_toolkit's FileHistory opens it — it may accumulate
    whatever the user types at the top-level prompt, including a
    target/host typed as part of a free-text objective.
    """
    try:
        reject_if_symlink(HISTORY_FILE)
    except ConfigPathError as e:
        console.print(f"[red]{_esc(str(e))}[/]")
        raise typer.Exit(1)
    if not HISTORY_FILE.exists():
        fd = os.open(HISTORY_FILE, os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(fd)
    try:
        os.chmod(HISTORY_FILE, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def _handle_builtin(query: str, session: Session, cfg) -> bool | str:
    q = query.strip()
    ql = q.lower()

    if ql in ("exit", "quit", "q"):
        return "exit"
    if ql == "help":
        print_help()
        return True
    if ql == "categories":
        print_categories()
        return True
    if ql == "status":
        _print_status()
        return True
    if ql == "gui":
        _launch_gui()
        return True
    if ql == "config":
        _config_wizard(cfg)
        return True
    if ql == "tools" or ql.startswith("tools "):
        parts = q.split(maxsplit=1)
        cat = parts[1].strip() if len(parts) > 1 else None
        if cat and cat not in all_categories():
            console.print(f"[yellow]Unknown category '{_esc(cat)}'. Try 'categories' to see valid keys.[/]")
            return True
        tools = list_category(cat) if cat else [t for c in all_categories() for t in list_category(c)]
        print_tool_list(rank_by_installed(tools), title=CATEGORY_LABELS.get(cat, "All tools") if cat else "All tools")
        return True
    if ql.startswith("show "):
        name = q.split(maxsplit=1)[1]
        tool = get_tool(name) or find_tool_fuzzy(name)
        if not tool:
            console.print(f"[yellow]No tool named '{_esc(name)}' in the knowledge base.[/]")
            return True
        print_tool_card(tool)
        session.last_tool = tool
        return True
    if ql in ("run", "run it", "execute", "run that"):
        _run_last(session)
        return True
    if ql in ("alternatives", "other options", "alternatives?"):
        _show_alternatives(session)
        return True

    return False


def _handle_objective(query: str, session: Session, cfg) -> None:
    session.record(query)
    result = classify(query)
    session.set_recommendation(result)

    if not result.candidates:
        print_candidates(result)
        return

    print_candidates(result)
    top = result.candidates[0]

    explanation = refine_explanation(query, top, cfg) if cfg.use_llm else None
    print_tool_card(top, explanation=explanation)

    if len(result.candidates) > 1:
        others = ", ".join(t.name for t in result.candidates[1:])
        console.print(f"\n[dim]Other relevant tools: {_esc(others)} — try 'show <name>' or 'alternatives'.[/]")

    console.print(
        "\n[dim]Type 'run' to build and execute this command (with your approval at every step), "
        "or ask me something else.[/]"
    )


def _run_last(session: Session) -> None:
    if not session.last_tool:
        console.print("[yellow]Nothing to run yet — ask me about an objective first, or 'show <tool>'.[/]")
        return
    tool = session.last_tool
    if not ensure_session_scope():
        return
    command = build_command_interactively(tool)
    session.last_command = command
    run_command(tool, command)


def _show_alternatives(session: Session) -> None:
    if not session.last_result or len(session.last_result.candidates) <= 1:
        console.print("[yellow]No alternatives tracked yet — ask about an objective first.[/]")
        return
    print_tool_list(session.last_result.candidates[1:], title="Alternatives")


def _print_status() -> None:
    scan_system.cache_clear()  # tools may have been installed since the last scan this session
    installed = installed_tools()
    missing = missing_tools()
    console.print(f"[green]{len(installed)} tools detected installed[/], [yellow]{len(missing)} not found[/].\n")
    if missing:
        console.print("[bold]Not installed (install with apt):[/]")
        for t in missing[:25]:
            console.print(f"  [dim]sudo apt install {_esc(t.package):<20}[/] # {_esc(t.name)}")
        if len(missing) > 25:
            console.print(f"  [dim]...and {len(missing) - 25} more[/]")


def _first_run_wizard(cfg) -> None:
    console.print(
        "[bold]Welcome to HACKiT.[/] A couple of one-time questions, then you're set.\n"
    )
    use_llm = Confirm.ask(
        "Enable optional AI-refined explanations via the Anthropic API? "
        "(HACKiT's tool knowledge base works fully offline either way)",
        default=False,
    )
    cfg.use_llm = use_llm
    if use_llm:
        key = Prompt.ask(
            "Paste your Anthropic API key (or leave blank to set ANTHROPIC_API_KEY env var instead)",
            password=True,
            default="",
        )
        if key:
            cfg.anthropic_api_key = key
    cfg.first_run_complete = True
    save_config(cfg)
    console.print("[green]Saved. You can change this anytime with the 'config' command.[/]\n")


def _config_wizard(cfg) -> None:
    console.print(f"[bold]Current config[/] (stored at ~/.config/hackit/config.json):")
    console.print(f"  use_llm: {cfg.use_llm}")
    console.print(f"  llm_model: {_esc(cfg.llm_model)}")
    console.print(f"  api key set: {'yes' if cfg.anthropic_api_key else 'no (checks ANTHROPIC_API_KEY env var too)'}")
    console.print(f"  log_sessions: {cfg.log_sessions}\n")
    if Confirm.ask("Change these now?", default=False):
        cfg.use_llm = Confirm.ask("Enable AI-refined explanations?", default=cfg.use_llm)
        if cfg.use_llm:
            key = Prompt.ask("Anthropic API key (blank = keep current / use env var)", password=True, default="")
            if key:
                cfg.anthropic_api_key = key
        save_config(cfg)
        console.print("[green]Saved.[/]")


def _launch_gui() -> None:
    try:
        from hackit.gui.app import launch
    except ImportError:
        console.print(
            "[yellow]The GUI needs PyQt6, which isn't installed.[/] "
            "Install it with: [bold]pip install hackit[gui][/] "
            "(or: sudo apt install python3-pyqt6)"
        )
        return
    console.print("[dim]Launching HACKiT GUI...[/]")
    launch()


# --------------------------------------------------------------------------
# Scriptable subcommands (non-interactive use)
# --------------------------------------------------------------------------
@app.command()
def ask(query: str = typer.Argument(..., help="Your objective in plain English.")) -> None:
    """One-shot: get a tool recommendation for a single objective and exit."""
    ensure_dirs()
    cfg = load_config()
    session = Session()
    _handle_objective(query, session, cfg)


@app.command("tools")
def tools_cmd(category: Optional[str] = typer.Argument(None, help="Filter by category key.")) -> None:
    """List known tools, optionally filtered by category."""
    if category and category not in all_categories():
        console.print(f"[yellow]Unknown category. Valid: {', '.join(all_categories())}[/]")
        raise typer.Exit(1)
    tools = list_category(category) if category else [t for c in all_categories() for t in list_category(c)]
    print_tool_list(rank_by_installed(tools))


@app.command()
def status() -> None:
    """Show which knowledge-base tools are installed on this system."""
    _print_status()


@app.command()
def gui() -> None:
    """Launch the optional graphical interface."""
    _launch_gui()


@app.command()
def config() -> None:
    """View or update HACKiT configuration (API key, preferences)."""
    cfg = load_config()
    _config_wizard(cfg)


if __name__ == "__main__":
    app()
