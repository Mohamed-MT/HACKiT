"""
Terminal presentation layer, built on Rich.

Keeps all the "how things look" logic out of cli.py so the control
flow there stays readable.
"""
from __future__ import annotations

import re

from rich.console import Console
from rich.markdown import Markdown
from rich.markup import escape as _esc
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from hackit.intent import IntentResult
from hackit.knowledge import ToolInfo
from hackit.knowledge.registry import ALL_TOOLS
from hackit.system_check import is_installed
from hackit.validation import flag_injection_warning

console = Console()

RISK_COLORS = {"passive": "green", "low": "cyan", "medium": "yellow", "high": "red"}

PLACEHOLDER_RE = re.compile(r"<([a-zA-Z0-9_\- ]+)>")


def print_help() -> None:
    table = Table(title="HACKiT commands", show_header=True, header_style="bold magenta")
    table.add_column("Command")
    table.add_column("What it does")
    table.add_row("<plain English objective>", "e.g. 'scan a network for open ports'")
    table.add_row("tools [category]", "List known tools, optionally filtered by category")
    table.add_row("show <tool name>", "Show full details for a specific tool")
    table.add_row("categories", "List engagement-phase categories")
    table.add_row("status", "Show which knowledge-base tools are installed on this system")
    table.add_row("gui", "Launch the optional graphical interface")
    table.add_row("config", "View/update API key and preferences")
    table.add_row("help", "Show this help")
    table.add_row("exit / quit", "Leave HACKiT")
    console.print(table)


def print_categories() -> None:
    from hackit.knowledge import CATEGORY_LABELS

    table = Table(title="Engagement-phase categories", header_style="bold magenta")
    table.add_column("Key")
    table.add_column("Label")
    table.add_column("# Tools")
    from hackit.knowledge.registry import list_category

    for key, label in CATEGORY_LABELS.items():
        table.add_row(key, label, str(len(list_category(key))))
    console.print(table)


def print_tool_list(tools: list[ToolInfo], title: str = "Tools") -> None:
    table = Table(title=title, header_style="bold magenta")
    table.add_column("Name", style="bold")
    table.add_column("Category")
    table.add_column("Risk")
    table.add_column("Installed")
    table.add_column("Summary")
    for t in tools:
        risk_style = RISK_COLORS[t.risk.value]
        installed = "[green]yes[/]" if is_installed(t) else "[dim]no[/]"
        # Table cell content goes through the same markup parser as
        # console.print() — escape tool-data fields so a stray '['/']'
        # in the knowledge base (e.g. a port/service notation) can't
        # be swallowed as an (invalid) style tag instead of displayed.
        table.add_row(_esc(t.name), _esc(t.category), f"[{risk_style}]{t.risk.value}[/]", installed, _esc(t.summary))
    console.print(table)


def print_tool_card(tool: ToolInfo, explanation: str | None = None) -> None:
    risk_style = RISK_COLORS[tool.risk.value]
    installed = is_installed(tool)
    install_note = (
        "[green]✓ installed[/]"
        if installed
        else f"[yellow]✗ not installed — install with:[/] [bold]sudo apt install {_esc(tool.package)}[/]"
    )

    header = f"[bold]{_esc(tool.name)}[/]  [dim]({_esc(tool.category)})[/]   {install_note}"
    console.print(Panel(header, border_style="magenta"))

    # Markdown() renders '[' / ']' as literal text rather than parsing
    # them as Rich markup, so these two don't need escaping — but the
    # plain f-strings below do, since console.print() on a bare string
    # always interprets [tags].
    body = explanation.strip() if explanation else tool.description
    console.print(Markdown(f"**What it does:** {body}"))
    console.print(Markdown(f"**When to use it:** {tool.when_to_use}"))
    console.print(f"[dim]Risk level:[/] [{risk_style}]{_esc(tool.risk_label())}[/]")

    console.print("\n[bold]Command:[/]")
    console.print(Panel(_esc(tool.command_template), border_style="cyan"))

    if tool.args_explained:
        table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
        table.add_column("Flag/Arg", style="cyan")
        table.add_column("Meaning")
        for flag, meaning in tool.args_explained.items():
            table.add_row(_esc(flag), _esc(meaning))
        console.print(table)

    if tool.example:
        console.print(f"\n[bold]Example:[/] [green]{_esc(tool.example)}[/]")

    if tool.expected_output:
        console.print(f"\n[bold]Expected output:[/] {_esc(tool.expected_output)}")

    if tool.common_errors:
        console.print("\n[bold]Common errors:[/]")
        for err in tool.common_errors:
            console.print(f"  • {_esc(err)}")

    if tool.next_steps:
        console.print("\n[bold]Possible next steps:[/]")
        for step in tool.next_steps:
            console.print(f"  → {_esc(step)}")

    if tool.alternatives:
        alt_names = ", ".join(tool.alternatives)
        console.print(f"\n[dim]Alternatives: {_esc(alt_names)}[/]")

    if not installed:
        console.print(
            f"\n[yellow]Note:[/] {_esc(tool.name)} isn't detected on this system. "
            f"HACKiT can still explain it, but you'll need to install it "
            f"(sudo apt install {_esc(tool.package)}) before running it."
        )


def print_candidates(result: IntentResult) -> None:
    if not result.candidates:
        console.print(
            "[yellow]I couldn't confidently match that to a specific tool.[/] "
            "Try 'categories' to browse by engagement phase, or 'tools' to see everything."
        )
        return
    label = result.category_label or "General"
    console.print(f"[dim]Best match area:[/] [bold]{label}[/]  [dim](confidence: {result.confidence})[/]\n")


def build_command_interactively(tool: ToolInfo) -> str:
    """
    Walks the user through filling in every <placeholder> in a tool's
    command_template, producing a concrete command. Never executes
    anything itself — that's executor.py's job, after safety approval.
    """
    command = tool.command_template
    placeholders = PLACEHOLDER_RE.findall(command)
    if not placeholders:
        return command

    console.print(f"\n[bold]Let's build the exact command for {tool.name}.[/]")
    seen: set[str] = set()
    for ph in placeholders:
        if ph in seen:
            continue
        seen.add(ph)
        hint = tool.args_explained.get(f"<{ph}>", "")
        prompt_text = f"  {ph}" + (f" [dim]({hint})[/]" if hint else "")
        value = Prompt.ask(prompt_text)
        warning = flag_injection_warning(ph, value)
        if warning:
            console.print(f"  [yellow]⚠ {_esc(warning)}[/]")
        command = command.replace(f"<{ph}>", value)
    return command


def find_tool_fuzzy(name: str) -> ToolInfo | None:
    name_l = name.lower().strip()
    for t in ALL_TOOLS:
        if t.name == name_l:
            return t
    for t in ALL_TOOLS:
        if name_l in t.name:
            return t
    return None
