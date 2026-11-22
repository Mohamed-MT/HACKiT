from rich.console import Console
from rich.text import Text

from hackit import __version__

BANNER = r"""
 ██╗  ██╗ █████╗  ██████╗██╗  ██╗██╗████████╗
 ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██║╚══██╔══╝
 ███████║███████║██║     █████╔╝ ██║   ██║
 ██╔══██║██╔══██║██║     ██╔═██╗ ██║   ██║
 ██║  ██║██║  ██║╚██████╗██║  ██╗██║   ██║
 ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝   ╚═╝
"""


def print_banner(console: Console) -> None:
    text = Text(BANNER, style="bold magenta")
    console.print(text)
    console.print(
        f"  [cyan]AI-powered penetration testing assistant for Kali Linux[/]  "
        f"[dim]v{__version__}[/]",
        justify="left",
    )
    console.print(
        "  [dim]Describe what you want to do in plain English. "
        "Type 'help' for commands, 'exit' to quit.[/]\n"
    )
