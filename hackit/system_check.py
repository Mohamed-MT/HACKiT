"""
Detects which Kali tools from the knowledge base are actually
installed/available on the current system, so HACKiT can tell the
user what's ready to go versus what needs `apt install`, and can
prefer an installed alternative over an uninstalled first choice.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass
from functools import lru_cache

from hackit.knowledge import ToolInfo
from hackit.knowledge.registry import ALL_TOOLS

# A few tool "names" in the knowledge base are GUIs, suites, or not
# the literal binary name — map those to the real binary to check for.
_BINARY_OVERRIDES: dict[str, str] = {
    "metasploit": "msfconsole",
    "openvas": "gvm-start",
    "volatility3": "vol",
    "zaproxy": "zap.sh",
}


@dataclass
class Availability:
    tool: ToolInfo
    installed: bool
    binary_checked: str


def _binary_for(tool: ToolInfo) -> str:
    return _BINARY_OVERRIDES.get(tool.name, tool.name)


@lru_cache(maxsize=1)
def scan_system() -> dict[str, Availability]:
    """Returns {tool_name: Availability} for every tool in the knowledge base."""
    result: dict[str, Availability] = {}
    for tool in ALL_TOOLS:
        binary = _binary_for(tool)
        installed = shutil.which(binary) is not None
        result[tool.name] = Availability(tool=tool, installed=installed, binary_checked=binary)
    return result


def is_installed(tool: ToolInfo) -> bool:
    avail = scan_system().get(tool.name)
    return bool(avail and avail.installed)


def missing_tools() -> list[ToolInfo]:
    return [a.tool for a in scan_system().values() if not a.installed]


def installed_tools() -> list[ToolInfo]:
    return [a.tool for a in scan_system().values() if a.installed]


def rank_by_installed(tools: list[ToolInfo]) -> list[ToolInfo]:
    """Stable-sorts a tool list so installed tools come first."""
    return sorted(tools, key=lambda t: 0 if is_installed(t) else 1)
