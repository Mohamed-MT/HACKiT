"""
HACKiT's built-in knowledge base of Kali Linux tools.

This is reference / documentation-level data only (what a tool is,
when to reach for it, how its flags work) — the same kind of
information found in each tool's own --help text or man page. It is
organized by pentesting-engagement phase so HACKiT can map a plain
English objective ("I want to scan a network for open ports") to the
right tool.

RiskLevel communicates how "loud" / disruptive a tool's default use
is, which HACKiT uses to decide how much friction (confirmation,
scope reminders) to put in front of running it. It is informational
for the user, not a technical restriction — HACKiT never silently
executes anything regardless of risk level.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(str, Enum):
    PASSIVE = "passive"        # no packets sent to the target (OSINT, local analysis)
    LOW = "low"                # light, generally unobtrusive active probing
    MEDIUM = "medium"          # noticeable active scanning / enumeration traffic
    HIGH = "high"              # exploitation, brute forcing, wireless injection, etc.


@dataclass
class ToolInfo:
    name: str                       # binary / package name, e.g. "nmap"
    category: str                   # engagement phase key, e.g. "scanning"
    package: str                    # apt package name on Kali
    summary: str                    # one-line description
    description: str                # longer explanation of what it does and why it exists
    when_to_use: str                # guidance on choosing this tool for an objective
    risk: RiskLevel
    requires_target_auth: bool      # True if it touches a target over the network
    command_template: str           # example command with placeholders like <target>
    args_explained: dict[str, str] = field(default_factory=dict)
    example: str = ""               # a concrete filled-in example command
    expected_output: str = ""       # what a successful run looks like / produces
    common_errors: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)  # keywords for intent matching
    alternatives: list[str] = field(default_factory=list)  # other tool names

    def risk_label(self) -> str:
        return {
            RiskLevel.PASSIVE: "Passive (no traffic to target)",
            RiskLevel.LOW: "Low (light active probing)",
            RiskLevel.MEDIUM: "Medium (noticeable active scanning)",
            RiskLevel.HIGH: "High (exploitation / brute-force / injection)",
        }[self.risk]


CATEGORY_LABELS: dict[str, str] = {
    "recon": "Reconnaissance (OSINT)",
    "scanning": "Network Scanning",
    "enumeration": "Enumeration",
    "vuln_assessment": "Vulnerability Assessment",
    "webapp": "Web Application Testing",
    "exploitation": "Exploitation",
    "password": "Password Auditing",  # nosec B105 — category label, not a credential
    "wireless": "Wireless Security",
    "forensics": "Digital Forensics",
}
