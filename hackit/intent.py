"""
Natural-language intent recognition.

HACKiT's core promise is that a user can type what they want in plain
English rather than knowing tool names up front. This module turns a
free-text objective into:

  1. A likely engagement phase/category (recon, scanning, ...)
  2. A ranked shortlist of candidate tools from the knowledge base

It is deliberately simple and fully offline (keyword/phrase scoring)
so HACKiT works with zero configuration. When an Anthropic API key is
configured, hackit.llm uses this shortlist as grounding context to
produce a more natural explanation — the LLM never invents tools or
commands outside this vetted knowledge base.
"""
from __future__ import annotations

from dataclasses import dataclass

from hackit.knowledge import CATEGORY_LABELS, ToolInfo
from hackit.knowledge.registry import list_category, search

# Phrases strongly associated with each engagement phase, used to pick
# a likely category before/alongside the general tool-level keyword
# search in registry.search(). Order doesn't matter; first match by
# score wins.
_CATEGORY_PHRASES: dict[str, list[str]] = {
    "recon": [
        "recon", "reconnaissance", "osint", "footprint", "footprinting", "gather information",
        "find emails", "find subdomains", "who owns", "whois", "passive information",
    ],
    "scanning": [
        "scan", "scanning", "open ports", "port scan", "network scan", "host discovery",
        "find hosts", "live hosts", "what's running", "which ports", "sweep the network",
        "sweep a network",
    ],
    "enumeration": [
        "enumerate", "enumeration", "shares", "smb shares", "list users", "snmp",
        "find directories", "hidden directories", "directory brute", "subdomain brute",
        "what services",
    ],
    "vuln_assessment": [
        "vulnerability", "vulnerabilities", "vuln scan", "cve", "known exploit",
        "is it vulnerable", "misconfiguration", "harden", "hardening", "audit the system",
    ],
    "webapp": [
        "web app", "website", "web application", "sql injection", "sqli", "xss",
        "wordpress", "http", "web server vulnerab", "burp", "proxy the traffic",
    ],
    "exploitation": [
        "exploit", "exploitation", "gain access", "get a shell", "reverse shell",
        "metasploit", "pop a box", "take over", "compromise the",
    ],
    "password": [
        "password", "crack", "cracking", "brute force", "brute-force", "hash",
        "wordlist", "login attempt", "credential stuffing", "dictionary attack",
    ],
    "wireless": [
        "wifi", "wi-fi", "wireless", "wpa", "wep", "handshake", "deauth", "access point",
        "wps",
    ],
    "forensics": [
        "forensic", "forensics", "memory dump", "disk image", "metadata", "exif",
        "incident response", "firmware", "recover deleted", "timeline analysis",
    ],
}


@dataclass
class IntentResult:
    query: str
    category: str | None
    category_label: str | None
    candidates: list[ToolInfo]
    confidence: str  # "high" | "medium" | "low"


def classify(query: str) -> IntentResult:
    category = _best_category(query)
    candidates = [tool for tool, _score in search(query, limit=5)]

    # If keyword search found nothing but we do have a category guess,
    # fall back to that category's tool list so the user never gets a
    # dead end.
    if not candidates and category:
        candidates = list_category(category)[:5]

    # If we have candidates but no category guess, infer the category
    # from the top candidate so the UI can still show a phase label.
    if candidates and not category:
        category = candidates[0].category

    if candidates:
        confidence = "high" if len(candidates) >= 2 and category else "medium"
    else:
        confidence = "low"

    return IntentResult(
        query=query,
        category=category,
        category_label=CATEGORY_LABELS.get(category) if category else None,
        candidates=candidates,
        confidence=confidence,
    )


def _best_category(query: str) -> str | None:
    q = query.lower()
    best_cat, best_score = None, 0
    for cat, phrases in _CATEGORY_PHRASES.items():
        score = sum(1 for p in phrases if p in q)
        if score > best_score:
            best_cat, best_score = cat, score
    return best_cat
