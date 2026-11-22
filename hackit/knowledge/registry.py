"""
Central registry over HACKiT's tool knowledge base.

Aggregates every category module's TOOLS list into one index and
exposes simple lookup/search functions used by the intent engine and
the UI layer.
"""
from __future__ import annotations

from hackit.knowledge import CATEGORY_LABELS, ToolInfo
from hackit.knowledge import (
    enumeration,
    exploitation,
    forensics,
    password,
    recon,
    scanning,
    vuln_assessment,
    webapp,
    wireless,
)

_MODULES = [recon, scanning, enumeration, vuln_assessment, webapp, exploitation, password, wireless, forensics]

ALL_TOOLS: list[ToolInfo] = [tool for mod in _MODULES for tool in mod.TOOLS]

# name -> ToolInfo (first definition wins if a name appears in two categories,
# e.g. searchsploit appears under both vuln_assessment and exploitation)
_BY_NAME: dict[str, ToolInfo] = {}
for _t in ALL_TOOLS:
    _BY_NAME.setdefault(_t.name, _t)


def get_tool(name: str) -> ToolInfo | None:
    return _BY_NAME.get(name.lower().strip())


def list_category(category: str) -> list[ToolInfo]:
    return [t for t in ALL_TOOLS if t.category == category]


def all_categories() -> list[str]:
    return list(CATEGORY_LABELS.keys())


import re as _re

# Common English words that are too generic/short to carry signal, and
# which (critically) are also prone to matching as bare *substrings*
# inside unrelated words (e.g. "for" inside "forensic"/"format"). Kept
# out of scoring entirely, on top of the word-boundary matching below.
_STOPWORDS = {
    "the", "and", "for", "with", "that", "this", "from", "about", "into",
    "your", "have", "has", "can", "you", "want", "need", "like", "using",
    "use", "find", "help", "please", "how", "what", "where", "when",
    "some", "any", "all", "out", "get", "got", "just", "would", "could",
    "should", "did", "does", "doing", "me", "i'm", "im", "its", "it's",
    "are", "was", "were", "been", "being", "there", "their", "them",
}


def search(query: str, limit: int = 5) -> list[tuple[ToolInfo, float]]:
    """
    Small, dependency-free keyword scorer: splits the query into
    lowercase tokens (dropping stopwords), then scores each tool by
    how many tokens match *whole words* in its name, tags, summary,
    category, or description — whole-word matching avoids false hits
    like "for" inside "forensic". Good enough as an offline fallback /
    first pass before (optionally) asking the LLM to refine the choice
    with actual reasoning about intent.
    """
    tokens = [t for t in _tokenize(query) if len(t) > 2 and t not in _STOPWORDS]
    if not tokens:
        return []

    # Naive singularization so "subdomains" in a query still matches a
    # "subdomain" tag/description, and vice versa — not real stemming,
    # just enough to not lose obvious plural/singular matches.
    def _singular(tok: str) -> str:
        if len(tok) > 4 and tok.endswith("es"):
            return tok[:-2]
        if len(tok) > 3 and tok.endswith("s") and not tok.endswith("ss"):
            return tok[:-1]
        return tok

    token_patterns = {
        tok: _re.compile(r"\b" + _re.escape(_singular(tok)) + r"(e?s)?\b") for tok in tokens
    }

    scored: list[tuple[ToolInfo, float]] = []
    for tool in ALL_TOOLS:
        haystack_weighted = [
            (tool.name, 3.0),
            (" ".join(tool.tags), 2.5),
            (tool.summary, 1.5),
            (tool.category, 1.5),
            (CATEGORY_LABELS.get(tool.category, ""), 1.0),
            (tool.description, 0.75),
            (tool.when_to_use, 0.75),
        ]
        score = 0.0
        for text, weight in haystack_weighted:
            text_l = text.lower()
            for tok, pattern in token_patterns.items():
                if pattern.search(text_l):
                    score += weight
        if score > 0:
            scored.append((tool, score))

    scored.sort(key=lambda pair: pair[1], reverse=True)
    return scored[:limit]


def _tokenize(text: str) -> list[str]:
    cleaned = "".join(ch if ch.isalnum() else " " for ch in text.lower())
    return cleaned.split()
