"""
Lightweight, dependency-free input checks shared by the terminal and
GUI command builders.

HACKiT never executes a command without the user reviewing the exact,
fully-substituted string and explicitly approving it (see
hackit.safety), so there is no path where a filled-in placeholder
value reaches a process without a human in the loop. These checks are
defense-in-depth on top of that: catching the common, easy-to-miss
mistake of a value that will be parsed as an extra flag rather than
the plain target/argument the user intended, so the reviewer's
attention is drawn to it before they approve.
"""
from __future__ import annotations


def flag_injection_warning(placeholder: str, value: str) -> str | None:
    """
    Returns a short warning string if `value` looks like it would be
    interpreted as a command-line flag rather than a literal argument
    (e.g. a target field that starts with '-'), or None if it looks
    fine. This never blocks anything — it just surfaces something
    worth a second look before approval.
    """
    v = value.strip()
    if not v:
        return None
    if v.startswith("-"):
        return (
            f"'{value}' starts with '-' — it will be parsed as an extra flag, "
            f"not a literal value for {placeholder!r}. Double-check this is what you intended."
        )
    return None
