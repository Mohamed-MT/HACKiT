"""
Optional LLM-backed natural-language layer.

HACKiT is fully functional offline: hackit.intent + the knowledge
base already map an objective to a vetted tool, command template, and
explanation. When the user configures an Anthropic API key, this
module asks Claude to turn that same vetted data into a more natural,
conversational explanation tailored to the user's exact wording —
but it is explicitly instructed to stay within the supplied tool data
and never invent commands, flags, or tools that aren't in the
knowledge base. If no key is configured, or the call fails for any
reason, callers fall back to the deterministic template in ui.py.
"""
from __future__ import annotations

from hackit.config import HackitConfig, get_api_key
from hackit.knowledge import ToolInfo

SYSTEM_PROMPT = """\
You are the natural-language explanation layer inside HACKiT, a \
terminal companion that helps authorized penetration testers and \
students use Kali Linux tools correctly.

You will be given the user's exact question and a small set of \
vetted tool entries from HACKiT's own knowledge base (name, \
description, when to use it, command template, argument \
explanations, expected output, common errors, next steps).

Rules:
- Only discuss the tool(s) provided to you. Do not recommend, name, \
  or describe any tool, flag, or command that is not present in the \
  supplied data.
- Do not invent capabilities, flags, or output details beyond what \
  is given.
- Be concise, concrete, and practical. Explain *why* the top choice \
  fits the user's specific wording, not just restate the generic \
  description.
- Never suggest running anything automatically — HACKiT always asks \
  the user to approve each command before it runs, so frame your \
  answer as guidance, not as something already in motion.
- If scope/authorization matters for the recommended tool, mention \
  it briefly.
- Keep it to a short paragraph plus, if useful, a couple of bullet \
  points. You are not generating the final command card — HACKiT's \
  UI already renders the structured command/args/output panel from \
  the same data, so don't repeat it verbatim; add the connective, \
  reasoning-level explanation a human expert would give.
"""


def refine_explanation(query: str, top_tool: ToolInfo, cfg: HackitConfig) -> str | None:
    """
    Returns a short natural-language explanation of why top_tool fits
    the user's query, or None if LLM augmentation is unavailable/
    disabled/fails (callers should fall back to the static template).
    """
    if not cfg.use_llm:
        return None
    api_key = get_api_key(cfg)
    if not api_key:
        return None

    try:
        import anthropic
    except ImportError:
        return None

    tool_payload = {
        "name": top_tool.name,
        "category": top_tool.category,
        "summary": top_tool.summary,
        "description": top_tool.description,
        "when_to_use": top_tool.when_to_use,
        "risk": top_tool.risk.value,
        "command_template": top_tool.command_template,
        "args_explained": top_tool.args_explained,
        "expected_output": top_tool.expected_output,
        "common_errors": top_tool.common_errors,
        "next_steps": top_tool.next_steps,
    }

    try:
        # Explicit timeout: without one, a stalled connection would
        # hang the CLI/GUI indefinitely on what's meant to be an
        # optional, best-effort enrichment call.
        client = anthropic.Anthropic(api_key=api_key, timeout=15.0)
        response = client.messages.create(
            model=cfg.llm_model,
            max_tokens=400,
            system=SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": (
                        f"User's objective: {query!r}\n\n"
                        f"Vetted tool data:\n{tool_payload}"
                    ),
                }
            ],
        )
        parts = [block.text for block in response.content if getattr(block, "type", None) == "text"]
        text = "\n".join(parts).strip()
        return text or None
    except Exception:
        # Network error, bad key, rate limit, etc. — degrade gracefully
        # to the offline template rather than crashing the session.
        return None
