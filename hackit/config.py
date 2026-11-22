"""
Local configuration storage for HACKiT.

Everything lives under ~/.config/hackit/. Nothing is ever sent
anywhere except, optionally, to the Anthropic API when the user has
configured an API key for richer natural-language explanations —
HACKiT works fully offline otherwise, using its built-in rule-based
knowledge base.

Security notes:
- config.json can hold an API key, so it and its parent directory are
  created with owner-only permissions (0600 / 0700) from the moment
  they're created, not chmod'd afterward — that would leave a brief
  window where a new file is readable under the process's default
  umask.
- Files at predictable, fixed paths under a user's home directory are
  a classic local symlink-attack target: something else could plant
  a symlink at ~/.config/hackit/config.json pointing elsewhere before
  HACKiT runs, and a naive open() would happily write HACKiT's
  (sensitive) config through it. Every file HACKiT creates here is
  opened with O_NOFOLLOW, and the config directory itself is checked
  for being a symlink before use, so HACKiT refuses to follow one
  rather than silently writing through it.
"""
from __future__ import annotations

import dataclasses
import json
import os
import stat
from dataclasses import asdict, dataclass
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("HACKIT_HOME", Path.home() / ".config" / "hackit"))
CONFIG_FILE = CONFIG_DIR / "config.json"
HISTORY_FILE = CONFIG_DIR / "history"
LOG_DIR = CONFIG_DIR / "logs"

# O_NOFOLLOW is POSIX-only (fine — HACKiT targets Kali/Linux); guard it
# anyway so this module doesn't hard-fail to import on an odd platform.
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


@dataclass
class HackitConfig:
    anthropic_api_key: str | None = None
    llm_model: str = "claude-sonnet-4-6"
    use_llm: bool = True
    log_sessions: bool = True
    color_theme: str = "cyberpunk"
    confirm_every_command: bool = True  # never let this be False from a config file
    first_run_complete: bool = False


_KNOWN_FIELDS = {f.name for f in dataclasses.fields(HackitConfig)}


class ConfigPathError(RuntimeError):
    """Raised when a HACKiT config path can't be safely used (e.g. it's a symlink)."""


def running_as_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def reject_if_symlink(path: Path) -> None:
    if path.is_symlink():
        raise ConfigPathError(
            f"Refusing to use {path} — it's a symlink, not a plain directory/file. "
            f"Remove it (or point HACKIT_HOME somewhere clean) and try again."
        )


def ensure_dirs() -> None:
    reject_if_symlink(CONFIG_DIR)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    reject_if_symlink(LOG_DIR)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(CONFIG_DIR, stat.S_IRWXU)  # 0700 — config may hold an API key
        os.chmod(LOG_DIR, stat.S_IRWXU)     # 0700 — logs may hold command-line secrets
    except OSError:
        pass


def load_config() -> HackitConfig:
    ensure_dirs()
    if not CONFIG_FILE.exists():
        return HackitConfig()
    try:
        reject_if_symlink(CONFIG_FILE)
        raw = json.loads(CONFIG_FILE.read_text())
    except (json.JSONDecodeError, OSError, ConfigPathError):
        # Corrupt, unreadable, or tampered-with config: degrade to
        # defaults rather than crash HACKiT on startup.
        return HackitConfig()

    if not isinstance(raw, dict):
        return HackitConfig()

    # Only accept keys HACKiT actually knows about — a hand-edited or
    # future/older config file with extra keys must not crash
    # HackitConfig(**raw) with a TypeError.
    known = {k: v for k, v in raw.items() if k in _KNOWN_FIELDS}
    try:
        cfg = HackitConfig(**{**asdict(HackitConfig()), **known})
    except TypeError:
        return HackitConfig()

    # Safety invariant: this can never be disabled via a config file edit.
    cfg.confirm_every_command = True
    return cfg


def save_config(cfg: HackitConfig) -> None:
    ensure_dirs()
    reject_if_symlink(CONFIG_FILE)
    payload = json.dumps(asdict(cfg), indent=2).encode()
    fd = os.open(CONFIG_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _NOFOLLOW, 0o600)
    try:
        os.chmod(CONFIG_FILE, stat.S_IRUSR | stat.S_IWUSR)  # belt-and-suspenders vs. umask
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
    except OSError:
        os.close(fd)
        raise


def get_api_key(cfg: HackitConfig) -> str | None:
    """API key resolution order: env var, then config file."""
    return os.environ.get("ANTHROPIC_API_KEY") or cfg.anthropic_api_key
