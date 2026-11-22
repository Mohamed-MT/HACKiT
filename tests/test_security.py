"""
Regression tests for HACKiT security-sensitive behavior.

Each test here corresponds to a specific finding — the goal is that a
future change can't silently reintroduce one of these without a test
failing.
"""
from __future__ import annotations

import io
import os
import stat

import pytest
from rich.console import Console

from hackit.validation import flag_injection_warning


# --------------------------------------------------------------------
# F1 / F2 — config & log files: atomic restrictive perms, symlink guard
# --------------------------------------------------------------------
def test_config_file_created_with_owner_only_perms(tmp_path, monkeypatch):
    monkeypatch.setenv("HACKIT_HOME", str(tmp_path))
    import importlib
    import hackit.config as config

    importlib.reload(config)  # pick up the new HACKIT_HOME

    cfg = config.HackitConfig(anthropic_api_key="sk-ant-test")
    config.save_config(cfg)

    mode = stat.S_IMODE(os.stat(config.CONFIG_FILE).st_mode)
    assert mode == 0o600
    dir_mode = stat.S_IMODE(os.stat(config.CONFIG_DIR).st_mode)
    assert dir_mode == 0o700


def test_save_config_refuses_a_symlinked_config_path(tmp_path, monkeypatch):
    monkeypatch.setenv("HACKIT_HOME", str(tmp_path))
    import importlib
    import hackit.config as config

    importlib.reload(config)

    target = tmp_path.parent / "evil_target.txt"
    target.write_text("should not be touched")
    config.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    config.CONFIG_FILE.symlink_to(target)

    with pytest.raises(config.ConfigPathError):
        config.save_config(config.HackitConfig(anthropic_api_key="sk-ant-should-not-write"))

    assert target.read_text() == "should not be touched"


def test_load_config_degrades_gracefully_on_symlinked_or_malformed_file(tmp_path, monkeypatch):
    monkeypatch.setenv("HACKIT_HOME", str(tmp_path))
    import importlib
    import hackit.config as config

    importlib.reload(config)
    config.ensure_dirs()

    # Symlinked config.json -> load_config must not follow it, and must
    # not raise out to the caller (startup should never crash on this).
    target = tmp_path.parent / "evil_target2.txt"
    target.write_text("nope")
    config.CONFIG_FILE.symlink_to(target)
    cfg = config.load_config()
    assert cfg.anthropic_api_key is None  # fell back to defaults, didn't follow the symlink


def test_load_config_ignores_unknown_keys_instead_of_crashing(tmp_path, monkeypatch):
    monkeypatch.setenv("HACKIT_HOME", str(tmp_path))
    import importlib
    import hackit.config as config

    importlib.reload(config)
    config.ensure_dirs()
    config.CONFIG_FILE.write_text('{"use_llm": false, "some_future_field_hackit_doesnt_know_yet": 123}')

    cfg = config.load_config()  # must not raise TypeError
    assert cfg.use_llm is False


def test_confirm_every_command_cannot_be_disabled_via_config_file(tmp_path, monkeypatch):
    monkeypatch.setenv("HACKIT_HOME", str(tmp_path))
    import importlib
    import hackit.config as config

    importlib.reload(config)
    config.ensure_dirs()
    config.CONFIG_FILE.write_text('{"confirm_every_command": false}')

    cfg = config.load_config()
    assert cfg.confirm_every_command is True  # invariant enforced regardless of file content


# --------------------------------------------------------------------
# F3 — log_sessions preference actually gates writing now
# --------------------------------------------------------------------
def test_log_sessions_false_suppresses_log_writes(tmp_path, monkeypatch):
    monkeypatch.setenv("HACKIT_HOME", str(tmp_path))
    import importlib
    import hackit.config as config
    import hackit.safety as safety

    importlib.reload(config)
    importlib.reload(safety)

    cfg = config.HackitConfig(log_sessions=False)
    config.save_config(cfg)

    safety.log_action("nmap", "nmap -sV 10.10.10.5", approved=True, output_summary="exit=0")
    assert not config.LOG_DIR.exists() or list(config.LOG_DIR.iterdir()) == []


def test_log_sessions_true_writes_an_owner_only_log_file(tmp_path, monkeypatch):
    monkeypatch.setenv("HACKIT_HOME", str(tmp_path))
    import importlib
    import hackit.config as config
    import hackit.safety as safety

    importlib.reload(config)
    importlib.reload(safety)

    cfg = config.HackitConfig(log_sessions=True)
    config.save_config(cfg)

    safety.log_action("hydra", "hydra -l admin -p hunter2 ssh://10.10.10.5", approved=True, output_summary="exit=0")
    files = list(config.LOG_DIR.iterdir())
    assert len(files) == 1
    assert stat.S_IMODE(os.stat(files[0]).st_mode) == 0o600


# --------------------------------------------------------------------
# F4 — Rich markup injection: dynamic text must render literally
# --------------------------------------------------------------------
def test_confirm_command_renders_markup_in_command_as_literal_text(monkeypatch):
    from hackit.knowledge import RiskLevel, ToolInfo
    from hackit import safety

    tool = ToolInfo(
        name="nmap", category="scanning", package="nmap", summary="t", description="t",
        when_to_use="t", risk=RiskLevel.LOW, requires_target_auth=False,
        command_template="nmap <target>",
    )

    buf = io.StringIO()
    test_console = Console(file=buf, force_terminal=False, width=200)
    monkeypatch.setattr(safety, "console", test_console)
    monkeypatch.setattr("rich.prompt.Confirm.ask", lambda *a, **k: False)

    safety.confirm_command(tool, "nmap [bold red]INJECTED[/]")
    output = buf.getvalue()
    # The literal bracket text must appear in the rendered output —
    # if markup injection weren't neutralized, "INJECTED" would be
    # styled (and the literal "[bold red]"/"[/]" text would vanish).
    assert "[bold red]INJECTED[/]" in output


# --------------------------------------------------------------------
# F5 — flag-injection advisory warning
# --------------------------------------------------------------------
@pytest.mark.parametrize(
    "value,expect_warning",
    [
        ("10.10.10.5", False),
        ("example.com", False),
        ("--script=vuln evil.com", True),
        ("-oA /tmp/out", True),
        ("", False),
    ],
)
def test_flag_injection_warning(value, expect_warning):
    warning = flag_injection_warning("target", value)
    assert (warning is not None) == expect_warning


# --------------------------------------------------------------------
# F6 — GUI detail panel: placeholders must survive HTML rendering
# --------------------------------------------------------------------
def test_render_tool_html_preserves_placeholder_syntax():
    pyqt6 = pytest.importorskip("PyQt6.QtWidgets")  # GUI extra not always installed
    from hackit.gui.widgets import render_tool_html
    from hackit.knowledge.registry import get_tool

    tool = get_tool("nmap")
    html_out = render_tool_html(tool)
    # <target> must be HTML-escaped (&lt;target&gt;), not left as a
    # bare tag that a renderer like QTextBrowser would silently drop.
    assert "&lt;target&gt;" in html_out
    assert "<target>" not in html_out.replace("&lt;target&gt;", "")
