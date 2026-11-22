from __future__ import annotations

import html
import re

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from hackit.knowledge import RiskLevel, ToolInfo
from hackit.system_check import is_installed
from hackit.validation import flag_injection_warning

PLACEHOLDER_RE = re.compile(r"<([a-zA-Z0-9_\- ]+)>")

RISK_OBJECT_NAMES = {
    RiskLevel.PASSIVE: "riskBadgePassive",
    RiskLevel.LOW: "riskBadgeLow",
    RiskLevel.MEDIUM: "riskBadgeMedium",
    RiskLevel.HIGH: "riskBadgeHigh",
}


def _e(text: str) -> str:
    """HTML-escape a piece of tool data before it goes into the detail panel's markup.

    QTextBrowser renders this content as real HTML, so without
    escaping, a literal '<' / '>' — most notably every command
    template's own <placeholder> syntax — is parsed as an (unknown,
    silently dropped) tag rather than shown to the user. Escaping
    fixes that correctness bug and, as a side effect, is also the
    right thing to do for any future knowledge-base text that happens
    to contain HTML-special characters.
    """
    return html.escape(text)


def render_tool_html(tool: ToolInfo) -> str:
    installed = is_installed(tool)
    install_line = (
        '<span style="color:#39f58a;">✓ installed</span>'
        if installed
        else f'<span style="color:#f5c542;">✗ not installed — sudo apt install {_e(tool.package)}</span>'
    )
    args_rows = "".join(
        f"<tr><td style='color:#00f0ff;padding:3px 10px 3px 0;'><code>{_e(k)}</code></td>"
        f"<td style='padding:3px 0;color:#d8e4f0;'>{_e(v)}</td></tr>"
        for k, v in tool.args_explained.items()
    )
    errors = "".join(f"<li>{_e(e)}</li>" for e in tool.common_errors)
    next_steps = "".join(f"<li>{_e(s)}</li>" for s in tool.next_steps)
    alternatives = ", ".join(tool.alternatives) if tool.alternatives else "—"

    return f"""
    <h2 style="color:#00f0ff;margin-bottom:0;">{_e(tool.name)}</h2>
    <p style="color:#7d8fa8;margin-top:2px;">{_e(tool.category)} · {install_line}</p>
    <p>{_e(tool.description)}</p>
    <p><b style="color:#ff2bd6;">When to use it</b><br>{_e(tool.when_to_use)}</p>
    <p><b style="color:#ff2bd6;">Risk level</b><br>{_e(tool.risk_label())}</p>
    <p><b style="color:#ff2bd6;">Command</b></p>
    <pre style="background:rgba(0,0,0,0.35);padding:10px;border-radius:8px;
                border:1px solid rgba(0,240,255,0.2);color:#7effc0;">{_e(tool.command_template)}</pre>
    <table>{args_rows}</table>
    <p><b style="color:#ff2bd6;">Example</b><br><code>{_e(tool.example)}</code></p>
    <p><b style="color:#ff2bd6;">Expected output</b><br>{_e(tool.expected_output)}</p>
    {"<p><b style='color:#ff2bd6;'>Common errors</b><ul>" + errors + "</ul></p>" if errors else ""}
    {"<p><b style='color:#ff2bd6;'>Next steps</b><ul>" + next_steps + "</ul></p>" if next_steps else ""}
    <p style="color:#7d8fa8;">Alternatives: {_e(alternatives)}</p>
    """


class ToolDetailPanel(QTextBrowser):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setOpenExternalLinks(False)
        self.show_placeholder()

    def show_placeholder(self) -> None:
        self.setHtml(
            '<p style="color:#45526b;">Select a tool from the list, or type an objective above '
            "and press Enter to get a recommendation.</p>"
        )

    def show_tool(self, tool: ToolInfo) -> None:
        self.setHtml(render_tool_html(tool))


class AuthorizationDialog(QDialog):
    """Session-level scope acknowledgment — mirrors hackit.safety's terminal flow."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Authorization check")
        self.setMinimumWidth(480)
        layout = QVBoxLayout(self)

        notice = QLabel(
            "Before HACKiT helps you run anything against a network target, confirm you "
            "are authorized to test it — your own lab, or explicit written permission "
            "(signed SOW, bug-bounty scope, CTF rules, etc.). Unauthorized access to "
            "systems you don't own or have permission to test is illegal in most "
            "jurisdictions."
        )
        notice.setWordWrap(True)
        layout.addWidget(notice)

        self.scope_input = QLineEdit()
        self.scope_input.setPlaceholderText("Describe the authorized scope, e.g. 'home lab 10.10.10.0/24'")
        form = QFormLayout()
        form.addRow("Scope:", self.scope_input)
        layout.addLayout(form)

        self.confirm_box = QCheckBox("I confirm I am authorized to test this scope.")
        layout.addWidget(self.confirm_box)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._buttons = buttons

    def _on_accept(self) -> None:
        if not self.confirm_box.isChecked():
            QMessageBox.warning(self, "Confirmation required", "Please check the authorization box to continue.")
            return
        self.accept()

    def scope_text(self) -> str:
        return self.scope_input.text().strip() or "unspecified"


class CommandBuilderDialog(QDialog):
    """
    Fills in <placeholders> for a tool's command template, then — for
    HIGH-risk tools — requires typing the tool's name back as an
    extra confirmation, exactly mirroring the terminal's safety gate.
    """

    def __init__(self, tool: ToolInfo, parent: QWidget | None = None):
        super().__init__(parent)
        self.tool = tool
        self.setWindowTitle(f"Build & run: {tool.name}")
        self.setMinimumWidth(520)
        layout = QVBoxLayout(self)

        risk_label = QLabel(f"Risk: {tool.risk_label()}")
        risk_label.setObjectName(RISK_OBJECT_NAMES[tool.risk])
        layout.addWidget(risk_label)

        self.placeholders = list(dict.fromkeys(PLACEHOLDER_RE.findall(tool.command_template)))
        self.inputs: dict[str, QLineEdit] = {}
        form = QFormLayout()
        for ph in self.placeholders:
            edit = QLineEdit()
            hint = tool.args_explained.get(f"<{ph}>", "")
            if hint:
                edit.setPlaceholderText(hint)
            form.addRow(f"{ph}:", edit)
            self.inputs[ph] = edit
        layout.addLayout(form)

        self.preview = QLabel(tool.command_template)
        self.preview.setWordWrap(True)
        # Force plain-text rendering: QLabel auto-detects HTML-ish
        # content by default, so a placeholder value containing '<'/'>'
        # (e.g. someone pastes an HTML snippet as a URL/target) could
        # otherwise be interpreted as markup instead of shown as typed.
        self.preview.setTextFormat(Qt.TextFormat.PlainText)
        self.preview.setStyleSheet(
            "background: rgba(0,0,0,0.35); border: 1px solid rgba(0,240,255,0.2); "
            "border-radius: 8px; padding: 10px; color: #7effc0; font-family: monospace;"
        )
        layout.addWidget(self.preview)

        self.warning_label = QLabel("")
        self.warning_label.setWordWrap(True)
        self.warning_label.setTextFormat(Qt.TextFormat.PlainText)
        self.warning_label.setStyleSheet("color: #f5c542;")
        layout.addWidget(self.warning_label)
        for edit in self.inputs.values():
            edit.textChanged.connect(self._update_preview)

        self.confirm_name: QLineEdit | None = None
        if tool.risk == RiskLevel.HIGH:
            warn = QLabel(
                f"{tool.name} is HIGH risk (exploitation / brute-force / injection). "
                f"Type the tool name below to confirm."
            )
            warn.setWordWrap(True)
            warn.setStyleSheet("color:#ff5c7a;")
            layout.addWidget(warn)
            self.confirm_name = QLineEdit()
            self.confirm_name.setPlaceholderText(f"Type '{tool.name}' to confirm")
            layout.addWidget(self.confirm_name)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _update_preview(self) -> None:
        cmd = self.tool.command_template
        warnings: list[str] = []
        for ph, edit in self.inputs.items():
            value = edit.text()
            warning = flag_injection_warning(ph, value)
            if warning:
                warnings.append(warning)
            cmd = cmd.replace(f"<{ph}>", value or f"<{ph}>")
        self.preview.setText(cmd)
        self.warning_label.setText(("⚠ " + "  |  ".join(warnings)) if warnings else "")

    def _on_accept(self) -> None:
        if self.confirm_name is not None:
            if self.confirm_name.text().strip().lower() != self.tool.name.lower():
                QMessageBox.warning(self, "Confirmation required", f"Type '{self.tool.name}' exactly to proceed.")
                return
        self.accept()

    def final_command(self) -> str:
        cmd = self.tool.command_template
        for ph, edit in self.inputs.items():
            cmd = cmd.replace(f"<{ph}>", edit.text().strip())
        return cmd
