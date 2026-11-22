from __future__ import annotations

import shlex
import sys
from pathlib import Path

from PyQt6.QtCore import QProcess, Qt
from PyQt6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from hackit import __version__
from hackit.gui.widgets import AuthorizationDialog, CommandBuilderDialog, ToolDetailPanel
from hackit.intent import classify
from hackit.knowledge import CATEGORY_LABELS, ToolInfo
from hackit.knowledge.registry import ALL_TOOLS, list_category
from hackit.safety import log_action
from hackit.system_check import is_installed, rank_by_installed

STYLE_PATH = Path(__file__).parent / "styles.qss"


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"HACKiT v{__version__}")
        self.resize(1180, 760)

        self._session_authorized = False
        self._session_scope = ""
        self._current_tools: list[ToolInfo] = []
        self._process: QProcess | None = None

        central = QWidget()
        central.setObjectName("centralWidget")
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_header())

        body = QSplitter(Qt.Orientation.Horizontal)
        body.setContentsMargins(14, 14, 14, 14)
        body.addWidget(self._build_sidebar())
        body.addWidget(self._build_main_panel())
        body.setStretchFactor(0, 0)
        body.setStretchFactor(1, 1)
        root.addWidget(body, stretch=1)

        self.statusBar().showMessage("Ready — ask an objective, or browse categories on the left.")
        self._populate_category_list()
        self._load_tools(ALL_TOOLS)

    # ---------------------------------------------------------------- UI
    def _build_header(self) -> QFrame:
        bar = QFrame()
        bar.setObjectName("headerBar")
        bar.setFixedHeight(64)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(20, 0, 20, 0)

        title_box = QVBoxLayout()
        title = QLabel("HACKiT")
        title.setObjectName("appTitle")
        subtitle = QLabel("AI-powered penetration testing assistant for Kali Linux")
        subtitle.setObjectName("appSubtitle")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        layout.addLayout(title_box)
        layout.addStretch()

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Describe your objective, e.g. 'scan a network for open ports'...")
        self.search_box.setFixedWidth(440)
        self.search_box.returnPressed.connect(self._on_ask)
        layout.addWidget(self.search_box)

        ask_btn = QPushButton("Ask")
        ask_btn.clicked.connect(self._on_ask)
        layout.addWidget(ask_btn)
        return bar

    def _build_sidebar(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("panel")
        frame.setMaximumWidth(260)
        layout = QVBoxLayout(frame)

        label = QLabel("CATEGORIES")
        label.setProperty("class", "sectionLabel")
        label.setStyleSheet("color:#ff2bd6; font-weight:600; letter-spacing:1.5px; font-size:11px;")
        layout.addWidget(label)

        self.category_list = QListWidget()
        self.category_list.itemClicked.connect(self._on_category_selected)
        layout.addWidget(self.category_list)
        return frame

    def _build_main_panel(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(14, 0, 0, 0)

        splitter = QSplitter(Qt.Orientation.Vertical)

        top_splitter = QSplitter(Qt.Orientation.Horizontal)

        self.tool_table = QTableWidget(0, 4)
        self.tool_table.setHorizontalHeaderLabels(["Tool", "Risk", "Installed", "Summary"])
        self.tool_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.tool_table.verticalHeader().setVisible(False)
        self.tool_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.tool_table.setAlternatingRowColors(True)
        self.tool_table.itemSelectionChanged.connect(self._on_tool_selected)
        top_splitter.addWidget(self.tool_table)

        right_panel = QFrame()
        right_panel.setObjectName("panel")
        right_layout = QVBoxLayout(right_panel)
        self.detail_panel = ToolDetailPanel()
        right_layout.addWidget(self.detail_panel, stretch=1)

        self.run_button = QPushButton("Build && Run Command")
        self.run_button.setEnabled(False)
        self.run_button.clicked.connect(self._on_run_clicked)
        right_layout.addWidget(self.run_button)

        top_splitter.addWidget(right_panel)
        top_splitter.setStretchFactor(0, 1)
        top_splitter.setStretchFactor(1, 1)
        splitter.addWidget(top_splitter)

        log_frame = QFrame()
        log_frame.setObjectName("panel")
        log_layout = QVBoxLayout(log_frame)
        log_label = QLabel("COMMAND OUTPUT")
        log_label.setStyleSheet("color:#ff2bd6; font-weight:600; letter-spacing:1.5px; font-size:11px;")
        log_layout.addWidget(log_label)
        self.log_view = QTextEdit()
        self.log_view.setObjectName("commandLog")
        self.log_view.setReadOnly(True)
        log_layout.addWidget(self.log_view)
        splitter.addWidget(log_frame)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter)
        return container

    # ------------------------------------------------------------- data
    def _populate_category_list(self) -> None:
        self.category_list.clear()
        all_item = QListWidgetItem("All tools")
        all_item.setData(Qt.ItemDataRole.UserRole, None)
        self.category_list.addItem(all_item)
        for key, label in CATEGORY_LABELS.items():
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, key)
            self.category_list.addItem(item)
        self.category_list.setCurrentRow(0)

    def _load_tools(self, tools: list[ToolInfo]) -> None:
        self._current_tools = rank_by_installed(tools)
        self.tool_table.setRowCount(len(self._current_tools))
        for row, tool in enumerate(self._current_tools):
            self.tool_table.setItem(row, 0, QTableWidgetItem(tool.name))
            self.tool_table.setItem(row, 1, QTableWidgetItem(tool.risk.value))
            self.tool_table.setItem(row, 2, QTableWidgetItem("yes" if is_installed(tool) else "no"))
            self.tool_table.setItem(row, 3, QTableWidgetItem(tool.summary))

    # ---------------------------------------------------------- handlers
    def _on_category_selected(self, item: QListWidgetItem) -> None:
        key = item.data(Qt.ItemDataRole.UserRole)
        tools = list_category(key) if key else ALL_TOOLS
        self._load_tools(tools)
        self.statusBar().showMessage(f"Showing {len(tools)} tools" + (f" in {item.text()}" if key else ""))

    def _on_tool_selected(self) -> None:
        rows = self.tool_table.selectionModel().selectedRows()
        if not rows:
            self.run_button.setEnabled(False)
            return
        tool = self._current_tools[rows[0].row()]
        self.detail_panel.show_tool(tool)
        self.run_button.setEnabled(True)
        self._selected_tool = tool

    def _on_ask(self) -> None:
        query = self.search_box.text().strip()
        if not query:
            return
        result = classify(query)
        if not result.candidates:
            self.statusBar().showMessage("No confident match — try browsing a category instead.")
            self.detail_panel.setHtml(
                "<p style='color:#f5c542;'>I couldn't confidently match that to a specific tool. "
                "Try a category on the left, or rephrase.</p>"
            )
            return
        self._load_tools(result.candidates)
        self.tool_table.selectRow(0)
        label = result.category_label or "General"
        self.statusBar().showMessage(f"Best match area: {label} (confidence: {result.confidence})")

    def _on_run_clicked(self) -> None:
        tool = getattr(self, "_selected_tool", None)
        if tool is None:
            return

        if not self._session_authorized:
            dialog = AuthorizationDialog(self)
            if dialog.exec() != AuthorizationDialog.DialogCode.Accepted:
                return
            self._session_authorized = True
            self._session_scope = dialog.scope_text()
            self._append_log(f"[authorization] scope confirmed: {self._session_scope}\n")

        builder = CommandBuilderDialog(tool, self)
        if builder.exec() != CommandBuilderDialog.DialogCode.Accepted:
            return

        command = builder.final_command()
        self._run_command(tool, command)

    # --------------------------------------------------------- execution
    def _run_command(self, tool: ToolInfo, command: str) -> None:
        # shlex.split, not str.split() — must match executor.py's
        # parsing exactly, or a quoted value (a password with a
        # space, a path with a space) silently splits into the wrong
        # number of arguments here vs. what the approval dialog showed.
        try:
            parts = shlex.split(command)
        except ValueError as e:
            self._append_log(f"[error] couldn't parse that command: {e}\n")
            log_action(tool.name, command, approved=True, output_summary="gui_parse_error")
            return
        if not parts:
            self._append_log("[error] empty command — nothing to run.\n")
            return

        self._append_log(f"\n$ {command}\n")
        log_action(tool.name, command, approved=True, output_summary="gui_start")

        self._process = QProcess(self)
        self._process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self._process.readyReadStandardOutput.connect(self._on_process_output)
        self._process.finished.connect(lambda code, _status: self._on_process_finished(tool, command, code))
        self._process.errorOccurred.connect(lambda _err: self._append_log(
            f"[error] '{parts[0]}' isn't installed, not on PATH, or couldn't start. "
            f"Try: sudo apt install {tool.package}\n"
        ))
        self._process.start(parts[0], parts[1:])

    def _on_process_output(self) -> None:
        if self._process is None:
            return
        data = bytes(self._process.readAllStandardOutput()).decode(errors="replace")
        self._append_log(data)

    def _on_process_finished(self, tool: ToolInfo, command: str, code: int) -> None:
        self._append_log(f"\n[process exited with code {code}]\n")
        log_action(tool.name, command, approved=True, output_summary=f"gui_exit={code}")

    def _append_log(self, text: str) -> None:
        self.log_view.insertPlainText(text)
        self.log_view.verticalScrollBar().setValue(self.log_view.verticalScrollBar().maximum())


def launch() -> None:
    app = QApplication(sys.argv)
    try:
        app.setStyleSheet(STYLE_PATH.read_text())
    except OSError:
        pass
    window = MainWindow()
    window.show()
    app.exec()


if __name__ == "__main__":
    launch()
