#!/usr/bin/env python3
"""decompile_gui.py - 拖拽式反编译 GUI（PySide6）

拖入二进制文件即可反编译，输出目录以文件树排列、点击即可查看代码。
支持：反编译 → 生成可编译工程 → 静态编译修复（fallback/LLM）。

界面：四个可拉伸、可隐藏的界块（输入 / 文件树 / 代码 / 日志），
支持暗色/亮色主题与自定义背景色。

用法：
    python decompile_gui.py
"""

import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal, QObject, QDir, QUrl, QSortFilterProxyModel
from PySide6.QtGui import (
    QDragEnterEvent, QDropEvent, QSyntaxHighlighter, QTextCharFormat,
    QColor, QFont, QFontDatabase, QAction,
)
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTreeView, QPlainTextEdit, QLabel, QPushButton, QComboBox, QFileDialog,
    QMessageBox, QFileSystemModel, QDockWidget, QColorDialog, QDialog,
    QListWidget, QListWidgetItem, QAbstractItemView, QToolButton, QSpinBox,
)

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from decompile_binary import detect_binary_type


# --------------------------------------------------------------------------- #
# C 语法高亮
# --------------------------------------------------------------------------- #
C_KEYWORDS = {
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if", "inline",
    "int", "long", "register", "restrict", "return", "short", "signed",
    "sizeof", "static", "struct", "switch", "typedef", "union", "unsigned",
    "void", "volatile", "while",
}
C_TYPES = {
    "undefined", "undefined1", "undefined2", "undefined3", "undefined4",
    "undefined5", "undefined6", "undefined7", "undefined8", "byte", "word",
    "uint", "ulong", "ulonglong", "qword", "dword", "ushort", "sbyte",
    "size_t", "ssize_t", "code", "bool", "FILE",
}


class CHighlighter(QSyntaxHighlighter):
    def __init__(self, doc):
        super().__init__(doc)
        import re
        self._re = re
        mono = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)

        def fmt(color, bold=False, italic=False):
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            f.setFontFamily(mono.family())
            if bold:
                f.setFontWeight(QFont.Bold)
            if italic:
                f.setFontItalic(True)
            return f

        self._fmt = {
            "keyword": fmt("#c586c0", bold=True),
            "type": fmt("#4ec9b0"),
            "string": fmt("#ce9178"),
            "comment": fmt("#6a9955", italic=True),
            "number": fmt("#b5cea8"),
            "preproc": fmt("#9b9b9b", bold=True),
        }

    def highlightBlock(self, text):
        re = self._re
        for m in re.finditer(r"//[^\n]*|/\*.*?\*/", text, re.DOTALL):
            self.setFormat(m.start(), m.end() - m.start(), self._fmt["comment"])
        for m in re.finditer(r'"(\\.|[^"\\])*"|\'(\\.|[^\'\\])*\'', text):
            self.setFormat(m.start(), m.end() - m.start(), self._fmt["string"])
        for m in re.finditer(r"^\s*#\s*\w+", text):
            self.setFormat(m.start(), m.end() - m.start(), self._fmt["preproc"])
        for m in re.finditer(r"\b(0[xX][0-9a-fA-F]+|\d+[uUlL]*)\b", text):
            self.setFormat(m.start(), m.end() - m.start(), self._fmt["number"])
        for m in re.finditer(r"\b[A-Za-z_]\w*\b", text):
            w = m.group(0)
            if w in C_KEYWORDS:
                self.setFormat(m.start(), m.end() - m.start(), self._fmt["keyword"])
            elif w in C_TYPES:
                self.setFormat(m.start(), m.end() - m.start(), self._fmt["type"])


# --------------------------------------------------------------------------- #
# 后台任务线程
# --------------------------------------------------------------------------- #
class TaskThread(QThread):
    log = Signal(str)
    done = Signal(str, bool, str)

    def __init__(self, kind, cmd, parent=None):
        super().__init__(parent)
        self.kind = kind
        self.cmd = cmd
        self._proc = None
        self._buf = []

    def cancel(self):
        if self._proc is not None and self._proc.poll() is None:
            try:
                # 杀整个进程树（python -> wsl -> make -> gcc）
                subprocess.run(
                    ["taskkill", "/pid", str(self._proc.pid), "/T", "/F"],
                    capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
            except Exception:
                try:
                    self._proc.terminate()
                except Exception:
                    pass

    def run(self):
        self.log.emit("$ " + " ".join(self.cmd))
        try:
            proc = subprocess.Popen(
                self.cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                cwd=str(SCRIPT_DIR),
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
            )
        except Exception as e:
            self.done.emit(self.kind, False, "启动失败: %s" % e)
            return
        self._proc = proc
        import time
        self._buf = []
        last_flush = time.time()
        try:
            for line in proc.stdout:
                self._buf.append(line.rstrip("\n"))
                now = time.time()
                if len(self._buf) >= 50 or (self._buf and now - last_flush >= 0.2):
                    self.log.emit("\n".join(self._buf))
                    self._buf = []
                    last_flush = now
        except Exception:
            pass
        if self._buf:
            self.log.emit("\n".join(self._buf))
            self._buf = []
        proc.wait()
        ok = proc.returncode == 0
        self.done.emit(self.kind, ok, "exit code %d" % proc.returncode)


# --------------------------------------------------------------------------- #
# 文件树过滤：隐藏编译中间产物（.o 等）
# --------------------------------------------------------------------------- #
class HideObjProxyModel(QSortFilterProxyModel):
    def filterAcceptsRow(self, row, parent):
        idx = self.sourceModel().index(row, 0, parent)
        p = self.sourceModel().filePath(idx)
        if p.lower().endswith(".o"):
            return False
        return True


# --------------------------------------------------------------------------- #
# 目录二进制选择弹窗
# --------------------------------------------------------------------------- #
class BinaryPickDialog(QDialog):
    def __init__(self, binaries, parent=None):
        super().__init__(parent)
        self.setWindowTitle("选择要反编译的二进制")
        self.resize(620, 420)
        self.selected = []

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("目录中识别到 %d 个二进制文件：" % len(binaries)))
        self.list = QListWidget()
        self.list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        for b in binaries:
            t = detect_binary_type(b) or "?"
            item = QListWidgetItem("%s  (%s)" % (b.name, t))
            item.setData(Qt.UserRole, str(b))
            self.list.addItem(item)
        layout.addWidget(self.list)

        btn_row = QHBoxLayout()
        btn_all = QPushButton("全部")
        btn_ok = QPushButton("反编译选中")
        btn_cancel = QPushButton("取消")
        btn_all.clicked.connect(self._pick_all)
        btn_ok.clicked.connect(self._pick_selected)
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_all)
        btn_row.addWidget(btn_ok)
        btn_row.addWidget(btn_cancel)
        layout.addLayout(btn_row)

    def _pick_all(self):
        self.list.selectAll()
        self._pick_selected()

    def _pick_selected(self):
        self.selected = [
            self.list.item(i).data(Qt.UserRole)
            for i in range(self.list.count())
            if self.list.item(i).isSelected()
        ]
        self.accept()


# --------------------------------------------------------------------------- #
# 文件列表条目（带移除按钮）
# --------------------------------------------------------------------------- #
class FileItemWidget(QWidget):
    def __init__(self, path, on_remove, parent=None):
        super().__init__(parent)
        p = Path(path)
        t = detect_binary_type(p) or "?"
        self.path = str(p)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 3, 8, 3)
        layout.setSpacing(8)
        label = QLabel("%s  (%s)" % (p.name, t))
        label.setToolTip(str(p))
        layout.addWidget(label)
        layout.addStretch(1)
        btn = QToolButton()
        btn.setText("✕")
        btn.setAutoRaise(True)
        btn.setToolTip("移除该文件")
        btn.clicked.connect(lambda: on_remove(self))
        layout.addWidget(btn)


# --------------------------------------------------------------------------- #
# 主窗口
# --------------------------------------------------------------------------- #
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("反编译器 · 拖入二进制即可")
        self.resize(1360, 860)
        self.setAcceptDrops(True)

        self.binary_paths = []
        self.map_path = None
        self.work_dir = None
        self.worker = None
        self._dark = True
        self._bg_color = QColor("#1e1e1e")

        self._create_central()
        self._create_docks()
        self._create_menus()
        self._apply_theme()

    # ---------------- 中央占位 ----------------
    def _create_central(self):
        self.central = QWidget()
        self.setCentralWidget(self.central)

    # ---------------- 四个界块 ----------------
    def _create_docks(self):
        # 1. 输入块（顶）
        self.input_dock = QDockWidget("输入", self)
        input_widget = QWidget()
        iv = QVBoxLayout(input_widget)
        iv.setContentsMargins(8, 8, 8, 8)

        self.drop_label = QLabel("把二进制文件拖到这里")
        self.drop_label.setAlignment(Qt.AlignCenter)
        self.drop_label.setMinimumHeight(64)
        self.drop_label.setStyleSheet(
            "QLabel { border: 2px dashed #666; border-radius: 8px; "
            "color: #888; font-size: 14px; }"
        )
        iv.addWidget(self.drop_label)

        self.file_list = QListWidget()
        self.file_list.setMaximumHeight(140)
        self.file_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        iv.addWidget(self.file_list)

        info_row = QHBoxLayout()
        self.binary_label = QLabel("未选择文件")
        self.binary_label.setStyleSheet("font-weight: bold;")
        info_row.addWidget(self.binary_label)
        info_row.addStretch(1)
        self.map_label = QLabel("map: 未指定")
        self.map_label.setStyleSheet("color: #888;")
        info_row.addWidget(self.map_label)
        iv.addLayout(info_row)

        btn_row = QHBoxLayout()
        self.btn_open = QPushButton("选择文件")
        self.btn_dir = QPushButton("选择目录")
        self.btn_map = QPushButton("选择 map")
        self.btn_decompile = QPushButton("反编译")
        self.btn_build = QPushButton("生成可编译工程")
        self.btn_repair = QPushButton("静态修复")
        self.btn_sigfix = QPushButton("签名修复")
        self.btn_cancel = QPushButton("取消")
        self.btn_open_dir = QPushButton("打开输出目录")
        self.btn_clear = QPushButton("清除")
        self.proposer_box = QComboBox()
        self.proposer_box.addItems(["fallback", "llm"])
        self.proposer_box.setToolTip("静态修复的补丁生成器")
        self.sigfix_spin = QSpinBox()
        self.sigfix_spin.setRange(1, 100000)
        self.sigfix_spin.setValue(50)
        self.sigfix_spin.setToolTip("签名修复最多处理的函数数")

        self.btn_decompile.setEnabled(False)
        self.btn_build.setEnabled(False)
        self.btn_repair.setEnabled(False)
        self.btn_sigfix.setEnabled(False)
        self.btn_cancel.setEnabled(False)

        for b in (self.btn_open, self.btn_dir, self.btn_map, self.btn_decompile,
                  self.btn_build, self.btn_repair, self.btn_sigfix, self.btn_cancel,
                  self.btn_open_dir, self.btn_clear):
            btn_row.addWidget(b)
        btn_row.addWidget(QLabel(" proposer:"))
        btn_row.addWidget(self.proposer_box)
        btn_row.addWidget(QLabel(" 签名修复上限:"))
        btn_row.addWidget(self.sigfix_spin)
        btn_row.addStretch(1)
        iv.addLayout(btn_row)

        self.btn_open.clicked.connect(self.on_open_file)
        self.btn_dir.clicked.connect(self.on_choose_dir)
        self.btn_map.clicked.connect(self.on_open_map)
        self.btn_clear.clicked.connect(self.clear_input)
        self.btn_decompile.clicked.connect(self.on_decompile)
        self.btn_build.clicked.connect(self.on_build)
        self.btn_repair.clicked.connect(self.on_repair)
        self.btn_sigfix.clicked.connect(self.on_sigfix)
        self.btn_cancel.clicked.connect(self.on_cancel)
        self.btn_open_dir.clicked.connect(self.on_open_dir)

        self.input_dock.setWidget(input_widget)
        self.addDockWidget(Qt.TopDockWidgetArea, self.input_dock)

        # 2. 文件树块（左）
        self.tree_dock = QDockWidget("文件树", self)
        tree_widget = QWidget()
        tv = QVBoxLayout(tree_widget)
        tv.setContentsMargins(0, 0, 0, 0)
        self.tree = QTreeView()
        self.tree.setAnimated(False)
        self.tree.setIndentation(14)
        tv.addWidget(self.tree)
        self.tree_dock.setWidget(tree_widget)
        self.addDockWidget(Qt.LeftDockWidgetArea, self.tree_dock)

        # 3. 代码块（右）
        self.code_dock = QDockWidget("代码", self)
        code_widget = QWidget()
        cv = QVBoxLayout(code_widget)
        cv.setContentsMargins(0, 0, 0, 0)
        self.code_label = QLabel("（点击左侧文件查看代码）")
        cv.addWidget(self.code_label)
        self.code_view = QPlainTextEdit()
        self.code_view.setReadOnly(True)
        mono = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        mono.setPointSize(11)
        self.code_view.setFont(mono)
        self.highlighter = CHighlighter(self.code_view.document())
        cv.addWidget(self.code_view)
        self.code_dock.setWidget(code_widget)
        self.addDockWidget(Qt.RightDockWidgetArea, self.code_dock)

        # 4. 日志块（底）
        self.log_dock = QDockWidget("日志", self)
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(10000)
        self.log_view.setFont(mono)
        self.log_dock.setWidget(self.log_view)
        self.addDockWidget(Qt.BottomDockWidgetArea, self.log_dock)

        # 均允许移动 + 关闭（隐藏）
        for d in (self.input_dock, self.tree_dock, self.code_dock, self.log_dock):
            d.setFeatures(QDockWidget.DockWidgetMovable |
                          QDockWidget.DockWidgetClosable)

        self.fs_model = QFileSystemModel()
        self.fs_model.setReadOnly(True)
        self.proxy_model = HideObjProxyModel()
        self.proxy_model.setSourceModel(self.fs_model)
        self.tree.setModel(self.proxy_model)
        # 初始根设为一个空目录，避免默认显示当前工作目录（含 .o 等杂项）
        self._empty_dir = tempfile.mkdtemp(prefix="decomp_gui_empty_")
        self.tree.setRootIndex(
            self.proxy_model.mapFromSource(self.fs_model.index(self._empty_dir))
        )
        self.tree.clicked.connect(self.on_tree_clicked)

    # ---------------- 菜单 ----------------
    def _create_menus(self):
        mb = self.menuBar()

        view_menu = mb.addMenu("视图")
        view_menu.addAction(self.input_dock.toggleViewAction())
        view_menu.addAction(self.tree_dock.toggleViewAction())
        view_menu.addAction(self.code_dock.toggleViewAction())
        view_menu.addAction(self.log_dock.toggleViewAction())
        view_menu.addSeparator()
        view_menu.addAction("全部显示", self._show_all_docks)

        settings_menu = mb.addMenu("设置")
        settings_menu.addAction("背景颜色...", self._choose_bg_color)
        settings_menu.addAction("恢复默认背景", self._reset_bg_color)
        settings_menu.addSeparator()
        self.dark_action = QAction("暗色主题", self, checkable=True, checked=True)
        self.light_action = QAction("亮色主题", self, checkable=True, checked=False)
        self.dark_action.triggered.connect(lambda: self._set_theme(True))
        self.light_action.triggered.connect(lambda: self._set_theme(False))
        settings_menu.addAction(self.dark_action)
        settings_menu.addAction(self.light_action)

    def _show_all_docks(self):
        for d in (self.input_dock, self.tree_dock, self.code_dock, self.log_dock):
            d.show()

    # ---------------- 主题 / 背景色 ----------------
    def _apply_theme(self):
        bg = self._bg_color.name()
        if self._dark:
            fg = "#d4d4d4"
            panel = "#252526"
            border = "#3c3c3c"
            btn_bg = "#3c3c3c"
            btn_hover = "#505050"
            edit_bg = "#1e1e1e"
            header = "#333333"
        else:
            fg = "#1f1f1f"
            panel = "#f3f3f3"
            border = "#cccccc"
            btn_bg = "#e1e1e1"
            btn_hover = "#d0d0d0"
            edit_bg = "#ffffff"
            header = "#e8e8e8"
        qss = """
        QMainWindow, QWidget { background-color: %(bg)s; color: %(fg)s; }
        QDockWidget { font-weight: bold; }
        QDockWidget::title {
            background: %(header)s; padding: 5px 8px; border: 1px solid %(border)s;
        }
        QTreeView, QPlainTextEdit, QComboBox {
            background-color: %(edit_bg)s; color: %(fg)s;
            border: 1px solid %(border)s;
        }
        QTreeView::item:selected { background: #0e639c; color: white; }
        QPushButton {
            background-color: %(btn_bg)s; color: %(fg)s;
            border: 1px solid %(border)s; border-radius: 4px; padding: 4px 12px;
        }
        QPushButton:hover { background-color: %(btn_hover)s; }
        QPushButton:disabled { color: #777; }
        QLabel { background: transparent; }
        QMenuBar { background: %(header)s; }
        QMenuBar::item:selected { background: %(btn_hover)s; }
        QMenu { background: %(panel)s; color: %(fg)s; border: 1px solid %(border)s; }
        QMenu::item:selected { background: %(btn_hover)s; }
        """ % {
            "bg": bg, "fg": fg, "panel": panel, "border": border,
            "btn_bg": btn_bg, "btn_hover": btn_hover,
            "edit_bg": edit_bg, "header": header,
        }
        self.setStyleSheet(qss)

    def _set_theme(self, dark):
        self._dark = dark
        self.dark_action.setChecked(dark)
        self.light_action.setChecked(not dark)
        self._apply_theme()

    def _choose_bg_color(self):
        c = QColorDialog.getColor(self._bg_color, self, "选择背景颜色")
        if c.isValid():
            self._bg_color = c
            self._apply_theme()

    def _reset_bg_color(self):
        self._bg_color = QColor("#1e1e1e" if self._dark else "#ffffff")
        self._apply_theme()

    # ---------------- 拖拽 ----------------
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        for url in event.mimeData().urls():
            p = url.toLocalFile()
            if p:
                self.set_input(p)
                return

    # ---------------- 文件选择 ----------------
    def on_open_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择二进制文件")
        if path:
            self.set_input(path)

    def on_choose_dir(self):
        path = QFileDialog.getExistingDirectory(self, "选择目录（自动扫描其中的二进制）")
        if path:
            self.set_input(path)

    def clear_input(self):
        self.file_list.clear()
        self.map_path = None
        self.map_label.setText("map: 未指定")
        self._sync_paths()
        self.append_log("已清除选择")

    def on_open_map(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择链接 map 文件", filter="Map files (*.map);;All files (*)"
        )
        if path:
            self.map_path = path
            self.map_label.setText("map: " + Path(path).name)

    def on_open_dir(self):
        if self.work_dir and Path(self.work_dir).exists():
            os.startfile(str(self.work_dir))
        else:
            QMessageBox.information(self, "提示", "还没有输出目录")

    def _scan_binaries(self, dir_path):
        results = []
        for p in sorted(Path(dir_path).iterdir()):
            if p.is_file() and detect_binary_type(p):
                results.append(p)
        return results

    def set_input(self, path):
        p = Path(path)
        if p.is_dir():
            binaries = self._scan_binaries(p)
            if not binaries:
                QMessageBox.information(self, "提示", "目录中未识别到二进制文件")
                return
            dlg = BinaryPickDialog(binaries, self)
            if dlg.exec() != QDialog.Accepted or not dlg.selected:
                return
            self.add_paths(dlg.selected)
        elif p.is_file():
            if detect_binary_type(p) is None:
                QMessageBox.warning(self, "提示", "不是可识别的二进制文件：\n%s" % path)
                return
            self.add_paths([p])
        else:
            QMessageBox.warning(self, "提示", "路径不存在：\n%s" % path)

    def add_paths(self, paths):
        existing = {
            self.file_list.itemWidget(self.file_list.item(i)).path
            for i in range(self.file_list.count())
        }
        added = 0
        for p in paths:
            p = str(Path(p))
            if p in existing:
                continue
            existing.add(p)
            item = QListWidgetItem()
            w = FileItemWidget(p, self._remove_file)
            item.setSizeHint(w.sizeHint())
            self.file_list.addItem(item)
            self.file_list.setItemWidget(item, w)
            added += 1
        self._sync_paths()
        if added:
            self.append_log("已添加 %d 个文件" % added)

    def _remove_file(self, widget):
        for i in range(self.file_list.count()):
            item = self.file_list.item(i)
            if self.file_list.itemWidget(item) is widget:
                self.file_list.takeItem(i)
                break
        self._sync_paths()

    def _sync_paths(self):
        self.binary_paths = []
        for i in range(self.file_list.count()):
            w = self.file_list.itemWidget(self.file_list.item(i))
            self.binary_paths.append(Path(w.path))

        n = len(self.binary_paths)
        if n == 0:
            self.binary_label.setText("未选择文件")
            self.work_dir = None
        elif n == 1:
            bp = self.binary_paths[0]
            self.work_dir = str(bp.parent / (bp.stem + "_work"))
            self.binary_label.setText(str(bp))
        else:
            first = self.binary_paths[0]
            self.work_dir = str(first.parent / "batch_work")
            self.binary_label.setText("%d 个二进制文件" % n)

        self.btn_decompile.setEnabled(n > 0)
        self.btn_build.setEnabled(n == 1)
        self.btn_repair.setEnabled(n == 1)
        self.btn_sigfix.setEnabled(n == 1)
        if self.work_dir:
            Path(self.work_dir).mkdir(parents=True, exist_ok=True)

    # ---------------- 任务 ----------------
    @property
    def decomp_dir(self):
        if len(self.binary_paths) != 1:
            return None
        stem = self.binary_paths[0].stem
        return str(Path(self.work_dir) / (stem + "_decomp"))

    @property
    def build_dir(self):
        if len(self.binary_paths) != 1:
            return None
        stem = self.binary_paths[0].stem
        return str(Path(self.work_dir) / (stem + "_build"))

    def _start_task(self, kind, cmd):
        if self.worker is not None and self.worker.isRunning():
            QMessageBox.warning(self, "提示", "已有任务在运行")
            return
        self.worker = TaskThread(kind, cmd)
        self.worker.log.connect(self.append_log)
        self.worker.done.connect(self.on_task_done)
        self._set_busy(True)
        self.worker.start()

    def _set_busy(self, busy):
        for b in (self.btn_decompile, self.btn_build, self.btn_repair,
                  self.btn_sigfix, self.btn_open, self.btn_dir, self.btn_map):
            b.setEnabled(not busy)
        self.btn_cancel.setEnabled(busy)

    def on_decompile(self):
        cmd = [sys.executable, str(SCRIPT_DIR / "decompile_binary.py")]
        cmd += [str(p) for p in self.binary_paths]
        cmd += ["-o", self.work_dir]
        self._start_task("decompile", cmd)

    def on_build(self):
        cmd = [
            sys.executable, str(SCRIPT_DIR / "decompile_helper.py"), "all",
            str(self.binary_paths[0]), self.decomp_dir, "-o", self.build_dir,
        ]
        if self.map_path:
            cmd += ["--map", self.map_path]
        self._start_task("build", cmd)

    def on_repair(self):
        cmd = [
            sys.executable, str(SCRIPT_DIR / "orchestrator.py"),
            str(self.binary_paths[0]), self.decomp_dir, "-o", self.build_dir,
            "--proposer", self.proposer_box.currentText(),
        ]
        if self.map_path:
            cmd += ["--map", self.map_path]
        self._start_task("repair", cmd)

    def on_sigfix(self):
        cmd = [
            sys.executable, str(SCRIPT_DIR / "fix_signatures_llm.py"),
            str(self.binary_paths[0]),
            "--max-functions", str(self.sigfix_spin.value()),
            "-o", self.decomp_dir,
        ]
        self._start_task("sigfix", cmd)

    def on_cancel(self):
        if self.worker is not None:
            self.worker.cancel()

    def on_task_done(self, kind, ok, message):
        self._set_busy(False)
        status = "成功" if ok else "失败"
        self.append_log("[%s] %s (%s)" % (kind, status, message))
        if kind == "decompile":
            self._refresh_tree(self.decomp_dir or self.work_dir)
            if ok:
                self.append_log("反编译完成，左侧可查看函数代码")
        elif kind == "sigfix":
            self._refresh_tree(self.decomp_dir or self.work_dir)
            if ok:
                self.append_log("签名修复完成，已重新反编译")
        elif kind == "build":
            self._refresh_tree(self.build_dir)
        elif kind == "repair":
            highlight = None
            if self.build_dir:
                pj = str(Path(self.build_dir) / "patches.json")
                if Path(pj).exists():
                    highlight = pj
            self._refresh_tree(self.build_dir, highlight)

    def _refresh_tree(self, target=None, highlight=None):
        if not target or not Path(target).exists():
            if self.work_dir and Path(self.work_dir).exists():
                target = self.work_dir
            else:
                return
        self.fs_model.setRootPath(target)
        self.tree.setRootIndex(
            self.proxy_model.mapFromSource(self.fs_model.index(target))
        )
        for i in range(1, 4):
            self.tree.resizeColumnToContents(i)
        if highlight and Path(highlight).exists():
            sidx = self.fs_model.index(str(highlight))
            if sidx.isValid():
                idx = self.proxy_model.mapFromSource(sidx)
                self.tree.setCurrentIndex(idx)
                self.tree.scrollTo(idx)

    def on_tree_clicked(self, index):
        path = self.fs_model.filePath(self.proxy_model.mapToSource(index))
        p = Path(path)
        if not p.is_file():
            return
        self.code_label.setText(path)
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            text = "（无法读取文件：%s）" % e
        self.code_view.setPlainText(text)

    # ---------------- 日志 ----------------
    def append_log(self, msg):
        self.log_view.appendPlainText(msg)

    def closeEvent(self, event):
        if self.worker is not None and self.worker.isRunning():
            self.worker.cancel()
            self.worker.wait(2000)
        if getattr(self, "_empty_dir", None) and Path(self._empty_dir).exists():
            shutil.rmtree(self._empty_dir, ignore_errors=True)
        event.accept()


def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
