"""Exercise the actual Qt action, background CLI, result handoff and report link."""
import json
from pathlib import Path
import shutil
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "plugins"))
sys.path.insert(0, str(ROOT / "scripts"))


@pytest.mark.skipif(sys.platform != "linux" or not shutil.which("gcc"), reason="Linux runtime integration")
def test_gui_dynamic_action_runs_cli_and_loads_report(tmp_path, monkeypatch):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtCore import QEventLoop, QTimer
    from PySide6.QtWidgets import QApplication, QFileDialog
    from PySide6.QtGui import QDesktopServices
    from decompile_gui import MainWindow
    from demo_dynamic import prepare

    config = prepare(tmp_path / "example")
    selections = iter([str(config), str(config.parent / "evaluation.json")])
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (next(selections), ""))
    opened = []
    monkeypatch.setattr(QDesktopServices, "openUrl", lambda url: opened.append(url.toLocalFile()) or True)
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    loop = QEventLoop()
    timer = QTimer()
    timer.setSingleShot(True)
    timer.timeout.connect(loop.quit)
    try:
        window.on_dynamic()
        window.worker.finished.connect(loop.quit)
        timer.start(30000)
        loop.exec()
        assert not window.worker.isRunning(), "GUI dynamic action timed out"
        data = json.loads(Path(window._dynamic_result_file).read_text())
        assert data["status"] == "TEST_VALIDATED", data["reason"]
        assert window.btn_dynamic_report.isEnabled()
        assert window.btn_dynamic.isEnabled()
        assert not window.btn_build.isEnabled()  # no static input was selected
        window.on_dynamic_report()
        assert opened == [str(Path(data["run_dir"]) / "report.html")]
    finally:
        timer.stop()
        window.close()
        app.processEvents()


def test_close_waits_for_worker_and_does_not_remove_handoff(tmp_path, monkeypatch):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication
    from PySide6.QtGui import QCloseEvent
    from decompile_gui import MainWindow
    from types import SimpleNamespace
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    calls = []
    window.worker = SimpleNamespace(isRunning=lambda: True, cancel=lambda: calls.append("cancel"),
                                    wait=lambda ms: False,
                                    finished=SimpleNamespace(connect=lambda callback: calls.append("wait-for-finish")))
    directory = Path(window._empty_dir)
    try:
        event = QCloseEvent()
        window.closeEvent(event)
        assert not event.isAccepted()
        assert directory.is_dir()
        assert calls == ["cancel", "wait-for-finish"]
    finally:
        window.worker = None
        window.close()
        app.processEvents()


def test_corrupt_handoff_is_reported_in_gui(monkeypatch):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication
    from decompile_gui import MainWindow
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    try:
        path = Path(window._empty_dir) / "result.json"
        path.write_text("{")
        window._dynamic_result_file = str(path)
        window.on_task_done("dynamic", False, "test interrupted write")
        assert "无法加载动态结果" in window.log_view.toPlainText()
        assert not window.btn_dynamic_report.isEnabled()
    finally:
        window.close()
        app.processEvents()


def test_cancel_before_spawn_does_not_start_a_process(monkeypatch):
    pytest.importorskip("PySide6")
    from decompile_gui import TaskThread
    import decompile_gui
    worker = TaskThread("dynamic", ["unused"])
    worker.cancel()
    monkeypatch.setattr(decompile_gui.subprocess, "Popen", lambda *a, **kw: pytest.fail("cancelled job must not spawn"))
    worker.run()
    assert worker._proc is None
