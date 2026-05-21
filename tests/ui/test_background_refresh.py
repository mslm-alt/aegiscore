from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ui.workers import run_guarded


def test_background_worker_exception_handling():
    ok, result, error = run_guarded(lambda: (_ for _ in ()).throw(RuntimeError("boom")))

    assert ok is False
    assert result is None
    assert error["type"] == "RuntimeError"
    assert error["message"] == "boom"
    assert "RuntimeError: boom" in error["traceback"]
