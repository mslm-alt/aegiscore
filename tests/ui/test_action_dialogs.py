import importlib
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def test_guarded_action_dialog_import_graceful():
    pytest.importorskip("PySide6")
    module = importlib.import_module("ui.actions.dialogs")
    assert module.GuardedActionDialog is not None
