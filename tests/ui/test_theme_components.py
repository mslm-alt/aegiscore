from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def test_theme_helpers_schema():
    from ui import theme

    assert "critical" in theme.SEVERITY_COLORS
    assert "blocked" in theme.STATUS_COLORS
    css = theme.common_stylesheet("dark")
    assert "QListWidget#sidebar" in css
    assert theme.apply_app_theme(None, "light") == "light"


def test_severity_color_mapping():
    from ui.theme import severity_color

    assert severity_color("critical").startswith("#")
    assert severity_color("high") != severity_color("low")
    assert severity_color("unexpected") == severity_color("unknown")


def test_badge_helper_qt():
    pytest.importorskip("PySide6")
    from ui.components import make_badge

    badge = make_badge("READ ONLY", "read_only")

    assert badge is not None
    assert badge.text() == "READ ONLY"


def test_components_import_qt():
    pytest.importorskip("PySide6")
    import ui.components

    assert ui.components is not None
