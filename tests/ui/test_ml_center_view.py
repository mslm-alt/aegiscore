import os
from pathlib import Path
import sys

import pytest
from ui.i18n import set_language

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _qt_app():
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


class _ImmediateController:
    def __init__(self, owner=None, interval_ms=None):
        return None

    def trigger(self, task=None, on_result=None, on_error=None, on_finished=None):
        try:
            if task is not None and on_result is not None:
                on_result(task())
        except Exception as exc:
            if on_error is not None:
                on_error({"message": str(exc)})
        if on_finished is not None:
            on_finished()
        return True


def _patch_base(monkeypatch, ml_module):
    monkeypatch.setattr(ml_module, "RefreshController", _ImmediateController)
    monkeypatch.setattr(ml_module.backend_facade, "collect_ml_center_summary", lambda **kwargs: {
        "status": "ok",
        "ml_mode": "audit_only",
        "ml_mode_text": "Audit-only",
        "ml_safety_text": "No autonomous action",
        "first_training": {
            "family_id": "ML-AUTH",
            "current_samples": 12,
            "needed_samples": 40,
            "missing_samples": 28,
            "ready": False,
            "status": "readiness_blocked",
        },
        "family_rows": [
            {
                "family_id": "ML-AUTH",
                "status": "readiness_blocked",
                "current_samples": 12,
                "needed_samples": 40,
                "missing_samples": 28,
                "ready": False,
            },
            {
                "family_id": "ML-PROC",
                "status": "ready",
                "current_samples": 40,
                "needed_samples": 40,
                "missing_samples": 0,
                "ready": True,
            },
        ],
    })
    monkeypatch.setattr(ml_module.backend_facade, "collect_training_status", lambda **kwargs: {
        "status": "ok",
        "timestamp_text": "Never",
        "training_status": "No model has been trained yet.",
        "family_info": "",
        "model_info": "",
    })
    monkeypatch.setattr(ml_module.backend_facade, "collect_historical_scan_status", lambda **kwargs: {
        "status": "ok",
        "timestamp_text": "Never",
        "scan_status": "Historical scan has not been run yet. Run it from the CLI when needed.",
        "note": "CLI/manual only",
        "artifact_path": "",
    })
    monkeypatch.setattr(ml_module.backend_facade, "collect_ml_alerts", lambda **kwargs: {
        "status": "ok",
        "alerts": [
            {
                "id": 21,
                "timestamp_text": "2026-05-19 11:00:00",
                "severity": "medium",
                "rule_id": "ML-AUTH-001",
                "entity": "alice",
                "source_ip": "10.0.0.5",
                "message": "Behavioral deviation detected",
            }
        ],
    })


def test_ml_center_default_view_removes_manual_actions_and_shows_summary(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.ml_center_compact as ml_module

    _patch_base(monkeypatch, ml_module)
    view = ml_module.MLCenterView()

    assert not hasattr(view, "_train_now_button")
    assert not hasattr(view, "_historical_scan_button")
    assert not hasattr(view, "_start_manual_training")
    assert not hasattr(view, "_scan_local_historical_logs")
    assert view._summary_cards["mode"].text() == "Audit-only"
    assert view._summary_cards["safety"].text() == "No autonomous action"
    assert "Current Samples" in view._quota_detail.text()
    assert view._alerts_table.item(0, 2).text() == "ML-AUTH-001"


def test_ml_center_last_training_and_historical_fallbacks_render(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.ml_center_compact as ml_module

    _patch_base(monkeypatch, ml_module)
    view = ml_module.MLCenterView()

    assert view._summary_cards["training"].text() == "Never"
    assert "No model has been trained yet." in view._training_detail.text()
    assert view._summary_cards["historical"].text() == "Never"
    assert "Run it from the CLI when needed." in view._historical_detail.text()


def test_ml_center_localization_is_clean_in_english_and_translated_in_turkish(monkeypatch):
    pytest.importorskip("PySide6")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    _qt_app()
    import ui.views.ml_center_compact as ml_module

    _patch_base(monkeypatch, ml_module)
    set_language("en")
    view = ml_module.MLCenterView()
    english_text = " ".join(
        [
            view._title.text(),
            view._refresh.text(),
            view._quota_detail.text(),
            view._historical_detail.text(),
        ]
    )
    for token in ("ç", "ğ", "ı", "İ", "ö", "ş", "ü", "Yenile", "Hazır", "Geçmiş"):
        assert token not in english_text

    set_language("tr")
    view = ml_module.MLCenterView()
    view.retranslate_ui()
    assert view._title.text() == "ML Merkezi"
    assert "Gerekli Örnekler" in view._quota_detail.text()

