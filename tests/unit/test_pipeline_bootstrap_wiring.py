from types import SimpleNamespace
from unittest.mock import Mock

import main as main_module
from main import SIEMPipeline
import pytest


def test_pipeline_init_passes_detection_and_normalizer_to_label_engine(monkeypatch, tmp_path):
    monkeypatch.setattr(main_module, "detect_distro", lambda: {"family": "debian"})
    monkeypatch.setattr(main_module, "ensure_database", lambda config: None)
    monkeypatch.setattr(main_module, "DistroMLAdapter", lambda distro_family: SimpleNamespace())
    monkeypatch.setattr(main_module, "PhaseManager", lambda **kwargs: SimpleNamespace(_save=lambda: None))
    monkeypatch.setattr(main_module, "Normalizer", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "DetectionEngine", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "CorrelationEngine", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "RiskScoringEngine", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "IncidentManager", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "ActiveMonitor", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "InstantMLEngine", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(
        main_module,
        "ScoreCalibrationEngine",
        lambda **kwargs: SimpleNamespace(set_label_engine=Mock(), save=lambda: None),
    )
    monkeypatch.setattr(main_module, "BaselineLearningEngine", lambda **kwargs: SimpleNamespace(_save=lambda: None))
    monkeypatch.setattr(main_module, "ReportEngine", lambda db: SimpleNamespace())
    monkeypatch.setattr(main_module, "MLController", lambda config, db: SimpleNamespace())
    monkeypatch.setattr(main_module, "ConfidenceScorer", lambda: SimpleNamespace())
    monkeypatch.setattr(main_module, "DelayedLearningBuffer", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "RareEventFilter", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "AnomalyGuard", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "BaselineValidator", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "HostBaselineEngine", lambda **kwargs: SimpleNamespace(set_model_dir=lambda *a, **k: None, _save=lambda: None))
    monkeypatch.setattr(main_module, "ContextStateStore", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "MLStateStore", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "RuntimeStateStore", lambda **kwargs: SimpleNamespace())

    class _Shutdown:
        def register(self, *args, **kwargs):
            return None

        def install(self):
            return None

    monkeypatch.setattr(main_module, "GracefulShutdown", lambda: _Shutdown())
    monkeypatch.setattr(SIEMPipeline, "_restore_state", lambda self: None)

    init_calls = []

    class _LabelEngine:
        def __init__(self, *args, **kwargs):
            pass

        def initialize(self, **kwargs):
            init_calls.append(kwargs)

    monkeypatch.setitem(__import__("sys").modules, "core.ml.label_engine", SimpleNamespace(LabelEngine=_LabelEngine))

    config = {
        "storage": {"models_dir": str(tmp_path / "models"), "state_dir": str(tmp_path / "state")},
        "detection": {"ioc": {}},
    }

    pipeline = SIEMPipeline(config=config)

    assert len(init_calls) == 1
    assert init_calls[0]["detection_engine"] is pipeline.detection
    assert init_calls[0]["normalizer"] is pipeline.normalizer


def test_pipeline_init_passes_bootstrap_scan_mode_to_label_engine(monkeypatch, tmp_path):
    monkeypatch.setattr(main_module, "detect_distro", lambda: {"family": "debian"})
    monkeypatch.setattr(main_module, "ensure_database", lambda config: None)
    monkeypatch.setattr(main_module, "DistroMLAdapter", lambda distro_family: SimpleNamespace())
    monkeypatch.setattr(main_module, "PhaseManager", lambda **kwargs: SimpleNamespace(_save=lambda: None))
    monkeypatch.setattr(main_module, "Normalizer", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "DetectionEngine", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "CorrelationEngine", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "RiskScoringEngine", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "IncidentManager", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "ActiveMonitor", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "InstantMLEngine", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(
        main_module,
        "ScoreCalibrationEngine",
        lambda **kwargs: SimpleNamespace(set_label_engine=Mock(), save=lambda: None),
    )
    monkeypatch.setattr(main_module, "BaselineLearningEngine", lambda **kwargs: SimpleNamespace(_save=lambda: None))
    monkeypatch.setattr(main_module, "ReportEngine", lambda db: SimpleNamespace())
    monkeypatch.setattr(main_module, "MLController", lambda config, db: SimpleNamespace())
    monkeypatch.setattr(main_module, "ConfidenceScorer", lambda: SimpleNamespace())
    monkeypatch.setattr(main_module, "DelayedLearningBuffer", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "RareEventFilter", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "AnomalyGuard", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "BaselineValidator", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "HostBaselineEngine", lambda **kwargs: SimpleNamespace(set_model_dir=lambda *a, **k: None, _save=lambda: None))
    monkeypatch.setattr(main_module, "ContextStateStore", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "MLStateStore", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "RuntimeStateStore", lambda **kwargs: SimpleNamespace())

    class _Shutdown:
        def register(self, *args, **kwargs):
            return None

        def install(self):
            return None

    monkeypatch.setattr(main_module, "GracefulShutdown", lambda: _Shutdown())
    monkeypatch.setattr(SIEMPipeline, "_restore_state", lambda self: None)

    ctor_calls = []

    class _LabelEngine:
        def __init__(self, *args, **kwargs):
            ctor_calls.append(kwargs)

        def initialize(self, **kwargs):
            return None

    monkeypatch.setitem(__import__("sys").modules, "core.ml.label_engine", SimpleNamespace(LabelEngine=_LabelEngine))

    config = {
        "storage": {"models_dir": str(tmp_path / "models"), "state_dir": str(tmp_path / "state")},
        "detection": {"ioc": {}},
        "ml": {"bootstrap_scan_mode": "auto"},
    }

    SIEMPipeline(config=config)

    assert ctor_calls[0]["bootstrap_scan_mode"] == "auto"


def test_pipeline_init_applies_shadow_mode_config(monkeypatch, tmp_path):
    monkeypatch.setattr(main_module, "detect_distro", lambda: {"family": "debian"})
    monkeypatch.setattr(main_module, "ensure_database", lambda config: None)
    monkeypatch.setattr(main_module, "DistroMLAdapter", lambda distro_family: SimpleNamespace())
    monkeypatch.setattr(main_module, "PhaseManager", lambda **kwargs: SimpleNamespace(_save=lambda: None))
    monkeypatch.setattr(main_module, "Normalizer", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "DetectionEngine", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "CorrelationEngine", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "RiskScoringEngine", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "IncidentManager", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "ActiveMonitor", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "InstantMLEngine", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(
        main_module,
        "ScoreCalibrationEngine",
        lambda **kwargs: SimpleNamespace(set_label_engine=Mock(), save=lambda: None),
    )
    monkeypatch.setattr(main_module, "BaselineLearningEngine", lambda **kwargs: SimpleNamespace(_save=lambda: None))
    monkeypatch.setattr(main_module, "ReportEngine", lambda db: SimpleNamespace())
    monkeypatch.setattr(main_module, "MLController", lambda config, db: SimpleNamespace())
    monkeypatch.setattr(main_module, "ConfidenceScorer", lambda: SimpleNamespace())
    monkeypatch.setattr(main_module, "DelayedLearningBuffer", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "RareEventFilter", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "AnomalyGuard", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "BaselineValidator", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "HostBaselineEngine", lambda **kwargs: SimpleNamespace(set_model_dir=lambda *a, **k: None, _save=lambda: None))
    monkeypatch.setattr(main_module, "ContextStateStore", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "MLStateStore", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "RuntimeStateStore", lambda **kwargs: SimpleNamespace())

    class _Shutdown:
        def register(self, *args, **kwargs):
            return None

        def install(self):
            return None

    monkeypatch.setattr(main_module, "GracefulShutdown", lambda: _Shutdown())
    monkeypatch.setattr(SIEMPipeline, "_restore_state", lambda self: None)

    class _LabelEngine:
        def __init__(self, *args, **kwargs):
            pass

        def initialize(self, **kwargs):
            return None

    monkeypatch.setitem(__import__("sys").modules, "core.ml.label_engine", SimpleNamespace(LabelEngine=_LabelEngine))

    config = {
        "storage": {"models_dir": str(tmp_path / "models"), "state_dir": str(tmp_path / "state")},
        "detection": {"ioc": {}},
        "ml": {
            "shadow_mode": {
                "enabled": True,
                "path": str(tmp_path / "ml_shadow.jsonl"),
                "sample_rate": 0.5,
                "sources": ["auth.log"],
                "include_raw_context": True,
            }
        },
    }

    pipeline = SIEMPipeline(config=config)

    assert pipeline._ml_shadow_enabled is True
    assert pipeline._ml_shadow_write_file is True
    assert pipeline._ml_shadow_path == str(tmp_path / "ml_shadow.jsonl")
    assert pipeline._ml_shadow_sample_rate == 0.5
    assert pipeline._ml_shadow_sources == ["auth.log"]
    assert pipeline._ml_shadow_include_raw_context is True


def test_main_bootstrap_label_scan_dry_run_uses_helper_without_starting_pipeline(monkeypatch):
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    monkeypatch.setattr(main_module, "load_config", lambda path: {"detection": {"ioc": {}}, "ml": {}})
    monkeypatch.setattr(main_module, "apply_distro_paths", lambda config, overrides=None: config)
    monkeypatch.setattr(
        main_module,
        "IntegrationSettings",
        SimpleNamespace(load=lambda config_dir=None: SimpleNamespace(log_overrides={})),
    )

    calls = []
    monkeypatch.setattr(main_module, "run_bootstrap_label_scan_dry_run", lambda config: calls.append(config) or 0)
    monkeypatch.setattr(main_module, "SIEMPipeline", lambda *args, **kwargs: pytest.fail("pipeline should not start"))
    monkeypatch.setattr(__import__("sys"), "argv", ["main.py", "--bootstrap-label-scan", "--dry-run"])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 0
    assert len(calls) == 1


def test_main_help_marks_bootstrap_scan_as_read_only_maintenance(monkeypatch, capsys):
    monkeypatch.setattr(__import__("sys"), "argv", ["main.py", "--help"])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "Read-only maintenance label scan" in out


@pytest.mark.parametrize("family", ["debian", "rhel", "suse"])
def test_first_boot_smoke_keeps_distro_first_wiring(monkeypatch, tmp_path, family):
    monkeypatch.setattr(main_module, "detect_distro", lambda: {"family": family})
    monkeypatch.setattr(main_module, "ensure_database", lambda config: None)
    monkeypatch.setattr(main_module, "DistroMLAdapter", lambda distro_family: SimpleNamespace(distro_family=distro_family))
    monkeypatch.setattr(main_module, "PhaseManager", lambda **kwargs: SimpleNamespace(_save=lambda: None))
    monkeypatch.setattr(main_module, "CorrelationEngine", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "RiskScoringEngine", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "IncidentManager", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "ActiveMonitor", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "InstantMLEngine", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(
        main_module,
        "ScoreCalibrationEngine",
        lambda **kwargs: SimpleNamespace(set_label_engine=Mock(), save=lambda: None),
    )
    monkeypatch.setattr(main_module, "BaselineLearningEngine", lambda **kwargs: SimpleNamespace(_save=lambda: None))
    monkeypatch.setattr(main_module, "ReportEngine", lambda db: SimpleNamespace())
    monkeypatch.setattr(main_module, "MLController", lambda config, db: SimpleNamespace())
    monkeypatch.setattr(main_module, "ConfidenceScorer", lambda: SimpleNamespace())
    monkeypatch.setattr(main_module, "DelayedLearningBuffer", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "RareEventFilter", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "AnomalyGuard", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "BaselineValidator", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "HostBaselineEngine", lambda **kwargs: SimpleNamespace(set_model_dir=lambda *a, **k: None, _save=lambda: None))
    monkeypatch.setattr(main_module, "ContextStateStore", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "MLStateStore", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(main_module, "RuntimeStateStore", lambda **kwargs: SimpleNamespace())

    class _Shutdown:
        def register(self, *args, **kwargs):
            return None

        def install(self):
            return None

    monkeypatch.setattr(main_module, "GracefulShutdown", lambda: _Shutdown())
    monkeypatch.setattr(SIEMPipeline, "_restore_state", lambda self: None)

    normalizer_calls = []
    detection_calls = []
    label_engine_ctor = []
    label_engine_init = []

    class _Normalizer:
        def __init__(self, **kwargs):
            normalizer_calls.append(kwargs)

    class _DetectionEngine:
        def __init__(self, **kwargs):
            detection_calls.append(kwargs)

    monkeypatch.setattr(main_module, "Normalizer", _Normalizer)
    monkeypatch.setattr(main_module, "DetectionEngine", _DetectionEngine)

    class _LabelEngine:
        def __init__(self, *args, **kwargs):
            label_engine_ctor.append(kwargs)

        def initialize(self, **kwargs):
            label_engine_init.append(kwargs)

    monkeypatch.setitem(__import__("sys").modules, "core.ml.label_engine", SimpleNamespace(LabelEngine=_LabelEngine))

    config = {
        "storage": {"models_dir": str(tmp_path / "models"), "state_dir": str(tmp_path / "state")},
        "detection": {"ioc": {}},
    }

    pipeline = SIEMPipeline(config=config)

    assert pipeline.distro_family == family
    assert normalizer_calls == [{"distro_family": family}]
    assert detection_calls[0]["distro_family"] == family
    assert label_engine_ctor[0]["distro_family"] == family
    assert label_engine_init[0]["detection_engine"] is pipeline.detection
    assert label_engine_init[0]["normalizer"] is pipeline.normalizer
