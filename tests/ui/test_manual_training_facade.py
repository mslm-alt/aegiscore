import ui.backend_facade as backend_facade


class _Db:
    def close(self):
        return None


def test_training_status_facade_uses_scheduler_report(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "_load_phase_manager_status", lambda config: {"current_phase": 2})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _Db())
    monkeypatch.setattr(
        backend_facade,
        "_ml_training_scheduler_report",
        lambda config, db, pm_status, trigger_request="scheduler": {"trigger_request": trigger_request, "training_mode": "manual"},
    )

    result = backend_facade.collect_ml_training_status()

    assert result["status"] == "ok"
    assert result["trigger_request"] == "scheduler"
    assert result["training_mode"] == "manual"


def test_manual_training_preview_facade_uses_manual_dry_run(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "_load_phase_manager_status", lambda config: {"current_phase": 2})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _Db())
    monkeypatch.setattr(
        backend_facade,
        "_ml_training_scheduler_report",
        lambda config, db, pm_status, trigger_request="scheduler": {"trigger_request": trigger_request, "train_now": True},
    )

    result = backend_facade.preview_manual_training_plan()

    assert result["status"] == "ok"
    assert result["trigger_request"] == "manual_dry_run"
    assert result["train_now"] is True


def test_manual_training_execute_facade_calls_main_wrapper(monkeypatch):
    monkeypatch.setattr(backend_facade, "_load_runtime_context", lambda config_path=None: {"config": {}})
    monkeypatch.setattr(backend_facade, "_load_phase_manager_status", lambda config: {"current_phase": 2})
    monkeypatch.setattr(backend_facade, "create_database", lambda config: _Db())

    class _Main:
        @staticmethod
        def execute_manual_training(config, db, pm_status):
            return {"trigger_request": "manual_execute", "training_started": True, "no_action_contract": True}

    monkeypatch.setattr(backend_facade, "main_module", _Main)

    result = backend_facade.execute_manual_training()

    assert result["status"] == "ok"
    assert result["trigger_request"] == "manual_execute"
    assert result["training_started"] is True
