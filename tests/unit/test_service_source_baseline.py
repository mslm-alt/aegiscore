import sys
import json
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def _evt(ts, process="systemd", action="service_heartbeat", outcome="success",
         category="process", source="auditd", **overrides):
    event = dict(
        ts=float(ts),
        process=process,
        action=action,
        outcome=outcome,
        category=category,
        source=source,
        user="root",
        src_ip="127.0.0.1",
        host="srv1",
        fields={},
        message="",
    )
    event.update(overrides)
    return SimpleNamespace(**event)


class TestServiceProcessBaselineSeparation:
    def _make_engine(self, tmp_path):
        from core.ml.baseline import BaselineLearningEngine
        return BaselineLearningEngine(model_dir=str(tmp_path), db=None)

    def test_service_baseline_is_primary_signal_for_service_drift(self, tmp_path):
        engine = self._make_engine(tmp_path)

        for i in range(140):
            engine.update(_evt(i, process="systemd", action="service_heartbeat"))

        scores, _ = engine.update(_evt(9999, process="systemd", action="service_restart"))

        assert scores.get("service_baseline", 0.0) > 0.0

    def test_frequency_context_score_is_capped(self, tmp_path):
        engine = self._make_engine(tmp_path)

        for hour in range(24):
            for day in range(7):
                ts = float(day * 86400 + hour * 3600)
                engine.update(_evt(ts, process="systemd", action="service_heartbeat"))

        for i in range(6):
            engine.update(_evt(700000 + i * 4000, source="auth.log", category="auth", action="ssh_login"))

        scores, _ = engine.update(
            _evt(800000, source="auth.log", category="auth", action="ssh_login", outcome="failure")
        )

        assert scores.get("freq_anomaly", 0.0) <= 12.0

    def test_peer_group_signal_removed_from_baseline_engine(self, tmp_path):
        engine = self._make_engine(tmp_path)

        for i in range(140):
            engine.update(_evt(i, process="systemd", action="service_heartbeat"))

        scores, _ = engine.update(_evt(9999, process="systemd", action="service_restart"))
        context_status = engine.get_context_status()

        assert "peer_group" not in scores
        assert "peer_groups" not in context_status

    def test_context_state_save_restore_tolerates_removed_peer_baseline(self, tmp_path):
        from core.state_manager import ContextStateStore

        engine = self._make_engine(tmp_path)
        store = ContextStateStore(state_dir=str(tmp_path))

        for i in range(40):
            engine.update(_evt(i, process="systemd", action="service_heartbeat"))

        assert store.save_all(engine) is True

        payload = json.loads(store.path.read_text())
        assert "peer_baseline" not in payload

        payload["peer_baseline"] = {
            "legacy": {"exec": {"mean": 1.0, "var": 0.1, "n": 3}}
        }
        payload.pop("_checksum", None)
        store.path.write_text(json.dumps(payload))

        restored = self._make_engine(tmp_path)
        assert store.restore_all(restored) is True
