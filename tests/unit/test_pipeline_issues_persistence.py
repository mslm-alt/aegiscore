import json
from types import SimpleNamespace

from main import SIEMPipeline


def test_persist_pipeline_issues_writes_both_system_stats(monkeypatch):
    writes = []
    pipeline = object.__new__(SIEMPipeline)
    pipeline.db = SimpleNamespace(set_stat=lambda key, value: writes.append((key, value)))

    pipeline._persist_pipeline_issues(["warn-1"], ts=1714212900.0)

    assert writes[0] == ("pipeline_issues", json.dumps(["warn-1"], ensure_ascii=False))
    assert writes[1] == ("pipeline_issues_ts", "2024-04-27T10:15:00Z")


def test_persist_pipeline_issues_swallow_db_write_errors(monkeypatch):
    pipeline = object.__new__(SIEMPipeline)

    class _DB:
        def __init__(self):
            self.calls = 0

        def set_stat(self, key, value):
            self.calls += 1
            raise RuntimeError("db locked")

    pipeline.db = _DB()

    pipeline._persist_pipeline_issues(["warn-1"], ts=1714212900.0)

    assert pipeline.db.calls == 1
