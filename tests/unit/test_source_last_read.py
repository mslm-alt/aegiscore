from types import SimpleNamespace

from main import SIEMPipeline


def test_record_source_last_read_throttles_per_source():
    writes = []
    pipeline = object.__new__(SIEMPipeline)
    pipeline.db = SimpleNamespace(set_stat=lambda key, value: writes.append((key, value)))
    pipeline._last_source_stat_write_ts = {}
    pipeline._last_read_stat_interval = 45.0

    pipeline._record_source_last_read("auth.log", 100.0)
    pipeline._record_source_last_read("auth.log", 120.0)
    pipeline._record_source_last_read("auth.log", 150.0)

    assert writes == [
        ("last_read:auth.log", "100.0"),
        ("last_read:auth.log", "150.0"),
    ]


def test_record_source_last_read_swallow_db_errors():
    pipeline = object.__new__(SIEMPipeline)
    pipeline._last_source_stat_write_ts = {}
    pipeline._last_read_stat_interval = 45.0

    class _DB:
        def set_stat(self, key, value):
            raise RuntimeError("db write failed")

    pipeline.db = _DB()

    pipeline._record_source_last_read("auth.log", 100.0)
