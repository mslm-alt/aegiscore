import logging

from core.hunting import HuntEngine


def test_load_ack_logs_warning_and_keeps_fail_open(monkeypatch, caplog):
    engine = HuntEngine(db=None)

    class BrokenAckFile:
        def exists(self):
            return True

        def read_text(self):
            raise OSError("permission denied")

    engine._ack_file = BrokenAckFile()

    with caplog.at_level(logging.WARNING):
        result = engine._load_ack()

    assert result == set()
    assert "Ack dosyasi okunamadi" in caplog.text
