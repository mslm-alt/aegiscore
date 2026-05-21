import logging
from pathlib import Path

from app.bootstrap import configure_logging

REAL_FILE_HANDLER = logging.FileHandler


def _reset_root_logging():
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass


def test_setup_logging_keeps_stream_handler_when_file_handler_fails(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _reset_root_logging()

    def fail_file_handler(*args, **kwargs):
        raise PermissionError("no write access")

    monkeypatch.setattr(logging, "FileHandler", fail_file_handler)

    warnings = []
    warning_logger = logging.getLogger("siem.main")
    original_warning = warning_logger.warning

    def capture_warning(msg, *args, **kwargs):
        warnings.append(msg % args if args else msg)
        return original_warning(msg, *args, **kwargs)

    monkeypatch.setattr(warning_logger, "warning", capture_warning)

    warning_emitted = configure_logging("INFO", warning_emitted=False)

    root = logging.getLogger()
    assert any(isinstance(h, logging.StreamHandler) for h in root.handlers)
    assert not any(isinstance(h, REAL_FILE_HANDLER) for h in root.handlers)
    assert warnings
    assert "stream logging ile devam ediliyor" in warnings[0]
    assert warning_emitted is True

    _reset_root_logging()


def test_setup_logging_preserves_normal_file_logging(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _reset_root_logging()

    configure_logging("INFO", warning_emitted=False)

    root = logging.getLogger()
    file_handlers = [h for h in root.handlers if isinstance(h, logging.FileHandler)]
    stream_handlers = [h for h in root.handlers if type(h) is logging.StreamHandler]

    assert file_handlers
    assert stream_handlers

    logger = logging.getLogger("siem.main")
    logger.info("normal file logging works")

    for handler in root.handlers:
        handler.flush()

    log_path = Path("data/siem.log")
    assert log_path.exists()
    assert "normal file logging works" in log_path.read_text(encoding="utf-8")

    _reset_root_logging()
