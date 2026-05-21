from __future__ import annotations

import sys

from ui.backend_facade import collect_overview_status


def _import_qt():
    try:
        from PySide6.QtCore import QtMsgType, qInstallMessageHandler
        from PySide6.QtWidgets import QApplication
    except ImportError as exc:
        return None, exc
    return (QApplication, QtMsgType, qInstallMessageHandler), None


_SUPPRESSED_QT_MESSAGES = {
    "This plugin does not support propagateSizeHints()",
}


def _install_qt_message_filter(qt_msg_type, install_handler) -> None:
    def _handler(message_type, _context, message):
        text = str(message or "").strip()
        if message_type == qt_msg_type.QtWarningMsg and text in _SUPPRESSED_QT_MESSAGES:
            return
        print(text, file=sys.stderr)

    install_handler(_handler)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    config_path = args[0] if args else None

    qt_imports, qt_error = _import_qt()
    if qt_error is not None:
        print(
            "PySide6 bulunamadı. Masaüstü UI için `pip install PySide6` çalıştırın ve sonra `python -m ui.app` ile tekrar deneyin.",
            file=sys.stderr,
        )
        return 2
    QApplication, QtMsgType, qInstallMessageHandler = qt_imports
    _install_qt_message_filter(QtMsgType, qInstallMessageHandler)

    from .main_window import MainWindow
    from .preflight import PreflightWindow
    from .theme import apply_app_theme

    app = QApplication([sys.argv[0], *args])
    app.setApplicationName("AegisCore")
    apply_app_theme(app, mode="dark")

    preflight = PreflightWindow(config_path=config_path)
    windows: dict[str, object] = {"preflight": preflight}

    def _open_main(preflight_payload: dict) -> None:
        overview = collect_overview_status(config_path=config_path)
        main_window = MainWindow(
            overview_status=overview,
            security_locks=preflight_payload.get("security_locks", {}),
            config_path=config_path,
        )
        windows["main"] = main_window
        main_window.show()
        preflight.close()

    preflight.continue_requested.connect(_open_main)
    preflight.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
