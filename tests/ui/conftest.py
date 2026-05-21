from __future__ import annotations

from ui.i18n import set_language


def pytest_runtest_setup(item):
    set_language("en")


def pytest_runtest_teardown(item, nextitem):
    set_language("en")
