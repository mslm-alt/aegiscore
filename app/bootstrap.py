from __future__ import annotations

import logging
import sys
from pathlib import Path

from core.distro import apply_distro_paths
from core.integrations import IntegrationSettings


def configure_logging(
    level: str = "WARNING",
    *,
    warning_emitted: bool = False,
    stdout = None,
    logging_module = None,
    file_handler_factory = None,
    logger_name: str = "siem.main",
    log_path: str = "data/siem.log",
) -> bool:
    logging_module = logging if logging_module is None else logging_module
    stdout = sys.stdout if stdout is None else stdout
    file_handler_factory = logging_module.FileHandler if file_handler_factory is None else file_handler_factory

    Path("data").mkdir(exist_ok=True)
    handlers = [logging_module.StreamHandler(stdout)]
    file_handler_error = None
    try:
        handlers.append(file_handler_factory(log_path, mode="a"))
    except OSError as exc:
        file_handler_error = exc

    logging_module.basicConfig(
        level=getattr(logging_module, str(level).upper(), logging_module.WARNING),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
    )

    if file_handler_error is not None and not warning_emitted:
        warning_emitted = True
        logging_module.getLogger(logger_name).warning(
            "Log dosyasi devre disi birakildi; stream logging ile devam ediliyor: %s",
            file_handler_error,
        )
    return warning_emitted


def prepare_startup_config(
    config_path: str,
    *,
    load_config_fn,
) -> tuple[dict, IntegrationSettings, str]:
    config = load_config_fn(config_path)
    config = apply_distro_paths(config, overrides=None)

    integration_settings = IntegrationSettings.load(config_dir=str(Path(config_path).parent))
    log_overrides = dict(getattr(integration_settings, "log_overrides", {}) or {})
    log_level = (
        log_overrides.get("level")
        or ((config.get("logging", {}) or {}).get("level"))
        or "WARNING"
    )
    return config, integration_settings, log_level
