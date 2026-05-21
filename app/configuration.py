from __future__ import annotations

from pathlib import Path

import yaml

from core.language import resolve_language


def read_version(path: str = "VERSION", *, default: str = "0.0.0") -> str:
    try:
        return Path(path).read_text(encoding="utf-8").splitlines()[0].strip()
    except Exception:
        return default


def resolve_output_language(
    config: dict | None = None,
    explicit: str | None = None,
    *,
    environ: dict | None = None,
) -> str:
    return resolve_language(
        explicit=explicit,
        env=environ or {},
        config=config or {},
        default="tr",
    )


def load_config(path: str = "config/config.yml") -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    with p.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}
