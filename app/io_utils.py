from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path


def ensure_jsonl_writable(path: str) -> bool:
    p = Path(path)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

    if not p.exists():
        try:
            p.touch(mode=0o664)
            return True
        except OSError as exc:
            logging.getLogger(__name__).warning("[FileIO] %s oluşturulamadı: %s", path, exc)
            return False

    if os.access(path, os.W_OK):
        return True

    log = logging.getLogger(__name__)
    try:
        existing = p.read_bytes()
    except OSError as exc:
        log.warning("[FileIO] %s okunamadı: %s", path, exc)
        existing = b""

    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(dir=str(p.parent), prefix=".tmp_", suffix=".jsonl")
        try:
            os.write(fd, existing)
            os.fchmod(fd, 0o664)
        finally:
            os.close(fd)
        os.rename(tmp_path, path)
        tmp_path = None
        log.info("[FileIO] %s sahipliği atomik rename ile devralındı", path)
        return True
    except OSError as exc:
        log.warning("[FileIO] %s izin düzeltme başarısız: %s — dosya çıktısı devre dışı (DB akışı etkilenmez)", path, exc)
        if tmp_path:
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except OSError:
                pass
        return False


__all__ = ["ensure_jsonl_writable"]
