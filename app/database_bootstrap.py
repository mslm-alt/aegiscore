from __future__ import annotations

from core.database import create_database


def ensure_database(config: dict):
    """
    PostgreSQL backend'ini oluştur.
    URL yoksa RuntimeError fırlatır — AegisCore PostgreSQL olmadan çalışmaz.
    """
    try:
        db = create_database(config)
        if db is None:
            raise RuntimeError(
                "[AegisCore:DB] PostgreSQL URL bulunamadı.\n"
                "  DATABASE_URL=postgresql://user:pass@host:5432/db ortam değişkenini\n"
                "  veya config.yml -> database.url alanını ayarlayın.\n"
                "  Hızlı başlangıç: bash scripts/preflight.sh"
            )
        health = db.health_check()
        if not health.get("ok", True):
            status = health.get("status", "?")
            err = health.get("error", "")
            err_type = health.get("error_type", "")
            detail = health.get("detail", "")
            db_ver = health.get("schema_version", "?")
            exp_ver = health.get("expected_version", "?")
            if status == "migration_needed":
                msg = (
                    f"[AegisCore:DB] Schema versiyonu geride: "
                    f"db={db_ver}, beklenen={exp_ver}. "
                    f"Veritabanını sıfırlayın veya migration çalıştırın."
                )
            elif err_type:
                msg = f"[AegisCore:DB] Sağlık kontrolü başarısız: {err_type}: {err} | {detail}"
            else:
                msg = f"[AegisCore:DB] Sağlık kontrolü başarısız: {health}"
            raise RuntimeError(msg)
        return db
    except Exception as e:
        raise RuntimeError(str(e)) from e


__all__ = ["ensure_database"]
