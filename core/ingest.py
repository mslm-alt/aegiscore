"""
core/ingest.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Log ingest layer — file and journald readers.

Split out of main.py.
"""

import os
import stat
import json as _json   # Bug #18: keep this at module scope instead of importing inside the function
import time as _time   # Bug #18: keep this at module scope instead of importing inside the function
import logging
import subprocess
import re
from pathlib import Path
from typing import Iterator, Optional, List

logger = logging.getLogger(__name__)

_UTMP_KEY_RE = re.compile(
    r'^(?P<user>\S+)\s+'
    r'(?P<tty>\S+)\s+'
    r'(?P<src>\S+)\s+'
    r'(?P<dow>\w{3})\s+(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2})'
)

_DEFAULT_APPROVED_LOG_ROOTS = (
    Path("/var/log"),
    Path("/var/lib/pgsql"),
    Path("/var/lib/postgresql"),
)


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _iter_extra_root_tokens(extra_roots: Optional[List[str | Path]] = None) -> List[str]:
    values: List[str] = []
    env_value = str(os.environ.get("AEGISCORE_EXTRA_APPROVED_LOG_ROOTS", "") or "").strip()
    if env_value:
        values.extend([item.strip() for item in env_value.split(os.pathsep) if item.strip()])
    for item in list(extra_roots or []):
        token = str(item or "").strip()
        if token:
            values.append(token)
    return values


def approved_log_roots(extra_roots: Optional[List[str | Path]] = None) -> List[Path]:
    project_root = Path.cwd().resolve()
    roots: List[Path] = []
    seen = set()
    for raw in [*list(_DEFAULT_APPROVED_LOG_ROOTS), *_iter_extra_root_tokens(extra_roots)]:
        token = Path(raw)
        candidate = token if token.is_absolute() else (project_root / token)
        resolved = candidate.resolve(strict=False)
        key = str(resolved)
        if key in seen:
            continue
        seen.add(key)
        roots.append(resolved)
    return roots


def _symlink_component_between(root: Path, target: Path) -> bool:
    try:
        relative = target.relative_to(root)
    except ValueError:
        return False
    current = root
    for part in relative.parts:
        current = current / part
        if current.exists() and current.is_symlink():
            return True
    return False


def validate_log_file_path(path: str, approved_roots: Optional[List[str | Path]] = None) -> tuple[Path | None, str | None]:
    token = str(path or "").strip()
    if not token:
        return None, "empty_path"
    project_root = Path.cwd().resolve()
    candidate = Path(token)
    candidate = candidate if candidate.is_absolute() else (project_root / candidate)
    approved = approved_log_roots(approved_roots)
    for root in approved:
        if _is_relative_to(candidate, root) and _symlink_component_between(root, candidate.parent):
            return None, "parent_symlink_blocked"
    candidate_resolved = candidate.resolve(strict=False)
    allowed_root = None
    for root in approved:
        if _is_relative_to(candidate_resolved, root):
            allowed_root = root
            break
    if allowed_root is None:
        return None, "path_outside_approved_roots"
    if candidate.exists() and candidate.is_symlink():
        return None, "symlink_blocked"
    if candidate.exists():
        try:
            mode = os.lstat(candidate).st_mode
        except OSError:
            return None, "path_stat_failed"
        if stat.S_ISDIR(mode):
            return None, "directory_blocked"
        if not stat.S_ISREG(mode):
            return None, "non_regular_file_blocked"
    return candidate, None


def tail_file(path: str, approved_roots: Optional[List[str | Path]] = None) -> Iterator[str]:
    """
    Follow the file like tail -f.
    Log rotation tracking: reopen the file if the inode changes.
    Compatible with logrotate, newsyslog, and similar tools.
    """
    if not path or not path.strip():
        logger.warning("tail_file: boş path — atlanıyor")
        return

    p, validation_error = validate_log_file_path(path, approved_roots=approved_roots)
    if validation_error == "path_outside_approved_roots":
        logger.warning("tail_file: approved log root dışında path — atlanıyor")
        return
    if validation_error in {"symlink_blocked", "parent_symlink_blocked"}:
        logger.warning("tail_file: symlink içeren log path reddedildi")
        return
    if validation_error == "directory_blocked":
        logger.warning("tail_file: directory path reddedildi")
        return
    if validation_error == "non_regular_file_blocked":
        logger.warning("tail_file: regular file olmayan path reddedildi")
        return
    if validation_error == "path_stat_failed":
        logger.warning("tail_file: log path doğrulanamadı")
        return
    if p is None:
        logger.warning("tail_file: geçersiz path — atlanıyor")
        return

    if not p.exists():
        logger.warning(f"Dosya yok: {path}")
        return

    try:
        p.stat()
    except PermissionError:
        logger.warning(f"Erişim reddedildi: {path} — root yetkisi gerekebilir")
        return

    def _open(resolved_path: Path):
        f = open(resolved_path, "r", errors="replace")
        f.seek(0, 2)
        try:
            inode = os.stat(resolved_path).st_ino
        except OSError:
            inode = None
        return f, inode

    f, inode = _open(p)
    try:
        while True:
            line = f.readline()
            if line:
                yield line.rstrip()
            else:
                _time.sleep(0.1)
                try:
                    current_inode = os.stat(p).st_ino
                    if current_inode != inode:
                        logger.info(f"[TAIL] Log rotation tespit edildi: {path}")
                        for remaining in f:
                            if remaining.strip():
                                yield remaining.rstrip()
                        f.close()
                        revalidated, error = validate_log_file_path(str(p), approved_roots=approved_roots)
                        if error or revalidated is None or not revalidated.exists():
                            break
                        f, inode = _open(revalidated)
                    elif f.tell() > os.stat(p).st_size:
                        # Bug #7: on truncation, seek to the end instead of the beginning,
                        # otherwise the entire file is reread (duplicate events)
                        logger.info(f"[TAIL] Truncation tespit edildi: {path}")
                        f.seek(0, 2)
                except OSError:
                    break
    finally:
        f.close()

def tail_journald(units: Optional[List[str]] = None) -> Iterator[str]:
    """
    Read the journal via journalctl --follow --output=json.
    On RHEL7 / older SUSE, JSON output may omit some fields.
    If JSON parsing fails, return the raw line so the syslog parser can take over.
    """
    cmd = ["journalctl", "--follow", "--output=json", "--no-pager"]
    if units:
        for u in units:
            cmd += ["-u", u]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, bufsize=1)
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                obj      = _json.loads(line)   # Bug #18: modül seviyesi _json
                msg      = obj.get("MESSAGE", "")
                hostname = obj.get("_HOSTNAME", "")
                unit     = obj.get("_SYSTEMD_UNIT", obj.get("SYSLOG_IDENTIFIER", ""))
                pid      = obj.get("_PID", "")
                if msg:
                    ts_us = obj.get("__REALTIME_TIMESTAMP", "")
                    try:
                        ts     = float(ts_us) / 1_000_000
                        ts_str = _time.strftime("%b %d %H:%M:%S", _time.localtime(ts))
                    except (ValueError, TypeError, OSError):
                        ts_str = _time.strftime("%b %d %H:%M:%S")  # Bug #18: modül seviyesi _time
                    pid_part = f"[{pid}]" if pid else ""
                    yield f"{ts_str} {hostname} {unit}{pid_part}: {msg}"
                else:
                    yield line
            except (_json.JSONDecodeError, ValueError):
                yield line
    except FileNotFoundError:
        logger.warning("journalctl yok — journald kaynağı devre dışı")
    except Exception as e:
        logger.error(f"Journald: {e}")


def tail_utmp(path: str, failed: bool = False,
              poll_seconds: float = 30.0) -> Iterator[str]:
    """
    Convert binary login records such as /var/log/wtmp and /var/log/btmp
    into readable lines through `last` / `lastb`.

    There is no full tail support; command output is scanned periodically and
    previously unseen session starts are emitted.
    """
    if not path or not path.strip():
        logger.warning("tail_utmp: boş path — atlanıyor")
        return

    p = Path(path)
    if not p.exists():
        logger.warning(f"UTMP dosyası yok: {path}")
        return

    cmd = ["lastb" if failed else "last", "-w", "-f", path]
    seen_keys = set()
    initialized = False

    while True:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            logger.warning(f"{cmd[0]} yok — {'btmp' if failed else 'wtmp'} kaynağı devre dışı")
            return
        except Exception as e:
            logger.error(f"{cmd[0]} çalıştırılamadı: {e}")
            return

        lines = []
        for raw in proc.stdout.splitlines():
            line = raw.strip()
            if not line:
                continue
            if line.startswith(("wtmp begins", "btmp begins")):
                continue
            if line.startswith(("reboot ", "shutdown ", "runlevel ")):
                continue
            lines.append(line)

        new_lines = []
        for line in reversed(lines):
            m = _UTMP_KEY_RE.match(line)
            key = m.group(0) if m else line
            if not initialized:
                seen_keys.add(key)
                continue
            if key in seen_keys:
                continue
            seen_keys.add(key)
            new_lines.append(line)

        initialized = True

        for line in new_lines:
            yield line

        _time.sleep(poll_seconds)
