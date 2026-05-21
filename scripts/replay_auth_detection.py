#!/usr/bin/env python3
"""
Test-only auth replay helper.

Purpose:
  Feed auth log lines directly into Normalizer + DetectionEngine without
  touching live files like /var/log/auth.log and without using SIEMPipeline.

This avoids side effects such as:
  - AUTH-004/DE-001 from sudo tee / log tampering style test methods
  - phase stats / duplicate / seen_ips pollution from runtime ingestion noise

Usage:
  python scripts/replay_auth_detection.py --file /tmp/auth-replay.log
  python scripts/replay_auth_detection.py --line "Mar  5 09:00:00 host sshd[1]: Invalid user test from 192.168.1.182"
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.distro import detect_distro  # noqa: E402
from core.detection import DetectionEngine  # noqa: E402
from core.normalize import Normalizer  # noqa: E402


def _default_source_for_family(family: str) -> str:
    if family == "rhel":
        return "auth_log"
    if family == "suse":
        return "syslog"
    return "auth.log"


def _iter_lines(file_path: str | None, inline_lines: list[str]) -> list[str]:
    lines = [line for line in inline_lines if line.strip()]
    if file_path:
        lines.extend(
            line.rstrip("\n")
            for line in Path(file_path).read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay auth lines into parser+detection without live log writes.")
    parser.add_argument("--file", help="Replay source file with one auth log line per row.")
    parser.add_argument("--line", action="append", default=[], help="Inline auth log line; may be used multiple times.")
    parser.add_argument("--distro", default="", help="Override distro family (debian/rhel/suse/generic).")
    parser.add_argument("--source", default="", help="Override logical source name (default depends on distro).")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    args = parser.parse_args()

    lines = _iter_lines(args.file, args.line)
    if not lines:
        print("No replay lines provided. Use --file or --line.", file=sys.stderr)
        return 2

    family = (args.distro or detect_distro().get("family", "debian") or "debian").lower()
    source = args.source or _default_source_for_family(family)

    normalizer = Normalizer(distro_family=family)
    engine = DetectionEngine(
        config={"rules_dir": "rules", "rules_source": "yaml"},
        allow_empty_rules=False,
        distro_family=family,
    )

    events = []
    alerts = []
    for idx, raw in enumerate(lines, start=1):
        event = normalizer.normalize(raw, source)
        if event is None:
            events.append({
                "line_no": idx,
                "raw": raw,
                "normalized": False,
            })
            continue

        hits = engine.analyze(event, current_phase=0)
        events.append({
            "line_no": idx,
            "raw": raw,
            "normalized": True,
            "source": event.source,
            "category": event.category,
            "action": event.action,
            "outcome": event.outcome,
            "user": event.user,
            "src_ip": event.src_ip,
        })
        for hit in hits:
            alerts.append({
                "line_no": idx,
                "rule_id": hit.rule_id,
                "severity": hit.severity,
                "score": hit.score,
                "category": hit.category,
                "message": hit.message,
            })

    if args.json:
        print(json.dumps({
            "distro_family": family,
            "source": source,
            "line_count": len(lines),
            "events": events,
            "alerts": alerts,
        }, ensure_ascii=False, indent=2))
        return 0

    print(f"Replay source={source} distro={family} lines={len(lines)}")
    print("Events:")
    for event in events:
        if not event["normalized"]:
            print(f"  L{event['line_no']}: normalize miss")
            continue
        print(
            f"  L{event['line_no']}: {event['category']}/{event['action']} "
            f"user={event['user'] or '-'} src={event['src_ip'] or '-'}"
        )

    print("Alerts:")
    if not alerts:
        print("  (none)")
        return 0

    for alert in alerts:
        print(
            f"  L{alert['line_no']}: {alert['rule_id']} "
            f"[{alert['severity']}] score={alert['score']:.0f} {alert['message']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
