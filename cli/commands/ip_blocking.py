from __future__ import annotations

import json


def _find_pending_block_suggestion(db, suggestion_id: int) -> dict | None:
    rows = db.get_ip_block_suggestions(reviewed=False, limit=10000)
    for row in rows or []:
        if int(row.get("id", 0) or 0) == int(suggestion_id):
            return row
    return None


def _print_ip_block_suggestions(rows: list[dict]) -> None:
    if not rows:
        print("Bekleyen IP block suggestion yok.")
        return
    print("Pending IP block suggestions:")
    for row in rows:
        reviewed = str(bool(row.get("reviewed", False))).lower()
        action = str(row.get("action", "") or "")
        abuse_score = row.get("abuse_score")
        abuse_reports = row.get("abuse_reports")
        abuse_country = str(row.get("abuse_country", "") or "")
        print(
            f"  id={row.get('id')} ip={row.get('ip','-')} "
            f"score={abuse_score if abuse_score is not None else ''} "
            f"reports={abuse_reports if abuse_reports is not None else ''} "
            f"country={abuse_country} source={row.get('source','-')} "
            f"reason={row.get('reason','-')} alert_id={row.get('alert_id')} "
            f"reviewed={reviewed} action={action}"
        )


def _print_ip_block_result(result: dict) -> None:
    print(json.dumps(result, indent=2, ensure_ascii=False))


def run_ip_blocking_cli(
    config: dict,
    args,
    *,
    ensure_database,
    ip_blocker_cls,
    sys_module,
) -> int:
    db = ensure_database(config)
    try:
        if args.list_ip_block_suggestions:
            rows = db.get_ip_block_suggestions(reviewed=False, limit=200)
            _print_ip_block_suggestions(rows)
            return 0

        blocker = ip_blocker_cls(config=config, db=db)

        if args.block_ip or args.block_suggestion_id is not None:
            suggestion = None
            ip = (args.block_ip or "").strip()
            reason = ""
            suggestion_id = None
            if args.block_suggestion_id is not None:
                suggestion_id = int(args.block_suggestion_id)
                suggestion = _find_pending_block_suggestion(db, suggestion_id)
                if not suggestion:
                    print(f"Bekleyen suggestion bulunamadı: id={suggestion_id}", file=sys_module.stderr)
                    return 2
                if not ip:
                    ip = str(suggestion.get("ip", "") or "").strip()
                reason = str(suggestion.get("reason", "") or "")
            result = blocker.block_ip(
                ip=ip,
                reason=reason,
                dry_run=bool(args.dry_run),
                executed_by="terminal",
                suggestion_id=suggestion_id,
            )
            if suggestion_id and result.ok and result.status == "applied":
                db.review_ip_block_suggestion(suggestion_id, "blocked")
            _print_ip_block_result(result.to_dict())
            return 0 if result.ok else 2

        if args.unblock_ip:
            result = blocker.unblock_ip(
                ip=args.unblock_ip,
                dry_run=bool(args.dry_run),
                executed_by="terminal",
            )
            _print_ip_block_result(result.to_dict())
            return 0 if result.ok else 2

        return 0
    finally:
        db.close()
