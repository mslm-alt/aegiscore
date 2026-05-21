from __future__ import annotations

import json
from typing import Callable


def build_bootstrap_manifest(report: dict) -> dict:
    return {
        "kind": "bootstrap_label_scan_candidate_manifest",
        "bootstrap_job_id": report["bootstrap_job_id"],
        "distro_family": report["distro_family"],
        "limits": report["limits"],
        "log_files": report["log_files"],
        "summary": {
            "scanned_files": report["scanned_files"],
            "scanned_bytes": report["scanned_bytes"],
            "candidate_attack": report["candidate_attack"],
            "candidate_normal": report["candidate_normal"],
            "skipped_reason": report["skipped_reason"],
            "attack_category_counts": report["attack_category_counts"],
            "normal_category_counts": report["normal_category_counts"],
            "duplicate_summary": report.get("duplicate_summary", {}),
        },
        "duplicate_summary": report.get("duplicate_summary", {}),
        "candidates": report["candidates"],
    }


def run_bootstrap_label_scan_dry_run(
    config: dict,
    *,
    detect_distro: Callable[[], dict],
    normalizer_cls,
    detection_engine_cls,
    bootstrap_log_scanner_cls,
    bootstrap_scan_artifact_paths: Callable[[str], dict],
    write_json_file: Callable[[str, dict], None],
) -> int:
    distro = detect_distro()
    distro_family = (distro or {}).get("family", "debian")
    det_cfg = (config.get("detection", {}) or {})

    scanner = bootstrap_log_scanner_cls(distro_family=distro_family)
    normalizer = normalizer_cls(distro_family=distro_family)
    detection = detection_engine_cls(
        config=det_cfg,
        db=None,
        ioc_file=det_cfg.get("ioc", {}).get("ioc_file", "config/ioc_list.txt"),
        allow_empty_rules=True,
        distro_family=distro_family,
    )
    report = scanner.dry_run_report(detection_engine=detection, normalizer=normalizer)
    manifest = build_bootstrap_manifest(report)
    paths = bootstrap_scan_artifact_paths(report["bootstrap_job_id"])
    write_json_file(paths["candidate_manifest"], manifest)
    write_json_file(paths["dry_run_report"], {key: value for key, value in report.items() if key != "candidates"})

    print(f"Bootstrap label scan dry-run ({report['distro_family']})")
    print(f"Suggested bootstrap_job_id: {report['bootstrap_job_id']}")
    limits = report["limits"]
    print(
        "Limits: "
        f"max_age_days={limits['max_age_days']} "
        f"max_file_mb={limits['max_file_mb']} "
        f"max_total_mb={limits['max_total_mb']} "
        f"category_quota={limits['category_quota']}"
    )
    print("Log files:")
    for item in report["log_files"]:
        size_text = str(item["size_bytes"]) if item["size_bytes"] is not None else "-"
        print(
            f"  {item['path']}: source={item['source']} "
            f"exists={'yes' if item['exists'] else 'no'} "
            f"readable={'yes' if item['readable'] else 'no'} "
            f"size_bytes={size_text}"
        )
    print(
        "Scan summary: "
        f"scanned_files={report['scanned_files']} "
        f"scanned_bytes={report['scanned_bytes']} "
        f"candidate_attack={report['candidate_attack']} "
        f"candidate_normal={report['candidate_normal']}"
    )
    print(f"Skipped reasons: {json.dumps(report['skipped_reason'], ensure_ascii=False, sort_keys=True)}")
    print(f"Candidate manifest: {paths['candidate_manifest']}")
    return 0


__all__ = ["build_bootstrap_manifest", "run_bootstrap_label_scan_dry_run"]
