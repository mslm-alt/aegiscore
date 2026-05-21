from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True)
class DispatchResult:
    action: str = "unhandled"
    code: int | None = None
    test_prechecked: bool = False


def is_info_only_command(args: Any) -> bool:
    return any([
        args.preflight, args.status, args.phase, args.metrics,
        args.report, args.validate_rules, args.doctor, args.smoke_test,
        args.diagnose_parse_fail, args.diagnose_event_growth,
        args.bootstrap_label_scan,
        args.ml_readiness,
        bool(args.ml_family_readiness),
        bool(args.ml_support_score_family),
        bool(args.ml_active_emit_dry_run),
        args.ml_mapping_audit,
        bool(args.ml_runtime_label_candidate_audit),
        args.ml_historical_scan_plan,
        args.ml_normal_label_plan,
        args.ml_label_trust_audit,
        args.ml_label_metadata_plan,
        args.ml_backfill_legacy_bootstrap_metadata,
        args.ml_label_extraction_audit,
        args.ml_summary,
        args.ml_train_scheduler_dry_run,
        args.ml_training_status,
        args.ml_train_now_dry_run,
        args.ml_model_status,
        args.ml_config_audit,
        args.ml_label_contract_audit,
        args.ml_verified_manifest_dry_run,
        bool(args.ml_verified_manifest_audit),
        args.db_doctor, args.db_version, args.db_pending,
        args.explain_alert is not None,
        args.alert_explanation_contract_audit,
        args.list_ip_block_suggestions,
        bool(args.block_ip), bool(args.unblock_ip), args.block_suggestion_id is not None,
        args.version if hasattr(args, "version") else False,
    ])


def dispatch_command(args: Any, config: dict, handlers: Mapping[str, Any]) -> DispatchResult:
    if args.preflight or args.doctor:
        script = Path(handlers["main_file"]).parent / "scripts" / "preflight.sh"
        return DispatchResult("raise", handlers["subprocess_run"](["bash", str(script), args.config]).returncode)

    if args.smoke_test:
        return DispatchResult("raise", handlers["run_smoke_test"](config))

    if args.diagnose_parse_fail:
        return DispatchResult("raise", handlers["run_diagnose_parse_fail"](config))

    if args.diagnose_event_growth:
        return DispatchResult("raise", handlers["run_diagnose_event_growth"](config))

    if args.bootstrap_label_scan:
        if args.dry_run:
            return DispatchResult("raise", handlers["run_bootstrap_label_scan_dry_run"](config))
        print("--bootstrap-label-scan yalnız --dry-run ile çalışır.", file=handlers["sys"].stderr)
        return DispatchResult("return", 2)

    if args.db_doctor:
        return DispatchResult("raise", handlers["run_db_doctor"](config))

    if args.db_version:
        return DispatchResult("raise", handlers["run_db_version"](config))

    if args.db_pending:
        return DispatchResult("raise", handlers["run_db_pending"](config))

    if args.explain_alert is not None:
        return DispatchResult("raise", handlers["run_explain_alert_cli"](config, args))

    if args.alert_explanation_contract_audit:
        return DispatchResult("raise", handlers["run_alert_explanation_contract_audit"](config))

    if args.block_ip and args.unblock_ip:
        print("--block-ip ve --unblock-ip birlikte kullanılamaz.", file=handlers["sys"].stderr)
        return DispatchResult("return", 2)

    if args.block_suggestion_id is not None and args.unblock_ip:
        print("--block-suggestion-id ile --unblock-ip birlikte kullanılamaz.", file=handlers["sys"].stderr)
        return DispatchResult("return", 2)

    if args.list_ip_block_suggestions or args.block_ip or args.unblock_ip or args.block_suggestion_id is not None:
        return DispatchResult("raise", handlers["run_ip_blocking_cli"](config, args))

    if args.ml_readiness:
        return DispatchResult("raise", handlers["run_ml_readiness_report"](config))

    if args.ml_family_readiness:
        return DispatchResult("raise", handlers["run_ml_family_readiness"](config, args.ml_family_readiness))

    if args.ml_support_score_family:
        return DispatchResult("raise", handlers["run_ml_support_score_family"](config, args.ml_support_score_family))

    if args.ml_active_emit_dry_run:
        return DispatchResult("raise", handlers["run_ml_active_emit_dry_run"](config, args.ml_active_emit_dry_run))

    if args.ml_mapping_audit:
        return DispatchResult("raise", handlers["run_ml_mapping_audit"](config))

    if args.ml_runtime_label_candidate_audit:
        return DispatchResult("raise", handlers["run_ml_runtime_label_candidate_audit"](config, args.ml_runtime_label_candidate_audit))

    if args.ml_historical_scan_plan:
        return DispatchResult("raise", handlers["run_ml_historical_scan_plan"](config))

    if args.ml_normal_label_plan:
        return DispatchResult("raise", handlers["run_ml_normal_label_plan"](config))

    if args.ml_label_trust_audit:
        return DispatchResult("raise", handlers["run_ml_label_trust_audit"](config))

    if args.ml_label_metadata_plan:
        return DispatchResult("raise", handlers["run_ml_label_metadata_plan"](config))

    if args.ml_backfill_legacy_bootstrap_metadata:
        if args.dry_run and args.apply:
            print("--ml-backfill-legacy-bootstrap-metadata için --dry-run ve --apply birlikte kullanılamaz.", file=handlers["sys"].stderr)
            return DispatchResult("return", 2)
        if args.apply:
            return DispatchResult("raise", handlers["run_ml_legacy_bootstrap_backfill"](config, apply=True))
        if args.dry_run:
            return DispatchResult("raise", handlers["run_ml_legacy_bootstrap_backfill"](config, apply=False))
        print("--ml-backfill-legacy-bootstrap-metadata için --dry-run veya --apply zorunlu.", file=handlers["sys"].stderr)
        return DispatchResult("return", 2)

    if args.ml_label_extraction_audit:
        return DispatchResult("raise", handlers["run_ml_label_extraction_audit"](config))

    if args.ml_summary:
        return DispatchResult("raise", handlers["run_ml_summary"](config))

    if args.ml_train_scheduler_dry_run:
        return DispatchResult("raise", handlers["run_ml_train_scheduler_dry_run"](config))

    if args.ml_training_status:
        return DispatchResult("raise", handlers["run_ml_training_status"](config))

    if args.ml_train_now_dry_run:
        return DispatchResult("raise", handlers["run_ml_train_now_dry_run"](config))

    if args.ml_train_now:
        return DispatchResult("raise", handlers["run_ml_train_now"](config))

    if args.ml_model_status:
        return DispatchResult("raise", handlers["run_ml_model_status"](config))

    if args.ml_config_audit:
        return DispatchResult("raise", handlers["run_ml_config_audit"](config))

    if args.ml_label_contract_audit:
        return DispatchResult("raise", handlers["run_ml_label_contract_audit"](config))

    if args.ml_verified_manifest_dry_run:
        return DispatchResult(
            "raise",
            handlers["run_verified_manifest_dry_run"](
                config,
                families=args.ml_verified_manifest_family,
                limit=args.ml_verified_manifest_limit,
                out_path=args.ml_verified_manifest_out,
            ),
        )

    if args.ml_verified_manifest_audit:
        return DispatchResult("raise", handlers["run_verified_manifest_audit_cli"](args.ml_verified_manifest_audit))

    ml_result = _dispatch_ml_control_command(args, config, handlers)
    if ml_result.action != "unhandled":
        return ml_result

    if args.validate_rules:
        from core.detection import RuleEngine

        cfg = config.get("detection", {})
        engine = RuleEngine(
            rules_dir=cfg.get("rules_dir", "rules"),
            allow_empty=True,
        )
        errors = engine.validate()
        total = len(engine.rules)
        lang = handlers["_output_language"](config)
        print(f"\n{'━'*52}")
        print(f"  {handlers['system_text']('rule_validation_report', lang)}")
        print(f"{'━'*52}")
        print(f"  {handlers['system_text']('loaded_rules', lang):<14}: {total}")
        if errors:
            print(f"  {handlers['system_text']('error_count', lang):<14}: {len(errors)}")
            for err in errors:
                print(f"  ❌ {err}")
        else:
            print(f"  ✅ {handlers['system_text']('all_rules_valid', lang)}")
        print(f"{'━'*52}\n")
        return DispatchResult("return")

    if args.pack_status:
        from core.detection import RuleEngine

        cfg = config.get("detection", {})
        engine = RuleEngine(
            rules_dir=cfg.get("rules_dir", "rules"),
            allow_empty=True,
        )
        status = engine.get_pack_status()
        bold = "\033[1m"
        cyan = "\033[96m"
        green = "\033[92m"
        red = "\033[91m"
        reset = "\033[0m"
        print(f"\n{bold}{cyan}{'━'*58}{reset}")
        print(f"{bold}  📦 Rule Pack Durumu{reset}")
        print(f"{'━'*58}")
        print(f"  Toplam kural: {status['total_rules']}")
        print(f"\n  Pack'ler:")
        for pack, data in sorted(status["packs"].items()):
            tactics = ", ".join(data["tactics"]) or "-"
            print(f"    {green}●{reset} {pack:<15} {data['rules']:3d} kural  |  taktik: {tactics}")
        if status["tactics_covered"]:
            print(f"\n  Kapsanan taktikler ({len(status['tactics_covered'])}):")
            for tactic in status["tactics_covered"]:
                print(f"    ✅ {tactic}")
        if status["blind_spots"]:
            print(f"\n  {red}Kör noktalar ({len(status['blind_spots'])}):{reset}")
            for tactic in status["blind_spots"]:
                print(f"    ❌ {tactic}")
        print(f"{'━'*58}\n")
        return DispatchResult("return")

    if args.hunt:
        from core.hunting import HuntEngine

        db = handlers["ensure_database"](config)
        try:
            handlers["time"].sleep(0.2)
            hunter = HuntEngine(
                db=db,
                days=args.hunt_days,
                user=args.hunt_user,
            )
            if args.hunt.upper() == "ALL":
                results = hunter.run_all()
                if not results:
                    print("\n  ✅ Hicbir hunt senaryosunda şüpheli bulgu yok.")
                for result in results:
                    result.print_report()
            else:
                result = hunter.run(args.hunt)
                result.print_report()
            return DispatchResult("return")
        finally:
            db.close()

    if args.metrics:
        return DispatchResult("return", handlers["run_metrics_cli"](config))

    if args.status:
        return DispatchResult("return", handlers["run_status_cli"](config))

    if args.phase:
        return DispatchResult("return", handlers["run_phase_cli"](config))

    if args.report:
        return DispatchResult("return", handlers["run_report_cli"](config))

    if args.test:
        precheck_rc, db_ready = handlers["run_test_precheck"](
            config,
            allow_empty_rules=args.allow_empty_rules,
        )
        if precheck_rc != 0:
            return DispatchResult("raise", precheck_rc)
        if not db_ready:
            return DispatchResult("return")
        return DispatchResult(test_prechecked=True)

    return DispatchResult()


def _dispatch_ml_control_command(args: Any, config: dict, handlers: Mapping[str, Any]) -> DispatchResult:
    ml_cmds = (args.ml_pause, args.ml_resume, args.ml_reset, args.ml_status, args.ml_exclude, args.ml_include)
    maint_cmds = (args.maintenance_mode, args.pentest_mode, args.maintenance_off)
    if not (any(ml_cmds) or any(maint_cmds)):
        return DispatchResult()

    db = handlers["ensure_database"](config)
    try:
        ml_ctrl = handlers["MLController"](config, db)

        if args.maintenance_mode or args.pentest_mode or args.maintenance_off:
            maint_file = Path("data/maintenance_mode.json")
            if args.maintenance_off:
                if maint_file.exists():
                    maint_file.unlink()
                ml_ctrl.resume()
                print("✅ Bakım/pentest modu kapatıldı. ML öğrenmesi devam ediyor.")
            else:
                mode = "pentest" if args.pentest_mode else "maintenance"
                reason = args.maintenance_reason or f"{mode} başlatıldı (CLI)"
                timeout = args.maintenance_timeout
                maint_file.write_text(handlers["json"].dumps({
                    "mode": mode,
                    "reason": reason,
                    "ts": handlers["time"].time(),
                    "timeout_hours": timeout,
                }))
                ml_ctrl.pause(reason=f"{mode}: {reason}")
                print(f"✅ {mode.capitalize()} modu aktif — ML öğrenmesi DONDURULDU.")
                print(f"   Neden  : {reason}")
                if timeout > 0:
                    print(f"   Timeout: {timeout} saat sonra otomatik kapanır")
                else:
                    print("   Timeout: Yok (manuel kapatma gerekli)")
                print("   Kapatmak için: python main.py --maintenance-off")
            return DispatchResult("return")

        if args.ml_pause:
            ml_ctrl.pause(reason="cli")
            print("✅ ML eğitimi donduruldu.")
        elif args.ml_resume:
            ml_ctrl.resume()
            print("✅ ML eğitimi devam ediyor.")
        elif args.ml_reset:
            ml_ctrl.reset_baseline()
            models_dir = Path(config.get("storage", {}).get("models_dir", "data/models"))
            if models_dir.exists():
                handlers["shutil"].rmtree(models_dir)
                models_dir.mkdir(parents=True, exist_ok=True)
            print("✅ ML baseline ve modeller sıfırlandı.")
        elif args.ml_status:
            st = ml_ctrl.status()
            green = "\033[92m"
            red = "\033[91m"
            reset = "\033[0m"
            bold = "\033[1m"
            print(f"\n{bold}{'━'*48}{reset}")
            print(f"{bold}  ML Kontrol Durumu{reset}")
            print(f"{'━'*48}")
            durum = f"{red}⏸  DONDURULMUŞ{reset}" if st["paused"] else f"{green}▶  AKTİF{reset}"
            print(f"  Durum          : {durum}")
            if st["paused"]:
                print(f"  Sebep          : {st['pause_reason']}")
                if st["paused_at"]:
                    stamp = handlers["datetime"].datetime.fromtimestamp(st["paused_at"])
                    print(f"  Dondurulma     : {stamp.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  Otomatik devam : {'Evet' if st['auto_resume'] else 'Hayır'}")
            print(f"  Temiz pencere  : {st['clean_window_h']} saat")
            excl = st["excluded_sources"]
            print(f"  Çıkarılan kay. : {', '.join(excl) if excl else '-'}")
            log = ml_ctrl._db.get_ml_control_log(limit=5)
            if log:
                print("\n  Son işlemler:")
                for row in log:
                    stamp = handlers["datetime"].datetime.fromtimestamp(row["ts"])
                    print(f"    {stamp.strftime('%m-%d %H:%M')}  {row['action']:<8}  {row['reason']}")
            print(f"{'━'*48}\n")
        elif args.ml_exclude:
            ml_ctrl.exclude_source(args.ml_exclude)
            print(f"✅ '{args.ml_exclude}' ML eğitiminden çıkarıldı.")
        elif args.ml_include:
            ml_ctrl.include_source(args.ml_include)
            print(f"✅ '{args.ml_include}' ML eğitimine geri eklendi.")
        return DispatchResult("return")
    finally:
        db.close()
