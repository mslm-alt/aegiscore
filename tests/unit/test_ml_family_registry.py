from core.ml.family_registry import (
    ML_FAMILY_REGISTRY,
    get_ml_family_spec,
    list_ml_families,
    ml_family_registry_snapshot,
    resolve_rule_id_to_ml_family,
)


def test_all_expected_ml_families_exist_and_no_action_contract_is_true():
    expected = {
        "ML-AUTH",
        "ML-SUDO",
        "ML-PROC",
        "ML-SERVICE",
        "ML-NET",
        "ML-SEQ",
        "ML-USER",
        "ML-HOST",
        "ML-DBAUTH",
        "ML-DNS",
        "ML-WEBPOST",
        "ML-IMPACT",
    }
    assert set(ML_FAMILY_REGISTRY) == expected
    assert {spec.family_id for spec in list_ml_families()} == expected
    assert all(spec.no_action_contract is True for spec in ML_FAMILY_REGISTRY.values())


def test_registry_snapshot_is_plain_data():
    snapshot = ml_family_registry_snapshot()
    assert snapshot["ML-AUTH"]["phase_gate"] == "PHASE_2"
    assert snapshot["ML-NET"]["time_features_enabled"] is True


def test_get_ml_family_spec_is_case_insensitive():
    spec = get_ml_family_spec("ml-auth")
    assert spec is not None
    assert spec.family_id == "ML-AUTH"


def test_auth_004_explicit_override_maps_to_ml_sudo():
    mapped = resolve_rule_id_to_ml_family("AUTH-004")
    assert mapped.matched is True
    assert mapped.ml_family == "ML-SUDO"
    assert mapped.ml_label == "sudo_escalation_or_root_access"
    assert mapped.label_class == "attack"


def test_generic_auth_prefix_maps_to_ml_auth():
    mapped = resolve_rule_id_to_ml_family("AUTH-014")
    assert mapped.matched is True
    assert mapped.ml_family == "ML-AUTH"
    assert mapped.ml_label == "auth_attack_or_abuse"
    assert mapped.mapping_reason == "prefix_rule_auth"


def test_web_and_net_web_map_to_ml_webpost():
    assert resolve_rule_id_to_ml_family("WEB-017").ml_family == "ML-WEBPOST"
    assert resolve_rule_id_to_ml_family("NET-WEB-001").ml_family == "ML-WEBPOST"
    web005 = resolve_rule_id_to_ml_family("WEB-005")
    assert web005.ml_family == "ML-WEBPOST"
    assert web005.ml_label == "web_discovery_probe"
    assert web005.label_class == "suspicious"


def test_thr_023_maps_to_ml_dns_with_explicit_burst_behavior():
    mapped = resolve_rule_id_to_ml_family("THR-023")
    assert mapped.matched is True
    assert mapped.ml_family == "ML-DNS"
    assert mapped.ml_label == "high_entropy_dns_burst"
    assert mapped.label_class == "suspicious"
    assert mapped.mapping_reason == "explicit_rule_override"


def test_pkg_repo_rules_map_to_ml_proc_with_repo_abuse_behavior():
    for rule_id in ("PKG-013", "PKG-014"):
        mapped = resolve_rule_id_to_ml_family(rule_id)
        assert mapped.matched is True
        assert mapped.ml_family == "ML-PROC"
        assert mapped.ml_label == "package_repository_abuse"
        assert mapped.label_class == "suspicious"
        assert mapped.mapping_reason == "explicit_rule_override"


def test_proc_and_lolbin_map_to_ml_proc():
    assert resolve_rule_id_to_ml_family("PROC-003").ml_family == "ML-PROC"
    lolbin = resolve_rule_id_to_ml_family("LOLBIN-001")
    assert lolbin.ml_family == "ML-PROC"
    assert lolbin.ml_label == "lolbin_abuse"


def test_dns_and_db_map_to_expected_families():
    assert resolve_rule_id_to_ml_family("DNS-001").ml_family == "ML-DNS"
    assert resolve_rule_id_to_ml_family("DB-001").ml_family == "ML-DBAUTH"


def test_mapping_regressions_for_db_fw_and_dns_rule_sets():
    expected = {
        "DB-002": "ML-DBAUTH",
        "DB-003": "ML-DBAUTH",
        "DB-004": "ML-DBAUTH",
        "DB-005": "ML-DBAUTH",
        "DB-006": "ML-DBAUTH",
        "DB-007": "ML-DBAUTH",
        "FW-002": "ML-NET",
        "FW-003": "ML-NET",
        "FW-004": "ML-NET",
        "FW-005": "ML-NET",
        "FW-006": "ML-NET",
        "DNS-005": "ML-DNS",
        "DNS-006": "ML-DNS",
        "DNS-007": "ML-DNS",
        "DNS-008": "ML-DNS",
        "DNS-009": "ML-DNS",
    }
    for rule_id, family in expected.items():
        assert resolve_rule_id_to_ml_family(rule_id).ml_family == family


def test_low_noise_mapping_regressions_remain_stable():
    expected = {
        "AUTH-003": ("ML-AUTH", "auth_attack_or_abuse"),
        "PROC-011": ("ML-PROC", "suspicious_process"),
        "FW-001": ("ML-NET", "network_abuse"),
        "WEB-005": ("ML-WEBPOST", "web_discovery_probe"),
    }
    for rule_id, (family, label) in expected.items():
        mapped = resolve_rule_id_to_ml_family(rule_id)
        assert mapped.ml_family == family
        assert mapped.ml_label == label


def test_unknown_rule_stays_unmatched():
    mapped = resolve_rule_id_to_ml_family("MISC-999")
    assert mapped.matched is False
    assert mapped.ml_family is None
    assert mapped.label_class == "unknown"
    assert mapped.mapping_reason == "unmapped_rule_id"


def test_explicit_override_wins_before_wildcard():
    sudo = resolve_rule_id_to_ml_family("AUTH-005")
    assert sudo.ml_family == "ML-SUDO"
    assert sudo.mapping_reason == "explicit_rule_override"


def test_impact_prefix_override_wins_before_generic_proc_prefix():
    impact = resolve_rule_id_to_ml_family("PROC-IMP-001")
    assert impact.ml_family == "ML-IMPACT"
    assert impact.ml_label == "impact_or_tamper"
    assert impact.mapping_reason == "prefix_override_impact"


def test_mapping_helper_is_pure_and_has_no_db_side_effects():
    first = resolve_rule_id_to_ml_family("AUTH-003").to_dict()
    second = resolve_rule_id_to_ml_family("AUTH-003").to_dict()
    assert first == second
    assert "ml_family" in first


def test_attack_bruteforce_prefix_maps_to_ml_auth():
    mapped = resolve_rule_id_to_ml_family("ATK-BF-001")
    assert mapped.ml_family == "ML-AUTH"
    assert mapped.ml_label == "brute_force_or_auth_attack"
    assert mapped.label_class == "attack"
    assert mapped.source_trust == "rule_high"


def test_attack_lateral_movement_prefix_maps_to_ml_seq():
    mapped = resolve_rule_id_to_ml_family("ATK-LM-001")
    assert mapped.ml_family == "ML-SEQ"
    assert mapped.ml_label == "lateral_movement_sequence"
    assert mapped.source_trust == "rule_high"


def test_attack_persistence_prefix_maps_to_ml_service():
    mapped = resolve_rule_id_to_ml_family("ATK-PER-001")
    assert mapped.ml_family == "ML-SERVICE"
    assert mapped.ml_label == "persistence_behavior"
    assert mapped.source_trust == "rule_high"


def test_audit_persist_prefix_maps_to_ml_service():
    mapped = resolve_rule_id_to_ml_family("AUDIT-PERSIST-001")
    assert mapped.ml_family == "ML-SERVICE"
    assert mapped.ml_label == "persistence_service_mod"
    assert mapped.source_trust == "rule_high"


def test_audit_privesc_prefix_maps_to_ml_sudo():
    mapped = resolve_rule_id_to_ml_family("AUDIT-PRIVESC-001")
    assert mapped.ml_family == "ML-SUDO"
    assert mapped.ml_label == "privilege_escalation_behavior"
    assert mapped.source_trust == "rule_high"


def test_defense_evasion_prefix_maps_without_high_trust():
    mapped = resolve_rule_id_to_ml_family("DE-001")
    assert mapped.ml_family == "ML-IMPACT"
    assert mapped.ml_label == "defense_evasion_or_tamper"
    assert mapped.source_trust == "rule_medium"


def test_discovery_prefix_maps_to_medium_trust_family():
    mapped = resolve_rule_id_to_ml_family("DISC-001")
    assert mapped.ml_family == "ML-PROC"
    assert mapped.ml_label == "discovery_behavior"
    assert mapped.source_trust in {"rule_medium", "rule_low"}


def test_first_seen_prefix_maps_to_low_trust_family():
    mapped = resolve_rule_id_to_ml_family("FIRST-001")
    assert mapped.ml_family == "ML-HOST"
    assert mapped.ml_label == "first_seen_behavior"
    assert mapped.source_trust == "rule_low"


def test_lol_prefix_maps_to_ml_proc():
    mapped = resolve_rule_id_to_ml_family("LOL-001")
    assert mapped.ml_family == "ML-PROC"
    assert mapped.ml_label == "lolbin_abuse"
    assert mapped.source_trust == "rule_high"


def test_pkg_prefix_maps_to_ml_proc():
    mapped = resolve_rule_id_to_ml_family("PKG-010")
    assert mapped.ml_family == "ML-PROC"
    assert mapped.ml_label == "package_install_or_package_abuse"
    assert mapped.source_trust == "rule_medium"


def test_privesc_prefix_maps_to_ml_sudo():
    mapped = resolve_rule_id_to_ml_family("PRIVESC-001")
    assert mapped.ml_family == "ML-SUDO"
    assert mapped.ml_label == "privilege_escalation_behavior"
    assert mapped.source_trust == "rule_high"


def test_generic_audit_prefix_maps_but_specific_audit_overrides_win():
    generic = resolve_rule_id_to_ml_family("AUDIT-001")
    specific = resolve_rule_id_to_ml_family("AUDIT-PERSIST-001")
    assert generic.ml_family == "ML-PROC"
    assert generic.ml_label == "suspicious_process"
    assert specific.ml_family == "ML-SERVICE"
    assert specific.mapping_reason == "prefix_rule_audit_persist"
