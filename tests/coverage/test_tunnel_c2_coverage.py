import pytest

from core.detection import DetectionEngine

from tests.coverage.credential_access_helper import collect_rule_ids, summarize_results
from tests.coverage.tunnel_c2_helper import build_attack_scenarios, build_benign_scenarios


@pytest.fixture
def engine():
    return DetectionEngine(
        config={"rules_dir": "rules", "rules_source": "yaml"},
        allow_empty_rules=True,
    )


ATTACK_SCENARIOS = build_attack_scenarios()
BENIGN_SCENARIOS = build_benign_scenarios()


class TestTunnelC2Coverage:
    @pytest.mark.parametrize("scenario", ATTACK_SCENARIOS, ids=[scenario.name for scenario in ATTACK_SCENARIOS])
    def test_attack_scenarios_are_detected(self, engine, scenario):
        hits = collect_rule_ids(engine, scenario.events)
        for rule_id in scenario.expected_ids:
            assert rule_id in hits

    @pytest.mark.parametrize("scenario", BENIGN_SCENARIOS, ids=[scenario.name for scenario in BENIGN_SCENARIOS])
    def test_benign_scenarios_are_rejected(self, engine, scenario):
        hits = collect_rule_ids(engine, scenario.events)
        for rule_id in scenario.forbidden_ids:
            assert rule_id not in hits

    def test_tunnel_c2_coverage_summary(self):
        scenarios = ATTACK_SCENARIOS + BENIGN_SCENARIOS
        results = []
        kinds = []

        for scenario in scenarios:
            local_engine = DetectionEngine(
                config={"rules_dir": "rules", "rules_source": "yaml"},
                allow_empty_rules=True,
            )
            hits = collect_rule_ids(local_engine, scenario.events)
            if scenario.kind == "attack":
                results.append(scenario.expected_ids.issubset(hits))
            else:
                results.append(scenario.forbidden_ids.isdisjoint(hits))
            kinds.append(scenario.kind)

        summary = summarize_results(results, kinds)
        print(
            "tunnel-c2 coverage: "
            f"attack={summary.detected_attack}/{summary.total_attack}, "
            f"benign={summary.rejected_benign}/{summary.total_benign}"
        )

        assert summary.detected_attack == summary.total_attack
        assert summary.rejected_benign == summary.total_benign
