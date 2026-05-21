from core.ml.host_baseline import HostProfile


class _Event:
    def __init__(self, ts, user="root", source="auth.log", process="sshd"):
        self.ts = float(ts)
        self.user = user
        self.source = source
        self.process = process
        self.outcome = "success"


def test_host_time_and_source_effects_stay_small_context_signal():
    profile = HostProfile("srv1")

    for i in range(60):
        profile.update(_Event(9 * 3600 + i, user="root", source="auth.log"))

    score = profile.anomaly_score(_Event(2 * 3600, user="deploy", source="auditd"))

    assert 0.0 < score <= 0.65
