from core.ml.instant_ml import InstantMLEngine, MLResult


def test_incremental_pca_anomaly_count_updates():
    engine = InstantMLEngine(config={"ml": {"warmup_samples": 1}}, model_dir="/tmp/test_models_status")
    engine._event_count = 1
    engine.iso.predict = lambda features: MLResult(model="isolation_forest", score=0.0, anomaly=False)
    engine.pca.predict = lambda features: MLResult(model="incremental_pca", score=91.0, anomaly=True)
    engine.ewma.update = lambda event, ml_score=0.0, should_learn=True: MLResult(model="ewma", score=0.0, anomaly=False)
    engine.iso.update = lambda features: None
    engine.pca.update = lambda features: None

    class _Evt:
        ts = 1.0
        category = "auth"
        action = "ssh_login"
        outcome = "success"
        user = "alice"
        src_ip = "10.0.0.1"
        pid = 1
        message = "ok"
        fields = {}
        distro_family = "debian"
        process = "sshd"

    engine.process(_Evt(), should_learn=True)

    assert engine.status()["anomaly_counts"]["pca"] == 1
