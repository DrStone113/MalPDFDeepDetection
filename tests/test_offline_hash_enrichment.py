from scripts.lab.offline_hash_enrichment import historical_scan_evidence, resolve_training_label


def test_historical_report_preserves_exact_identity_and_vote_counts():
    report = {"sha256": "A" * 64, "response_code": 1, "total": 2, "positives": 1,
              "scans": {"a": {"detected": True}, "b": {"detected": False}}, "scan_date": "2017-05-07 16:10:00"}
    assert historical_scan_evidence(report) == ("a" * 64, 1, 2, "2017-05-07 16:10:00")
    assert historical_scan_evidence(report | {"positives": 0}) is None
    assert historical_scan_evidence(report | {"sha256": "invalid"}) is None


def test_label_enrichment_quarantines_cic_and_never_infers_benign_from_absence():
    assert resolve_training_label(1, "cic_protocol_g_verified", True) == (None, "cic_identity_review")
    assert resolve_training_label(None, "unlabeled", False) == (None, "unlabeled")
    assert resolve_training_label(None, "unlabeled", True) == (1, "zenodo2017_exact_historical_consensus")
    assert resolve_training_label(0, "vapd_v5_d1_benign", True) == (None, "conflicting_source_evidence")
    assert resolve_training_label(1, "vapd_v5_d1_malicious", False) == (1, "vapd_v5_d1_malicious")
