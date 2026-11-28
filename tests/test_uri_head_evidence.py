from pathlib import Path
import subprocess

import pytest


@pytest.mark.parametrize(
    ("hits", "unobserved", "gate_status", "bounds"),
    [(1, 0, "passed", [0.01, 0.01]), (2, 0, "failed", [0.02, 0.02]), (1, 1, "inconclusive", [0.01, 0.02])],
)
def test_gate_b_publisher_rate_uses_only_observed_labeled_rows(hits, unobserved, gate_status, bounds):
    from scripts.lab.summarize_uri_head_eval import summarize_evaluation

    def record(cohort, status, tier):
        return {"cohort": cohort, "eval_status": status, "tier": tier}

    records = [record("benign_ood_v1", "observed", "or_gate")] * hits
    records += [record("benign_ood_expanded_v1", "observed", "benign")] * (100 - hits - unobserved)
    records += [record("benign_ood_v1", "ingest_error", "or_gate")] * unobserved
    records += [record("uri_review_v1", "observed", "or_gate")]
    summary = summarize_evaluation({"runner_status": "partial", "records": records})

    assert summary["publisher_or_gate"] == {
        "selected": 100,
        "observed": 100 - unobserved,
        "unobserved": unobserved,
        "or_gate_count": hits,
        "observed_rate": pytest.approx(hits / (100 - unobserved)),
        "full_cohort_rate_bounds": bounds,
        "threshold": 0.01,
        "gate_status": gate_status,
    }
    assert summary["cohorts"]["uri_review_v1"]["or_gate_count"] == 1
    assert summary["publisher_final_verdict_fpr"] is None
    assert summary["verified_real_phishing_pdf_recall"] is None


def test_gate_b_without_observations_leaves_rates_unavailable():
    from scripts.lab.summarize_uri_head_eval import summarize_evaluation

    no_records = summarize_evaluation({"export_mode": "failure_receipt_only", "runner": {"status": "failed"}})
    publisher = no_records["publisher_or_gate"]
    assert publisher["observed_rate"] is None
    assert publisher["full_cohort_rate_bounds"] is None
    assert publisher["gate_status"] == "inconclusive"

    record = {"cohort": "benign_ood_v1", "eval_status": "ingest_error", "tier": "or_gate"}
    unreadable = summarize_evaluation({"runner_status": "partial", "records": [record]})["publisher_or_gate"]
    assert unreadable["observed_rate"] is None
    assert unreadable["full_cohort_rate_bounds"] == [0.0, 1.0]


def test_gate_b_rejects_archive_checksum_mismatch(tmp_path, monkeypatch):
    from scripts.lab.summarize_uri_head_eval import read_saved_evaluation

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts" / "lab"))
    (tmp_path / "locked_methodology.json").write_text(
        '{"artifact_sha256s":{"profile_export.json":"incorrect"}}', encoding="utf-8"
    )
    (tmp_path / "profile_export.json").write_bytes(b"{}")

    with pytest.raises(ValueError, match="uri_gate_b_export_checksum_mismatch"):
        read_saved_evaluation(tmp_path)


def test_uri_source_fingerprint_detects_uncommitted_source_changes(tmp_path):
    from scripts.lab.train_uri_lexical_head_v4 import require_unchanged_uri_source, uri_source_provenance

    source = tmp_path / "src" / "malpdf" / "scanner.py"
    source.parent.mkdir(parents=True)
    source.write_text("VALUE = 1\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "src"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(tmp_path),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "source",
        ],
        check=True,
    )
    before = uri_source_provenance(tmp_path)
    assert len(before["git_commit"]) == 40
    assert "src/malpdf/scanner.py" in before["files_sha256"]
    require_unchanged_uri_source(tmp_path, before)

    source.write_text("VALUE = 2\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="uri_evaluation_source_changed"):
        require_unchanged_uri_source(tmp_path, before)

    source.write_text("VALUE = 1\n", encoding="utf-8")
    source.with_name("local_helper.py").write_text("VALUE = 3\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="uri_evaluation_source_changed"):
        require_unchanged_uri_source(tmp_path, before)
