"""Offline CIC transfer checks use only synthetic identities, tables and inert bytes."""

import hashlib
import json
from types import SimpleNamespace
import zipfile

import numpy as np
import pandas as pd
import pytest
from sklearn.linear_model import LogisticRegression

from malpdf.data import cic_normalization as data
from malpdf.data.raw_cohort import RAW_FEATURES
from malpdf.experiments import cic_cross_dataset as runner


def identities():
    source = pd.DataFrame({"sample_id": ["source_a", "source_b"], "pdf_sha256": ["a" * 64, "b" * 64],
                           "Label": [1, 1], "pdf_relative_path": ["data/raw/a.pdf", "data/raw/b.pdf"]})
    target = pd.DataFrame({"FileName": ["a" * 64, "b" * 64, "c" * 64, "unsupported"],
                           "Class": ["Malicious", "Benign", "Benign", "Malicious"]})
    return target, source


def frozen_lock():
    return {"seed": 42, "branches": list(runner.BRANCHES), "test_used_for_fitting_or_selection": False,
            "refit_after_selection": False, "threshold": 0.37, "referral_rate": 0.1, "ece_bins": 10,
            "meta_learner": {"coefficients": [[0.1, 0.2, 0.3, 0.4, 0.5, 0.6]], "intercept": [-0.7], "classes": [0, 1], "C": 0.1},
            "platt_calibrator": {"coefficients": [[1.2]], "intercept": [-0.9], "classes": [0, 1], "C": 1.0},
            "selection": {"partition": "validation_threshold_selection"}, "validation_roles": {}}


def test_source_matches_excluded_even_when_labels_agree_and_conflicts_not_relabelled():
    target, source = identities()
    original = target.copy(deep=True)
    plan = data.plan_cic_rows(target, source)
    assert plan.Label.tolist() == [1, 0, 0, 1]
    assert plan.source_Label.iloc[:2].tolist() == [1, 1]
    assert plan.source_overlap.tolist() == [True, True, False, False]
    assert plan.label_conflict.tolist() == [False, True, False, False]
    assert plan.exclusion_reason.iloc[:2].tolist() == ["source_identity_overlap"] * 2
    assert plan.exclusion_reason.iloc[3] == "unsupported_identifier_requires_publisher_mapping"
    assert plan.ground_truth_status.iloc[1] == "unresolved_conflict"
    pd.testing.assert_frame_equal(target, original)


@pytest.mark.parametrize("fault", ["duplicate_id", "case_duplicate", "missing_id", "bad_label", "duplicate_source", "bad_source_hash", "bad_source_label"])
def test_ambiguous_identities_or_labels_fail_closed(fault):
    target, source = identities()
    if fault == "duplicate_id": target.loc[1, "FileName"] = target.loc[0, "FileName"]
    elif fault == "case_duplicate": target.loc[1, "FileName"] = target.loc[0, "FileName"].upper()
    elif fault == "missing_id": target.loc[0, "FileName"] = None
    elif fault == "bad_label": target.loc[0, "Class"] = "unknown"
    elif fault == "duplicate_source": source.loc[1, "pdf_sha256"] = source.loc[0, "pdf_sha256"]
    elif fault == "bad_source_hash": source.loc[0, "pdf_sha256"] = "invalid"
    else: source.loc[0, "Label"] = 2
    with pytest.raises(ValueError):
        data.plan_cic_rows(target, source)


def test_pdf_inventory_uses_bytes_not_names_and_collapses_exact_duplicates(tmp_path):
    raw = tmp_path / "data/raw/cic_pdf"
    raw.mkdir(parents=True)
    pdf = b"%PDF-1.4\n% synthetic inert fixture\n%%EOF\n"
    (raw / "benign.pdf").write_bytes(pdf)
    (raw / "another_name.pdf").write_bytes(pdf)
    (raw / "table.csv").write_text("ignored")
    found = data.inventory_local_pdfs(tmp_path, raw)
    assert list(found) == [hashlib.sha256(pdf).hexdigest()]
    assert found[list(found)[0]] == "data/raw/cic_pdf/another_name.pdf"


@pytest.mark.parametrize("fault", ["bad_magic", "oversize", "symlink", "escape", "file_count"])
def test_pdf_inventory_caps_and_boundary_are_enforced(fault, tmp_path):
    raw = tmp_path / "data/raw/cic_pdf"
    raw.mkdir(parents=True)
    path = raw / "inert.pdf"
    path.write_bytes(b"%PDF-1.4\n% inert fixture\n")
    options = {}
    if fault == "bad_magic": path.write_bytes(b"<html>not a PDF</html>")
    elif fault == "oversize": options["max_pdf_bytes"] = 5
    elif fault == "symlink": (raw / "link.pdf").symlink_to(path)
    elif fault == "escape": raw = tmp_path
    else:
        (raw / "ignored.txt").write_text("inert")
        options["max_files"] = 1
    with pytest.raises(ValueError):
        data.inventory_local_pdfs(tmp_path, raw, **options)


def test_archive_checksum_is_capped_and_stable(tmp_path):
    raw = tmp_path / "data/raw"
    raw.mkdir(parents=True)
    path = raw / "inert.zip"
    path.write_bytes(b"synthetic archive bytes")
    evidence = data.bounded_archive_checksum(path, raw, 1000)
    assert evidence == {"bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    with pytest.raises(ValueError, match="cap"):
        data.bounded_archive_checksum(path, raw, 1)
    with pytest.raises(ValueError, match="ignored"):
        data.bounded_archive_checksum(path, raw / "other", 1000)
    link = raw / "link.zip"
    link.symlink_to(path)
    with pytest.raises(ValueError, match="symbolic"):
        data.bounded_archive_checksum(link, raw, 1000)


def test_local_zip_extraction_records_checksums_and_does_not_trust_archive_name(tmp_path, monkeypatch):
    raw = tmp_path / "data/raw/cic_pdf"
    raw.mkdir(parents=True)
    report, artifacts = tmp_path / "reports/run_fixture", tmp_path / "artifacts/run_fixture"
    report.mkdir(parents=True)
    artifacts.mkdir(parents=True)
    events = []
    run = SimpleNamespace(identifier="run_fixture", report=report, artifacts=artifacts,
                          progress=lambda *a, **k: events.append(k))
    paths = []
    pdf = b"%PDF-1.4\n% synthetic inert fixture\n%%EOF\n"
    for index, name in enumerate(("Benign.zip", "Malicious.zip", "Malicious2.zip")):
        path = raw / name
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(f"opaque_name_{index}", pdf)
            archive.writestr("false.pdf", b"<html>not PDF</html>")
        paths.append(path)
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0))
    assert runner.extract_cic_archives(tmp_path, raw, run, archive_files=paths) == 3
    assert len(data.inventory_local_pdfs(tmp_path, raw)) == 1
    assert json.loads((report / "acquisition_summary.json").read_text())["network_requests"] == 0
    assert len(events) == 3
    for index, path in enumerate(paths, 1):
        saved = json.loads((artifacts / f"archive_{index}_checksum.json").read_text())
        assert saved["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert json.loads((report / f"archive_{index}_summary.json").read_text())["rejected"] == 1
    with pytest.raises(FileExistsError):
        runner.extract_cic_archives(tmp_path, raw, run, archive_files=paths)


def test_unignored_zip_and_html_response_fail_closed(tmp_path, monkeypatch):
    raw = tmp_path / "data/raw/cic_pdf"
    raw.mkdir(parents=True)
    path = raw / "not_real.zip"
    path.write_bytes(b"<html>HTTP error</html>")
    run = SimpleNamespace(identifier="run_fixture", artifacts=tmp_path / "artifacts", report=tmp_path / "report")
    run.artifacts.mkdir()
    run.report.mkdir()
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=1))
    with pytest.raises(ValueError, match="gitignored"):
        runner.extract_cic_archives(tmp_path, raw, run, archive_files=[path])
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0))
    with pytest.raises(ValueError, match="ZIP directory"):
        runner.extract_cic_archives(tmp_path, raw, run, archive_files=[path])


def test_nested_zip_tree_keeps_pdf_caps_crc_and_opaque_paths(tmp_path):
    import io
    from malpdf.data.cic_archives import extract_nested_cic_archive
    from malpdf.data.raw_downloads import DownloadLimits
    raw = tmp_path / "data/raw"
    raw.mkdir(parents=True)
    inner = io.BytesIO()
    pdf = b"%PDF-1.4\n% inert nested fixture\n%%EOF\n"
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("opaque", pdf)
        archive.writestr("bad.pdf", b"HTML")
    outer = raw / "parent.zip"
    with zipfile.ZipFile(outer, "w") as archive:
        archive.writestr("folder/child.zip", inner.getvalue())
    output = raw / "output"
    output.mkdir()
    ledger = {"boundary": raw, "members": 0, "pdf_bytes": 0, "container_bytes": 0,
              "container_count": 0, "seen_archives": set()}
    records = []
    result = extract_nested_cic_archive(outer, output, DownloadLimits(), ledger, record=records.append)
    assert result["accepted"] == result["rejected"] == 1 and result["blocked_archives"] == 0
    assert ledger["container_bytes"] == len(inner.getvalue()) and ledger["pdf_bytes"] == len(pdf)
    assert (output / "pdfs" / (hashlib.sha256(pdf).hexdigest() + ".pdf")).read_bytes() == pdf
    assert records[0]["status"] == "nested_zip_crc_verified"
    assert not (output / "folder").exists()
    assert extract_nested_cic_archive(outer, output, DownloadLimits(), ledger)["duplicate_archives"] == 1


@pytest.mark.parametrize("fault", ["depth", "member_cap", "container_cap", "pdf_cap", "bad_magic", "mixed"])
def test_nested_archive_budgets_fail_closed(fault, tmp_path):
    import io
    from malpdf.data.cic_archives import extract_nested_cic_archive
    from malpdf.data.raw_downloads import DownloadLimits
    raw = tmp_path / "data/raw"
    raw.mkdir(parents=True)
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("inert.pdf", b"%PDF-1.4\n% inert\n%%EOF\n")
    path = raw / "outer.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("child.zip", b"HTML" if fault == "bad_magic" else inner.getvalue())
        if fault == "mixed": archive.writestr("other.pdf", b"%PDF-1.4\n")
    output = raw / "output"
    output.mkdir()
    ledger = {"boundary": raw, "members": 40000 if fault == "member_cap" else 0, "pdf_bytes": 0,
              "container_bytes": 0, "container_count": 0, "seen_archives": set()}
    options = {"max_total_download_bytes": 1} if fault == "container_cap" else {}
    if fault == "pdf_cap": options["max_total_pdf_bytes"] = 1
    with pytest.raises(ValueError):
        extract_nested_cic_archive(path, output, DownloadLimits(**options), ledger, depth=3 if fault == "depth" else 0)
    assert not (output / "pdfs").exists()


def test_encrypted_zip_without_password_is_reported_unavailable_not_guessed(tmp_path):
    from malpdf.data.cic_archives import extract_nested_cic_archive
    from malpdf.data.raw_downloads import DownloadLimits
    from test_raw_downloads import ENCRYPTED
    raw = tmp_path / "data/raw"
    raw.mkdir(parents=True)
    path = raw / "encrypted.zip"
    path.write_bytes(ENCRYPTED)
    ledger = {"boundary": raw, "members": 0, "pdf_bytes": 0, "container_bytes": 0,
              "container_count": 0, "seen_archives": set()}
    records = []
    result = extract_nested_cic_archive(path, raw, DownloadLimits(), ledger, record=records.append)
    assert result["blocked_archives"] == 1 and result["accepted"] == 0
    assert records[0]["status"] == "encrypted_archive_no_password"
    assert not (raw / "pdfs").exists()


def test_frozen_coefficients_predict_without_any_fit(monkeypatch):
    lock = frozen_lock()
    probabilities = np.arange(18, dtype=float).reshape(3, 6) / 18
    sigmoid = lambda x: 1 / (1 + np.exp(-x))
    expected = sigmoid(1.2 * sigmoid(probabilities @ np.array(lock["meta_learner"]["coefficients"])[0] - 0.7) - 0.9)
    def forbidden(*a, **k):
        raise AssertionError("No fit on external data is permitted")
    monkeypatch.setattr(LogisticRegression, "fit", forbidden)
    stack = runner.restore_frozen_stack(lock)
    np.testing.assert_allclose(stack.predict_proba(probabilities), expected, rtol=1e-12)
    assert stack.threshold == 0.37


@pytest.mark.parametrize("fault", ["branches", "seed", "test_fit", "refit", "threshold", "nan_coef", "coef_shape", "classes", "C"])
def test_corrupt_frozen_stack_is_refused(fault):
    lock = frozen_lock()
    if fault == "branches": lock["branches"].reverse()
    elif fault == "seed": lock["seed"] = 1
    elif fault == "test_fit": lock["test_used_for_fitting_or_selection"] = True
    elif fault == "refit": lock["refit_after_selection"] = True
    elif fault == "threshold": lock["threshold"] = float("nan")
    elif fault == "nan_coef": lock["meta_learner"]["coefficients"][0][0] = float("nan")
    elif fault == "coef_shape": lock["meta_learner"]["coefficients"] = [[1]]
    elif fault == "classes": lock["platt_calibrator"]["classes"] = [1, 0]
    else: lock["platt_calibrator"]["C"] = 0
    with pytest.raises(ValueError):
        runner.restore_frozen_stack(lock)


def test_feature_equivalence_exclusion_ignores_labels_and_numeric_dtypes():
    source = pd.DataFrame({"JS": [1, 2], "pages": [np.nan, 5], "Label": [1, 0]})
    target = pd.DataFrame({"JS": [2.0, 1.0, 3.0], "pages": [5.0, np.nan, 6.0], "Label": [1, 0, 1]})
    np.testing.assert_array_equal(runner.exclude_source_feature_groups(source, target, ["JS", "pages"]), [True, True, False])


def test_external_evaluation_claim_survives_renaming_and_row_order(tmp_path):
    report = tmp_path / "reports/run_fixture"
    report.mkdir(parents=True)
    run = SimpleNamespace(report=report)
    cohort = pd.DataFrame({"sample_id": ["a", "b"], "pdf_sha256": ["a" * 64, "b" * 64], "Label": [0, 1]})
    runner.claim_external_evaluation(tmp_path, run, "c" * 64, cohort)
    marker = (report / "external_evaluation_started.json").read_bytes()
    reordered = cohort.iloc[::-1].copy()
    reordered["sample_id"] = ["different_a", "different_b"]
    with pytest.raises(FileExistsError):
        runner.claim_external_evaluation(tmp_path, run, "c" * 64, reordered)
    assert (report / "external_evaluation_started.json").read_bytes() == marker


def synthetic_features(ids):
    return pd.DataFrame([{"sample_id": sid, "Label": i % 2,
                          **{key: float(10 + i) for key in RAW_FEATURES}, "parser_failed": False}
                         for i, sid in enumerate(ids)])


def test_missing_metadata_remains_null_and_missing_security_fails_closed():
    features = synthetic_features(["one", "two"])
    features.loc[0, "pages"] = np.nan
    features.loc[0, "parser_failed"] = True
    data.validate_external_features(features)
    assert np.isnan(features.loc[0, "pages"])
    features.loc[1, "JS"] = np.nan
    with pytest.raises(ValueError, match="security measurements"):
        data.validate_external_features(features)


def test_extraction_preserves_nulls_aligns_parser_results_and_reuses_real_markov_cache(tmp_path, monkeypatch):
    raw = tmp_path / "data/raw/cic_pdf"
    raw.mkdir(parents=True)
    inventory = []
    for index in range(2):
        path = raw / f"inert_{index}.pdf"
        content = f"%PDF-1.4\n% synthetic inert fixture {index}\n%%EOF\n".encode()
        path.write_bytes(content)
        inventory.append({"sample_id": f"fixture_{index}", "Label": index,
                          "pdf_relative_path": str(path.relative_to(tmp_path)),
                          "pdf_sha256": hashlib.sha256(content).hexdigest()})
    inventory = pd.DataFrame(inventory)
    def parser(*args, **kwargs):
        for position in [1, 0]:  # Isolated workers can finish out of order.
            features = {key: float(position + 1) for key in RAW_FEATURES}
            if position == 0: features["pages"] = None
            yield position, {"features": features, "complete": position != 0,
                             "errors": ["reference_page_count_unavailable"] if position == 0 else [], "warnings": []}
    class Executor:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def submit(self, function, argument):
            return SimpleNamespace(result=lambda: function(argument))
    monkeypatch.setattr(data, "isolated_features", parser)
    monkeypatch.setattr(data, "ProcessPoolExecutor", Executor)
    output = tmp_path / "data/processed/first"
    features, cache = data.extract_cic_rows(tmp_path, inventory, output, workers=1)
    assert features.sample_id.tolist() == inventory.sample_id.tolist()
    assert features.Label.tolist() == [0, 1]
    assert features.parser_failed.tolist() == [True, False]
    assert pd.isna(features.loc[0, "pages"])
    assert pd.isna(pd.read_csv(output / "raw_v3_features.csv").loc[0, "pages"])
    assert cache.status.tolist() == ["created", "created"]
    assert json.loads((output / "parser_errors.json").read_text())[0]["sample_id"] == "fixture_0"
    _, cached = data.extract_cic_rows(tmp_path, inventory, tmp_path / "data/processed/second", workers=1)
    assert cached.status.tolist() == ["reused", "reused"]
    assert cached.npy_sha256.tolist() == cache.npy_sha256.tolist()
    with pytest.raises(ValueError, match="collision"):
        data.extract_cic_rows(tmp_path, inventory, output, workers=1)


def test_input_checksum_lock_is_verified_before_interpreting_bytes(tmp_path):
    path = tmp_path / "data/raw/fixture"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"inert")
    spec = {"path": str(path.relative_to(tmp_path)), "sha256": hashlib.sha256(b"inert").hexdigest()}
    assert data.locked_bytes(tmp_path, spec, "data/raw") == b"inert"
    path.write_bytes(b"changed")
    with pytest.raises(ValueError, match="checksum"):
        data.locked_bytes(tmp_path, spec, "data/raw")


@pytest.fixture
def pipeline(tmp_path, monkeypatch):
    def save(relative, content):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return {"path": relative, "sha256": hashlib.sha256(content).hexdigest()}
    target, source = identities()
    target = target.iloc[:3].copy()
    target.loc[3] = ["d" * 64, "Malicious"]
    source_lock = save("data/processed/source.csv", source.to_csv(index=False).encode())
    source_features = synthetic_features(source.sample_id)
    source_features.loc[:, list(RAW_FEATURES)] = 1.0
    feature_lock = save("data/processed/features.csv", source_features.to_csv(index=False).encode())
    reference = {"status": "completed", "test_evaluation_count": 1,
                 "inputs": {"source_manifest": source_lock, "all_features": feature_lock}}
    lock = frozen_lock()
    lock["feature_order"] = list(RAW_FEATURES[:40])
    summary_lock = save("reports/experiments/reference/run_summary.json", json.dumps(reference).encode())
    model_lock = save("reports/experiments/reference/validation_lock.json", json.dumps(lock).encode())
    config = {"seed": 42, "workers": 1, "target": save("data/raw/target.parquet", target.to_parquet(index=False)),
              "reference": {"directory": "reports/experiments/reference", "summary_sha256": summary_lock["sha256"],
                            "validation_lock_sha256": model_lock["sha256"]},
              "raw_directory": "data/raw/cic_pdf", "source_inspection": {"raw_zip_verified": False}}
    class Run:
        def __init__(self, *a, **k):
            self.identifier = "run_fixture"
            self.report, self.artifacts = tmp_path / "reports/experiments/preparation/run_fixture", tmp_path / "artifacts/run_fixture"
            self.report.mkdir(parents=True)
            self.artifacts.mkdir(parents=True)
            self.state = {"status": "started", "code_worktree": {"status": "clean"}, "metrics": {}}
        def __enter__(self): return self
        def __exit__(self, *a):
            if self.state["status"] == "started": self.state["status"] = "completed"
        def progress(self, *a, **k): pass
    monkeypatch.setattr(runner, "ResearchRun", Run)
    local = {"c" * 64: "data/raw/one.pdf", "d" * 64: "data/raw/two.pdf"}
    monkeypatch.setattr(runner, "inventory_local_pdfs", lambda *a, **k: local)
    selected_ids = []
    def extract(root, selected, output, **kwargs):
        selected_ids.extend(selected.sample_id)
        frame = synthetic_features(selected.sample_id.tolist())
        frame["Label"] = selected.Label.to_numpy()
        cache = selected[["sample_id", "pdf_sha256"]].copy()
        cache["status"] = "created"
        return frame, cache
    monkeypatch.setattr(runner, "extract_cic_rows", extract)
    evaluations = []
    def evaluate(root, run, config, reference, lock, frame, cache):
        assert (run.report / "locked_external_cohort.json").is_file()
        assert reference["test_evaluation_count"] == 1
        assert frame.sample_id.tolist() == ["cic_000002", "cic_000003"]
        evaluations.append(1)
    monkeypatch.setattr(runner, "_evaluate_frozen", evaluate)
    return tmp_path, config, local, selected_ids, evaluations


def test_external_pipeline_uses_complete_independent_cohort_and_locks_before_inference(pipeline):
    root, config, _, selected, calls = pipeline
    result = runner.run_cic_cross_dataset(root, root, config, evaluate=True)
    assert result["status"] == "completed" and result["known_source_overlap"] == 2
    assert result["target_labels_changed"] == result["ground_truth_adjudications"] == 0
    assert result["original_test_reevaluations"] == 0
    assert calls == [1] and selected == ["cic_000002", "cic_000003"]


def test_incomplete_raw_cohort_stops_without_available_only_subset_metrics(pipeline):
    root, config, local, selected, calls = pipeline
    del local["d" * 64]
    result = runner.run_cic_cross_dataset(root, root, config, evaluate=True)
    assert result["status"] == "blocked" and result["independent_raw_missing"] == 1
    assert result["metrics"] == {} and calls == []
    assert selected == ["cic_000002"]


def test_label_conflicts_reparsed_for_audit_never_enter_external_cohort(pipeline):
    root, config, _, selected, calls = pipeline
    result = runner.run_cic_cross_dataset(root, root, config, audit_conflicts=True, evaluate=True)
    assert result["conflict_rows_reparsed_for_audit"] == 1 and calls == [1]
    assert selected == ["cic_000001", "cic_000002", "cic_000003"]


def test_reference_checksum_failure_precedes_parser_and_inference(pipeline):
    root, config, _, selected, calls = pipeline
    config["reference"]["validation_lock_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="checksum"):
        runner.run_cic_cross_dataset(root, root, config, evaluate=True)
    assert selected == calls == []


def prepared_fixture(pipeline, monkeypatch):
    root, config, _, _, _ = pipeline
    target = pd.read_parquet(root / config["target"]["path"])
    # A third independent identity remains unavailable under the fixed caps.
    target.loc[len(target)] = ["e" * 64, "Malicious"]
    target.to_parquet(root / config["target"]["path"], index=False)
    config["target"]["sha256"] = hashlib.sha256((root / config["target"]["path"]).read_bytes()).hexdigest()
    sources = pd.read_csv(root / "data/processed/source.csv")
    plan = data.plan_cic_rows(target, sources)
    plan["target_pdf_byte_verified"] = plan.sample_id.isin(["cic_000002", "cic_000003"])
    measured = root / "data/processed/prepared"
    (measured / "static_extraction").mkdir(parents=True)
    plan.to_csv(measured / "final_eligibility_manifest.csv", index=False)
    frame = synthetic_features(["cic_000002", "cic_000003"])
    frame.to_csv(measured / "static_extraction/raw_v3_features.csv", index=False)
    pd.DataFrame({"sample_id": frame.sample_id, "pdf_sha256": ["c" * 64, "d" * 64]}).to_csv(
        measured / "static_extraction/cache_manifest.csv", index=False)
    previous = root / "reports/experiments/cic_normalization_v3/run_prepared"
    previous.mkdir(parents=True)
    (previous / "run_summary.json").write_text(json.dumps({"status": "blocked", "external_evaluation_count": 0,
        "original_test_reevaluations": 0, "target_labels_changed": 0, "outputs": "data/processed/prepared", "target_rows": len(plan)}))
    calls = []
    def evaluate(root, run, config, reference, lock, features, cache):
        assert (run.report / "locked_external_cohort.json").is_file()
        assert features.sample_id.tolist() == ["cic_000002", "cic_000003"]
        calls.append(1)
        run.state["routing"] = [{}, {"referred_count": 1}]
    monkeypatch.setattr(runner, "_evaluate_frozen", evaluate)
    return root, config, measured, calls


def test_separate_valid_pdf_study_persists_scope_and_input_referrals(pipeline, monkeypatch):
    root, config, _, calls = prepared_fixture(pipeline, monkeypatch)
    result = runner.evaluate_prepared_cic(root, root, config, "run_prepared", allow_input_referrals=True)
    assert result["evaluated_rows"] == 2 and result["input_referrals"] == 1
    assert result["source_identity_exclusions"] == 2 and calls == [1]
    report = root / "reports/experiments/preparation/run_fixture"
    policy = json.loads((report / "locked_external_cohort.json").read_text())
    assert policy["metrics_scope"].startswith("Verified independent valid PDFs only")
    assert json.loads((report / "input_referral_analysis.json").read_text())["scope_denominator"] == 3


def test_prepared_full_cohort_still_refuses_missing_inputs_without_separate_profile(pipeline, monkeypatch):
    root, config, _, calls = prepared_fixture(pipeline, monkeypatch)
    with pytest.raises(ValueError, match="separately declared"):
        runner.evaluate_prepared_cic(root, root, config, "run_prepared")
    assert calls == []


@pytest.mark.parametrize("fault", ["labels", "source_exclusion", "cache_identity", "feature_equivalence", "dirty"])
def test_prepared_external_cohort_guards_precede_any_prediction(fault, pipeline, monkeypatch):
    root, config, measured, calls = prepared_fixture(pipeline, monkeypatch)
    plan_path = measured / "final_eligibility_manifest.csv"
    if fault in {"labels", "source_exclusion"}:
        frame = pd.read_csv(plan_path, keep_default_na=False)
        if fault == "labels": frame.loc[frame.sample_id.eq("cic_000003"), "Label"] = 0
        else: frame.loc[frame.sample_id.eq("cic_000000"), "exclusion_reason"] = ""
        frame.to_csv(plan_path, index=False)
    elif fault == "cache_identity":
        path = measured / "static_extraction/cache_manifest.csv"
        frame = pd.read_csv(path)
        frame.loc[0, "pdf_sha256"] = "f" * 64
        frame.to_csv(path, index=False)
    elif fault == "feature_equivalence":
        path = measured / "static_extraction/raw_v3_features.csv"
        frame = pd.read_csv(path)
        frame.loc[0, list(RAW_FEATURES)] = 1.0
        frame.to_csv(path, index=False)
    else:
        original = runner.ResearchRun
        class Dirty(original):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.state["code_worktree"]["status"] = "dirty"
        monkeypatch.setattr(runner, "ResearchRun", Dirty)
    with pytest.raises(ValueError):
        runner.evaluate_prepared_cic(root, root, config, "run_prepared", allow_input_referrals=True)
    assert calls == []
