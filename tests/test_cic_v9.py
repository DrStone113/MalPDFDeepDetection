"""V9 campaign regressions use synthetic metadata and mocked inert workers."""

from contextlib import AbstractContextManager
from dataclasses import asdict
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest

from malpdf.experiments import cic_v9 as campaign
from malpdf.experiments.cic_static_accuracy import PROFILE_VARIANTS
from malpdf.static.profiling import STAGES


def _save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_campaign_claim_is_shared_across_different_preparations(tmp_path):
    campaign.claim_v9_campaign(tmp_path, "run_prepare_a", "run_final_a")
    path = tmp_path / "artifacts/cic_v9_campaign/final_attempt.json"
    saved = path.read_bytes()
    with pytest.raises(ValueError, match="already attempted"):
        campaign.claim_v9_campaign(tmp_path, "run_prepare_b", "run_final_b")
    assert path.read_bytes() == saved
    assert campaign.v9_campaign_outcome(tmp_path)["status"] == "claimed_without_final_outcome"


@pytest.mark.parametrize("status", ["failed", "interrupted", "completed"])
def test_saved_outcome_is_readable_without_current_sources(tmp_path, monkeypatch, status):
    campaign.claim_v9_campaign(tmp_path, "run_prepare", "run_final")
    _save(tmp_path / "reports/experiments/cic_v9_final/run_final/run_summary.json",
          {"status": status, "recorded": 2, "release_status": "blocked"})
    monkeypatch.setattr(campaign, "v9_source_fingerprint", lambda *args: pytest.fail("Historical outcome needs no current source"))
    assert campaign.v9_campaign_outcome(tmp_path)["status"] == status


@pytest.mark.parametrize("value", ["../run_x", "run_../../escape", "", "not_a_run", None])
def test_unsafe_claim_identifiers_are_refused(tmp_path, value):
    with pytest.raises(ValueError, match="identity"):
        campaign.claim_v9_campaign(tmp_path, value, "run_final")
    assert not (tmp_path / "artifacts/cic_v9_campaign/final_attempt.json").exists()


def test_campaign_symlink_is_refused(tmp_path):
    directory = tmp_path / "artifacts"
    directory.mkdir()
    target = tmp_path / "alternate"
    target.mkdir()
    (directory / "cic_v9_campaign").symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="Unsafe"):
        campaign.claim_v9_campaign(tmp_path, "run_prepare", "run_final")
    assert not (target / "final_attempt.json").exists()


@pytest.mark.parametrize("relative", ["data/raw/cic_pdf/synthetic.pdf", "artifacts/private/sample.pdf",
    "data/raw/cic_pdf/disguised.json", "../reports/outside.json", "/tmp/outside.json"])
def test_metadata_only_reader_cannot_access_raw_samples(tmp_path, monkeypatch, relative):
    monkeypatch.setattr(campaign, "read_bounded_bytes", lambda *args, **kwargs: pytest.fail("Metadata tried raw bytes"))
    with pytest.raises(ValueError):
        campaign._content(tmp_path, relative)


def test_three_failure_integration_selection_has_no_label_or_score_filter():
    rows = [{"sample_id": str(index), "Label": str(index % 2)} for index in range(6)]
    old = [{**row, "status": "worker_error" if index in {0, 2, 5} else "partial",
            "errors": ["AttributeError"] if index in {0, 2, 5} else []}
           for index, row in enumerate(rows)]
    assert campaign.integration_rows(rows, old) == [rows[0], rows[2], rows[5]]
    old[0]["errors"] = ["generic_failure"]
    with pytest.raises(ValueError, match="exactly the three"):
        campaign.integration_rows(rows, old)


@pytest.fixture
def integration_profile(monkeypatch):
    monkeypatch.setattr("malpdf.experiments.cic_static_accuracy.profile_input_available", lambda *args: True)
    digest = "a" * 64
    return {"status": "partial", "errors": [], "worker_cleanup_complete": True,
        "static": {"input": {"sha256": digest}, "features": {"obj": 3}},
        "analysis_v9": {"schema_version": "pdf-evidence-v9", "document_sha256": digest,
            "observations": [{"id": "primary", "kind": "catalog", "backend": "pypdf", "status": "observed",
                "locator": "object:1:0", "document_sha256": digest}], "capability_checks": [{"id": "catalog"}],
            "original_bytes_changed": False, "active_content_executed": False,
            "backend_results": [{"backend": "MuPDF", "status": "partial", "stage": "reference_resolution",
                                 "reason_codes": ["reference_unavailable"]}]}},


def _previous(profile):
    return {"pdf_sha256": "a" * 64, "static": profile["static"]}


def test_integration_accepts_localized_partial_without_detector_metrics(integration_profile):
    profile = integration_profile[0]
    result = campaign.assess_integration(profile, _previous(profile))
    assert result["passed"] and result["source_hash_verified"]
    assert "recall" not in result and "probability" not in result


def test_integration_raw_or_model_checkpoint_alone_cannot_claim_graph_fix(integration_profile):
    profile = integration_profile[0]
    profile["analysis_v9"]["observations"][0]["kind"] = "primary_model_inputs"
    result = campaign.assess_integration(profile, _previous(profile))
    assert not result["passed"] and "completed_graph_checkpoint_missing" in result["reason_codes"]


@pytest.mark.parametrize("failure", ["AttributeError", "backend_exception", "unknown_backend_failure"])
def test_integration_generic_failure_relabeling_is_not_success(integration_profile, failure):
    profile = integration_profile[0]
    profile["analysis_v9"]["backend_results"][0].update(status="failed", reason_codes=[failure])
    result = campaign.assess_integration(profile, _previous(profile))
    assert not result["passed"]
    assert "generic_backend_failure_not_resolved" in result["reason_codes"]


def test_integration_graph_or_script_summary_needs_local_source_identity(integration_profile):
    profile = integration_profile[0]
    analysis = profile["analysis_v9"]
    backend = analysis["backend_results"][0]
    backend["stage"] = "graph_or_script"
    assert not campaign.assess_integration(profile, _previous(profile))["passed"]
    analysis["observations"] += [{"id": "unresolved", "kind": "unresolved_reference", "backend": "MuPDF",
        "document_sha256": "a" * 64, "locator": "object:5:0"},
        {"id": "local_failure", "kind": "stage_failure", "backend": "MuPDF", "capability": "catalog",
         "affected_ids": ["unresolved"], "reason_codes": ["reference_unavailable"]}]
    assert campaign.assess_integration(profile, _previous(profile))["passed"]


@pytest.mark.parametrize("code", ["graph_backend_failure", "graph_backend_attribute_error", "recovery_backend_failure"])
def test_integration_rejects_generic_legacy_overlay_errors(integration_profile, code):
    profile = integration_profile[0]
    profile["analysis_v8"] = {"backends": [{"backend": "MuPDF", "status": "error", "error_code": code}]}
    assert not campaign.assess_integration(profile, _previous(profile))["passed"]


@pytest.mark.parametrize("field", ["worker_cleanup_complete", "original_bytes_changed", "active_content_executed", "document_sha256", "observations", "capability_checks"])
def test_integration_requires_checkpoint_cleanup_and_immutable_identity(integration_profile, field):
    profile = integration_profile[0]
    if field == "worker_cleanup_complete":
        profile.pop(field)
    else:
        profile["analysis_v9"].pop(field)
    assert not campaign.assess_integration(profile, _previous(profile))["passed"]


def test_metrics_use_actual_labels_and_separate_probability_cohort():
    decisions = [{"Label": 1, "predicted_label": 1, "malicious_probability": .2},
                 {"Label": 0, "predicted_label": 0, "malicious_probability": .9},
                 {"Label": 1, "predicted_label": None, "malicious_probability": .8},
                 {"Label": 0, "predicted_label": None, "malicious_probability": None}]
    result = campaign.v9_decision_metrics(decisions)
    assert result["actual_label_metrics"]["f1_malicious"] == 1
    assert result["actual_label_metrics"]["confusion_matrix"] == [[1, 0], [0, 1]]
    assert result["classified"] == 2 and result["probability_metrics"]["rows"] == 3
    assert result["end_to_end_detected_fraction"] == .5
    assert result["conditional_recall"] == 1 and result["conditional_fpr"] == 0


def test_all_abstentions_are_neither_detection_nor_benign():
    result = campaign.v9_decision_metrics([
        {"Label": label, "predicted_label": None, "malicious_probability": .9} for label in (0, 1)])
    assert result["classified"] == 0 and result["coverage"] == 0
    assert result["actual_label_metrics"] is None
    assert result["conditional_recall"] is None and result["end_to_end_detected_fraction"] == 0
    assert result["probability_metrics"]["rows"] == 2


@pytest.mark.parametrize("before,after,unchanged,regression", [(.7, .7 + 5e-13, True, False),
    (.7, .7 + 2e-12, True, True), (.5 - 2e-13, .5 + 2e-13, True, True), (.7, .8, False, False)])
def test_parity_tolerance_and_hard_labels(before, after, unchanged, regression):
    assert campaign.probability_parity(before, after, input_unchanged=unchanged)["regression"] is regression


def test_frozen_inference_preserves_original_order_nulls_and_never_fits():
    class Frozen:
        def fit(self, *args):
            pytest.fail("Frozen inference attempted fitting")

        def predict_proba(self, frame):
            assert list(frame.columns) == ["a", "b"]
            assert np.isnan(frame.iloc[0, 1])
            return np.array([[.25, .75]])

    assert campaign.frozen_probability(Frozen(), {"a": 1, "b": None}, ["a", "b"]) == .75
    with pytest.raises(ValueError, match="order"):
        campaign.frozen_probability(Frozen(), {"b": None, "a": 1}, ["a", "b"])


def test_pickle_loading_is_never_reached_before_offline_guard(tmp_path, monkeypatch):
    import joblib
    def refuse(*args, **kwargs):
        raise ValueError("offline refused")
    monkeypatch.setattr(campaign, "require_offline_lab", refuse)
    monkeypatch.setattr(joblib, "load", lambda *args: pytest.fail("Unpickled before LAB guard"))
    monkeypatch.setattr(campaign, "_verify_model_specs", lambda *args: pytest.fail("Read model before LAB guard"))
    with pytest.raises(ValueError, match="offline refused"):
        campaign.load_frozen_models(tmp_path, {}, lab_attested=False)


def test_frozen_loader_derives_only_original_missing_indicator_columns(tmp_path, monkeypatch):
    import joblib
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.pipeline import make_pipeline
    imputer = SimpleImputer(strategy="median", add_indicator=True, keep_empty_features=True)
    imputer.statistics_ = np.array([1., 2.])
    imputer.feature_names_in_ = np.array(["a", "b"])
    imputer.indicator_ = SimpleNamespace(features_=np.array([1]))
    forest = RandomForestClassifier(n_estimators=200, max_depth=12, min_samples_leaf=2,
        class_weight="balanced", random_state=42, n_jobs=1)
    forest.classes_ = np.array([0, 1])
    model = make_pipeline(imputer, forest)
    monkeypatch.setattr(campaign, "require_offline_lab", lambda *args: {})
    monkeypatch.setattr(campaign, "_verify_model_specs", lambda *args: None)
    monkeypatch.setattr(campaign, "_content", lambda *args, **kwargs: b"controlled model bytes")
    monkeypatch.setattr(joblib, "load", lambda *args: model)
    specs = {"C1_v8": {"snapshot_path": "artifacts/cic_v9_prepare/run_x/C1.joblib",
        "manifest": {"feature_order": ["a", "b"], "configuration": {"n_estimators": 200,
            "max_depth": 12, "min_samples_leaf": 2, "class_weight": "balanced"}}}}
    loaded, supported = campaign.load_frozen_models(tmp_path, specs, lab_attested=True)
    assert loaded["C1_v8"] is model and supported == {"C1_v8": ["b"]}


def test_metadata_model_copy_never_unpickles(tmp_path, monkeypatch):
    import joblib
    from malpdf.experiments.cic_static_accuracy import profile_feature_values
    run = SimpleNamespace(artifacts=tmp_path / "artifacts/cic_v9_prepare/run_mock")
    run.artifacts.mkdir(parents=True)
    for name in ("C1_v8", *PROFILE_VARIANTS):
        origin = campaign.V8_RUN if name == "C1_v8" else campaign.V7_RUN
        target = tmp_path / "artifacts/cic_static_profile" / origin / (name + ".joblib")
        target.parent.mkdir(parents=True, exist_ok=True)
        content = b"inert checksum fixture, never a pickle"
        target.write_bytes(content)
        order = list(campaign.v8_feature_values({})) if name == "C1_v8" else list(profile_feature_values({}, name))
        manifest = {"feature_order": order, "threshold": .5, "seed": 42,
            "train_rows": 31 if name == "C1_v8" else 32,
            "model_id": "c1-v8-fixed-rf-evidence-v1" if name == "C1_v8" else name + "-v1",
            "artifact_path": str(target.relative_to(tmp_path)), "artifact_sha256": hashlib.sha256(content).hexdigest()}
        _save(tmp_path / "reports/experiments/cic_static_profile" / origin / (name + "_manifest.json"), manifest)
    monkeypatch.setattr(joblib, "load", lambda *args: pytest.fail("Preparation unpickled a model"))
    models = campaign._freeze_models(tmp_path, run)
    assert len(models) == 4 and len(models["C1_v8"]["manifest"]["feature_order"]) == 173
    assert all((tmp_path / spec["snapshot_path"]).read_bytes() == b"inert checksum fixture, never a pickle" for spec in models.values())


@pytest.fixture
def fake_runs(tmp_path, monkeypatch):
    created = []

    class Run(AbstractContextManager):
        def __init__(self, root, study, method):
            self.root, self.identifier = root, "run_fake_" + str(len(created))
            self.report = root / "reports/experiments" / study / self.identifier
            self.artifacts = root / "artifacts" / study / self.identifier
            self.report.mkdir(parents=True)
            self.artifacts.mkdir(parents=True)
            self.state = {"status": "started", "run_id": self.identifier, "metrics": {},
                "report_path": str((self.report / "run_summary.json").relative_to(root))}
            created.append(self)

        def progress(self, *args, **kwargs):
            pass

        def __exit__(self, kind, error, traceback):
            if error:
                self.state["status"] = "interrupted" if isinstance(error, KeyboardInterrupt) else "failed"
            _save(self.report / "run_summary.json", self.state)
            return False

    monkeypatch.setattr(campaign, "ResearchRun", Run)
    return created


@pytest.mark.parametrize("reason", ["offline", "dirty", "ram"])
def test_zero_input_refusal_is_audited_without_claim(tmp_path, monkeypatch, fake_runs, reason):
    def fail(*args, **kwargs):
        raise ValueError(reason)
    monkeypatch.setattr(campaign, "require_offline_lab", fail if reason == "offline" else lambda *args: {})
    monkeypatch.setattr(campaign, "clean_code", fail if reason == "dirty" else lambda *args: None)
    monkeypatch.setattr(campaign, "load_v9_job", lambda *args, **kwargs: ([], {}, campaign.LIMITS))
    monkeypatch.setattr(campaign, "_worker_count", fail if reason == "ram" else lambda *args: 1)
    monkeypatch.setattr(campaign, "load_frozen_models", lambda *args, **kwargs: pytest.fail("Preflight loaded models"))
    with pytest.raises(ValueError, match=reason):
        campaign._guarded_preflight(tmp_path, "run_prepared", "integration")
    assert len(fake_runs) == 1 and fake_runs[0].state["status"] == "failed"
    assert campaign.v9_campaign_outcome(tmp_path) is None


def test_final_requires_matching_successful_integration_and_full_regression(tmp_path, monkeypatch):
    fingerprint = {"source": "locked"}
    monkeypatch.setattr(campaign, "v9_source_fingerprint", lambda *args: fingerprint)
    integration = tmp_path / "reports/experiments/cic_v9_integration/run_integration"
    validation = tmp_path / "reports/experiments/cic_v9_validation/run_validation"
    for directory in (integration, validation):
        _save(directory / "run_summary.json", {"status": "completed"})
    _save(integration / "integration_evidence.json", {"status": "passed", "fingerprint": fingerprint, "recorded": 3, "planned": 3})
    evidence = {"status": "passed", "fingerprint": fingerprint, "python_major_minor": "3.11",
        "cpu_only": True, "clean_generating_code": True,
        "checks": {name: 0 for name in ("pytest", "pip_check", "diff_check", "source_integrity", "ignore_check")}}
    _save(validation / "validation_evidence.json", evidence)
    prerequisites = campaign._validated_prerequisites(tmp_path, "run_integration", "run_validation")
    assert set(prerequisites) == {"integration", "validation"}
    evidence["checks"]["pytest"] = 1
    _save(validation / "validation_evidence.json", evidence)
    with pytest.raises(ValueError, match="regression"):
        campaign._validated_prerequisites(tmp_path, "run_integration", "run_validation")
    evidence["checks"]["pytest"] = 0
    evidence["fingerprint"] = {"source": "changed"}
    _save(validation / "validation_evidence.json", evidence)
    with pytest.raises(ValueError, match="fingerprint changed"):
        campaign._validated_prerequisites(tmp_path, "run_integration", "run_validation")


@pytest.fixture
def final_campaign(tmp_path, monkeypatch, fake_runs):
    import malpdf.inference.evidence_policy_v9 as policy
    from malpdf.experiments.cic_static_accuracy import profile_feature_values
    rows = [{"sample_id": "synthetic-" + str(index), "pdf_sha256": format(index + 1, "064x"),
        "pdf_relative_path": "data/raw/cic_pdf/synthetic-" + str(index) + ".pdf",
        "split": "train" if index < 32 else "validation", "Label": str(index % 2)} for index in range(64)]
    before = [{**row, "cache_mode": "cold", "static": {}, "code": None, "status": "partial",
        "analysis_v8": {"status": "partial" if 32 <= index < 53 else "complete"}} for index, row in enumerate(rows)]
    fingerprint = {"locked": "synthetic"}
    manifests = {name: {"feature_order": list(campaign.v8_feature_values({})) if name == "C1_v8" else list(profile_feature_values({}, name)),
        "artifact_sha256": "b" * 64} for name in ("C1_v8", *PROFILE_VARIANTS)}
    lock = {"fingerprint": fingerprint, "prerequisites": {}, "models": {name: {"manifest": value} for name, value in manifests.items()},
        "configuration": {}, "subset_sha256": "c" * 64}
    monkeypatch.setattr(campaign, "_attestation", lambda *args: (rows, lock, campaign.LIMITS, {}))
    monkeypatch.setattr(campaign, "require_offline_lab", lambda *args: {})
    monkeypatch.setattr(campaign, "_worker_count", lambda *args: 1)
    monkeypatch.setattr(campaign, "worker_memory_budget", lambda *args: {})
    monkeypatch.setattr(campaign, "v9_source_fingerprint", lambda *args: fingerprint)
    monkeypatch.setattr(campaign, "_verify_prerequisites", lambda *args: None)
    events = []
    def load(*args, **kwargs):
        events.append("load")
        return {name: object() for name in manifests}, {name: [] for name in manifests}
    monkeypatch.setattr(campaign, "load_frozen_models", load)
    original_claim = campaign.claim_v9_campaign
    def claim(*args):
        events.append("claim")
        original_claim(*args)
    monkeypatch.setattr(campaign, "claim_v9_campaign", claim)
    monkeypatch.setattr(campaign, "_baseline_metadata", lambda *args: (rows, before, before, {}))
    monkeypatch.setattr(campaign, "baseline_records", lambda *args: (before, {}, {}))
    saved_decisions = [{"sample_id": row["sample_id"], "malicious_probability": .8} for row in rows if row["split"] == "validation"]
    def metadata(root, path):
        if str(path).endswith("c1_v8_decisions.json"):
            return saved_decisions
        return {"sample_ids": [row["sample_id"] for row in rows if row["split"] == "validation"],
            "probabilities": {name: [.8] * 32 for name in PROFILE_VARIANTS}}
    monkeypatch.setattr(campaign, "_json", metadata)
    monkeypatch.setattr("malpdf.experiments.cic_static_accuracy.profile_input_available", lambda *args: True)
    monkeypatch.setattr(policy, "verify_model_inputs", lambda *args, **kwargs: {"verified": True})
    monkeypatch.setattr(policy, "evidence_decision_v9", lambda probability, *args, **kwargs:
        {"predicted_label": 1, "decision": "Malicious", "malicious_probability": probability, "reason_codes": []})
    monkeypatch.setattr(campaign, "frozen_probability", lambda *args: .8)
    monkeypatch.setattr("malpdf.experiments.cic_v8.fit_c1_v8", lambda *args: pytest.fail("V9 attempted refitting"))
    def profile(root, row, run, **kwargs):
        events.append("profile")
        return {**row, "status": "partial", "static": {}, "code": None, "analysis_v8": {},
            "analysis_v9": {"status": "partial", "complete": False, "original_bytes_changed": False,
                "active_content_executed": False}, "errors": [], "reasons": [], "cache_hit": False,
            "timings": {name: 0 for name in STAGES}, "total_seconds": 0., "overhead_seconds": 0.,
            "peak_rss_bytes": 0, "peak_family_rss_sampled_bytes": 0, "rss_quality": "sampled_lower_bound"}
    monkeypatch.setattr(campaign, "_profile", profile)
    return events, fake_runs


def test_final_has_one_claim_and_frozen_cold_warm_loop(tmp_path, final_campaign):
    events, runs = final_campaign
    state = campaign.run_v9_final(tmp_path, "run_prepared", lab_attested=True)
    assert events[:3] == ["load", "claim", "profile"]
    assert events.count("claim") == 1 and events.count("profile") == 128
    assert state["status"] == "completed" and state["recorded"] == 128
    private = [json.loads(line) for line in (runs[0].artifacts / "paired_evidence.jsonl").read_text().splitlines()]
    assert len(private) == 64 and sum(row["old_partial_reason_review_required"] for row in private) == 21
    public = (runs[0].report / "v9_acceptance.json").read_text()
    assert "synthetic-" not in public and "pdf_relative_path" not in public


@pytest.mark.parametrize("exception", [RuntimeError("model-call-failed"), KeyboardInterrupt()])
def test_final_failure_preserves_first_profile_and_consumed_claim(tmp_path, monkeypatch, final_campaign, exception):
    _, runs = final_campaign
    def fail(*args):
        raise exception
    monkeypatch.setattr(campaign, "frozen_probability", fail)
    with pytest.raises(type(exception)):
        campaign.run_v9_final(tmp_path, "run_prepared", lab_attested=True)
    assert (tmp_path / "artifacts/cic_v9_campaign/final_attempt.json").exists()
    assert len((runs[0].artifacts / "per_file.jsonl").read_text().splitlines()) == 1
    assert runs[0].state["recorded"] == 1
    assert runs[0].state["status"] == ("interrupted" if isinstance(exception, KeyboardInterrupt) else "failed")


@pytest.fixture
def launcher(tmp_path, monkeypatch):
    path = Path(__file__).resolve().parents[1] / "scripts/20_launch_cic_v9.py"
    spec = importlib.util.spec_from_file_location("cic_v9_launcher", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "ROOT", tmp_path)
    return module


def test_launcher_check_never_prompts_loads_pickle_or_starts_worker(launcher, monkeypatch):
    monkeypatch.setattr(campaign, "v9_campaign_outcome", lambda *args: None)
    monkeypatch.setattr(campaign, "latest_v9_job", lambda *args, **kwargs: "run_prepared")
    monkeypatch.setattr(campaign, "load_v9_job", lambda *args: ([{}] * 3, {"kind": "integration"}, None))
    monkeypatch.setattr(campaign, "run_v9_integration", lambda *args, **kwargs: pytest.fail("Check started worker"))
    monkeypatch.setattr(campaign, "load_frozen_models", lambda *args, **kwargs: pytest.fail("Check unpickled"))
    monkeypatch.setattr("builtins.input", lambda *args: pytest.fail("Check prompted for attestation"))
    assert launcher.main(["--check"]) == 0


def test_launcher_menu_cancel_never_starts_analysis(launcher, monkeypatch):
    monkeypatch.setattr(campaign, "v9_campaign_outcome", lambda *args: None)
    monkeypatch.setattr("builtins.input", lambda *args: "q")
    monkeypatch.setattr(campaign, "run_v9_integration", lambda *args, **kwargs: pytest.fail("Cancelled analysis started"))
    assert launcher.main([]) == 0


def test_launcher_enter_integration_passes_console_attestation(launcher, monkeypatch):
    monkeypatch.setattr(campaign, "v9_campaign_outcome", lambda *args: None)
    monkeypatch.setattr(campaign, "latest_v9_job", lambda *args, **kwargs: "run_prepared")
    calls = []
    monkeypatch.setattr(campaign, "run_v9_integration", lambda root, job, **kwargs:
        calls.append((root, job, kwargs)) or {"report_path": "reports/experiments/synthetic/run_summary.json", "integration_status": "passed"})
    monkeypatch.setattr("builtins.input", lambda *args: "")
    assert launcher.main([]) == 0
    assert calls == [(launcher.ROOT, "run_prepared", {"lab_attested": True})]
