"""Offline synthetic-only tests for v2 leakage guards, stacking and referral."""

from dataclasses import replace
import hashlib
import inspect
import json
from pathlib import Path
import runpy

import numpy as np
import pandas as pd
import pytest
import yaml

from malpdf.data.rit_pdfmal_split import create_rit_pdfmal_split
from malpdf.evaluation.selective import calibration_metrics
from malpdf.experiments import late_fusion_runner as runner
from malpdf.experiments import protocol_g_benchmark as protocol_g
from malpdf.experiments.selective_static_ensemble import _safe_id
from malpdf.models import late_fusion as fusion
from malpdf.static.schema import RIT_FEATURES


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def synthetic_partition(partition="validation", *, vision=False):
    labels = np.tile([0, 1], 24)
    xgb = np.where(labels, 0.80, 0.20) + np.linspace(-0.04, 0.04, len(labels))
    ft = np.where(labels, 0.75, 0.25) - np.linspace(-0.06, 0.06, len(labels))
    scores = np.column_stack((xgb, ft))
    if vision:
        scores = np.column_stack((scores, np.where(labels, 0.7, 0.3)))

    return fusion.FusionPartition(partition, tuple(f"id_{index:03}" for index in range(len(labels))),
                                  tuple(f"group_{index // 4}_{label}" for index, label in enumerate(labels)), labels, scores,
                                  fusion.VISION_BRANCHES if vision else fusion.BASE_BRANCHES)


def test_validation_roles_are_group_disjoint_deterministic_and_order_independent():
    validation = synthetic_partition()
    roles = fusion.validation_roles(validation)
    assert sum(map(len, roles.values())) == len(validation.sample_ids)
    group_sets = [{validation.group_ids[index] for index in positions} for positions in roles.values()]
    assert not any(group_sets[left] & group_sets[right] for left in range(3) for right in range(left + 1, 3))
    order = np.arange(len(validation.sample_ids))[::-1]
    reordered = replace(validation, sample_ids=tuple(validation.sample_ids[index] for index in order), group_ids=tuple(validation.group_ids[index] for index in order), labels=validation.labels[order], probabilities=validation.probabilities[order])
    second = fusion.validation_roles(reordered)
    assert {name: {validation.sample_ids[index] for index in positions} for name, positions in roles.items()} == {name: {reordered.sample_ids[index] for index in positions} for name, positions in second.items()}


def test_meta_and_platt_fit_separate_validation_roles_without_refitting(monkeypatch):
    validation = synthetic_partition()
    roles = fusion.validation_roles(validation)
    actual_fit = fusion.LogisticRegression.fit
    calls = []
    def fit(model, features, labels, *args, **kwargs):
        calls.append((np.array(features), np.array(labels)))
        return actual_fit(model, features, labels, *args, **kwargs)
    monkeypatch.setattr(fusion.LogisticRegression, "fit", fit)
    stack, rows, _ = fusion.fit_validation_stack(validation, (fusion.FusionCandidate("stacking"),))
    assert len(calls) == 2
    assert np.array_equal(calls[0][0], validation.probabilities[roles["meta_fit"]])
    assert np.array_equal(calls[0][1], validation.labels[roles["meta_fit"]])
    assert calls[1][0].shape == (len(roles["calibration_fit"]), 1)
    assert np.array_equal(calls[1][1], validation.labels[roles["calibration_fit"]])
    assert rows[0]["partition"] == "validation_selection"
    assert not stack.lock_metadata()["test_used_for_fitting_or_selection"]
    assert not stack.lock_metadata()["refit_after_selection"]
    assert "test" not in inspect.signature(fusion.fit_validation_stack).parameters
    before = stack.lock_metadata()
    stack.predict_proba(replace(validation, partition="test"))
    assert len(calls) == 2 and stack.lock_metadata() == before
    with pytest.raises(ValueError, match="validation only"):
        fusion.fit_validation_stack(replace(validation, partition="test"), (fusion.FusionCandidate("stacking"),))


def test_equal_metrics_keep_declared_order_and_repeated_fit_is_deterministic():
    validation = synthetic_partition()
    validation = replace(validation, probabilities=np.column_stack((validation.probabilities[:, 0], validation.probabilities[:, 0])))
    candidates = (fusion.FusionCandidate("weighted_average", xgb_weight=1), fusion.FusionCandidate("weighted_average", xgb_weight=0))
    stack, rows, _ = fusion.fit_validation_stack(validation, candidates)
    repeated, _, _ = fusion.fit_validation_stack(validation, candidates)
    assert rows[0]["mcc"] == rows[1]["mcc"] and rows[0]["f1_malicious"] == rows[1]["f1_malicious"]
    assert stack.selection["candidate_order"] == 0
    assert stack.lock_metadata() == repeated.lock_metadata()
    assert np.array_equal(stack.predict_proba(validation), repeated.predict_proba(validation))


def test_vision_weights_use_real_third_branch_and_cannot_be_fabricated():
    validation = synthetic_partition(vision=True)
    candidate = fusion.FusionCandidate("weighted_average", xgb_weight=0.75, vision_weight=0.25)
    raw = fusion._raw_probability(candidate, validation.probabilities, None)
    expected = 0.5625 * validation.probabilities[:, 0] + 0.1875 * validation.probabilities[:, 1] + 0.25 * validation.probabilities[:, 2]
    assert np.allclose(raw, expected)
    stack, _, _ = fusion.fit_validation_stack(validation, (candidate,))
    assert np.isfinite(stack.predict_proba(validation)).all()
    with pytest.raises(ValueError, match="Vision weights"):
        fusion.fit_validation_stack(synthetic_partition(), (candidate,))
    with pytest.raises(ValueError, match="branch order"):
        stack.predict_proba(synthetic_partition())


@pytest.mark.parametrize("case", ["nan", "range", "label", "one_class", "id", "group", "shape", "partition"])
def test_fusion_partition_rejects_invalid_or_ambiguous_inputs(case):
    validation = synthetic_partition()
    changes = {}
    if case in {"nan", "range", "shape"}:
        values = validation.probabilities.copy()
        if case == "shape":
            values = values[:, :1]
        else:
            values[0, 0] = float("nan") if case == "nan" else 1.1
        changes["probabilities"] = values
    elif case in {"label", "one_class"}:
        labels = validation.labels.copy()
        labels[:] = 1 if case == "one_class" else labels
        if case == "label":
            labels[0] = 2
        changes["labels"] = labels
    elif case == "id":
        changes["sample_ids"] = (validation.sample_ids[1], *validation.sample_ids[1:])
    elif case == "group":
        changes["group_ids"] = (validation.group_ids[1], *validation.group_ids[1:])
    else:
        changes["partition"] = "train"
    with pytest.raises(ValueError):
        replace(validation, **changes)


def test_entropy_routing_catches_only_referred_false_negatives_and_reports_retained_calibration():
    labels = np.tile([0, 1], 10)
    scores = np.where(labels, 0.9, 0.1)
    scores[[1, 3, 5]] = [0.49, 0.4, 0.1]
    scores[10] = 0.501
    ids = tuple(f"id_{index:02}" for index in range(20))
    summary, mask = fusion.entropy_routing(labels, scores, ids)
    assert mask.sum() == 2 and set(np.flatnonzero(mask)) == {1, 10}
    assert summary["coverage"] == 0.9 and summary["fn_catch_rate"] == pytest.approx(1 / 3)
    assert summary["fn_total"] == 3 and summary["fn_referred"] == 1 and summary["fn_retained"] == 2
    expected = calibration_metrics(labels[~mask], scores[~mask], n_bins=10)
    assert summary["retained_metrics"] == expected and not summary["referrals_counted_as_corrected"]
    assert summary["dynamic_samples_executed"] == 0


def test_entropy_ties_follow_ids_without_label_based_selection_and_no_fn_is_na():
    labels = np.tile([0, 1], 10)
    scores = np.full(20, 0.5)
    ids = tuple(f"id_{index:02}" for index in range(20))[::-1]
    summary, mask = fusion.entropy_routing(labels, scores, ids)
    changed, second = fusion.entropy_routing(1 - labels, scores, ids)
    assert np.array_equal(mask, second) and {ids[index] for index in np.flatnonzero(mask)} == {"id_00", "id_01"}
    assert summary["fn_catch_rate"] is None and changed["fn_catch_rate"] is None
    assert summary["fn_catch_rate_unavailable_reason"]


@pytest.fixture
def probability_sources(tmp_path, monkeypatch):
    root = tmp_path
    data = root / "data/processed"
    data.mkdir(parents=True)
    reports = root / "reports"
    (reports / "experiments/base").mkdir(parents=True)
    (reports / "research_log.md").write_text("# Historical research log\n")
    frame = pd.DataFrame([{**{column: index + offset * 13 for offset, column in enumerate(RIT_FEATURES)}, "Label": index % 2} for index in range(100)])
    dataset = data / "synthetic.csv"
    frame.to_csv(dataset, index=False)
    manifest, summary = create_rit_pdfmal_split(frame, seed=42)
    split_path = data / "rit-pdfmal-2026_split_manifest.csv"
    manifest.to_csv(split_path, index=False)
    (reports / "rit-pdfmal-2026_split_report.json").write_text(json.dumps({"seed": 42, "dataset": {"sha256": sha(dataset)}}))
    monkeypatch.setattr(protocol_g, "VERIFIED_DATASET_SHA256", sha(dataset))
    expected = {name: {"rows": values["row_count"], "groups": values["unique_group_count"], "label_0": values["benign"]["count"], "label_1": values["malicious"]["count"]} for name, values in summary["split_statistics"].items()}
    monkeypatch.setattr(protocol_g, "EXPECTED_G_SPLIT", {**expected, "total_rows": len(frame), "total_groups": manifest.duplicate_group_id.nunique()})
    monkeypatch.setattr(runner, "_current_commit_sha", lambda root: "a" * 40)
    monkeypatch.setattr(runner, "repository_git_state", lambda root: {"status": "clean", "porcelain_entries": []})
    config = yaml.safe_load((Path(__file__).resolve().parents[1] / "configs/late_fusion_stacking.yaml").read_text())
    def spec(path):
        return {"path": str(path.relative_to(root)), "sha256": sha(path)}
    config["inputs"]["dataset"] = spec(dataset)
    config["inputs"]["split_manifest"] = spec(split_path)
    for partition in ("validation", "test"):
        subset = manifest.loc[manifest.split == partition]
        table = pd.DataFrame({"sample_id": [_safe_id(value) for value in subset.sample_id], "true_label": subset.Label,
                              "xgb_probability": np.where(subset.Label, 0.8, 0.2), "ft_probability": np.where(subset.Label, 0.75, 0.25),
                              "selected_xgb_probability": 0.5, "ensemble_probability": 0.5})
        path = reports / "experiments/base" / f"{partition}.parquet"
        table.iloc[::-1].to_parquet(path, index=False)
        config["inputs"][partition] = spec(path)
    proof = {"experiment": "selective_static_ensemble_protocol_g_seed42", "code_commit_sha": "b" * 40,
             "dataset_sha256": sha(dataset), "protocol_g_manifest_sha256": sha(split_path),
             "environment": {"git_working_tree": {"status": "clean"}}, "test_evaluation": {"test_not_used_for_selection": True}}
    proof_path = reports / "experiments/base/provenance.json"
    proof_path.write_text(json.dumps(proof))
    config["inputs"]["base_provenance"] = spec(proof_path)
    base_config = {"protocol": "G", "split_seed": 42, "model_seed": 42, "dataset_sha256": sha(dataset), "split_manifest_sha256": sha(split_path),
                   "base_models": {"ft_transformer": {"preprocessing": "StandardScaler fit on Protocol G train only"}}}
    base_path = reports / "experiments/base/config.json"
    base_path.write_text(json.dumps(base_config))
    config["inputs"]["base_configuration"] = spec(base_path)
    return root, config, manifest


def test_dry_run_never_fits_or_decodes_test_and_preserves_history(probability_sources, monkeypatch):
    root, config, _ = probability_sources
    before = {path: sha(path) for path in root.rglob("*") if path.is_file()}
    log_before = (root / "reports/research_log.md").read_bytes()
    monkeypatch.setattr(runner, "repository_git_state", lambda root: {"status": "dirty"})
    actual_load = runner._load_partition
    def load(root, config, manifest, partition, groups):
        assert partition == "validation"
        return actual_load(root, config, manifest, partition, groups)
    monkeypatch.setattr(runner, "_load_partition", load)
    monkeypatch.setattr(runner, "fit_validation_stack", lambda *args, **kwargs: pytest.fail("Dry-run fit a model"))
    report = runner.run_late_fusion(root, config, run_id="preflight")
    assert report["status"] == "dry_run_completed" and report["test_evaluation_count"] == 0 and report["metrics"] == {}
    assert not report["official_execution_ready"] and report["skipped_vision_weights"] == [0.1, 0.25]
    assert report["candidate_count"] == 8
    assert all(sha(path) == digest for path, digest in before.items() if path.name != "research_log.md")
    assert (root / "reports/research_log.md").read_bytes().startswith(log_before)
    with pytest.raises(ValueError, match="run directory exists"):
        runner.run_late_fusion(root, config, run_id="preflight")


def test_official_pipeline_locks_before_test_and_fits_only_before_lock(probability_sources, monkeypatch):
    root, config, _ = probability_sources
    lock_path = root / "reports/experiments/late_fusion_v2/official/validation_lock.json"
    actual_fit = fusion.LogisticRegression.fit
    def fit(model, *args, **kwargs):
        assert not lock_path.exists(), "A model was refit after selection lock"
        return actual_fit(model, *args, **kwargs)
    monkeypatch.setattr(fusion.LogisticRegression, "fit", fit)
    actual_load = runner._load_partition
    decoded = []
    def load(root, config, manifest, partition, groups):
        decoded.append(partition)
        if partition == "test":
            assert lock_path.exists()
            assert json.loads(lock_path.read_text())["test_evaluations_before_lock"] == 0
        return actual_load(root, config, manifest, partition, groups)
    monkeypatch.setattr(runner, "_load_partition", load)
    report = runner.run_late_fusion(root, config, execute=True, run_id="official")
    assert report["status"] == "completed" and decoded == ["validation", "test"] and report["test_evaluation_count"] == 1
    directory = root / "reports/experiments/late_fusion_v2/official"
    assert json.loads((directory / "metrics.json").read_text()) == report["metrics"]
    assert len(pd.read_csv(directory / "model_comparison.csv")) == 7
    assert len(pd.read_csv(directory / "routing_analysis.csv")) == 1
    assert (root / report["artifact_directory"] / "test_predictions.parquet").exists()
    assert report["metrics"]["xgboost/test"]["accuracy"] == 1
    assert report["routing"]["coverage"] == 0.9
    false_negatives = report["metrics"]["late_fusion_v2/test"]["confusion_matrix"][1][0]
    assert report["routing"]["fn_total"] == false_negatives
    assert report["routing"]["fn_catch_rate"] == (report["routing"]["fn_referred"] / false_negatives if false_negatives else None)
    assert (root / "reports/research_log.md").read_text().count("late fusion execute / completed") == 7


def test_dirty_official_run_is_refused_and_failure_is_logged(probability_sources, monkeypatch):
    root, config, _ = probability_sources
    monkeypatch.setattr(runner, "repository_git_state", lambda root: {"status": "dirty"})
    monkeypatch.setattr(runner, "fit_validation_stack", lambda *args, **kwargs: pytest.fail("Dirty run fit a model"))
    with pytest.raises(ValueError, match="clean committed worktree"):
        runner.run_late_fusion(root, config, execute=True, run_id="dirty")
    report = json.loads((root / "reports/experiments/late_fusion_v2/dirty/run_summary.json").read_text())
    assert report["status"] == "failed" and report["test_evaluation_count"] == 0
    assert "late fusion execute / failed" in (root / "reports/research_log.md").read_text()


@pytest.mark.parametrize("case", ["id", "duplicate", "label", "nan", "hash"])
def test_saved_probabilities_fail_closed_before_fitting(probability_sources, case):
    root, config, _ = probability_sources
    spec = config["inputs"]["validation"]
    path = root / spec["path"]
    table = pd.read_parquet(path)
    if case == "id":
        table.loc[0, "sample_id"] = "unmapped"
    elif case == "duplicate":
        table.loc[0, "sample_id"] = table.loc[1, "sample_id"]
    elif case == "label":
        table.loc[0, "true_label"] = 1 - table.loc[0, "true_label"]
    elif case == "nan":
        table.loc[0, "xgb_probability"] = float("nan")
    else:
        spec["sha256"] = "0" * 64
    if case != "hash":
        table.to_parquet(path, index=False)
        spec["sha256"] = sha(path)
    with pytest.raises(ValueError):
        runner.run_late_fusion(root, config, execute=True, run_id=f"invalid_{case}")
    report = json.loads((root / f"reports/experiments/late_fusion_v2/invalid_{case}/run_summary.json").read_text())
    assert report["metrics"] == {} and report["test_evaluation_count"] == 0


def test_test_checksum_failure_preserves_validation_lock_and_failure_evidence(probability_sources):
    root, config, _ = probability_sources
    config["inputs"]["test"]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="SHA-256 lock"):
        runner.run_late_fusion(root, config, execute=True, run_id="bad_test")
    directory = root / "reports/experiments/late_fusion_v2/bad_test"
    report = json.loads((directory / "run_summary.json").read_text())
    assert (directory / "validation_lock.json").exists() and report["status"] == "failed"
    assert report["test_evaluation_count"] == 0 and all(key.endswith("validation_selection") for key in report["metrics"])
    assert not (root / report["artifact_directory"] / "test_predictions.parquet").exists()


@pytest.fixture
def vision_probability_sources(probability_sources):
    root, config, manifest = probability_sources
    rows = [{"sample_id": row.sample_id, "Label": row.Label, "pdf_relative_path": f"data/raw/synthetic_{index}.pdf", "pdf_sha256": hashlib.sha256(f"benign fixture {index}".encode()).hexdigest()} for index, row in manifest.iterrows()]
    source = root / "data/processed/source_pdf_manifest.csv"
    pd.DataFrame(rows).to_csv(source, index=False)
    def spec(path):
        return {"path": str(path.relative_to(root)), "sha256": sha(path)}
    vision = {}
    for partition in ("validation", "test"):
        subset = manifest.loc[manifest.split == partition]
        path = root / f"data/processed/vision_{partition}.csv"
        pd.DataFrame({"sample_id": subset.sample_id, "true_label": subset.Label, "vision_probability": np.where(subset.Label, 0.7, 0.3)}).iloc[::-1].to_csv(path, index=False)
        vision[partition] = spec(path)
    proof = {"protocol": "G", "seed": 42, "model": "vision_resnet18", "official_model": True, "base_fit_partition": "train", "checkpoint_selection_partition": "validation", "worktree": "clean",
             "dataset_sha256": config["inputs"]["dataset"]["sha256"], "split_manifest_sha256": config["inputs"]["split_manifest"]["sha256"], "source_manifest": spec(source), "predictions": dict(vision)}
    path = root / "data/processed/vision_provenance.json"
    path.write_text(json.dumps(proof))
    vision["provenance"] = spec(path)
    config["vision"] = vision
    return root, config, manifest


def test_three_branch_pipeline_checks_vision_provenance_and_evaluates_declared_weights(vision_probability_sources):
    root, config, _ = vision_probability_sources
    report = runner.run_late_fusion(root, config, execute=True, run_id="three_branch")
    assert report["vision_status"] == "verified_official_predictions" and report["candidate_count"] == 18
    assert report["skipped_vision_weights"] == [] and "vision_resnet18/test" in report["metrics"]
    directory = root / "reports/experiments/late_fusion_v2/three_branch"
    rows = pd.read_csv(directory / "selection_results.csv")
    assert {0, 0.1, 0.25} == set(rows.vision_weight)
    assert json.loads((directory / "validation_lock.json").read_text())["branches"] == list(fusion.VISION_BRANCHES)


def test_smoke_vision_provenance_is_ineligible(vision_probability_sources):
    root, config, _ = vision_probability_sources
    spec = config["vision"]["provenance"]
    path = root / spec["path"]
    proof = json.loads(path.read_text())
    proof["official_model"] = False
    path.write_text(json.dumps(proof))
    spec["sha256"] = sha(path)
    with pytest.raises(ValueError, match="smoke checkpoints are ineligible"):
        runner.run_late_fusion(root, config, run_id="smoke_ineligible")


def test_known_vision_pdf_duplicates_cannot_cross_validation_and_test(vision_probability_sources):
    root, config, manifest = vision_probability_sources
    proof_path = root / config["vision"]["provenance"]["path"]
    proof = json.loads(proof_path.read_text())
    source = root / proof["source_manifest"]["path"]
    table = pd.read_csv(source)
    left = manifest.index[(manifest.split == "validation") & (manifest.Label == 0)][0]
    right = manifest.index[(manifest.split == "test") & (manifest.Label == 0)][0]
    table.loc[right, "pdf_sha256"] = table.loc[left, "pdf_sha256"]
    table.to_csv(source, index=False)
    proof["source_manifest"]["sha256"] = sha(source)
    proof_path.write_text(json.dumps(proof))
    config["vision"]["provenance"]["sha256"] = sha(proof_path)
    with pytest.raises(ValueError, match="crosses Protocol G partitions"):
        runner.run_late_fusion(root, config, run_id="duplicate_file")


def test_known_vision_family_components_stay_in_one_validation_role(vision_probability_sources):
    root, config, manifest = vision_probability_sources
    proof_path = root / config["vision"]["provenance"]["path"]
    proof = json.loads(proof_path.read_text())
    source = root / proof["source_manifest"]["path"]
    table = pd.read_csv(source)
    table["related_group_id"] = [f"family_{index}" for index in table.index]
    paired = manifest.index[(manifest.split == "validation") & (manifest.Label == 0)][:2]
    table.loc[paired, "related_group_id"] = "shared_validation_family"
    table.to_csv(source, index=False)
    proof["source_manifest"]["sha256"] = sha(source)
    proof_path.write_text(json.dumps(proof))
    config["vision"]["provenance"]["sha256"] = sha(proof_path)
    groups = runner._vision_groups(root, config, manifest)
    ids = tuple(manifest.loc[paired, "sample_id"])
    assert groups[ids[0]] == groups[ids[1]]
    validation = runner._load_partition(root, config, manifest, "validation", groups)
    roles = fusion.validation_roles(validation)
    role_by_id = {validation.sample_ids[index]: name for name, positions in roles.items() for index in positions}
    assert role_by_id[ids[0]] == role_by_id[ids[1]]


def test_fusion_cli_defaults_to_preflight(probability_sources, monkeypatch, capsys):
    root, config, _ = probability_sources
    path = root / "configs/fusion.yaml"
    path.parent.mkdir()
    path.write_text(yaml.safe_dump(config))
    main = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/04_evaluate_late_fusion.py"))["main"]
    monkeypatch.setitem(main.__globals__, "ROOT", root)
    assert main(["--config", str(path), "--run-id", "cli"]) == 0
    assert "No fitting/test evaluation" in capsys.readouterr().out


@pytest.mark.parametrize("change", ["seed", "unsafe_path", "bad_weight", "unbounded_grid"])
def test_configuration_rejects_unlocked_and_unsafe_inputs(probability_sources, change):
    root, config, _ = probability_sources
    if change == "seed":
        config["seed"] = 43
    elif change == "unsafe_path":
        config["inputs"]["test"]["path"] = "../test.csv"
    elif change == "bad_weight":
        config["candidates"]["vision_weights"] = [0, float("nan")]
    else:
        config["candidates"]["regularization_cs"] = list(range(1, 50))
    with pytest.raises(ValueError):
        runner.run_late_fusion(root, config)
    assert not (root / "reports/experiments/late_fusion_v2").exists()
