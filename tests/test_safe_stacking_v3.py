"""Offline v3 security/leakage tests using synthetic tables and benign PDF bytes."""

import hashlib
import json
from pathlib import Path
import runpy

import numpy as np
import pandas as pd
import pytest
import yaml

from malpdf.data.rit_pdfmal_split import create_rit_pdfmal_split
from malpdf.evaluation.selective import calibration_metrics
from malpdf.experiments import protocol_g_benchmark as protocol_g
from malpdf.experiments import safe_stacking_v3 as runner
from malpdf.models import safe_stacking as stacking
from malpdf.models.late_fusion import entropy_routing
from malpdf.static.obfuscation import MAX_PDF_BYTES, count_escaped_pdf_names, measure_pdf_obfuscation
from malpdf.static.schema import PROTOCOL_G_DROPPED_CONSTANT_FEATURES, RIT_FEATURES


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def sources(tmp_path, monkeypatch):
    root = tmp_path
    processed = root / "data/processed"
    raw = root / "data/raw/synthetic"
    processed.mkdir(parents=True)
    raw.mkdir(parents=True)
    (root / "reports").mkdir()
    (root / "reports/research_log.md").write_text("# Historical log\n")
    frame = pd.DataFrame([{**{column: (index // 2 + offset + 1) for offset, column in enumerate(RIT_FEATURES)},
                          **{column: 0 for column in PROTOCOL_G_DROPPED_CONSTANT_FEATURES}, "Label": index // 2 % 2} for index in range(240)])
    dataset = processed / "synthetic.csv"
    frame.to_csv(dataset, index=False)
    manifest, split = create_rit_pdfmal_split(frame, seed=42)
    split_path = processed / "rit-pdfmal-2026_split_manifest.csv"
    manifest.to_csv(split_path, index=False)
    (root / "reports/rit-pdfmal-2026_split_report.json").write_text(json.dumps({"seed": 42, "dataset": {"sha256": sha(dataset)}}))
    monkeypatch.setattr(protocol_g, "VERIFIED_DATASET_SHA256", sha(dataset))
    expected = {name: {"rows": value["row_count"], "groups": value["unique_group_count"], "label_0": value["benign"]["count"], "label_1": value["malicious"]["count"]} for name, value in split["split_statistics"].items()}
    monkeypatch.setattr(protocol_g, "EXPECTED_G_SPLIT", {**expected, "total_rows": len(frame), "total_groups": manifest.duplicate_group_id.nunique()})
    monkeypatch.setattr(runner, "_current_commit_sha", lambda root: "d" * 40)
    monkeypatch.setattr(runner, "repository_git_state", lambda root: {"status": "clean", "porcelain_entries": []})
    rows = []
    for index, row in manifest.iterrows():
        content = f"%PDF-1.4\n% benign fixture {index}\n".encode() + b"/Java#53cript " * (index % 3) + b"\n%%EOF\n"
        path = raw / f"synthetic_{index}.pdf"
        path.write_bytes(content)
        rows.append({"sample_id": row.sample_id, "Label": row.Label, "pdf_relative_path": str(path.relative_to(root)), "pdf_sha256": sha(path)})
    source = processed / "source_pdf_manifest.csv"
    pd.DataFrame(rows).iloc[::-1].to_csv(source, index=False)
    config = yaml.safe_load((Path(__file__).resolve().parents[1] / "configs/safe_stacking_v3.yaml").read_text())
    for name, path in (("dataset", dataset), ("split_manifest", split_path), ("source_manifest", source)):
        config["inputs"][name] = {"path": str(path.relative_to(root)), "sha256": sha(path)}
    config["models"]["xgboost"].update(n_estimators=5, max_depth=2)
    config["models"]["lightgbm"].update(n_estimators=5, num_leaves=4, min_child_samples=2)
    config["models"]["catboost"].update(iterations=5, depth=2)
    config["models"]["random_forest"].update(n_estimators=5, max_depth=2)
    config["models"]["ft_transformer"].update(d_token=8, n_blocks=1, n_heads=2, d_ffn=16, attention_dropout=0.0, ffn_dropout=0.0)
    config["training"].update(max_epochs=1, patience=1, batch_size=16)
    return root, config, manifest, frame


def test_escaped_name_count_is_an_actual_raw_measurement_not_encoding_proxy(tmp_path):
    content = b"%PDF-1.4\n/Java#53cript /#4A#53 /AA#00 /JS#ZZ /Encoding /ObjStm\n%%EOF\n"
    assert count_escaped_pdf_names(content) == 3
    path = tmp_path / "benign.pdf"
    path.write_bytes(content)
    result = measure_pdf_obfuscation(path, boundary=tmp_path, expected_sha256=sha(path))
    assert result["ObfuscationCount"] == 3 and result["raw_pdf_sha256_verified"]
    with pytest.raises(ValueError, match="SHA-256"):
        measure_pdf_obfuscation(path, boundary=tmp_path, expected_sha256="0" * 64)
    with pytest.raises(ValueError):
        count_escaped_pdf_names(b"%PDF-" + b"a" * MAX_PDF_BYTES)
    with pytest.raises(ValueError, match="header"):
        count_escaped_pdf_names(b"not a PDF /Java#53cript")


def test_only_three_training_constants_are_removed_and_all_other_values_survive(sources):
    _, _, _, frame = sources
    source = frame.copy()
    source["ObfuscationCount"] = np.arange(len(frame)) % 4
    source["contains_text"] = -1
    source["RichMedia"] = 0
    result = stacking.safe_feature_view(source, check_training_constants=True)
    assert tuple(result.columns) == stacking.V3_FEATURES and len(result.columns) == 40
    for column in RIT_FEATURES:
        if column not in PROTOCOL_G_DROPPED_CONSTANT_FEATURES:
            pd.testing.assert_series_equal(result[column], source[column])
    assert result.script_ratio.equals((source.JS + source.JavaScript).astype(float) / (1 + source.obj.astype(float)))
    assert result.ObfuscationCount.equals(source.ObfuscationCount)
    source.loc[0, "Acroform"] = 1
    with pytest.raises(ValueError, match="zero-variance"):
        stacking.safe_feature_view(source, check_training_constants=True)

    stacking.safe_feature_view(source)
    with pytest.raises(ValueError, match="real checksum-verified PDF"):
        stacking.safe_feature_view(source.drop(columns="ObfuscationCount"))


def test_train_cv_and_four_validation_roles_are_disjoint_and_repeatable(sources):
    _, _, manifest, _ = sources
    train = manifest.loc[manifest.split.eq("train")].sort_values("sample_id").reset_index(drop=True)
    folds = stacking.train_cv_folds(train)
    assert len(folds) == 5
    seen = []
    for (fit, held), repeated in zip(folds, stacking.train_cv_folds(train)):
        assert not set(train.iloc[fit].duplicate_group_id) & set(train.iloc[held].duplicate_group_id)
        assert np.array_equal(fit, repeated[0]) and np.array_equal(held, repeated[1])
        seen.extend(held)
    assert sorted(seen) == list(range(len(train)))
    validation = manifest.loc[manifest.split.eq("validation")].sort_values("sample_id").reset_index(drop=True)
    roles = stacking.v3_validation_roles(validation)
    assert set(roles) == {"base_selection", "meta_fit", "calibration_fit", "threshold_selection"}
    sets = [{validation.iloc[index].duplicate_group_id for index in positions} for positions in roles.values()]
    assert not any(sets[i] & sets[j] for i in range(4) for j in range(i + 1, 4))
    assert sum(map(len, roles.values())) == len(validation)
    for function in (stacking.train_cv_folds, stacking.v3_validation_roles):
        with pytest.raises(ValueError):
            function(manifest.loc[manifest.split.eq("test")])


def test_meta_and_platt_fit_only_disjoint_validation_rows_and_use_youden(sources, monkeypatch):
    _, _, manifest, _ = sources
    validation = manifest.loc[manifest.split.eq("validation")].sort_values("sample_id").reset_index(drop=True)
    roles = stacking.v3_validation_roles(validation)
    labels = validation.Label.to_numpy()
    scores = np.column_stack([np.where(labels, 0.7 + i * 0.03, 0.1 + i * 0.02) for i in range(5)])
    original = stacking.LogisticRegression.fit
    calls = []
    def fit(self, x, y, **kwargs):
        calls.append((np.array(x), np.array(y)))
        return original(self, x, y, **kwargs)
    monkeypatch.setattr(stacking.LogisticRegression, "fit", fit)
    stack, rows = stacking.fit_validation_v3(validation, scores, [1.0])
    assert len(calls) == 2 and np.array_equal(calls[0][0], scores[roles["meta_fit"]])
    assert np.array_equal(calls[1][1], labels[roles["calibration_fit"]])
    assert calls[1][0].shape[0] == len(roles["calibration_fit"])
    selected = roles["threshold_selection"]
    t, decision = stacking.youden_threshold(labels[selected], stack.predict_proba(scores)[selected])
    assert stack.threshold == t and rows[0]["youden_j"] == decision["youden_j"]
    stack.predict_proba(scores)
    assert len(calls) == 2 and not stack.lock_metadata()["refit_after_selection"]
    with pytest.raises(ValueError):
        stacking.fit_validation_v3(validation.assign(split="test"), scores, [1.0])


def test_youden_metrics_and_fn_catch_consistently_use_selected_threshold():
    labels = np.tile([0, 1], 10)
    probabilities = np.where(labels, 0.35, 0.2)
    t, _ = stacking.youden_threshold(labels, probabilities)
    assert t == 0.35 and calibration_metrics(labels, probabilities, threshold=t)["accuracy"] == 1
    assert calibration_metrics(labels, probabilities)["recall_malicious"] == 0
    result, _ = entropy_routing(labels, probabilities, tuple(f"id_{i}" for i in range(20)), threshold=t)
    assert result["threshold"] == t and result["fn_total"] == 0 and result["fn_catch_rate"] is None
    assert result["retained_metrics"]["accuracy"] == 1 and result["retained_metrics"]["threshold"] == t
    for invalid in (float("nan"), -1, 2, True):
        with pytest.raises(ValueError):
            calibration_metrics(labels, probabilities, threshold=invalid)


def test_complete_offline_pipeline_trains_all_five_models_and_locks_before_test(sources, monkeypatch):
    root, config, manifest, frame = sources
    before = {path: sha(path) for path in root.rglob("*") if path.is_file()}
    old_log = (root / "reports/research_log.md").read_bytes()
    original_fit, original_measure = runner.fit_v3_fold, runner.PdfSources.measured_frame
    lock = root / "reports/experiments/safe_stacking_v3/full/validation_lock.json"
    fits, measured = [], []
    def fit(name, config, tx, ty, vx, vy, directory):
        assert not lock.exists()
        assert len(tx) < manifest.split.eq("train").sum()

        assert tx.drop(columns=["ObfuscationCount"]).value_counts().eq(2).all()
        fits.append((name, len(tx), len(vx)))
        return original_fit(name, config, tx, ty, vx, vy, directory)
    def measure(self, source, subset, partition, path):
        measured.append(partition)
        if partition == "test":
            assert path == lock and lock.exists() and json.loads(lock.read_text())["test_evaluations_before_lock"] == 0
        return original_measure(self, source, subset, partition, path)
    monkeypatch.setattr(runner, "fit_v3_fold", fit)
    monkeypatch.setattr(runner.PdfSources, "measured_frame", measure)
    result = runner.run_safe_stacking_v3(root, config, execute=True, run_id="full")
    assert result["status"] == "completed" and result["completed_base_fits"] == 25 and result["test_evaluation_count"] == 1
    assert measured == ["train", "validation", "test"] and {name: sum(row[0] == name for row in fits) for name in stacking.V3_BRANCHES} == {name: 5 for name in stacking.V3_BRANCHES}
    directory, artifacts = lock.parent, root / result["artifact_directory"]
    proof = json.loads(lock.read_text())
    assert proof["branches"] == list(stacking.V3_BRANCHES) and not proof["test_used_for_fitting_or_selection"]
    assert len(proof["base_fit_evidence"]) == 25 and proof["feature_order"] == list(stacking.V3_FEATURES)
    scores = pd.read_parquet(artifacts / "test_predictions.parquet")
    assert len(scores) == manifest.split.eq("test").sum()
    metrics = calibration_metrics(scores.true_label.to_numpy(), scores.ensemble_probability.to_numpy(), threshold=proof["threshold"])
    assert result["metrics"]["safe_stacking_v3/test"] == metrics
    assert result["routing"]["threshold"] == proof["threshold"] and result["routing"]["fn_total"] == metrics["confusion_matrix"][1][0]
    assert len(pd.read_csv(directory / "cv_fold_metrics.csv")) == 25 and len(pd.read_csv(directory / "model_comparison.csv")) == 18
    assert len(pd.read_csv(artifacts / "measured_obfuscation.csv")) == len(frame)
    for path in artifacts.glob("fold_*/ft_transformer/scaler.json"):
        scaler = json.loads(path.read_text()); assert scaler["fit_scope"] == "train_fitting_fold_only" and scaler["fit_rows"] < manifest.split.eq("train").sum()
    assert all(sha(path) == digest for path, digest in before.items() if path.name != "research_log.md")
    assert (root / "reports/research_log.md").read_bytes().startswith(old_log)
    with pytest.raises(ValueError, match="directory exists"):
        runner.run_safe_stacking_v3(root, config, execute=True, run_id="full")


def test_foreign_pdf_cohort_blocks_measurements_fit_and_test_and_logs_na(sources, monkeypatch):
    root, config, manifest, _ = sources
    path = root / config["inputs"]["source_manifest"]["path"]
    rows = pd.read_csv(path).iloc[:5].copy()
    rows.sample_id = [f"foreign:{i}" for i in range(5)]
    rows.to_csv(path, index=False)
    config["inputs"]["source_manifest"]["sha256"] = sha(path)
    monkeypatch.setattr(runner, "measure_pdf_obfuscation", lambda *a, **kw: pytest.fail("Foreign cohort reached byte measurement"))
    monkeypatch.setattr(runner, "fit_v3_fold", lambda *a, **kw: pytest.fail("Foreign cohort reached training"))
    result = runner.run_safe_stacking_v3(root, config, execute=True, run_id="foreign")
    assert result["status"] == "blocked_missing_pdf_source" and result["pdf_readiness"]["matched_ids"] == 0
    assert result["pdf_readiness"]["missing_source_ids"] == len(manifest)
    assert result["completed_base_fits"] == result["test_evaluation_count"] == 0 and result["metrics"] == {}
    assert "no proxy" in result["error"]["message"]
    directory = root / "reports/experiments/safe_stacking_v3/foreign"
    assert not (directory / "validation_lock.json").exists()
    assert pd.read_csv(directory / "model_comparison.csv").accuracy.isna().all()
    assert "safe stacking v3 execute / blocked_missing_pdf_source" in (root / "reports/research_log.md").read_text()


def test_dry_run_and_dirty_official_never_read_raw_pdf_bytes(sources, monkeypatch):
    root, config, _, _ = sources
    monkeypatch.setattr(runner, "measure_pdf_obfuscation", lambda *a, **kw: pytest.fail("Unexpected raw PDF read"))
    monkeypatch.setattr(runner, "fit_v3_fold", lambda *a, **kw: pytest.fail("Unexpected training"))
    result = runner.run_safe_stacking_v3(root, config, run_id="preflight")
    assert result["status"] == "dry_run_completed" and result["metrics"] == {} and result["test_evaluation_count"] == 0
    monkeypatch.setattr(runner, "repository_git_state", lambda root: {"status": "dirty"})
    with pytest.raises(ValueError, match="clean committed worktree"):
        runner.run_safe_stacking_v3(root, config, execute=True, run_id="dirty")
    assert "execute / failed" in (root / "reports/research_log.md").read_text()


def test_modified_raw_pdf_hash_fails_closed_and_preserves_partial_evidence(sources):
    root, config, manifest, _ = sources
    path = root / config["inputs"]["source_manifest"]["path"]
    source = pd.read_csv(path).set_index("sample_id")
    identifier = manifest.loc[manifest.split.eq("train"), "sample_id"].iloc[0]
    raw = root / source.loc[identifier, "pdf_relative_path"]
    raw.write_bytes(b"%PDF-1.4\n% altered benign fixture\n%%EOF\n")
    with pytest.raises(ValueError, match="SHA-256"):
        runner.run_safe_stacking_v3(root, config, execute=True, run_id="changed_pdf")
    report = json.loads((root / "reports/experiments/safe_stacking_v3/changed_pdf/run_summary.json").read_text())
    assert report["status"] == "failed" and report["test_evaluation_count"] == 0 and report["completed_base_fits"] == 0


def test_known_file_duplicates_cannot_cross_protocol_g_partitions(sources):
    root, config, manifest, _ = sources
    path = root / config["inputs"]["source_manifest"]["path"]
    rows = pd.read_csv(path).set_index("sample_id")
    train = manifest.loc[manifest.split.eq("train") & manifest.Label.eq(1)].iloc[0].sample_id
    test = manifest.loc[manifest.split.eq("test") & manifest.Label.eq(1)].iloc[0].sample_id
    rows.loc[test, "pdf_sha256"] = rows.loc[train, "pdf_sha256"]
    rows.reset_index().to_csv(path, index=False)
    config["inputs"]["source_manifest"]["sha256"] = sha(path)
    with pytest.raises(ValueError, match="duplicate PDF hash crosses"):
        runner.run_safe_stacking_v3(root, config, run_id="duplicate")


def test_test_pdf_hash_failure_occurs_only_after_lock_and_preserves_validation(sources):
    root, config, manifest, _ = sources
    rows = pd.read_csv(root / config["inputs"]["source_manifest"]["path"]).set_index("sample_id")
    identifier = manifest.loc[manifest.split.eq("test"), "sample_id"].iloc[0]
    (root / rows.loc[identifier, "pdf_relative_path"]).write_bytes(b"%PDF-1.4\n% modified benign test fixture\n%%EOF\n")
    with pytest.raises(ValueError, match="SHA-256"):
        runner.run_safe_stacking_v3(root, config, execute=True, run_id="test_changed")
    directory = root / "reports/experiments/safe_stacking_v3/test_changed"
    report = json.loads((directory / "run_summary.json").read_text())
    assert (directory / "validation_lock.json").exists() and report["status"] == "failed"
    assert report["completed_base_fits"] == 25 and report["test_evaluation_count"] == 0
    assert "safe_stacking_v3/validation_threshold_selection" in report["metrics"]
    assert not any(key.endswith("/test") for key in report["metrics"])
    assert "safe stacking v3 execute / failed" in (root / "reports/research_log.md").read_text()


def test_interrupted_training_keeps_partial_measurements_and_log(sources, monkeypatch):
    root, config, _, _ = sources
    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt("Synthetic interruption")
    monkeypatch.setattr(runner, "fit_v3_fold", interrupt)
    with pytest.raises(KeyboardInterrupt):
        runner.run_safe_stacking_v3(root, config, execute=True, run_id="interrupted")
    report = json.loads((root / "reports/experiments/safe_stacking_v3/interrupted/run_summary.json").read_text())
    assert report["status"] == "interrupted" and report["completed_base_fits"] == 0 and report["test_evaluation_count"] == 0
    assert (root / report["artifact_directory"] / "measured_obfuscation.csv").is_file()
    assert "execute / interrupted" in (root / "reports/research_log.md").read_text()


@pytest.mark.parametrize("case", ["folds", "seed", "proxy_only", "removed_branch", "input", "tree_cap", "FT_cap", "unsafe_catboost", "bad_c", "bad_rate"])
def test_unsafe_or_incomplete_configuration_is_rejected_before_run(sources, case):
    root, config, _, _ = sources
    if case == "folds":config["folds"] = 10
    elif case == "seed":config["seed"] = 43
    elif case == "proxy_only":del config["inputs"]["source_manifest"]
    elif case == "removed_branch":del config["models"]["catboost"]
    elif case == "input":config["inputs"]["dataset"]["path"] = "data/processed/../../escape.csv"
    elif case == "tree_cap":config["models"]["random_forest"]["n_estimators"] = 100_000
    elif case == "FT_cap":config["models"]["ft_transformer"]["input_features"] = 38
    elif case == "unsafe_catboost":config["models"]["catboost"]["allow_writing_files"] = True
    elif case == "bad_c":config["meta_regularization_cs"] = [float("nan")]
    else:config["training"]["learning_rate"] = 0
    with pytest.raises(ValueError):runner.run_safe_stacking_v3(root, config)
    assert not (root / "reports/experiments/safe_stacking_v3").exists()


def test_cli_exit_two_explains_real_pdf_missing_without_fabricated_counts(sources, monkeypatch, capsys):
    root, config, _, _ = sources
    path = root / config["inputs"]["source_manifest"]["path"]
    rows = pd.read_csv(path).iloc[:5].copy()
    rows.sample_id = [f"foreign:{i}" for i in range(5)]
    rows.to_csv(path, index=False)
    config["inputs"]["source_manifest"]["sha256"] = sha(path)
    c = root / "configs/safe_stacking_v3.yaml"; c.parent.mkdir(); c.write_text(yaml.safe_dump(config, sort_keys=False))
    main = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/06_optimize_and_stack_v3_safe.py"))["main"]
    monkeypatch.setitem(main.__globals__, "ROOT", root)
    assert main(["--config", str(c), "--execute", "--run-id", "cli"]) == 2
    text = capsys.readouterr().out
    assert "blocked_missing_pdf_source" in text and "base fits: 0; test evaluations: 0" in text and "metrics N/A" in text
