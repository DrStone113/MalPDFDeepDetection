"""Unit tests for Regime B/A slicing, debiased weighting, format invariance, and calibration."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from types import SimpleNamespace

import numpy as np
import pytest

from scripts.lab import train_eval_transgraph_v3 as training
from scripts.lab.train_eval_transgraph_v3 import (
    AST_INDICES,
    AST_NAMES,
    IDX,
    REGIME_A_INDICES,
    REGIME_A_NAMES,
    REGIME_B_INDICES,
    REGIME_B_NAMES,
    apply_stress_transform,
    apply_temperature,
    compute_debiased_weights,
    fit_constrained_stacker,
    fit_temperature,
    perturb_raw_format,
    select_thresholds,
    simulate_objstm_tabular_mask,
    slice_regime_inputs,
)


def test_aggregate_seed_runs_keeps_legacy_metrics_and_reports_seed_stability() -> None:
    model_names = ("v3_tab_graph_supervised", "v3_tab_graph_ssl_inv", "xgboost_v3", "lightgbm_v3", "hybrid_stacking_v3")
    seed_reports = []
    expected_rows = []
    stress_keys = ("mean_abs_delta_p", "max_abs_delta_p", "mean_signed_delta_p", "pos_rate_before", "pos_rate_after")
    for seed, value, alerts in ((42, 0.25, 0), (43, 0.75, 2)):
        model = {
            "test_internal": {"slices": {
                "all": {"pr_auc": 0.75, "roc_auc": 1.0, "ece": 1 - value, "thr_f1_macro": {"f1_macro": value}},
                "bounded_complete": {
                    "pr_auc": 0.5, "roc_auc": 0.75, "recall_at_1pct_fpr": value,
                    "ece": value / 2, "thr_f1_macro": {"f1_macro": value / 2},
                },
            }},
            "reviewed_controls": {"alerts_at_thr_f1": alerts},
            "temperature": 1 + value,
            "mean_modality_weights_test": [value, 1 - value, 0.0],
        }
        seed_reports.append({
            "seed": seed,
            "models": dict.fromkeys(model_names, model),
            "reload_max_abs_logit_diff": {"v3_tab_graph_ssl_inv": 0.0} if seed == 42 else {},
            "stress_tests": {
                name: {"count": 12, "models": {"v3_tab_graph_ssl_inv": dict.fromkeys(stress_keys, value)}}
                for name in ("benign_linearization", "malicious_padding_dilution")
            },
        })
        expected_rows.append({
            "seed": seed, "temperature": 1 + value, "mean_branch_weights": [value, 1 - value, 0.0],
            "reload_max_abs_logit_diff": 0.0 if seed == 42 else None,
            "test_all_pr_auc": 0.75, "test_all_roc_auc": 1.0, "test_all_f1_macro": value,
            "test_all_ece": 1 - value, "test_bc_pr_auc": 0.5, "test_bc_roc_auc": 0.75,
            "test_bc_f1_macro": value / 2, "test_bc_ece": value / 2, "test_bc_recall_at_1pct_fpr": value,
            "reviewed_controls_alerts_thr_f1": alerts,
        })

    result = training._aggregate_seed_runs(seed_reports)
    assert result["seeds"] == [42, 43]
    assert result["per_seed"] == expected_rows
    for model_name in model_names:
        model = result["models"][model_name]
        assert model["test_all_pr_auc"] == {"mean": 0.75, "std": 0.0}
        assert model["test_all_roc_auc"] == {"mean": 1.0, "std": 0.0}
        assert model["test_bc_pr_auc"] == {"mean": 0.5, "std": 0.0}
        assert model["test_bc_roc_auc"] == {"mean": 0.75, "std": 0.0}
        assert model["test_bc_recall_at_1pct_fpr"] == {"mean": 0.5, "std": 0.25}
        assert model["reviewed_controls_alerts_thr_f1"] == [0, 2]
        for metric in ("test_all_f1_macro", "test_all_ece"):
            assert model[metric] == {"mean": 0.5, "std": 0.25}
        for metric in ("test_bc_f1_macro", "test_bc_ece"):
            assert model[metric] == {"mean": 0.25, "std": 0.125}
    stress = result["models"]["v3_tab_graph_ssl_inv"]["stress_tests"]
    assert set(stress) == {"benign_linearization", "malicious_padding_dilution"}
    for case in stress.values():
        assert case == {"count": 12, **dict.fromkeys(stress_keys, {"mean": 0.5, "std": 0.25})}


@pytest.mark.parametrize("save_all_seeds", [False, True])
def test_main_saves_secondary_seed_artifacts_only_when_requested(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, save_all_seeds: bool,
) -> None:
    pooled = tmp_path / "data/processed/pooled_bulk"
    provenance = pooled / "offline_provenance"
    provenance.mkdir(parents=True)
    split = provenance / "locked_split.jsonl"
    for path in (
        split, pooled / "pooled.jsonl.gz", provenance / "tabular_v3.jsonl.gz",
        provenance / "training_labels_20261122T055618Z.jsonl", provenance / "reviewed_controls_v3.json",
    ):
        path.touch()
    corpus = SimpleNamespace(shas=("a",), roles=np.array(["train"]), labels=np.array([0]), raw_73=np.zeros((1, 73)))
    monkeypatch.setattr(training, "REPO", tmp_path)
    monkeypatch.setattr(training.subprocess, "check_output", lambda *args, **kwargs: "test_revision")
    monkeypatch.setattr(training, "load_pooled_corpus", lambda **kwargs: corpus)
    monkeypatch.setattr(training, "_load_controls", lambda path: ([], None, [], None))
    monkeypatch.setattr(training, "_aggregate_seed_runs", lambda runs: {"seeds": [run["seed"] for run in runs]})

    def save_run(regime, *args, seed, save_dir, **kwargs):
        if save_dir is not None:
            save_dir.mkdir()
            (save_dir / "v3_tab_graph_ssl_inv.npz").write_text(str(seed), encoding="utf-8")
        return {"regime": regime, "seed": seed}

    monkeypatch.setattr(training, "run_regime", save_run)
    argv = ["train_eval_transgraph_v3.py", "--split-view", str(split), "--seeds", "42", "43"]
    monkeypatch.setattr(sys, "argv", argv + (["--save-all-seeds"] if save_all_seeds else []))
    training.main()

    (artifacts,) = (pooled / "transgraph_v3").iterdir()
    assert (artifacts / "regime_b/v3_tab_graph_ssl_inv.npz").read_text(encoding="utf-8") == "42"
    assert (artifacts / "regime_a/v3_tab_graph_ssl_inv.npz").read_text(encoding="utf-8") == "42"
    secondary = artifacts / "regime_b_seed43/v3_tab_graph_ssl_inv.npz"
    assert secondary.is_file() == save_all_seeds
    if save_all_seeds:
        assert secondary.read_text(encoding="utf-8") == "43"
        (report,) = (tmp_path / "reports/experiments/transgraph_v3").iterdir()
        metrics = json.loads((report / "metrics.json").read_text(encoding="utf-8"))
        assert [run["seed"] for run in metrics["seed_runs_b"]] == [42, 43]


def test_regime_feature_contract_sizes_and_zero_nan_guard() -> None:
    assert len(REGIME_B_NAMES) == 29
    assert len(REGIME_A_NAMES) == 46
    assert len(AST_NAMES) == 26
    assert set(REGIME_B_NAMES).issubset(set(REGIME_A_NAMES))
    assert not (set(REGIME_A_NAMES) & set(AST_NAMES))
    assert "lexical_AcroForm" not in REGIME_A_NAMES and "lexical_AcroForm" not in AST_NAMES
    assert len(REGIME_A_NAMES) + len(AST_NAMES) + 1 == 73

    scaled = np.zeros((4, 73), dtype=np.float32)
    miss = np.ones((4, 73), dtype=bool)
    miss[:, REGIME_B_INDICES] = False
    tx_b, tm_b, ax_b, am_b = slice_regime_inputs(scaled, miss, "regime_b")
    assert tx_b.shape == (4, 29)
    assert tm_b is None
    assert ax_b.shape == (4, 26)
    assert am_b.shape == (4, 26)

    miss_bad = miss.copy()
    miss_bad[0, REGIME_B_INDICES[0]] = True
    with pytest.raises(ValueError, match="missing values"):
        slice_regime_inputs(scaled, miss_bad, "regime_b")

    tx_a, tm_a, _, _ = slice_regime_inputs(scaled, miss, "regime_a")
    assert tx_a.shape == (4, 46)
    assert tm_a is not None and tm_a.shape == (4, 46)


def test_compute_debiased_weights_class_and_status_balance() -> None:
    labels = np.array([0] * 100 + [0] * 2 + [1] * 30 + [1] * 120, dtype=np.int64)
    is_bc = np.array([True] * 100 + [False] * 2 + [True] * 30 + [False] * 120, dtype=bool)
    w = compute_debiased_weights(labels, is_bc)

    assert np.isclose(w[labels == 0].sum(), len(labels) / 2.0, atol=1e-4)
    assert np.isclose(w[labels == 1].sum(), len(labels) / 2.0, atol=1e-4)
    assert np.isclose(w[(labels == 1) & is_bc].sum(), w[(labels == 1) & (~is_bc)].sum(), atol=1e-4)
    ratio_deg_ben = float(w[(labels == 0) & (~is_bc)][0] / w[(labels == 0) & is_bc][0])
    assert ratio_deg_ben <= 5.0 + 1e-6


def test_perturb_and_stress_preserve_triggers_and_derived_ratios() -> None:
    rng = np.random.default_rng(123)
    raw = np.zeros((20, 73), dtype=np.float32)
    raw[:, IDX["lexical_JS"]] = 2.0
    raw[:, IDX["lexical_JavaScript"]] = 1.0
    raw[:, IDX["lexical_OpenAction"]] = 1.0
    raw[:, IDX["lexical_AA"]] = 1.0
    raw[:, IDX["lexical_obj"]] = 50.0
    raw[:, IDX["lexical_endobj"]] = 50.0
    raw[:, IDX["lexical_stream"]] = 10.0
    raw[:, IDX["lexical_endstream"]] = 10.0
    raw[:, IDX["raw_size_bytes"]] = 10000.0
    raw[:, IDX["raw_entropy"]] = 6.5

    can_lin = np.array([True] * 10 + [False] * 10, dtype=bool)
    pert = perturb_raw_format(raw, can_lin, rng)
    for trigger in ("lexical_JS", "lexical_JavaScript", "lexical_OpenAction", "lexical_AA"):
        assert np.array_equal(pert[:, IDX[trigger]], raw[:, IDX[trigger]])
    # Malicious rows (can_lin=False) never receive linearization trailer increments.
    assert np.array_equal(pert[10:, IDX["lexical_trailer"]], raw[10:, IDX["lexical_trailer"]])
    assert np.allclose(pert[:, IDX["stream_per_obj"]], pert[:, IDX["lexical_stream"]] / pert[:, IDX["lexical_obj"]], atol=1e-6)
    assert np.allclose(pert[:, IDX["js_per_obj"]], 3.0 / pert[:, IDX["lexical_obj"]], atol=1e-6)

    stressed = apply_stress_transform(raw[:4], "linearize")
    assert np.all(stressed[:, IDX["lexical_trailer"]] == 1.0)
    assert np.all(stressed[:, IDX["lexical_obj"]] == 52.0)
    assert np.all(stressed[:, IDX["obj_endobj_diff"]] == 0.0)

    padded = perturb_raw_format(raw, np.ones(20, dtype=bool), rng, enable_padding=True)
    for trigger in ("lexical_JS", "lexical_JavaScript", "lexical_OpenAction", "lexical_AA"):
        assert np.array_equal(padded[:, IDX[trigger]], raw[:, IDX[trigger]])
    assert np.allclose(padded[:, IDX["js_per_obj"]], 3.0 / padded[:, IDX["lexical_obj"]], atol=1e-6)
    assert np.all(padded[:, IDX["obj_endobj_diff"]] == 0.0)

    raw_multi = np.repeat(raw[:1], 100, axis=0)
    padded_multi = perturb_raw_format(raw_multi, np.ones(100, dtype=bool), np.random.default_rng(42), enable_padding=True)
    assert padded_multi[:, IDX["lexical_obj"]].max() > 300.0
    assert padded_multi[:, IDX["raw_size_bytes"]].max() > 500_000.0
    for trigger in ("lexical_JS", "lexical_JavaScript", "lexical_OpenAction", "lexical_AA"):
        assert np.array_equal(padded_multi[:, IDX[trigger]], raw_multi[:, IDX[trigger]])
    assert np.allclose(padded_multi[:, IDX["js_per_obj"]], 3.0 / padded_multi[:, IDX["lexical_obj"]], atol=1e-6)
    assert np.all(padded_multi[:, IDX["obj_endobj_diff"]] == 0.0)

    has_graph = np.array([True] * 10 + [False] * 10, dtype=bool)
    masked_ostm = simulate_objstm_tabular_mask(raw, has_graph, rng, prob=1.0)
    assert np.all(masked_ostm[:10, IDX["lexical_ObjStm"]] >= 1.0)
    assert np.all(masked_ostm[:10, IDX["lexical_JS"]] == 0.0)
    assert np.all(masked_ostm[:10, IDX["lexical_OpenAction"]] == 0.0)
    assert np.array_equal(masked_ostm[10:], raw[10:])


def test_temperature_and_stacker_invariants() -> None:
    rng = np.random.default_rng(7)
    n = 400
    groups = np.repeat(np.arange(40), 10)
    base_signal = rng.normal(0.0, 1.5, size=n)
    probs_true = 1.0 / (1.0 + np.exp(-base_signal))
    labels = rng.binomial(1, probs_true).astype(np.int64)
    overconfident = base_signal * 5.0
    temp = fit_temperature(overconfident, labels)
    assert 0.1 <= temp <= 10.0
    assert temp > 1.5
    p_cal = apply_temperature(overconfident, temp)
    assert np.all((p_cal > 0.0) & (p_cal < 1.0))

    z_mat = np.column_stack((base_signal, base_signal * 0.8 + rng.normal(0.0, 0.2, size=n), -base_signal * 0.1))
    fitted = fit_constrained_stacker(z_mat, labels, groups, seed=42)
    w = fitted["weights"]
    assert w.shape == (3,)
    assert np.all(w >= 0.0)
    assert np.isclose(w.sum(), 1.0, atol=1e-6)
    assert w[2] < 0.1
    assert np.all((fitted["oof_probs"] >= 0.0) & (fitted["oof_probs"] <= 1.0))

    thrs = select_thresholds(labels, fitted["oof_probs"], np.ones(n, dtype=bool))
    assert 0.0 < thrs["thr_f1_macro"] < 1.0
    assert 0.0 < thrs["thr_fpr1"] < 1.0


def test_reviewed_controls_v3_have_zero_regime_b_missingness() -> None:
    controls_path = Path("data/processed/pooled_bulk/offline_provenance/reviewed_controls_v3.json")
    if not controls_path.exists():
        pytest.skip("reviewed_controls_v3.json not staged")
    data = json.loads(controls_path.read_text(encoding="utf-8"))
    for cname in ("original", "repacked", "title_extended", "linearized"):
        vec = data["controls"][cname]["vector_v3"]
        for i in REGIME_B_INDICES:
            assert vec[i] is not None
        assert len(AST_INDICES) == 26
        assert REGIME_A_INDICES.shape == (46,)


def test_source_aware_benign_supplement_weights_and_test_guard(tmp_path: Path) -> None:
    labels = np.array([0] * 60 + [0] * 10 + [0] * 10 + [1] * 80, dtype=np.int64)
    is_bc = np.ones(len(labels), dtype=bool)
    label_sources = np.asarray(
        ["vapd_v5_d1_benign"] * 60
        + ["verified_benign_supplement:arxiv"] * 10
        + ["verified_benign_supplement:pdfjs"] * 10
        + ["vapd_v5_d1_malicious"] * 80,
        dtype=object,
    )
    w = compute_debiased_weights(labels, is_bc, label_sources)
    assert np.isclose(w[labels == 0].sum(), len(labels) / 2.0, atol=1e-4)
    assert np.isclose(w[labels == 1].sum(), len(labels) / 2.0, atol=1e-4)
    neg_tot = float(w[labels == 0].sum())
    assert np.isclose(w[:60].sum() / neg_tot, 0.60, atol=1e-4)
    assert np.isclose(w[60:70].sum() / neg_tot, 0.20, atol=1e-4)
    assert np.isclose(w[70:80].sum() / neg_tot, 0.20, atol=1e-4)

    import gzip
    from malpdf.features.contract_v3 import FEATURES
    from scripts.lab.train_eval_transgraph_v3 import load_pooled_corpus

    pool = tmp_path / "pool.jsonl.gz"
    tab = tmp_path / "tab.jsonl.gz"
    lbl = tmp_path / "lbl.jsonl"
    spl = tmp_path / "spl.jsonl"
    supp = tmp_path / "supp.json"
    with gzip.open(pool, "wt", encoding="utf-8") as f:
        f.write(json.dumps({"schema": 1}) + "\n")
    with gzip.open(tab, "wt", encoding="ascii") as f:
        f.write(json.dumps({"features": list(FEATURES)}) + "\n")
    lbl.write_text(json.dumps({"schema": 1}) + "\n", encoding="ascii")
    spl.write_text(json.dumps({"schema": 1}) + "\n", encoding="ascii")
    supp.write_text(
        json.dumps({"rows": [{"sha256": "a" * 64, "role": "test_internal", "source": "pdfjs", "status": "bounded_complete", "group": "g0", "features": [0.0] * len(FEATURES), "graph": None}]}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="forbidden_supplement_role:test_internal"):
        load_pooled_corpus(pool_path=pool, tabular_path=tab, label_view_path=lbl, split_view_path=spl, benign_supplement_path=supp)


def test_calibrate_load_validation_supports_benign_supplement_and_guards(tmp_path: Path) -> None:
    import gzip
    from malpdf.features.contract_v3 import FEATURES
    from scripts.lab.calibrate_regime_b_v3 import load_validation

    base_ben, base_mal, supp_val, supp_tr = "0" * 64, "1" * 64, "2" * 64, "3" * 64
    empty_g = [[[0.0] * 23], [0], [], [], []]
    pool = tmp_path / "pool.jsonl.gz"
    tab = tmp_path / "tab.jsonl.gz"
    lbl = tmp_path / "lbl.jsonl"
    spl = tmp_path / "spl.jsonl"
    supp = tmp_path / "supp.json"
    with gzip.open(pool, "wt", encoding="ascii") as f:
        f.write(json.dumps({"schema": 1}) + "\n")
        for s in (base_ben, base_mal):
            f.write(json.dumps([s, 0, 0, 0, 0, empty_g]) + "\n")
    with gzip.open(tab, "wt", encoding="ascii") as f:
        f.write(json.dumps({"features": list(FEATURES)}) + "\n")
        for s in (base_ben, base_mal):
            f.write(json.dumps([s, [0.0] * len(FEATURES)]) + "\n")
    lbl.write_text(
        json.dumps({"schema": 1}) + "\n" + json.dumps({"sha256": base_ben, "label": 0}) + "\n" + json.dumps({"sha256": base_mal, "label": 1}) + "\n",
        encoding="ascii",
    )
    spl.write_text(
        json.dumps({"schema": 1}) + "\n" + json.dumps({"sha256": base_ben, "role": "val_calib"}) + "\n" + json.dumps({"sha256": base_mal, "role": "val_calib"}) + "\n",
        encoding="ascii",
    )

    supp.write_text(json.dumps({"rows": [
        {"sha256": supp_tr, "role": "train", "features": [1.0] * len(FEATURES), "graph": empty_g},
        {"sha256": supp_val, "role": "val_calib", "features": [2.0] * len(FEATURES), "graph": empty_g},
    ]}), encoding="utf-8")
    y, feats, graphs = load_validation(pool, tab, lbl, spl, benign_supplement=supp)
    assert y == [0, 1, 0]
    assert len(feats) == len(graphs) == 3
    assert feats[2][0] == 2.0

    supp.write_text(json.dumps({"rows": [
        {"sha256": supp_val, "role": "test_internal", "features": [0.0] * len(FEATURES), "graph": empty_g},
    ]}), encoding="utf-8")
    with pytest.raises(ValueError, match="forbidden_supplement_role:test_internal"):
        load_validation(pool, tab, lbl, spl, benign_supplement=supp)

    supp.write_text(json.dumps({"rows": [
        {"sha256": base_ben, "role": "val_calib", "features": [0.0] * len(FEATURES), "graph": empty_g},
    ]}), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate_calibration_identity"):
        load_validation(pool, tab, lbl, spl, benign_supplement=supp)
