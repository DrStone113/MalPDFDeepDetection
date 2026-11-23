"""Unit tests for LOSO zero-shot OOD malicious evaluation and TLSH leakage screening."""

from __future__ import annotations

from pathlib import Path
import gzip
import json

import numpy as np
import pytest

from scripts.lab.eval_loso_malicious_ood import (
    _load_all_pool_corpus,
    compute_ood_cohort_metrics,
    screen_partition_against_holdouts,
)


def test_screen_partition_against_holdouts_blocks_sha_tlsh_and_exact_vector() -> None:
    cand_shas = ["keep_sha", "dup_sha", "near_tlsh_sha", "exact_vec_sha"]
    cand_tlsh = {
        "keep_sha": "T1AAAA",
        "dup_sha": "T1BBBB",
        "near_tlsh_sha": "T1CCCC",
        "exact_vec_sha": "T1DDDD",
    }
    cand_vkeys = {
        "keep_sha": b"vec_unique",
        "dup_sha": b"vec_other",
        "near_tlsh_sha": b"vec_other2",
        "exact_vec_sha": b"vec_shared",
    }
    holdout_shas = ["dup_sha", "hold_tlsh", "hold_vec"]
    holdout_tlsh = {"dup_sha": "T1BBBB", "hold_tlsh": "T1EEEE", "hold_vec": "T1FFFF"}
    holdout_vkeys = {"dup_sha": b"vec_h0", "hold_tlsh": b"vec_h1", "hold_vec": b"vec_shared"}

    def fake_distances(refs, queries):
        # Match near_tlsh_sha at distance 19 (<= 30), others far at 85.
        return [19 if q == "T1CCCC" else 85 for q in queries]

    res = screen_partition_against_holdouts(
        cand_shas, cand_tlsh, cand_vkeys, holdout_shas, holdout_tlsh, holdout_vkeys, fake_distances
    )
    assert res["retained_shas"] == ["keep_sha"]
    assert res["excluded_count"] == 3
    assert res["min_retained_tlsh"] == 85


def test_compute_ood_cohort_metrics_clusters_and_strata() -> None:
    # 4 samples in 2 clusters: cluster 0 has 3 copies (1 flagged, 2 missed); cluster 1 has 1 (flagged).
    probs = np.array([0.90, 0.01, 0.02, 0.80])
    is_bc = np.array([True, True, False, True])
    gp = np.array([True, True, True, True])
    clusters = [0, 0, 0, 3]
    out = compute_ood_cohort_metrics(probs, is_bc, gp, clusters, thr_primary=0.10, thr_secondary=0.50)

    assert out["count"] == 4
    assert out["cluster_count"] == 2
    at = out["at_locked_midpoint"]
    assert at["flagged"] == 2
    assert np.isclose(at["overall_recall"], 0.5)
    assert np.isclose(at["cluster_representative_recall"], 1.0)
    assert np.isclose(at["bounded_complete_recall"], 2.0 / 3.0)
    assert np.isclose(at["degraded_recall"], 0.0)


def test_loso_loads_benign_supplement_and_screens_tlsh(tmp_path: Path) -> None:
    from malpdf.features.contract_v3 import FEATURES
    from scripts.lab.train_eval_transgraph_v3 import SUPPLEMENT_PREFIX

    tr_sha, cal_sha, mal_sha = "a" * 64, "b" * 64, "c" * 64
    near_sha, dup_sha, clean_sha = "d" * 64, "e" * 64, "f" * 64
    g = [[[0.0] * 23], [0], [], [], []]

    pool = tmp_path / "pool.jsonl.gz"
    tab = tmp_path / "tab.jsonl.gz"
    lbl = tmp_path / "lbl.jsonl"
    spl = tmp_path / "spl.jsonl"
    supp = tmp_path / "supp.json"

    with gzip.open(pool, "wt", encoding="ascii") as f:
        f.write(json.dumps({"schema": 1}) + "\n")
        for s in (tr_sha, cal_sha, mal_sha):
            f.write(json.dumps([s, 0, 0, 0, 0, g]) + "\n")
    with gzip.open(tab, "wt", encoding="ascii") as f:
        f.write(json.dumps({"features": list(FEATURES)}) + "\n")
        for k, s in enumerate((tr_sha, cal_sha, mal_sha)):
            v = [float(k + 1)] + [0.0] * (len(FEATURES) - 1)
            f.write(json.dumps([s, v]) + "\n")
    lbl.write_text(
        json.dumps({"schema": 1}) + "\n"
        + json.dumps({"sha256": tr_sha, "label": 0, "label_source": "vapd_v5_d1_benign", "status": "bounded_complete"}) + "\n"
        + json.dumps({"sha256": cal_sha, "label": 0, "label_source": "vapd_v5_d1_benign", "status": "bounded_complete"}) + "\n"
        + json.dumps({"sha256": mal_sha, "label": 1, "label_source": "zenodo2017_exact_historical_consensus", "status": "bounded_complete"}) + "\n",
        encoding="ascii",
    )
    spl.write_text(
        json.dumps({"schema": 1}) + "\n"
        + json.dumps({"sha256": tr_sha, "role": "train", "group": "g0"}) + "\n"
        + json.dumps({"sha256": cal_sha, "role": "val_calib", "group": "g1"}) + "\n"
        + json.dumps({"sha256": mal_sha, "role": "holdout", "group": "g2"}) + "\n",
        encoding="ascii",
    )

    t_clean, t_near, t_dup = "T1" + "0" * 70, "T1" + "1" * 70, "T1" + "2" * 70
    t_b0, t_b1, t_hold = "T1" + "3" * 70, "T1" + "4" * 70, "T1" + "5" * 70

    supp.write_text(
        json.dumps({
            "rows": [
                {"sha256": clean_sha, "role": "val_calib", "source": "pdfjs", "status": "bounded_complete", "group": "sb0", "tlsh": t_clean, "features": [10.0] + [0.0] * (len(FEATURES) - 1), "graph": g},
                {"sha256": near_sha, "role": "train", "source": "verapdf", "status": "bounded_complete", "group": "sb1", "tlsh": t_near, "features": [11.0] + [0.0] * (len(FEATURES) - 1), "graph": g},
                {"sha256": dup_sha, "role": "train", "source": "arxiv", "status": "bounded_complete", "group": "sb2", "tlsh": t_dup, "features": [12.0] + [0.0] * (len(FEATURES) - 1), "graph": g},
            ]
        }),
        encoding="utf-8",
    )
    corpus, sha_to_row, raw_vecs, supp_fps = _load_all_pool_corpus(
        pool_path=pool, tabular_path=tab, label_view_path=lbl, split_view_path=spl, benign_supplement_path=supp
    )
    assert len(corpus.shas) == 6
    assert corpus.label_sources[sha_to_row[clean_sha]] == f"{SUPPLEMENT_PREFIX}pdfjs"
    assert supp_fps == {clean_sha: t_clean, near_sha: t_near, dup_sha: t_dup}

    fps = {tr_sha: t_b0, cal_sha: t_b1, mal_sha: t_hold, **supp_fps}
    vkeys = {s: f"v_{i}".encode("ascii") for i, s in enumerate(corpus.shas)}
    holdout_shas = [mal_sha, dup_sha]
    cand_cals = [corpus.shas[i] for i, r in enumerate(corpus.roles) if r == "val_calib" and str(corpus.label_sources[i]).startswith(("vapd_v5_d1_", SUPPLEMENT_PREFIX))]
    cand_trains = [corpus.shas[i] for i, r in enumerate(corpus.roles) if r == "train" and str(corpus.label_sources[i]) not in {"zenodo2017_exact_historical_consensus"}]
    assert set(cand_cals) == {cal_sha, clean_sha}

    res_cal = screen_partition_against_holdouts(cand_cals, fps, vkeys, holdout_shas, fps, vkeys, lambda _r, qs: [75 for _ in qs])
    assert res_cal["retained_shas"] == [cal_sha, clean_sha]

    res_tr = screen_partition_against_holdouts(
        cand_trains, fps, vkeys, holdout_shas, fps, vkeys, lambda _r, qs: [18 if q == t_near else 90 for q in qs]
    )
    assert res_tr["retained_shas"] == [tr_sha]
    assert res_tr["excluded_count"] == 2

    supp.write_text(
        json.dumps({"rows": [{"sha256": clean_sha, "role": "test_internal", "source": "pdfjs", "status": "bounded_complete", "group": "sb0", "tlsh": t_clean, "features": [0.0] * len(FEATURES), "graph": g}]}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="forbidden_supplement_role:test_internal"):
        _load_all_pool_corpus(pool_path=pool, tabular_path=tab, label_view_path=lbl, split_view_path=spl, benign_supplement_path=supp)
