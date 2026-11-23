"""Unit tests for diverse publisher OOD + hard-benign track partitioning and scoring."""

from __future__ import annotations

from scripts.lab.benign_ood_intake import URLS, candidate_rows
from scripts.lab.score_diverse_benign_ood import IDX, active_feature_slices, partition_by_track


def test_diverse_urls_and_track_partitioning() -> None:
    docs = [
        {"source": "arxiv", "id": "arxiv-101", "url": "https://arxiv.org/pdf/2401.12345", "status": 200},
        {"source": "nist", "id": "nist-001", "url": "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf", "status": 200},
        {"source": "nasa", "id": "nasa-450", "url": "https://ntrs.nasa.gov/api/citations/20140009575/downloads/20140009575.pdf", "status": 200},
        {"source": "irs", "id": "irs-101", "url": "https://www.irs.gov/pub/irs-pdf/f1065.pdf", "status": 200},
        {"source": "verapdf", "id": "verapdf-001", "url": "https://raw.githubusercontent.com/veraPDF/veraPDF-corpus/staging/ISO%2032000-1/sample.pdf", "status": 200},
        {"source": "pdfjs", "id": "pdfjs-001", "url": "https://raw.githubusercontent.com/mozilla/pdf.js/master/test/pdfs/issue123.pdf", "status": 200},
    ]
    rows = candidate_rows({"schema_version": 1, "documents": docs})
    assert len(rows) == 6
    assert set(URLS) >= {"arxiv", "nist", "nasa", "irs", "verapdf", "pdfjs"}

    entries = [{"id": d["id"], "source": d["source"], "sha256": f"{i:064x}"} for i, d in enumerate(docs)]
    export_rows = [{"id": d["id"], "source": d["source"], "sha256": f"{i:064x}"} for i, d in enumerate(docs)]
    tracks = partition_by_track(entries, export_rows)
    assert len(tracks["prospective_diverse_publishers"][0]) == 4
    assert len(tracks["hard_benign_stress"][0]) == 2


def test_active_feature_slices_tracks_js_acroform_and_degraded() -> None:
    vec_js = [0.0] * len(IDX)
    vec_js[IDX["lexical_JS"]] = 2.0
    vec_js[IDX["lexical_AcroForm"]] = 1.0
    export_rows = [
        {"id": "pdfjs-001", "features": vec_js},
        {"id": "verapdf-001", "features": [0.0] * len(IDX)},
    ]
    eval_rows = [
        {"id": "pdfjs-001", "status": "bounded_complete", "score_status": "scored", "probability": 0.12},
        {"id": "verapdf-001", "status": "partial", "score_status": "scored", "probability": 0.01},
    ]
    slices = active_feature_slices(export_rows, eval_rows, prospective_thr=0.08)
    assert slices["has_js"]["count"] == 1
    assert slices["has_js"]["fp_prospective"] == 1
    assert slices["has_acroform"]["count"] == 1
    assert slices["degraded_status"]["count"] == 1
    assert slices["degraded_status"]["fp_prospective"] == 0


def test_v32_disjointness_and_subset_b_partitioning() -> None:
    from scripts.lab.prepare_v32_benign_cohort import verify_subset_disjointness
    from scripts.lab.score_v32_prospective import IDX as P_IDX, compute_hard_benign_slices, partition_subset_b

    rows = [
        {"id": "pdfjs-100", "source": "pdfjs", "url": "https://raw.githubusercontent.com/mozilla/pdf.js/master/test/pdfs/a.pdf"},
        {"id": "arxiv-300", "source": "arxiv", "url": "https://arxiv.org/pdf/2401.00001"},
        {"id": "pdfjs-350", "source": "pdfjs", "url": "https://raw.githubusercontent.com/mozilla/pdf.js/master/test/pdfs/b.pdf"},
    ]
    verify_subset_disjointness(rows, {"https://arxiv.org/pdf/9999.99999"})

    entries = [{"id": r["id"], "source": r["source"], "sha256": f"{i:064x}"} for i, r in enumerate(rows)]
    exp_rows = [{"id": r["id"], "source": r["source"], "sha256": f"{i:064x}", "features": [0.0] * len(P_IDX)} for i, r in enumerate(rows)]
    exp_rows[2]["features"][P_IDX["raw_size_bytes"]] = 1500.0
    assigns = {
        "pdfjs-100": "train_val_benign_supplement",
        "arxiv-300": "prospective_diverse_publishers_v2",
        "pdfjs-350": "prospective_hard_benign_v2",
    }
    part = partition_subset_b(entries, exp_rows, assigns)
    assert [r["id"] for r in part["prospective_diverse_publishers_v2"][0]] == ["arxiv-300"]
    assert [r["id"] for r in part["prospective_hard_benign_v2"][0]] == ["pdfjs-350"]

    eval_rows = [{"id": "pdfjs-350", "status": "bounded_complete", "score_status": "scored", "probability": 0.62}]
    slices = compute_hard_benign_slices([exp_rows[2]], eval_rows, prospective_thr=0.05)
    assert slices["small_le_10kb"]["count"] == 1
    assert slices["small_le_10kb"]["fp_prospective"] == 1
    assert slices["small_le_10kb"]["fp_050"] == 1


def test_build_supplement_excludes_protected_tlsh_and_never_assigns_test(monkeypatch) -> None:
    from pathlib import Path
    from scripts.lab import build_v32_benign_supplement as bvs
    from scripts.lab.train_eval_transgraph_v3 import REGIME_B_INDICES
    from malpdf.features.contract_v3 import FEATURES

    def make_row(idx: int, src: str):
        vec = [0.0] * len(FEATURES)
        vec[REGIME_B_INDICES[0]] = float(idx)
        return {
            "id": f"{src}-{idx:03d}",
            "sha256": f"{idx:064x}",
            "tlsh": "T1" + f"{idx % 10}" * 70,
            "source": src,
            "status": "bounded_complete",
            "cohort": "test",
            "features": vec,
            "graph": [[[0.0] * 23, [0.0] * 23], [0, 1], [0], [1], [0]],
        }

    cands = [make_row(i, "pdfjs" if i % 2 == 0 else "arxiv") for i in range(1, 25)]
    monkeypatch.setattr(bvs, "nearest_distances", lambda _exec, _refs, queries: [15 if q.endswith("1" * 10) else 80 for q in queries])
    monkeypatch.setattr(bvs, "native", lambda _exec, _cmd, _hdr, hashes: list(range(len(hashes))))

    rows, audit = bvs.build_supplement(
        candidates=cands,
        test_refs={"f" * 64: "T1" + "1" * 70},
        subset_b_refs={"e" * 64: "T1" + "9" * 70},
        existing_shas={cands[1]["sha256"]},
        distance_exec=Path("dummy_dist"),
        component_exec=Path("dummy_comp"),
        seed=42,
    )
    assert audit["retained"] == len(rows) == 20
    assert {r["role"] for r in rows} <= {"train", "val_select", "val_calib"}
    assert "test_internal" not in {r["role"] for r in rows}
    assert audit["min_tlsh_vs_test_internal"] == 80
