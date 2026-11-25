from __future__ import annotations

import io
from pathlib import Path
import sys

import numpy as np
import pikepdf
import pymupdf as fitz
import torch

from malpdf.cdr.engine import PDFDisarmer, _compute_ssim_uint8
from malpdf.cdr.fixtures import load_real_benign_bytes, load_real_threat_bytes
from malpdf.evaluation.problem_space_attack import (
    graft_benign_subtree_pair,
    physical_binary_graft_pdf,
    run_greedy_adaptive_graft_attack,
)
from malpdf.models.pdf_transgraph_v4 import (
    ACTION_IR_DIM,
    PDFTransGraphV4,
    TransGraphV4Config,
    build_padded_graph_tensors,
    compute_dag_structural_encodings,
    load_v4_weights_npz,
    save_v4_weights_npz,
    subtree_monotonic_loss,
)
from malpdf.scanner.conformal import MondrianConformalEvaluator

REPO_ROOT = Path(__file__).resolve().parents[2] if False else Path(__file__).resolve().parents[1]
PROD_DIR = REPO_ROOT / "production"
if str(PROD_DIR) not in sys.path:
    sys.path.insert(0, str(PROD_DIR))


def test_transgraph_v4_global_spd_active_action_ir_and_monotonic_loss(tmp_path: Path) -> None:
    cfg = TransGraphV4Config(tab_dim=29, action_ir_dim=ACTION_IR_DIM, hidden_dim=64, num_graph_layers=2, num_heads=4)
    model = PDFTransGraphV4(cfg).eval()

    # Chain 0 -> 1 -> 2 -> 3 -> 4(script), unreachable 5(page)
    nx = np.ones((6, 23), dtype=np.float32) * 0.25
    nt = np.array([0, 1, 2, 3, 4, 2], dtype=np.int64)
    es = np.array([0, 1, 2, 3, 1], dtype=np.int64)
    ed = np.array([1, 2, 3, 4, 5], dtype=np.int64)
    er = np.array([0, 1, 2, 3, 1], dtype=np.int64)
    spd, drel, rd, sd = compute_dag_structural_encodings(6, nt, es, ed, er)
    assert spd[0, 4] == 4
    assert rd[4] == 4
    assert sd[0] == 3
    assert sd[5] == 9

    g_tensors = build_padded_graph_tensors([(nx, nt, es, ed, er, spd, drel, rd, sd)], torch.device("cpu"))
    tab_x = torch.zeros((1, 29), dtype=torch.float32)
    ir_x = torch.ones((1, ACTION_IR_DIM), dtype=torch.float32)
    ir_act = torch.tensor([True], dtype=torch.bool)
    with torch.inference_mode():
        out = model(tab_x, ir_x, ir_act, *g_tensors)
    assert out["logits"].shape == (1,)
    assert out["weights"].shape == (1, 3)
    assert float(out["weights"][0, 2]) > 0.05

    npz_path = tmp_path / "v4_test.npz"
    save_v4_weights_npz(model, npz_path)
    reloaded = PDFTransGraphV4(cfg).eval()
    load_v4_weights_npz(reloaded, npz_path)
    with torch.inference_mode():
        out2 = reloaded(tab_x, ir_x, ir_act, *g_tensors)
    assert float(torch.max(torch.abs(out["logits"] - out2["logits"]))) < 1e-6

    loss_val = subtree_monotonic_loss(torch.tensor([2.5]), torch.tensor([1.0]), margin=0.25)
    assert float(loss_val) == ((2.5 - 1.0 + 0.25) ** 2)


def test_problem_space_physical_binary_grafting_preserves_pdf_validity_and_triggers() -> None:
    threat = load_real_threat_bytes()
    benign = load_real_benign_bytes()
    grafted = physical_binary_graft_pdf(threat, benign, num_padding_objects=25, payload_bytes_per_obj=512)
    assert len(grafted) > len(threat) + 5000
    with pikepdf.open(io.BytesIO(grafted)) as pdf:
        assert len(pdf.pages) >= 2
        assert "/OpenAction" in pdf.Root or ("/Names" in pdf.Root and "/JavaScript" in pdf.Root["/Names"])

    idx_map = {
        "lexical_obj": 0,
        "lexical_endobj": 1,
        "lexical_stream": 2,
        "lexical_endstream": 3,
        "lexical_page_command": 4,
        "lexical_Resources": 5,
        "lexical_JS": 6,
        "lexical_JavaScript": 7,
        "raw_size_bytes": 8,
        "js_per_obj": 9,
        "stream_per_obj": 10,
        "obj_endobj_diff": 11,
        "stream_endstream_diff": 12,
    }
    mal_raw = np.array([20, 20, 4, 4, 1, 1, 2, 1, 5000, 0.15, 0.2, 0, 0], dtype=np.float32)
    donor_raw = np.array([40, 40, 12, 12, 2, 2, 0, 0, 12000, 0.0, 0.3, 0, 0], dtype=np.float32)
    mal_g = (
        np.ones((4, 23), dtype=np.float32),
        np.array([0, 1, 3, 4]),
        np.array([0, 0, 2]),
        np.array([1, 2, 3]),
        np.array([0, 2, 3]),
    )
    don_g = (
        np.ones((4, 23), dtype=np.float32),
        np.array([0, 1, 2, 8]),
        np.array([0, 1, 2]),
        np.array([1, 2, 3]),
        np.array([0, 1, 5]),
    )
    out_r, out_g = graft_benign_subtree_pair(mal_raw, mal_g, donor_raw, don_g, idx_map)
    assert out_r[idx_map["lexical_obj"]] == 60.0
    assert len(out_g[0]) == 6

    res = run_greedy_adaptive_graft_attack(
        mal_raw[None, :],
        [mal_g],
        donor_raw[None, :],
        [don_g],
        idx_map,
        lambda r, _g: np.clip(1.0 - 0.005 * r[:, idx_map["lexical_obj"]], 0.0, 1.0),
        decision_threshold=0.5,
        budgets=(0, 25),
        beam_candidates=1,
    )
    assert set(res["budgets"].keys()) == {"0", "25"}


def test_mondrian_conformal_evaluator_coverage_and_states() -> None:
    # The smoothed p-value can fall below 0.05 with 20 calibration scores per class.
    labels = np.repeat([0, 1], 20)
    crisp = MondrianConformalEvaluator.fit_from_calibration(
        np.r_[np.linspace(0.01, 0.10, 20), np.linspace(0.90, 0.99, 20)],
        labels,
        alpha_benign=0.05,
        alpha_malicious=0.05,
    )
    for probability, state in ((0.01, "CERTIFIED_BENIGN"), (0.99, "CERTIFIED_MALICIOUS")):
        result = crisp.evaluate(probability)
        assert result["conformal_state"] == state
        assert result["reject_for_cdr"] is False

    empty = crisp.evaluate(0.50)
    assert empty["p_benign"] <= 0.05
    assert empty["p_malicious"] <= 0.05
    assert empty["prediction_set"] == []
    assert empty["conformal_state"] == "DRIFT_OOD_EMPTY"
    assert empty["reject_for_cdr"] is True

    overlapping = MondrianConformalEvaluator.fit_from_calibration(
        np.tile(np.linspace(0.40, 0.60, 20), 2),
        labels,
        alpha_benign=0.05,
        alpha_malicious=0.05,
    )
    ambiguous = overlapping.evaluate(0.50)
    assert ambiguous["conformal_state"] == "AMBIGUOUS_BOTH"
    assert ambiguous["prediction_set"] == ["BENIGN", "MALICIOUS"]
    assert ambiguous["reject_for_cdr"] is True

    observed = crisp.evaluate(0.01, has_observed_threat=True)
    assert observed["prediction_set"] == ["MALICIOUS"]
    assert observed["conformal_state"] == "CERTIFIED_MALICIOUS"

    saved = MondrianConformalEvaluator.from_json_file(REPO_ROOT / "configs" / "conformal_calibration_v3.json")
    for probability in (0.002, 0.999):
        result = saved.evaluate(probability)
        assert result["calibration_n_benign"] == 1023
        assert result["calibration_n_malicious"] == 1129
        for metric in ("p_benign", "p_malicious", "credibility", "confidence"):
            assert np.isfinite(result[metric])
            assert 0.0 <= result[metric] <= 1.0


def test_cf_cdr_minimal_cut_and_perceptual_ssim(tmp_path: Path) -> None:
    benign = load_real_benign_bytes()
    threat = load_real_threat_bytes()
    buffer = io.BytesIO()
    with pikepdf.open(io.BytesIO(benign)) as pdf, pikepdf.open(io.BytesIO(benign)) as source:
        # Give the search more than eight candidates using navigation on copies of a real page.
        pdf.pages.extend(source.pages[0] for _ in range(8 - len(pdf.pages)))
        destination = pikepdf.Array([pdf.pages[0].obj, pikepdf.Name.Fit])
        pdf.Root.OpenAction = destination
        for page in pdf.pages:
            page.obj.AA = pikepdf.Dictionary(O=pikepdf.Dictionary(S=pikepdf.Name.GoTo, D=destination))
        alert = pdf.make_indirect(
            pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS=pikepdf.String("app.alert('controlled-test');"))
        )
        pdf.Root.Names = pikepdf.Dictionary(
            JavaScript=pikepdf.Dictionary(Names=pikepdf.Array([pikepdf.String("controlled-test"), alert]))
        )
        pdf.save(buffer)
    raw = buffer.getvalue()

    rescored_with_javascript = []

    def rescore_after_javascript_removal(candidate: bytes) -> dict[str, str]:
        with pikepdf.open(io.BytesIO(candidate)) as pdf:
            has_javascript = "/Names" in pdf.Root and "/JavaScript" in pdf.Root.Names
        rescored_with_javascript.append(has_javascript)
        return {"verdict": "MALICIOUS" if has_javascript else "BENIGN"}

    disarmer = PDFDisarmer()
    cleaned, audit = disarmer.sanitize_bytes(raw, mode="minimal_cut", rescore_fn=rescore_after_javascript_removal)
    assert rescored_with_javascript == [False]
    assert audit.is_sanitized is True
    assert audit.sanitization_mode == "minimal_cut"
    assert len(cleaned) > 0.8 * len(raw)
    assert audit.sanitized_pages == audit.original_pages
    assert audit.extracted_text_chars > 0
    assert audit.text_integrity_verified is True
    assert audit.visual_similarity["mean_ssim"] >= 0.99
    assert "catalog_OpenAction" in audit.preserved_interactive_elements
    with pikepdf.open(io.BytesIO(cleaned)) as pdf:
        assert pdf.Root.OpenAction[0].objgen == pdf.pages[0].obj.objgen
        assert pdf.Root.OpenAction[1] == pikepdf.Name.Fit

    cleaned_threat, threat_audit = disarmer.sanitize_bytes(
        threat, mode="minimal_cut", rescore_fn=rescore_after_javascript_removal
    )
    assert threat_audit.is_sanitized is True
    assert len(cleaned_threat) > 0.8 * len(threat)
    assert threat_audit.sanitized_pages == threat_audit.original_pages
    assert threat_audit.extracted_text_chars > 0
    assert threat_audit.text_integrity_verified is True

    rejected_candidates = 0

    def rescore_always_malicious(_: bytes) -> dict[str, str]:
        nonlocal rejected_candidates
        rejected_candidates += 1
        return {"verdict": "MALICIOUS"}

    _, fallback = disarmer.sanitize_bytes(raw, mode="minimal_cut", rescore_fn=rescore_always_malicious)
    assert 2 <= rejected_candidates <= 8
    assert fallback.sanitization_mode == "full_fallback"
    assert fallback.is_sanitized is False

    raster_path = tmp_path / "raster-only.pdf"
    with fitz.open(stream=benign, filetype="pdf") as source, fitz.open() as raster:
        source_page = source[0]
        png = source_page.get_pixmap(dpi=84).tobytes("png")
        page = raster.new_page(width=source_page.rect.width, height=source_page.rect.height)
        page.insert_image(page.rect, stream=png, keep_proportion=False)
        assert page.get_text("text") == ""
        raster.save(raster_path, deflate=True)

    raster_raw = raster_path.read_bytes()
    raster_cleaned, raster_audit = disarmer.sanitize_bytes(raster_raw)
    assert raster_audit.is_sanitized is True
    assert len(raster_cleaned) > 0.8 * len(raster_raw)
    assert raster_audit.original_pages == raster_audit.sanitized_pages == 1
    assert raster_audit.original_text_chars == raster_audit.extracted_text_chars == 0
    assert raster_audit.visual_similarity["mean_ssim"] >= 0.99
    assert raster_audit.cdr_evaluation_pillars["visual_similarity_verified"] is True

    image = np.tile(np.array([0, 255], dtype=np.uint8), (16, 8))
    degraded = np.full_like(image, 127)
    assert _compute_ssim_uint8(image, image.copy()) == 1.0
    score = _compute_ssim_uint8(image, degraded)
    assert abs(score - _compute_ssim_uint8(degraded, image)) < 1e-6
    assert score < 0.95
