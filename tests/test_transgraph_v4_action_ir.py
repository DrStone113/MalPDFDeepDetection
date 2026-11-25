from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import torch

from malpdf.cdr.fixtures import load_real_benign_bytes
from malpdf.extraction.numeric_export import EDGE_TYPES as OFFLINE_EDGE_TYPES
from malpdf.extraction.numeric_export import NODE_TYPES as OFFLINE_NODE_TYPES
from malpdf.models.pdf_transgraph_v4 import (
    ACTION_IR_DIM,
    CANONICAL_NODE_TYPES,
    SINK_NODE_TYPES,
    SPD_UNREACHABLE,
    PDFTransGraphV4,
    TransGraphV4Config,
    benign_graft_stability_loss,
    build_padded_graph_tensors,
    compute_dag_structural_encodings,
    extract_observable_action_ir_np,
    extract_single_graph_action_ir_np,
    subtree_monotonic_loss,
)
from malpdf.scanner.ingestion import EDGE_TYPES as LIVE_EDGE_TYPES
from malpdf.scanner.ingestion import NODE_TYPES as LIVE_NODE_TYPES
from malpdf.scanner.ingestion import InstantPDFIngestion

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_canonical_node_and_edge_schema_alignment() -> None:
    assert CANONICAL_NODE_TYPES == OFFLINE_NODE_TYPES == LIVE_NODE_TYPES
    assert SINK_NODE_TYPES == (
        CANONICAL_NODE_TYPES["action"],
        CANONICAL_NODE_TYPES["script"],
        CANONICAL_NODE_TYPES["filespec"],
    )
    inv = {v: k for k, v in CANONICAL_NODE_TYPES.items()}
    for (src_id, dst_id), rel_id in OFFLINE_EDGE_TYPES.items():
        assert LIVE_EDGE_TYPES[(inv[src_id], inv[dst_id])] == rel_id


def test_action_ir_distinguishes_catalog_autoopen_from_widget_form_and_ignores_tabular() -> None:
    nx_auto = np.zeros((4, 23), dtype=np.float32)
    nx_auto[2, 0] = 4.2
    nx_auto[2, 1] = 1.0
    nx_auto[3, 0] = 5.5
    nx_auto[3, 1] = 1.0
    nx_auto[3, 2] = 5.1
    nx_auto[3, 3] = 1.0
    nt_auto = np.array([0, 1, 3, 5], dtype=np.int64)
    es_auto = np.array([0, 0, 2], dtype=np.int64)
    ed_auto = np.array([1, 2, 3], dtype=np.int64)
    er_auto = np.array([0, 2, 4], dtype=np.int64)
    ir_auto, act_auto = extract_single_graph_action_ir_np(nx_auto, nt_auto, es_auto, ed_auto, er_auto)
    assert act_auto is True
    assert ir_auto.shape == (ACTION_IR_DIM,)
    assert ir_auto[8] > 0.0
    assert ir_auto[11] == 0.0
    assert ir_auto[12] == 1.0 / SPD_UNREACHABLE
    assert ir_auto[13] == 1.0
    assert ir_auto[14] == 1.0
    assert ir_auto[15] == 0.0
    assert np.isclose(ir_auto[16], 5.5)
    assert np.isclose(ir_auto[18], 5.1)

    nx_form = np.zeros((6, 23), dtype=np.float32)
    nx_form[4, 0] = 4.0
    nx_form[4, 1] = 0.0
    nx_form[5, 2] = 9.9
    nx_form[5, 3] = 0.0
    nt_form = np.array([0, 1, 2, 4, 3, 5], dtype=np.int64)
    es_form = np.array([0, 1, 2, 3, 4], dtype=np.int64)
    ed_form = np.array([1, 2, 3, 4, 5], dtype=np.int64)
    er_form = np.array([0, 1, 7, 7, 4], dtype=np.int64)
    ir_form, act_form = extract_single_graph_action_ir_np(nx_form, nt_form, es_form, ed_form, er_form)
    assert act_form is True
    assert ir_form[8] == 0.0
    assert ir_form[11] > 0.0
    assert ir_form[12] == 4.0 / SPD_UNREACHABLE
    assert ir_form[13] == 1.0 / SPD_UNREACHABLE
    assert ir_form[14] == 0.0
    assert ir_auto[15] < ir_form[15] == 1.0
    assert ir_form[16] == 0.0
    assert ir_form[18] == 0.0

    raw_a = np.zeros((1, 73), dtype=np.float32)
    raw_b = np.full((1, 73), 999.0, dtype=np.float32)
    node_ptr = np.array([0, 4], dtype=np.int64)
    edge_ptr = np.array([0, 3], dtype=np.int64)
    edge_idx = np.vstack([es_auto, ed_auto])
    ir_batch_a, _ = extract_observable_action_ir_np(
        raw_a,
        node_x=nx_auto,
        node_type=nt_auto,
        node_ptr=node_ptr,
        edge_index=edge_idx,
        edge_rel=er_auto,
        edge_ptr=edge_ptr,
        row_indices=np.array([0], dtype=np.int64),
    )
    ir_batch_b, _ = extract_observable_action_ir_np(
        raw_b,
        node_x=nx_auto,
        node_type=nt_auto,
        node_ptr=node_ptr,
        edge_index=edge_idx,
        edge_rel=er_auto,
        edge_ptr=edge_ptr,
        row_indices=np.array([0], dtype=np.int64),
    )
    np.testing.assert_array_equal(ir_batch_a, ir_batch_b)
    np.testing.assert_allclose(ir_batch_a[0], ir_auto, atol=1e-6)


def test_live_benign_fixture_and_offline_reviewed_controls_ir_determinism() -> None:
    ing = InstantPDFIngestion(as_numpy=True)
    d = ing.ingest(load_real_benign_bytes())
    assert d["graph_present"] is True
    nx = d["node_features"]
    nt = d["node_types"]
    ei = d["edge_index"]
    er = d["edge_rel"]
    spd, direct_rel, rd, sd = compute_dag_structural_encodings(len(nt), nt, ei[0], ei[1], er)
    ir_live, active_live = extract_single_graph_action_ir_np(nx, nt, ei[0], ei[1], er, spd, rd, sd)
    assert active_live is True
    assert np.isfinite(ir_live).all()

    ctrl_path = REPO_ROOT / "data/processed/pooled_bulk/offline_provenance/reviewed_controls_v3.json"
    if ctrl_path.is_file():
        controls = json.loads(ctrl_path.read_text(encoding="utf-8"))["controls"]
        rows = controls.values() if isinstance(controls, dict) else controls
        for row in rows:
            nf_c, nt_c, es_c, ed_c, er_c = row["graph"]
            nx_c = np.asarray(nf_c, dtype=np.float32)
            nt_arr = np.asarray(nt_c, dtype=np.int64)
            es_arr = np.asarray(es_c, dtype=np.int64)
            ed_arr = np.asarray(ed_c, dtype=np.int64)
            er_arr = np.asarray(er_c, dtype=np.int64)
            ir_1, act_1 = extract_single_graph_action_ir_np(nx_c, nt_arr, es_arr, ed_arr, er_arr)
            spd_c, drel_c, rd_c, sd_c = compute_dag_structural_encodings(len(nt_arr), nt_arr, es_arr, ed_arr, er_arr)
            ir_2, act_2 = extract_observable_action_ir_np(
                node_x=nx_c,
                node_type=nt_arr,
                node_ptr=np.array([0, len(nt_arr)], dtype=np.int64),
                row_indices=np.array([0], dtype=np.int64),
                precomputed_graphs=[(nx_c, nt_arr, es_arr, ed_arr, er_arr, spd_c, drel_c, rd_c, sd_c)],
            )
            assert act_1 == bool(act_2[0])
            np.testing.assert_allclose(ir_1, ir_2[0], atol=1e-7)


def test_v4_and_gin_forward_ssl_and_symmetric_graft_losses() -> None:
    nx = np.random.default_rng(7).normal(size=(5, 23)).astype(np.float32)
    nt = np.array([0, 1, 2, 3, 5], dtype=np.int64)
    es = np.array([0, 1, 0, 3], dtype=np.int64)
    ed = np.array([1, 2, 3, 4], dtype=np.int64)
    er = np.array([0, 1, 2, 4], dtype=np.int64)
    spd, drel, rd, sd = compute_dag_structural_encodings(5, nt, es, ed, er)
    ir, act = extract_single_graph_action_ir_np(nx, nt, es, ed, er, spd, rd, sd)
    g_tensors = build_padded_graph_tensors([(nx, nt, es, ed, er, spd, drel, rd, sd), None], torch.device("cpu"))
    tab_x = torch.randn(2, 29)
    ir_x = torch.stack([torch.from_numpy(ir), torch.zeros(ACTION_IR_DIM)])
    ir_act = torch.tensor([act, False])

    for enc_type, spd_flag, ir_flag in (
        ("graphormer_dag", True, True),
        ("graphormer_dag", False, True),
        ("graphormer_dag", True, False),
        ("gin", False, False),
    ):
        cfg = TransGraphV4Config(
            tab_dim=29,
            encoder_type=enc_type,
            enable_spd_bias=spd_flag,
            enable_action_ir=ir_flag,
        )
        model = PDFTransGraphV4(cfg)
        out = model(tab_x, ir_x, ir_act, *g_tensors, return_graph_details=True)
        ssl = model.ssl_loss(
            tab_x,
            torch.ones_like(tab_x, dtype=torch.bool),
            *g_tensors,
            torch.ones((2, 5), dtype=torch.bool),
        )
        mono = subtree_monotonic_loss(out["logits"][:1], out["logits"][:1] - 0.5)
        stab = benign_graft_stability_loss(out["logits"][1:], out["logits"][1:] + 0.5)
        total = out["logits"].sum() + ssl + mono + stab
        total.backward()
        assert torch.isfinite(total)


def test_passive_filespec_without_action_or_script_is_not_execution_sink() -> None:
    nt_passive = np.array([0, 1, 2, 6, 7, 7, 8], dtype=np.int64)
    nx_passive = np.zeros((7, 23), dtype=np.float32)
    es_passive = np.array([0, 1, 0, 0], dtype=np.int64)
    ed_passive = np.array([1, 2, 4, 5], dtype=np.int64)
    er_passive = np.array([0, 1, 5, 5], dtype=np.int64)
    spd, _, rd, sd = compute_dag_structural_encodings(7, nt_passive, es_passive, ed_passive, er_passive)
    assert (sd == SPD_UNREACHABLE).all()
    ir_p, act_p = extract_single_graph_action_ir_np(
        nx_passive, nt_passive, es_passive, ed_passive, er_passive, spd, rd, sd
    )
    assert act_p is True
    assert ir_p[4] == 0.0
    assert ir_p[5] == 0.0
    assert ir_p[12] == 1.0
    assert ir_p[14] == 0.0
    assert ir_p[22] == 0.0


def test_bug035_failclosed_runtime_and_checkpoint_identity_invariants(tmp_path) -> None:
    from dataclasses import replace
    from email import message_from_bytes
    from email.mime.application import MIMEApplication
    from email.mime.multipart import MIMEMultipart
    from pathlib import Path
    import shutil
    from unittest.mock import MagicMock

    from production.onnx_engine import ONNXMalPDFScannerEngine
    import pytest

    from malpdf.cdr.engine import PDFDisarmer
    from malpdf.cdr.fixtures import load_real_benign_bytes, load_real_threat_bytes
    from malpdf.gateway.mail_filter import MailGatewayFilter
    from malpdf.scanner.engine import MalPDFScannerEngine
    from malpdf.web.store import ScanJobStore

    repo_root = Path(__file__).resolve().parents[1]

    store = ScanJobStore(quarantine_dir=tmp_path / "quarantine")
    benign = load_real_benign_bytes()
    cleaned_benign, audit_ok = PDFDisarmer().sanitize_bytes(benign)
    job = store.create_job(benign, "sample.pdf")
    attempt_1 = store.begin_disarm(job.scan_id)
    attempt_2 = store.begin_disarm(job.scan_id)
    assert attempt_2 == attempt_1 + 1
    store.set_status(job.scan_id, "FAILED", error="second_attempt_failed", attempt_id=attempt_2)
    stale_attached = store.attach_sanitized(
        job.scan_id,
        cleaned_benign,
        audit_ok,
        {"prediction_available": True, "verdict_after": "BENIGN"},
        attempt_id=attempt_1,
    )
    assert stale_attached is False
    assert store.get_job(job.scan_id).status == "FAILED"
    assert store.get_job(job.scan_id).sanitized_bytes is None

    mock_disarmer = MagicMock()
    zero_page_audit = replace(audit_ok, original_pages=0, sanitized_pages=0, is_sanitized=True)
    mock_disarmer.sanitize_bytes.return_value = (b"", zero_page_audit)
    scanner = MalPDFScannerEngine(device="cpu")
    gw = MailGatewayFilter(scanner_engine=scanner, disarmer=mock_disarmer, quarantine_dir=tmp_path / "mail_q")
    msg = MIMEMultipart()
    msg["Subject"] = "Test"
    part = MIMEApplication(load_real_threat_bytes(), _subtype="pdf")
    part.add_header("Content-Disposition", "attachment", filename="threat.pdf")
    msg.attach(part)
    out_bytes, report = gw.inspect_eml_bytes(msg.as_bytes())
    parsed = message_from_bytes(out_bytes)
    assert "X-MalPDF-Sanitized" not in out_bytes.decode("latin1")
    assert report.action_taken == "QUARANTINED_ATTACHMENT"

    v3_src = repo_root / "artifacts" / "models" / "pdf_transgraph_v3" / "pdf_transgraph_v3_regime_b_seed42.npz"
    if v3_src.is_file():
        tricky_v3 = tmp_path / "legacy_v3_for_v4_comparison.npz"
        shutil.copy2(v3_src, tricky_v3)
        eng_v3 = MalPDFScannerEngine(model_path=tricky_v3, device="cpu")
        assert eng_v3.is_v3 is True and eng_v3.is_v4 is False

    v4_onnx = repo_root / "production" / "models" / "pdf_transgraph_v4.onnx"
    with pytest.raises((FileNotFoundError, ValueError), match="conformal_calibration"):
        ONNXMalPDFScannerEngine(model_path=v4_onnx, temperature=1.0)
    with pytest.raises((FileNotFoundError, ValueError), match="conformal_calibration"):
        MalPDFScannerEngine(device="cpu", temperature=1.0)
    assert parsed is not None
