from __future__ import annotations

import gzip
import json
from pathlib import Path
import pytest
import torch

from malpdf.data.graph_export_v2_loader import (
    MultimodalPDFDatasetV2,
    collate_multimodal_batch_v2,
    sha256_bytes,
    verify_graph_export_v2_directory,
)
from malpdf.extraction.graph_projection_v2 import NODE_FEATURE_DIM_V2
from malpdf.models.pdf_transgraph import PDFTransGraph


def _make_valid_v2_sample(idx: int, gnn_ok: bool = True) -> dict:
    if gnn_ok:
        return {
            "index": idx,
            "sha256": f"{idx:064x}",
            "sample_id": f"s_{idx}",
            "split": "train",
            "label": idx % 2,
            "gnn_message_passing_eligible": True,
            "evaluation_handling": "graph_and_tabular",
            "placeholder_nodes_inserted": False,
            "node_features": torch.randn(5, NODE_FEATURE_DIM_V2),
            "node_types": torch.tensor([0, 1, 2, 3, 5], dtype=torch.long),
            "edge_src": torch.tensor([0, 1, 2], dtype=torch.long),
            "edge_dst": torch.tensor([1, 2, 3], dtype=torch.long),
            "edge_rel": torch.tensor([0, 1, 2], dtype=torch.long),
            "ast_tokens": torch.randint(0, 64, (32,), dtype=torch.long),
            "tab_features": torch.randn(38, dtype=torch.float32),
        }
    return {
        "index": idx,
        "sha256": f"{idx:064x}",
        "sample_id": f"s_{idx}",
        "split": "validation",
        "label": idx % 2,
        "gnn_message_passing_eligible": False,
        "evaluation_handling": "abstention_or_tabular_only_no_placeholder_graph",
        "placeholder_nodes_inserted": False,
        "node_features": None,
        "node_types": None,
        "edge_src": None,
        "edge_dst": None,
        "edge_rel": None,
        "ast_tokens": torch.randint(0, 64, (32,), dtype=torch.long),
        "tab_features": torch.randn(38, dtype=torch.float32),
    }


@pytest.mark.parametrize(
    "mode",
    ["full", "tab_only", "graph_only", "ast_only", "tab_ast", "tab_graph"],
)
def test_pdf_transgraph_v2_23d_forward_all_modes(mode: str):
    model = PDFTransGraph(
        node_in_dim=NODE_FEATURE_DIM_V2,
        num_node_types=9,
        num_relations=8,
        ast_vocab_size=64,
        tabular_in_features=38,
        hidden_dim=64,
        ablation_mode=mode,
    )
    batch = collate_multimodal_batch_v2([_make_valid_v2_sample(0, True), _make_valid_v2_sample(1, True)])
    logits, attn = model(
        batch["node_features"],
        batch["node_types"],
        batch["edge_index"],
        batch["edge_rel"],
        batch["batch"],
        batch["ast_tokens"],
        batch["tab_features"],
    )
    assert logits.shape == (2,)
    assert attn.shape == (2, 1, 2)
    assert torch.isfinite(logits).all()


def test_pdf_transgraph_v2_unavailable_graph_handling_no_placeholder_nodes():
    unavail_batch = collate_multimodal_batch_v2([_make_valid_v2_sample(3, False), _make_valid_v2_sample(141, False)])
    assert unavail_batch["node_features"] is None
    assert unavail_batch["edge_index"] is None

    full_model = PDFTransGraph(
        node_in_dim=NODE_FEATURE_DIM_V2,
        tabular_in_features=38,
        hidden_dim=64,
        ablation_mode="full",
    )
    logits, attn = full_model(
        unavail_batch["node_features"],
        unavail_batch["node_types"],
        unavail_batch["edge_index"],
        unavail_batch["edge_rel"],
        unavail_batch["batch"],
        unavail_batch["ast_tokens"],
        unavail_batch["tab_features"],
    )
    assert logits.shape == (2,)
    assert attn.shape == (2, 1, 2)

    graph_only_model = PDFTransGraph(
        node_in_dim=NODE_FEATURE_DIM_V2,
        tabular_in_features=38,
        hidden_dim=64,
        ablation_mode="graph_only",
    )
    with pytest.raises(ValueError, match="graph_only_requires_measured_graph"):
        graph_only_model(
            unavail_batch["node_features"],
            unavail_batch["node_types"],
            unavail_batch["edge_index"],
            unavail_batch["edge_rel"],
            unavail_batch["batch"],
            unavail_batch["ast_tokens"],
            unavail_batch["tab_features"],
        )


def test_collate_multimodal_batch_v2_forbids_mixed_or_empty_graphs():
    ds = MultimodalPDFDatasetV2([_make_valid_v2_sample(0, True), _make_valid_v2_sample(1, False)])
    assert len(ds) == 2
    with pytest.raises(ValueError, match="mixed_gnn_and_unavailable_graph_batch_forbidden"):
        collate_multimodal_batch_v2([ds[0], ds[1]])

    bad_sample = _make_valid_v2_sample(2, True)
    bad_sample["node_features"] = torch.zeros((0, NODE_FEATURE_DIM_V2), dtype=torch.float32)
    bad_sample["node_types"] = torch.zeros((0,), dtype=torch.long)
    with pytest.raises(ValueError, match="empty_graph_in_gnn_batch_forbidden"):
        collate_multimodal_batch_v2([bad_sample])


def test_verify_graph_export_v2_directory_fail_closed_checks(tmp_path: Path):
    with pytest.raises(ValueError, match="v2_export_manifest_missing"):
        verify_graph_export_v2_directory(tmp_path)

    canon_dir = Path("data/processed/graph_exports_v2/export_20261106T135440198431Z_89bf66f04d93")
    if canon_dir.is_dir():
        verified = verify_graph_export_v2_directory(canon_dir)
        assert len(verified["tabular_rows"]) == 1452
        assert len(verified["graph_dict"]) == 1446
        assert len(verified["ledger"]["records"]) == 6

        tampered = tmp_path / "tampered_export"
        tampered.mkdir()
        for name in (
            "manifest.json",
            "locked_methodology.json",
            "quality_gate_summary.json",
            "unavailable_document_ledger.json",
            "tabular_features_v2.jsonl.gz",
            "hetero_graphs_v2.jsonl.gz",
        ):
            (tampered / name).write_bytes((canon_dir / name).read_bytes())

        gate = json.loads((tampered / "quality_gate_summary.json").read_text(encoding="utf-8"))
        gate["cohort_gate_verdict"] = "hold_pending_v2_projection_and_size_contract"
        gate["v2_graph_model_input_ready"] = False
        gate["training_unlocked"] = False
        gate_bytes = json.dumps(gate, sort_keys=True).encode("utf-8")
        (tampered / "quality_gate_summary.json").write_bytes(gate_bytes)

        with pytest.raises(ValueError, match="v2_export_checksum_mismatch"):
            verify_graph_export_v2_directory(tampered)

        manifest = json.loads((tampered / "manifest.json").read_text(encoding="utf-8"))
        manifest["files"]["quality_gate_summary.json"] = {
            "bytes": len(gate_bytes),
            "sha256": sha256_bytes(gate_bytes),
        }
        (tampered / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

        with pytest.raises(ValueError, match="v2_quality_gate_not_unlocked_for_training"):
            verify_graph_export_v2_directory(tampered)

