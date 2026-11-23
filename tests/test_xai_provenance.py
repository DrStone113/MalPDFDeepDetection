from __future__ import annotations

from pathlib import Path
import io
import math
import sys
from typing import Any

import pikepdf
import pymupdf
import pytest

from malpdf.cdr.engine import PDFDisarmer
from malpdf.cdr.fixtures import load_real_benign_bytes
from malpdf.scanner.engine import MalPDFScannerEngine

PRODUCTION = Path(__file__).resolve().parents[1] / "production"
if str(PRODUCTION) not in sys.path:
    sys.path.insert(0, str(PRODUCTION))

from onnx_engine import ONNXMalPDFScannerEngine


@pytest.fixture
def document_with_navigation() -> bytes:
    with pikepdf.open(io.BytesIO(load_real_benign_bytes())) as pdf:
        pdf.Root["/OpenAction"] = pikepdf.Array([pdf.pages[0].obj, pikepdf.Name.FitH, None])
        output = io.BytesIO()
        pdf.save(output)
        return output.getvalue()


@pytest.mark.parametrize("runtime", ["onnx", "pytorch"])
def test_navigation_does_not_become_an_observed_trigger(document_with_navigation: bytes, runtime: str) -> None:
    scanner = ONNXMalPDFScannerEngine() if runtime == "onnx" else MalPDFScannerEngine(device="cpu")
    scan = scanner.scan_bytes(document_with_navigation)
    node_id = "action:open_action"
    node = next(node for node in scan.graph_nodes if node["id"] == node_id)
    assert node["action_role"] == "destination"
    assert node["is_threat_trigger"] is False
    assert node["size_bytes"] is node["entropy"] is None
    assert scan.forensic_dossier["attack_path_kind"] == "document_structure"
    assert not scan.forensic_dossier["threat_scripts"]

    ingest = scanner.ingestion.ingest(document_with_navigation)
    below = scanner.taxonomy.classify(document_with_navigation, ingest, {}, "BENIGN", 0.061)
    above = scanner.taxonomy.classify(document_with_navigation, ingest, {}, "MALICIOUS", 0.916)
    navigation_head = next(head for head in above["ml_label_predictions"] if head["id"] == "auto_open_trigger")
    assert navigation_head["evidence_status"] in {"model_signal", "not_observed"}
    assert not navigation_head["detected"]
    assert "autoaction" not in above["behavior_tags"]
    assert [head["probability"] for head in below["ml_label_predictions"]] == [
        head["probability"] for head in above["ml_label_predictions"]
    ]

    ablation = scanner.ablate_node(document_with_navigation, node_id, ablate_mode="surgical")
    assert not ablation["is_threat_trigger"]
    assert ablation["ablation_method"] == "graph_tensor_counterfactual_mask"
    assert ablation["masked_node_ids"] == [node_id]
    assert ablation["excised_keys"] == ablation["excised_node_ids"] == []
    assert not ablation["remaining_threat_node_ids"]


def test_disarm_preserves_navigation_and_page_content(document_with_navigation: bytes) -> None:
    cleaned, audit = PDFDisarmer().sanitize_bytes(document_with_navigation)
    assert audit.is_sanitized
    assert len(cleaned) > 0.8 * len(document_with_navigation)
    assert audit.sanitized_pages == audit.original_pages
    assert audit.content_streams_preserved and audit.resources_preserved
    with pikepdf.open(io.BytesIO(cleaned)) as pdf:
        assert pdf.Root["/OpenAction"][0].objgen == pdf.pages[0].obj.objgen
        assert pdf.Root["/OpenAction"][1] == pikepdf.Name.FitH
    with pymupdf.open(stream=document_with_navigation, filetype="pdf") as original:
        expected_text = [page.get_text() for page in original]
    with pymupdf.open(stream=cleaned, filetype="pdf") as sanitized:
        assert "".join(expected_text).strip()
        assert [page.get_text() for page in sanitized] == expected_text


def test_onnx_reports_occlusion_and_keeps_unmeasured_saliency_unknown() -> None:
    result = ONNXMalPDFScannerEngine().scan_bytes(load_real_benign_bytes(), explain=True)
    dossier = result.forensic_dossier
    assert dossier["cross_attention_matrix_status"] == "measured_occlusion_saliency"
    assert dossier["xai_method"] == "occlusion"
    coverage = dossier["xai_coverage"]
    assert coverage["nodes_total"] == len(result.graph_nodes)
    assert coverage["nodes_measured"] == min(24, len(result.graph_nodes))
    assert coverage["tabular_features_measured"] <= 16
    assert coverage["tabular_features_total"] == 29
    measured_nodes = {node["id"] for node in result.graph_nodes if node["xai_saliency"] is not None}
    assert len(measured_nodes) == coverage["nodes_measured"]
    assert all(row["node_id"] in measured_nodes for row in dossier["cross_attention_matrix"])
    assert all(row["attribution_score"] is not None for row in dossier["tabular_attributions"])


def test_pytorch_reports_its_actual_gradient_method() -> None:
    result = MalPDFScannerEngine(device="cpu").scan_bytes(load_real_benign_bytes(), explain=True)
    dossier = result.forensic_dossier
    assert dossier["cross_attention_matrix_status"] == "measured_gradient_saliency"
    assert dossier["xai_method"] == "gradient_input"
    assert dossier["xai_coverage"]["nodes_measured"] == len(result.graph_nodes)
    assert dossier["xai_coverage"]["tabular_features_measured"] == 29
    assert len(dossier["tabular_attributions"]) == 29
    assert dossier["cross_modal_weights"]["ast_weight"] == 0.0


def test_onnx_sparsity_uses_only_evaluated_attribution_values() -> None:
    class RecordingONNXScanner(ONNXMalPDFScannerEngine):
        def _compute_xai_signals_ort(
            self, *args: Any, **kwargs: Any
        ) -> tuple[list[float | None], list[float], list[float], list[float | None], dict[str, float]]:
            signals = super()._compute_xai_signals_ort(*args, **kwargs)
            self.recorded_signals = signals
            return signals

    scanner = RecordingONNXScanner()
    result = scanner.scan_bytes(load_real_benign_bytes(), explain=True)
    nodes, _, _, tabular, proof = scanner.recorded_signals
    reported = nodes + tabular
    evaluated = [abs(value) for value in reported if value is not None]
    assert len(evaluated) < len(reported)
    assert len(evaluated) > 1
    length = math.sqrt(len(evaluated))
    norm = math.sqrt(math.fsum(value * value for value in evaluated))
    assert norm > 0.0
    expected_pct = max(0.0, min(100.0, 100.0 * (length - math.fsum(evaluated) / norm) / (length - 1.0)))
    assert proof["sparsity_index"] == pytest.approx(round(expected_pct, 1), abs=0.01)
    assert result.forensic_dossier["xai_metrics"]["sparsity_index"] == proof["sparsity_index"]
    assert result.forensic_dossier["xai_metrics"]["sparsity_scope"] == "evaluated_inputs"
