from __future__ import annotations

from pathlib import Path
import math
import sys
from typing import Any

import pytest

from malpdf.cdr.fixtures import load_real_benign_bytes
from malpdf.scanner.engine import MalPDFScannerEngine

PRODUCTION = Path(__file__).resolve().parents[1] / "production"
if str(PRODUCTION) not in sys.path:
    sys.path.insert(0, str(PRODUCTION))

from onnx_engine import ONNXMalPDFScannerEngine


def test_onnx_reports_occlusion_and_keeps_unmeasured_saliency_unknown() -> None:
    result = ONNXMalPDFScannerEngine().scan_bytes(load_real_benign_bytes(), explain=True)
    dossier = result.forensic_dossier
    assert dossier["cross_attention_matrix_status"] == "measured_occlusion_saliency"
    assert dossier["xai_method"] == "occlusion"
    coverage = dossier["xai_coverage"]
    assert coverage["nodes_total"] == len(result.graph_nodes)
    assert coverage["nodes_measured"] == min(24, len(result.graph_nodes))
    assert coverage["tabular_features_measured"] <= 16
    assert coverage["tabular_features_total"] == 38
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
    assert dossier["xai_coverage"]["tabular_features_measured"] == 38


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
