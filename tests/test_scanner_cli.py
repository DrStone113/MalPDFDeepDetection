from __future__ import annotations

import io
import json
from pathlib import Path
import os
import subprocess
import sys
import time

import pytest
import torch

from malpdf.cdr.fixtures import load_real_benign_bytes, load_real_threat_bytes
from malpdf.scanner.engine import MalPDFScannerEngine, ScanResult
from malpdf.scanner.forensic import ForensicAttributionEngine
from malpdf.scanner.ingestion import InstantPDFIngestion


def load_benign_fixture() -> bytes:
    return load_real_benign_bytes()


def load_active_fixture() -> bytes:
    return load_real_threat_bytes()


def test_instant_ingestion_structure():
    data = load_benign_fixture()
    ingestion = InstantPDFIngestion()
    res = ingestion.ingest(data)

    assert "sha256" in res
    assert res["node_features"].shape[1] in (19, 23)
    assert res["node_types"].dim() == 1
    assert res["edge_index"].shape[0] == 2
    assert res["ast_tokens"].shape == (1, 32)
    assert res["tab_features"] is not None
    assert res["tab_features"].shape == (1, 38)
    assert len(res["raw_feature_vec"]) == 38
    assert not res["prediction_blockers"]


def test_instant_ingestion_with_javascript():
    data = load_active_fixture()
    ingestion = InstantPDFIngestion()
    res = ingestion.ingest(data)

    assert len(res["extracted_scripts"]) >= 1
    assert "alert" in res["extracted_scripts"][0]["code"]
    assert res["ast_tokens"].sum().item() > 0


def test_scanner_engine_inference():
    data = load_active_fixture()
    scanner = MalPDFScannerEngine(device="cpu")
    result = scanner.scan_bytes(data, file_name="malicious_sample.pdf", explain=True)

    assert isinstance(result, ScanResult)
    assert result.verdict == "MALICIOUS"
    assert result.malware_probability is not None
    assert result.malware_probability >= 0.50
    assert result.confidence in ("HIGH", "MEDIUM", "LOW")
    assert result.ood_score is not None
    assert result.prediction_available is True
    assert result.latency_ms > 0.0
    assert "attack_path_string" in result.forensic_dossier


def test_energy_ood_calculation():
    scanner = MalPDFScannerEngine(device="cpu")
    energy_high_conf, is_ood_high = scanner.calculate_energy_ood(logit=5.0)
    assert energy_high_conf < -2.0
    assert not is_ood_high

    energy_uncertain, is_ood_uncertain = scanner.calculate_energy_ood(logit=0.0)
    assert energy_uncertain >= -0.75
    assert is_ood_uncertain


def test_forensic_attribution_engine(tmp_path: Path):
    engine = ForensicAttributionEngine()
    mock_data = {
        "raw_records": [
            {"kind": "catalog", "evidence_id": "catalog:root"},
            {"kind": "action", "evidence_id": "action:open_action"},
        ],
        "raw_edges": [{"source": "catalog:root", "target": "action:open_action"}],
        "extracted_scripts": [
            {"script_id": "s1", "parent_id": "action:open_action", "code": "eval('app.alert(1);');"}
        ],
    }

    explanation = engine.explain(mock_data, malware_prob=0.95)
    assert "Action (/OpenAction)" in explanation["attack_path"]
    assert len(explanation["threat_scripts"]) == 1
    assert "eval_exec" in explanation["threat_scripts"][0]["dangerous_indicators"]

    diagram_path = tmp_path / "test_attack.png"
    out = engine.save_attack_path_diagram(
        output_path=diagram_path,
        sha256="abcdef1234567890",
        malware_prob=0.95,
        attack_path=explanation["attack_path"],
        cross_modal_weights=explanation["cross_modal_weights"],
    )
    assert out.exists()
    assert out.stat().st_size > 1000


def test_cli_single_file_json_execution(tmp_path: Path):
    pdf_file = tmp_path / "test_target.pdf"
    pdf_file.write_bytes(load_active_fixture())

    cmd = [
        sys.executable,
        "scripts/malpdf_scan.py",
        str(pdf_file),
        "--json",
        "--cpu",
        "--explain",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True, env=dict(os.environ, PYTHONPATH="src"))
    out_json = json.loads(proc.stdout)

    assert out_json["sha256"]
    assert out_json["verdict"] == "MALICIOUS"
    assert out_json["malware_probability"] is not None
    assert out_json["malware_probability"] >= 0.50
    assert "forensic_dossier" in out_json
    assert "attack_path_string" in out_json["forensic_dossier"]


def test_cli_explain_mode_png_creation(tmp_path: Path):
    pdf_file = tmp_path / "test_sample.pdf"
    pdf_file.write_bytes(load_active_fixture())
    out_dir = tmp_path / "out_diagrams"

    cmd = [
        sys.executable,
        "scripts/malpdf_scan.py",
        str(pdf_file),
        "--explain",
        "--cpu",
        "--output-dir",
        str(out_dir),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True, env=dict(os.environ, PYTHONPATH="src"))
    assert proc.returncode == 0
    png_files = list(out_dir.glob("*.png"))
    assert len(png_files) >= 1


def test_cli_batch_dir_execution(tmp_path: Path):
    batch_dir = tmp_path / "batch_pdfs"
    batch_dir.mkdir(parents=True, exist_ok=True)

    for i in range(3):
        f = batch_dir / f"sample_{i}.pdf"
        f.write_bytes(load_benign_fixture() if i % 2 == 0 else load_active_fixture())

    cmd = [
        sys.executable,
        "scripts/malpdf_scan.py",
        "--dir",
        str(batch_dir),
        "--cpu",
        "--json",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True, env=dict(os.environ, PYTHONPATH="src"))
    out_json = json.loads(proc.stdout)
    assert len(out_json) == 3


def test_scanner_latency_benchmark():
    data = load_active_fixture()
    scanner = MalPDFScannerEngine(device="cpu")
    scanner.scan_bytes(data, file_name="warmup.pdf")

    latencies: list[float] = []
    for _ in range(5):
        t0 = time.perf_counter()
        res = scanner.scan_bytes(data, file_name="benchmark.pdf")
        latencies.append((time.perf_counter() - t0) * 1000)

    avg_latency = sum(latencies) / len(latencies)
    assert avg_latency < 250.0
