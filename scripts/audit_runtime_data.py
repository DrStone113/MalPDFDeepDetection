from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import importlib.metadata
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import pyarrow.parquet as pq

from malpdf.cdr.engine import PDFDisarmer
from malpdf.cdr.fixtures import BENIGN_FIXTURE_PATH, THREAT_FIXTURE_PATH
from malpdf.data.graph_contract import index_measured_graphs
from malpdf.scanner.engine import MalPDFScannerEngine


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Measure reviewed fixture integrity and existing numeric cache coverage")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = args.output or ROOT / "reports" / "experiments" / "runtime_data_audit" / f"run_{stamp}_{commit[:12]}"
    output.mkdir(parents=True, exist_ok=False)
    source_files = sorted({*ROOT.glob("src/malpdf/scanner/*.py"), *ROOT.glob("src/malpdf/cdr/*.py"), *ROOT.glob("src/malpdf/gateway/*.py"), *ROOT.glob("src/malpdf/web/*.py"), ROOT / "src/malpdf/web/templates/index.html", ROOT / "src/malpdf/data/graph_contract.py", ROOT / "scripts/lab/train_pdf_transgraph.py", ROOT / "scripts/lab/academic_evaluation_transgraph.py", ROOT / "scripts/lab/evaluate_adversarial_stress.py", Path(__file__).resolve(), ROOT / "pyproject.toml"})
    methodology = {
        "base_commit": commit,
        "python": sys.version.split()[0],
        "packages": {name: importlib.metadata.version(name) for name in ("torch", "numpy", "pikepdf", "PyMuPDF", "pypdf", "pyarrow", "fastapi")},
        "source_kind": "worktree_snapshot",
        "source_sha256": {path.relative_to(ROOT).as_posix(): sha256(path) for path in source_files},
        "fixture_scope": "Reviewed academic document and controlled harmless active-action variant; these are not a real-malware evaluation corpus",
        "data_access": "Only reviewed fixtures and existing numeric Parquet/graph cache; no raw malware PDFs",
        "training": "Not run; missing measured graph inputs must never become invented zero-node samples",
        "live_classification": "Blocked until the extraction and training feature contracts match",
        "historical_metrics": "Preserved; no historical result is promoted to freshly verified performance",
    }
    (output / "locked_methodology.json").write_text(json.dumps(methodology, indent=2), encoding="utf-8")
    scanner = MalPDFScannerEngine(device="cpu")
    disarmer = PDFDisarmer()
    outcomes = []
    for path in (BENIGN_FIXTURE_PATH, THREAT_FIXTURE_PATH):
        original = path.read_bytes()
        scan = scanner.scan_bytes(original, file_name=path.name)
        cleaned, audit = disarmer.sanitize_bytes(original, file_name=path.name)
        passed = len(cleaned) > 0.8 * len(original) and audit.original_pages == audit.sanitized_pages and audit.extracted_text_chars > 0 and audit.text_integrity_verified is True and audit.content_streams_preserved and audit.resources_preserved
        if not passed:
            raise ValueError("reviewed_fixture_integrity_failed")
        outcomes.append({
            "file_name": path.name, "fixture_only": True,
            "sha256_before": audit.sha256_before, "sha256_after": audit.sha256_after,
            "size_before": len(original), "size_after": len(cleaned),
            "size_retention_pct": audit.size_retention_pct,
            "pages_before": audit.original_pages, "pages_after": audit.sanitized_pages,
            "text_chars": audit.extracted_text_chars,
            "text_equal": audit.text_integrity_verified,
            "contents_equal": audit.content_streams_preserved, "resources_equal": audit.resources_preserved,
            "removed_keys": len(audit.removed_triggers), "cdr_latency_ms": audit.disarm_latency_ms,
            "parsed_objects": len(scan.graph_nodes), "scripts_observed": scan.forensic_dossier["script_count"],
            "prediction_available": scan.prediction_available, "probability": scan.malware_probability,
            "prediction_blockers": scan.prediction_blockers,
        })
    features_path = ROOT / "data/processed/cic_full/cic_features_1452.parquet"
    graphs_path = ROOT / "data/processed/cic_full/hetero_cic_graphs.json.gz"
    frame = pq.read_table(features_path, columns=["pdf_sha256", "split"]).to_pandas()
    with gzip.open(graphs_path, "rt", encoding="utf-8") as stream:
        graphs = json.load(stream)
    observed = {graph["sha256"] for graph in graphs if graph.get("num_nodes", 0) > 0}
    missing = frame.loc[~frame.pdf_sha256.isin(observed)]
    cache = {
        "numeric_rows": len(frame), "measured_graphs": len(graphs), "missing_graphs": len(missing),
        "split_counts": frame.split.value_counts().to_dict(),
        "missing_graphs_by_split": missing.split.value_counts().to_dict(),
        "inputs_sha256": {path.relative_to(ROOT).as_posix(): sha256(path) for path in (features_path, graphs_path)},
    }
    try:
        index_measured_graphs(graphs, set(frame.pdf_sha256))
        cache["status"] = "complete_measured_graph_coverage"
    except ValueError as error:
        cache["status"] = "blocked_missing_or_invalid_measured_graphs"
        cache["reason"] = str(error)
    metrics = {"generated_utc": datetime.now(timezone.utc).isoformat(), "fixture_integrity": outcomes, "numeric_cache_audit": cache, "model_performance": "not_evaluated", "lab_raw_pdf_execution": "requires_operator_lab_run"}
    (output / "metrics.json").write_text(json.dumps(metrics, indent=2, allow_nan=False), encoding="utf-8")
    print(json.dumps({"report": str(output), "reviewed_fixtures_measured": len(outcomes), "missing_graphs": len(missing), "classification": "unavailable_until_contract_verified"}))


if __name__ == "__main__":
    main()
