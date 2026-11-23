from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

FIXTURE_HASH = "ef43e7f9e1c138d5d5279fe3c16e54c7d0a63c1a056f5008550872e31b4b0fa7"
DEFAULT_FIXTURE = REPO / "tests/fixtures/real_benign_document.pdf"
DEFAULT_SCALER = REPO / "production/configs/tabular_scaler.json"
MAX_FIXTURE_BYTES = 2 * 1024**2
CANONICAL_COLUMNS = {
    "Javascript": "canonical_JavaScript", "JS": "canonical_JS",
    "Stream": "canonical_stream", "Endstream": "canonical_endstream",
    "Obj": "canonical_obj", "Endobj": "canonical_endobj",
    "MetadataSize": "canonical_metadata size", "PdfSize": "canonical_pdfsize",
    "Pages": "canonical_pages", "PageNo": "canonical_page_command",
    "XFA": "canonical_XFA", "OpenAction": "canonical_OpenAction",
    "Colors": "canonical_Colors", "Images": "canonical_images",
}
RATIOS = {
    "density_stream_ratio": ("canonical_stream", "canonical_pdfsize"),
    "density_obj_stream_ratio": ("canonical_obj", "canonical_stream"),
    "density_metadata_ratio": ("canonical_metadata size", "canonical_pdfsize"),
    "ast_complexity_per_node": ("legacy_observed_ast_max_depth", "legacy_observed_ast_node_count"),
    "ast_call_ratio": ("legacy_observed_ast_type_CallExpression", "legacy_observed_ast_node_count"),
    "ast_identifier_ratio": ("legacy_observed_ast_type_Identifier", "legacy_observed_ast_node_count"),
    "ast_computed_ratio": ("legacy_observed_ast_computed_members", "legacy_observed_ast_node_count"),
}


def fixture_data(path):
    with path.open("rb") as handle:
        data = handle.read(MAX_FIXTURE_BYTES + 1)
    if len(data) > MAX_FIXTURE_BYTES or hashlib.sha256(data).hexdigest() != FIXTURE_HASH:
        raise ValueError("fixture_not_approved_for_feature_audit")
    return data


def value_or_none(value):
    if type(value) not in (int, float, bool) or not math.isfinite(value):
        return None
    return float(value)


def lab_vector(features, names):
    def source_value(name):
        return value_or_none(features.get(name, {}).get("value"))

    vector = {}
    for name in names:
        if name in RATIOS or name == "entropy_gap":
            operands = RATIOS.get(name, ("raw_prefix_entropy", "raw_suffix_entropy"))
            left, right = map(source_value, operands)
            value = None
            if left is not None and right is not None:
                value = abs(left - right) if name == "entropy_gap" else left / max(abs(right), 1.0)
            vector[name] = {"value": value, "sources": list(operands)}
        else:
            source = CANONICAL_COLUMNS.get(name, name)
            vector[name] = {
                "value": source_value(source), "sources": [source],
                "status": features.get(source, {}).get("observation_status", "missing"),
            }
    return vector


def measure(mode, fixture, scaler_path):
    data = fixture_data(fixture)
    scaler_bytes = scaler_path.read_bytes()
    scaler = json.loads(scaler_bytes)
    names = scaler["feature_names"]
    if len(names) != 38 or len(set(names)) != 38:
        raise ValueError("unexpected_feature_order")
    report = {
        "schema_version": 1, "measurement": mode, "fixture_sha256": FIXTURE_HASH,
        "scaler_sha256": hashlib.sha256(scaler_bytes).hexdigest(), "feature_order": names,
    }
    if mode == "scanner":
        from malpdf.scanner.ingestion import InstantPDFIngestion

        parsed = InstantPDFIngestion(scaler_path=scaler_path, as_numpy=True).ingest(data)
        report["features"] = {
            name: {"value": value_or_none(value)}
            for name, value in zip(names, parsed["raw_feature_vec"], strict=True)
        }
        report["prediction_blocker_count"] = len(parsed["prediction_blockers"])
    else:
        from malpdf.extraction import extract_pdf

        bundle = extract_pdf(fixture, expected_sha256=FIXTURE_HASH, coalesce_checkpoints=True)
        if bundle["sample_sha256"] != FIXTURE_HASH:
            raise ValueError("lab_fixture_identity_changed")
        features = {row["feature_name"]: row for row in bundle["feature_store"]["records"]}
        report["features"] = lab_vector(features, names)
        report["extraction_status"] = bundle["status"]
        coverage = bundle["coverage_report"]
        worker = coverage["worker"]
        report["worker_coverage"] = {
            "worker_status": worker["status"],
            "worker_exit_code": worker["worker_exit_code"],
            "last_worker_stage": worker["last_stage"],
            "worker_seconds": worker["worker_seconds"],
            "worker_cleanup_complete": worker["worker_cleanup_complete"],
            "checkpoint_coalescing": True,
            "byte_image_status": coverage["backends"]["byte_images"]["observation_status"],
        }
    return report


def compare(lab, scanner):
    if lab["measurement"] != "lab" or scanner["measurement"] != "scanner":
        raise ValueError("expected_lab_and_scanner_reports")
    for key in ("fixture_sha256", "scaler_sha256", "feature_order"):
        if lab[key] != scanner[key]:
            raise ValueError(f"audit_identity_mismatch:{key}")
    rows = []
    for name in lab["feature_order"]:
        left = lab["features"][name]["value"]
        right = scanner["features"][name]["value"]
        if left is None or right is None:
            status = "unavailable"
        else:
            status = "numeric_match" if math.isclose(left, right, rel_tol=1e-6, abs_tol=1e-8) else "numeric_difference"
        rows.append({"name": name, "lab": left, "scanner": right, "comparison": status,
                     "lab_sources": lab["features"][name]["sources"]})
    return {
        "schema_version": 1, "fixture_sha256": lab["fixture_sha256"], "scaler_sha256": lab["scaler_sha256"],
        "lab_extraction_status": lab["extraction_status"],
        "lab_worker_coverage": lab.get("worker_coverage"),
        "scanner_prediction_blocker_count": scanner["prediction_blocker_count"],
        "counts": {status: sum(row["comparison"] == status for row in rows)
                   for status in ("numeric_match", "numeric_difference", "unavailable")},
        "columns": rows,
    }


def main():
    parser = argparse.ArgumentParser(description="Compare model-order features on one hash-pinned benign fixture")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("scanner", "lab"):
        mode = commands.add_parser(name)
        mode.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
        mode.add_argument("--scaler", type=Path, default=DEFAULT_SCALER)
    comparisons = commands.add_parser("compare")
    comparisons.add_argument("lab", type=Path)
    comparisons.add_argument("scanner", type=Path)
    args = parser.parse_args()
    if args.command == "compare":
        result = compare(json.loads(args.lab.read_text(encoding="utf-8")),
                         json.loads(args.scanner.read_text(encoding="utf-8")))
    else:
        result = measure(args.command, args.fixture, args.scaler)
    print(json.dumps(result, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
