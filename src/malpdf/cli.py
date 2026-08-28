"""Command-line entry point for the project."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from malpdf import __version__
from malpdf.inference import scan_pdf
from malpdf.reproducibility import DEFAULT_RANDOM_SEED, set_random_seed
from malpdf.static import StaticInspectionLimits, inspect_pdf


def build_parser() -> argparse.ArgumentParser:
    """Build the project command-line parser."""
    parser = argparse.ArgumentParser(
        prog="malpdf",
        description="Malicious PDF detection research utilities.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_RANDOM_SEED,
        help=f"random seed (default: {DEFAULT_RANDOM_SEED})",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command")
    inspect_parser = subparsers.add_parser(
        "inspect",
        help="perform bounded, non-executing static inspection of one local PDF",
    )
    inspect_parser.add_argument("path", help="local untrusted PDF path; it is read as bytes only")
    inspect_parser.add_argument("--json", action="store_true", help="emit full machine-readable JSON")
    inspect_parser.add_argument(
        "--max-file-size-mib", type=int, default=50,
        help="maximum input size before full parsing (default: 50 MiB)",
    )
    inspect_parser.add_argument("--max-pages", type=int, default=1_000, help="maximum pages inspected (default: 1000)")
    inspect_parser.add_argument("--max-objects", type=int, default=10_000, help="maximum structural objects traversed (default: 10000)")
    scan_parser = subparsers.add_parser(
        "scan",
        help="perform static inspection, strict compatibility validation, and frozen local-model inference",
    )
    scan_parser.add_argument("path", help="local untrusted PDF path; it is read as bytes only")
    scan_parser.add_argument("--json", action="store_true", help="emit stable machine-readable JSON")
    scan_parser.add_argument(
        "--max-file-size-mib", type=int, default=50,
        help="maximum input size before full parsing (default: 50 MiB)",
    )
    scan_parser.add_argument("--max-pages", type=int, default=1_000, help="maximum pages inspected (default: 1000)")
    scan_parser.add_argument("--max-objects", type=int, default=10_000, help="maximum structural objects traversed (default: 10000)")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Initialize deterministic state for a future experiment command."""
    args = build_parser().parse_args(argv)
    set_random_seed(args.seed)
    if args.command not in {"inspect", "scan"}:
        print(f"malpdf ready (seed={args.seed})")
        return 0

    try:
        limits = StaticInspectionLimits(
            max_file_size_bytes=args.max_file_size_mib * 1024 * 1024,
            max_pages=args.max_pages,
            max_objects=args.max_objects,
        )
    except ValueError as error:
        parser.error(str(error))
    if args.command == "scan":
        result = scan_pdf(
            args.path,
            repository_root=Path(__file__).resolve().parents[2],
            limits=limits,
        )
        payload = result.to_dict()
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False))
        else:
            print("Static Malicious-PDF Scan")
            print(f"SHA-256: {payload['input']['sha256'] or 'unavailable'}")
            print(f"Size: {payload['input']['size_bytes'] if payload['input']['size_bytes'] is not None else 'unavailable'} bytes")
            compatibility = payload["compatibility"]
            print(
                "Model compatibility: "
                f"{'PASS' if compatibility['passed'] else 'FAIL'} "
                f"({compatibility['compatible_features']}/{compatibility['expected_features']})"
            )
            if payload["prediction"]["available"]:
                print(f"Model: {payload['model']['name']}")
                print(f"Malicious probability: {payload['prediction']['malicious_probability']:.4%}")
                print(f"Model verdict: {payload['prediction']['verdict']}")
                for heading, key in (("Top contributions toward malicious", "top_positive_contributions"), ("Top contributions toward benign", "top_negative_contributions")):
                    print(f"{heading}:")
                    for item in payload["explanation"][key]:
                        print(f"  {item['feature']}: value={item['extracted_value']:.6g}; model contribution={item['contribution']:.6g}")
                if not payload["explanation"]["available"]:
                    print("Local TreeSHAP explanation unavailable: " + str(payload["explanation"]["error"]))
            else:
                print("Prediction unavailable: " + str(payload["prediction"]["error"]))
                if compatibility["blockers"]:
                    print("Blocking features: " + "; ".join(f"{item['feature']} ({item['reason']})" for item in compatibility["blockers"]))
            print("Safety: no active PDF content was executed or external resource followed.")
        if payload["prediction"]["available"]:
            return 0
        return 2 if not payload["compatibility"]["passed"] else 3

    result = inspect_pdf(args.path, limits=limits)
    payload = result.to_dict()
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False))
    else:
        coverage = payload["feature_coverage"]
        header = payload["diagnostics"].get("file_header", {})
        gate = payload["model_compatibility"]["protocol_g_drop3constant"]
        print("Static PDF Inspection")
        print(f"SHA-256: {payload['input']['sha256'] or 'unavailable'}")
        print(f"Size: {payload['input']['size_bytes'] if payload['input']['size_bytes'] is not None else 'unavailable'} bytes")
        print(f"PDF version: {header.get('header_version_string') or 'unavailable'}")
        for feature in ("JavaScript", "JS", "URI", "OpenAction", "Launch", "EmbeddedFile", "pages", "images"):
            print(f"{feature}: {payload['features'].get(feature)}")
        print("RIT schema coverage:")
        for status, count in coverage.items():
            print(f"  {status}: {count} / 41")
        print(f"Protocol G 38-feature compatibility gate: {'PASS' if gate['passed'] else 'FAIL'} ({gate['compatible_feature_count']}/38)")
        print("No malware probability or verdict is produced.")
        if payload["errors"]:
            print("Errors: " + "; ".join(str(item["message"]) for item in payload["errors"]))
    return 2 if any(item["fatal"] for item in payload["errors"]) else 0
