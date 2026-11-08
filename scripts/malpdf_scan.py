from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "src"))

from malpdf.cdr.engine import PDFDisarmer
from malpdf.scanner.engine import MalPDFScannerEngine


def main() -> None:
    parser = argparse.ArgumentParser(description="PDF static evidence and in-place CDR inspector")
    parser.add_argument("path", nargs="?", type=Path)
    parser.add_argument("--dir", type=Path)
    parser.add_argument("--explain", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--cpu", action="store_true")
    parser.add_argument("--disarm", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=Path("reports/figures"))
    args = parser.parse_args()
    if (args.path is None) == (args.dir is None):
        parser.error("Provide one PDF path or --dir")
    paths = sorted(args.dir.glob("*.pdf")) if args.dir else [args.path]
    if not paths:
        parser.error("No existing PDF files selected")
    scanner = MalPDFScannerEngine(device="cpu" if args.cpu else "auto")
    results = []
    failed = False
    for path in paths:
        try:
            result = scanner.scan_file(path, explain=args.explain)
            payload = result.to_dict()
            if args.explain:
                diagram = args.output_dir / f"attack_flow_{result.sha256[:10]}.png"
                scanner.forensic.save_attack_path_diagram(
                    output_path=diagram, sha256=result.sha256,
                    malware_prob=result.malware_probability,
                    attack_path=result.forensic_dossier.get("attack_path", []),
                    cross_modal_weights=result.forensic_dossier.get("cross_modal_weights"),
                )
                payload["diagram_path"] = str(diagram)
            if args.disarm:
                output = args.output_dir / f"{path.stem}_sanitized.pdf"
                _, audit = PDFDisarmer().sanitize_file(path, output_path=output)
                payload["cdr_disarm"] = audit.to_dict()
            results.append(payload)
        except (OSError, ValueError, RuntimeError) as error:
            failed = True
            results.append({"file_name": path.name, "status": "FAILED", "error": str(error)})
    output = results if args.dir else results[0]
    print(json.dumps(output, indent=2, ensure_ascii=True, allow_nan=False))
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
