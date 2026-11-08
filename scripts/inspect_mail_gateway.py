from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "src"))

from malpdf.gateway import MailGatewayFilter


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect an existing EML file and its PDF attachments")
    parser.add_argument("eml", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--quarantine", type=Path, default=Path("data/quarantine"))
    parser.add_argument("--device", default="cpu")
    args = parser.parse_args()
    gateway = MailGatewayFilter(quarantine_dir=args.quarantine, device=args.device)
    sanitized_email, report = gateway.inspect_eml_file(args.eml)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(sanitized_email)
    print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
