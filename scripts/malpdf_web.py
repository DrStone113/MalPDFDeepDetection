from __future__ import annotations

import argparse
from pathlib import Path
import sys
import uvicorn

ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from malpdf.web.app import app


def main() -> None:
    parser = argparse.ArgumentParser(description="Launch MalPDF Luminous Liquid Glass Web Dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on")
    parser.add_argument("--reload", action="store_true", help="Enable hot reload")
    args = parser.parse_args()

    print(f"Starting MalPDF Web Dashboard at http://{args.host}:{args.port}")
    uvicorn.run("malpdf.web.app:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()

