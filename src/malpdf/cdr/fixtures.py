from __future__ import annotations

from pathlib import Path
import os

PROJECT_ROOT = Path(__file__).resolve().parents[3]
FIXTURES_DIR = Path(os.environ.get("MALPDF_REVIEWED_FIXTURES", PROJECT_ROOT / "tests" / "fixtures"))
BENIGN_FIXTURE_PATH = FIXTURES_DIR / "real_benign_document.pdf"
THREAT_FIXTURE_PATH = FIXTURES_DIR / "real_threat_document.pdf"


def ensure_real_fixtures() -> tuple[Path, Path]:
    for path in (BENIGN_FIXTURE_PATH, THREAT_FIXTURE_PATH):
        if not path.is_file():
            raise FileNotFoundError(f"Reviewed on-disk PDF fixture unavailable: {path}")
    return BENIGN_FIXTURE_PATH, THREAT_FIXTURE_PATH


def load_real_benign_bytes() -> bytes:
    return BENIGN_FIXTURE_PATH.read_bytes()


def load_real_threat_bytes() -> bytes:
    return THREAT_FIXTURE_PATH.read_bytes()
