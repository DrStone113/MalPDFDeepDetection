from __future__ import annotations

import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
from urllib.request import urlopen
from zipfile import ZipFile

REPO = Path(__file__).resolve().parents[2]
EMBER_REVISION = "3d23efef7c0f0b702c5024400cfff4c3744a3832"
EMBER_PDF_TEST_URL = f"https://huggingface.co/datasets/joyce8/EMBER2024/resolve/{EMBER_REVISION}/PDF_test.zip"
EMBER_PDF_TEST_BYTES = 28_833_740
EMBER_PDF_TEST_SHA256 = "953742edb8bbe1f729f32b546c142f8600811a16652822473222e48fc9e826dc"
HISTORICAL_SOURCE = REPO / "data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732/source_manifest.csv"
HISTORICAL_SOURCE_SHA256 = "d74729236017dc27a71c999bc4d69f84a16fa4148573c3bbc7f4eb03709b150b"
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
TLSH_RE = re.compile(r"(?:T1)?[0-9A-F]{70}\Z")
WEEKS = range(52, 64)
FIELDS = ("sha256", "tlsh", "label", "week_id", "first_submission_utc", "candidate_role")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def ember_records(archive):
    with ZipFile(io.BytesIO(archive)) as bundle:
        members = [item for item in bundle.infolist() if not item.is_dir()]
        if (not members or any(Path(item.filename).suffix != ".jsonl" for item in members)
                or sum(item.file_size for item in members) > 160_000_000):
            raise ValueError("unexpected_EMBER_metadata_members")
        for member in members:
            with bundle.open(member) as stream:
                for raw in stream:
                    if len(raw) > 250_000:
                        raise ValueError("oversized_EMBER_metadata_row")
                    record = json.loads(raw)
                    identity, label, week = record["sha256"], record["label"], record["week_id"]
                    seen = record["first_submission_date"]
                    if (
                        not isinstance(identity, str) or not SHA256_RE.fullmatch(identity)
                        or type(label) is not int or label not in (0, 1)
                        or type(week) is not int or week not in WEEKS
                        or type(seen) is not int or record["file_type"] != "PDF"
                    ):
                        raise ValueError("invalid_EMBER_PDF_metadata")
                    tlsh = str(record.get("tlsh") or "").upper()
                    yield {
                        "sha256": identity, "label": label, "week_id": week,
                        "tlsh": tlsh if TLSH_RE.fullmatch(tlsh) else "",
                        "first_submission_utc": datetime.fromtimestamp(seen, timezone.utc).isoformat(),
                        "candidate_role": "validation_candidate" if week < 56 else "test_candidate",
                    }


def deduplicate_metadata(records):
    unique = {}
    for row in records:
        digest = row["sha256"]
        if digest in unique and unique[digest] != row:
            raise ValueError("conflicting_EMBER_metadata_for_same_sha256")
        unique[digest] = row
    return list(unique.values())


def main():
    parser = argparse.ArgumentParser(description="Audit official EMBER PDF feature metadata without raw PDFs")
    parser.add_argument("--bulk-sha256", required=True, type=Path)
    parser.add_argument("--candidate-output", required=True, type=Path)
    args = parser.parse_args()
    if args.candidate_output.exists():
        raise FileExistsError("candidate output already exists")
    historical_bytes = HISTORICAL_SOURCE.read_bytes()
    if sha256(historical_bytes) != HISTORICAL_SOURCE_SHA256:
        raise ValueError("historical_source_manifest_changed")
    history = {row["pdf_sha256"] for row in csv.DictReader(io.StringIO(historical_bytes.decode("utf-8-sig")))}
    bulk = set(args.bulk_sha256.read_text(encoding="utf-8").splitlines())
    if len(bulk) != 41_727 or not all(SHA256_RE.fullmatch(value) for value in bulk | history):
        raise ValueError("invalid_known_SHA256_identities")

    with urlopen(EMBER_PDF_TEST_URL, timeout=40) as stream:
        artifact = stream.read(EMBER_PDF_TEST_BYTES + 1)
    if len(artifact) != EMBER_PDF_TEST_BYTES or sha256(artifact) != EMBER_PDF_TEST_SHA256:
        raise ValueError("EMBER_PDF_feature_archive_hash_mismatch")
    metadata_rows = list(ember_records(artifact))
    candidates = deduplicate_metadata(metadata_rows)
    if len(candidates) != 12_000:
        raise ValueError("unexpected_EMBER_PDF_test_membership")
    eligible = sorted((row for row in candidates if row["sha256"] not in bulk and row["sha256"] not in history),
                      key=lambda row: (row["week_id"], row["sha256"]))
    with args.candidate_output.open("x", encoding="ascii", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(eligible)
    counts = Counter((row["candidate_role"], row["label"]) for row in eligible)
    print(json.dumps({
        "source_url": EMBER_PDF_TEST_URL, "archive_sha256": EMBER_PDF_TEST_SHA256,
        "archive_bytes": len(artifact), "archive_metadata_rows": len(metadata_rows),
        "unique_pdf_identities": len(candidates), "identical_metadata_rows_removed": len(metadata_rows) - len(candidates),
        "known_bulk_identities": len(bulk), "known_historical_identities": len(history),
        "exact_overlap_bulk": sum(row["sha256"] in bulk for row in candidates),
        "exact_overlap_history": sum(row["sha256"] in history for row in candidates),
        "metadata_candidates": len(eligible), "available_tlsh": sum(bool(row["tlsh"]) for row in eligible),
        "first_submission_utc_min": min(row["first_submission_utc"] for row in eligible),
        "first_submission_utc_max": max(row["first_submission_utc"] for row in eligible),
        "candidate_counts": {role: {str(label): counts[role, label] for label in (0, 1)}
                             for role in ("validation_candidate", "test_candidate")},
        "candidate_manifest_sha256": sha256(args.candidate_output.read_bytes()),
        "stage": "metadata_candidates_only",
    }, indent=2))


if __name__ == "__main__":
    main()
