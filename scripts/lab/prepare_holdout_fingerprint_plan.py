from __future__ import annotations

import argparse
from collections import Counter
import csv
from decimal import Decimal
import hashlib
import io
import json
from pathlib import Path
import re
import stat

HISTORICAL = "data/processed/multi_cohort_v4/run_20261003T124714720715Z_c96868a21732/source_manifest.csv"
BULK_MANIFEST = "data/raw/bulk_20261116/manifest.csv"
HISTORICAL_SHA256 = "d74729236017dc27a71c999bc4d69f84a16fa4148573c3bbc7f4eb03709b150b"
BULK_MANIFEST_SHA256 = "c4e59ad6040dbd6b2ebeba9142d68979a789c2c8d3ecb5f9c27616c72f7dc6f8"
CATALOG_SHA256 = "54046abb2a7526e0c68019ba80cf9e85515b439d1263f08116d78520f3c33863"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_FILE_BYTES = 50 * 1024**2
MAX_PLAN_BYTES = 2 * 1024**3


def pinned_metadata(path, expected_hash, cap):
    with path.open("rb") as handle:
        data = handle.read(cap + 1)
    if len(data) > cap or hashlib.sha256(data).hexdigest() != expected_hash:
        raise ValueError("unexpected_pinned_metadata")
    return data


def metadata_row(raw_root, path, sha, expected_size, group):
    if (not SHA256.fullmatch(sha) or not path.is_relative_to(raw_root) or ".." in path.parts
            or path.resolve() != path):
        raise ValueError("untrusted_pilot_path_or_identity")
    info = path.stat()
    if (not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_FILE_BYTES
            or expected_size is not None and info.st_size != expected_size):
        raise ValueError("unexpected_pilot_file_metadata")
    return {"path": path.relative_to(raw_root).as_posix(), "sha256": sha,
            "bytes": info.st_size, "group": group}


def build_plan(repo, catalog):
    raw_root = repo / "data/raw"
    bulk_root = raw_root / "bulk_20261116"
    history_bytes = pinned_metadata(repo / HISTORICAL, HISTORICAL_SHA256, 16 * 1024**2)
    bulk_bytes = pinned_metadata(repo / BULK_MANIFEST, BULK_MANIFEST_SHA256, 24 * 1024**2)
    cases = json.loads(pinned_metadata(catalog, CATALOG_SHA256, 128 * 1024))
    historical = csv.DictReader(io.StringIO(history_bytes.decode("utf-8-sig")))
    acquisition = csv.DictReader(io.StringIO(bulk_bytes.decode("utf-8-sig")))

    reference = {}
    for row in historical:
        sha = row["pdf_sha256"]
        if sha in reference:
            raise ValueError("duplicate_reference_identity")
        size = Decimal(row["bytes"]) if row["bytes"] else None
        reference[sha] = metadata_row(raw_root, repo / row["pdf_relative_path"], sha, size, "historical_v4")

    candidate_groups = {row["sha256"]: row["candidate_group"] for row in cases}
    entries = {}
    for row in acquisition:
        sha = row["sha256"]
        if sha not in candidate_groups:
            continue
        entry = metadata_row(raw_root, bulk_root / row["stored_relpath"], sha,
                             int(row["bytes"]), candidate_groups[sha])
        if entries.setdefault(sha, entry) != entry:
            raise ValueError("conflicting_candidate_location")
    if (len(reference) != 21414 or len(cases) != 145 or len(candidate_groups) != len(cases)
            or entries.keys() != candidate_groups.keys() or reference.keys() & entries.keys()):
        raise ValueError("unexpected_holdout_membership")

    rows = [reference[sha] for sha in sorted(reference)] + [entries[sha] for sha in sorted(entries)]
    total_bytes = sum(row["bytes"] for row in rows)
    if total_bytes > MAX_PLAN_BYTES:
        raise ValueError("holdout_total_byte_limit")
    return {"schema_version": 1, "metadata_only": True, "total_bytes": total_bytes,
            "input_sha256": {"catalog": CATALOG_SHA256, "history": HISTORICAL_SHA256,
                             "acquisition": BULK_MANIFEST_SHA256}, "entries": rows}


def main():
    parser = argparse.ArgumentParser(description="Seal paths and recorded hashes without reading PDFs")
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    plan = build_plan(args.repo.resolve(strict=True), args.catalog)
    data = (json.dumps(plan, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    with args.out.open("xb") as handle:
        handle.write(data)
    print(json.dumps({"plan_sha256": hashlib.sha256(data).hexdigest(),
                      "member_counts": dict(Counter(row["group"] for row in plan["entries"])),
                      "total_bytes": plan["total_bytes"], "max_file_bytes": MAX_FILE_BYTES,
                      "metadata_only": True, "queued": False}, indent=2))


if __name__ == "__main__":
    main()
