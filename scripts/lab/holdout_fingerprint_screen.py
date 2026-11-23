from __future__ import annotations

import argparse
from collections import Counter
import csv
from functools import partial
import hashlib
import io
import json
from pathlib import Path
import re

from malpdf.extraction.tlsh import DISTANCE_LIMIT, TLSH_RE, nearest_distances, screen

SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_ROWS = 50_000
MAX_CSV_BYTES = 8 * 1024**2


def read_fingerprints(path):
    with path.open("rb") as handle:
        data = handle.read(MAX_CSV_BYTES + 1)
    if len(data) > MAX_CSV_BYTES:
        raise ValueError("fingerprint_manifest_too_large")
    reader = csv.DictReader(io.StringIO(data.decode("ascii")))
    if reader.fieldnames != ["sha256", "tlsh"]:
        raise ValueError("invalid_fingerprint_manifest_fields")
    rows = {}
    for row in reader:
        sha, digest = row["sha256"], row["tlsh"]
        if (None in row or not sha or not SHA256.fullmatch(sha) or sha in rows
                or digest is None or digest and not TLSH_RE.fullmatch(digest)):
            raise ValueError("invalid_fingerprint_manifest_row")
        rows[sha] = digest or None
        if len(rows) > MAX_ROWS:
            raise ValueError("fingerprint_manifest_too_large")
    if not rows:
        raise ValueError("empty_fingerprint_manifest")
    return rows, hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Screen a holdout from SSH-safe SHA-256/TLSH manifests")
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--tlsh-executable", type=Path, required=True)
    args = parser.parse_args()
    reference, reference_hash = read_fingerprints(args.reference)
    candidates, candidates_hash = read_fingerprints(args.candidates)
    measurements = screen(reference, candidates, partial(nearest_distances, args.tlsh_executable))
    print(json.dumps({
        "schema_version": 1,
        "reference_manifest_sha256": reference_hash,
        "candidate_manifest_sha256": candidates_hash,
        "reference_count": len(reference),
        "measured_reference_count": sum(digest is not None for digest in reference.values()),
        "candidate_count": len(candidates),
        "distance_threshold_inclusive": DISTANCE_LIMIT,
        "disposition_counts": dict(Counter(row["disposition"] for row in measurements.values())),
        "measurements": measurements,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
