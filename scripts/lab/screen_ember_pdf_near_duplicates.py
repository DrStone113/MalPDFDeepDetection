from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import io
import json
from pathlib import Path
from malpdf.extraction.tlsh import DISTANCE_LIMIT, TLSH_RE, nearest_distances

SOURCE_MANIFEST_SHA256 = "976926d266aa072908ded69a6b702fb6b002ee05b1defa9abc5a0983d8070523"
VALIDATION = "validation_candidate"
TEST = "test_candidate"


def screen(validation, test, distances):
    if len(test) != len(distances) or any(distance < 0 for distance in distances):
        raise ValueError("invalid_TLSH_distance_results")
    retained = []
    excluded = Counter()
    for row, distance in zip(test, distances, strict=True):
        if distance <= DISTANCE_LIMIT:
            excluded[row["label"]] += 1
        else:
            retained.append(row)
    return validation + retained, excluded


def main():
    parser = argparse.ArgumentParser(description="Check EMBER candidate Validation/Test TLSH overlap")
    parser.add_argument("--candidates", required=True, type=Path)
    parser.add_argument("--tlsh-executable", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    if args.out.exists():
        raise FileExistsError("screened manifest already exists")

    source = args.candidates.read_bytes()
    if hashlib.sha256(source).hexdigest() != SOURCE_MANIFEST_SHA256:
        raise ValueError("unexpected_candidate_manifest")
    reader = csv.DictReader(io.StringIO(source.decode("ascii")))
    fields = reader.fieldnames
    validation, test = [], []
    for row in reader:
        if not TLSH_RE.fullmatch(row["tlsh"]):
            raise ValueError("missing_or_invalid_TLSH")
        if row["candidate_role"] == VALIDATION:
            validation.append(row)
        elif row["candidate_role"] == TEST:
            test.append(row)
        else:
            raise ValueError("unexpected_candidate_role")
    if len(validation) != 4_000 or len(test) != 7_999:
        raise ValueError("unexpected_candidate_partition_sizes")

    distances = nearest_distances(
        args.tlsh_executable,
        [row["tlsh"] for row in validation],
        [row["tlsh"] for row in test],
    )
    retained, excluded = screen(validation, test, distances)
    with args.out.open("x", encoding="ascii", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(retained)

    counts = Counter((row["candidate_role"], row["label"]) for row in retained)
    print(json.dumps({
        "schema_version": 1, "method": "minimum standard TLSH distance from Test to Validation",
        "threshold_inclusive": DISTANCE_LIMIT, "validation_input": len(validation), "test_input": len(test),
        "pairs_screened_logically": len(validation) * len(test),
        "test_nearest_validation_distance_min": min(distances),
        "zero_distance_test_rows": distances.count(0),
        "test_rows_excluded_by_label": {str(i): excluded[str(i)] for i in range(2)},
        "retained_counts": {role: {str(i): counts[role, str(i)] for i in range(2)} for role in (VALIDATION, TEST)},
        "candidate_manifest_sha256": SOURCE_MANIFEST_SHA256,
        "screened_manifest_sha256": hashlib.sha256(args.out.read_bytes()).hexdigest(),
        "development_corpus_TLSH_screened": False, "status": "candidate_metadata_internal_screen_only",
    }, indent=2))


if __name__ == "__main__":
    main()
