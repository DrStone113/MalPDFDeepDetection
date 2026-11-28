"""Summarize observed coverage and OR-gate rates from a saved Gate B run."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

PUBLISHER_COHORTS = frozenset({"benign_ood_v1", "benign_ood_expanded_v1"})


def _counts(records: list[dict]) -> dict:
    observed = [row for row in records if row["eval_status"] == "observed"]
    hits = sum(row["tier"] == "or_gate" for row in observed)
    return {
        "selected": len(records),
        "observed": len(observed),
        "unobserved": len(records) - len(observed),
        "or_gate_count": hits,
        "observed_rate": hits / len(observed) if observed else None,
    }


def summarize_evaluation(evaluation: dict) -> dict:
    records = evaluation.get("records", [])
    by_cohort: dict[str, list[dict]] = {}
    publishers = []
    for record in records:
        cohort = record["cohort"]
        by_cohort.setdefault(cohort, []).append(record)
        if cohort in PUBLISHER_COHORTS:
            publishers.append(record)

    publisher = _counts(publishers)
    total = publisher["selected"]
    hits = publisher["or_gate_count"]
    possible_hits = hits + publisher["unobserved"]
    status = "inconclusive"
    if total and possible_hits * 100 <= total:
        status = "passed"
    elif total and hits * 100 > total:
        status = "failed"

    return {
        "job_id": evaluation.get("job_id"),
        "runner_status": evaluation.get("runner_status") or evaluation.get("runner", {}).get("status"),
        "cohorts": {name: _counts(rows) for name, rows in sorted(by_cohort.items())},
        "publisher_or_gate": {
            **publisher,
            "full_cohort_rate_bounds": [hits / total, possible_hits / total] if total else None,
            "threshold": 0.01,
            "gate_status": status,
        },
        "publisher_final_verdict_fpr": None,
        "verified_real_phishing_pdf_recall": None,
    }


def read_saved_evaluation(run_directory: Path) -> dict:
    from lab_contract import parse_json
    from lab_oneshot_adm import EXPORT_CONTRACTS, jobs, validate_export
    from lab_side import bounded_read

    kind = jobs.URI_HEAD_EVAL_KIND
    methodology = parse_json(bounded_read(run_directory / "locked_methodology.json", 256 * 1024))
    raw = bounded_read(run_directory / "profile_export.json", EXPORT_CONTRACTS[kind])
    if hashlib.sha256(raw).hexdigest() != methodology["artifact_sha256s"]["profile_export.json"]:
        raise ValueError("uri_gate_b_export_checksum_mismatch")
    job = methodology["job"]
    if job["kind"] != kind:
        raise ValueError("uri_gate_b_job_kind_mismatch")
    return validate_export(raw, job)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(summarize_evaluation(read_saved_evaluation(args.run_directory)), indent=2))


if __name__ == "__main__":
    main()
