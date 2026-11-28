from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
import sys

from lab_contract import parse_json
import lab_jobs as jobs
import lab_side as side


def _quantile(sorted_vals: list[float], q: float) -> float:
    if not sorted_vals:
        return 0.0
    pos = q * (len(sorted_vals) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = pos - lo
    return round(sorted_vals[lo] * (1.0 - frac) + sorted_vals[hi] * frac, 6)


def _cohort_metrics(records: list[dict]) -> dict[str, dict]:
    by_cohort: dict[str, list[dict]] = {}
    for rec in records:
        by_cohort.setdefault(str(rec["cohort"]), []).append(rec)
    out: dict[str, dict] = {}
    for cohort, items in sorted(by_cohort.items()):
        probs = sorted(float(item["max_prob"]) for item in items if item["eval_status"] == "observed")
        or_cnt = sum(1 for item in items if item["tier"] == "or_gate")
        gf_cnt = sum(1 for item in items if item["tier"] == "gated_fusion")
        heur_cnt = sum(1 for item in items if item["heuristic_phishing"])
        vec_totals: dict[str, int] = {}
        for item in items:
            for vec, cnt in (item.get("vector_counts") or {}).items():
                vec_totals[str(vec)] = vec_totals.get(str(vec), 0) + int(cnt)
        out[cohort] = {
            "count": len(items),
            "observed": sum(1 for item in items if item["eval_status"] == "observed"),
            "password_locked": sum(1 for item in items if item["eval_status"] == "password_locked"),
            "ingest_error": sum(1 for item in items if item["eval_status"] == "ingest_error"),
            "missing_or_invalid": sum(1 for item in items if item["eval_status"] in {"missing", "invalid"}),
            "or_gate_count": or_cnt,
            "gated_fusion_count": gf_cnt,
            "or_gate_rate": round(or_cnt / max(len(items), 1), 6),
            "heuristic_phishing_count": heur_cnt,
            "max_prob_p50": _quantile(probs, 0.50),
            "max_prob_p95": _quantile(probs, 0.95),
            "max_prob_p99": _quantile(probs, 0.99),
            "max_prob_max": round(probs[-1], 6) if probs else 0.0,
            "total_scored_urls": sum(int(item["scored_url_count"]) for item in items),
            "total_allowlisted_urls": sum(int(item["allowlisted_url_count"]) for item in items),
            "total_filtered_xml_xmp": sum(int(item["filtered_xml_xmp_count"]) for item in items),
            "vector_counts": vec_totals,
        }
    return out


def export_eval(job_id: str) -> dict:
    if sys.platform != "linux":
        raise ValueError("runtime_unavailable")
    job = jobs.load_job(job_id)
    if job["kind"] != jobs.URI_HEAD_EVAL_KIND or job["mode"] != "offline":
        raise ValueError("job_mismatch")
    metadata = side.verify_release(job["commit"], job["manifest_sha256"])
    jobs.verify_helpers(metadata)
    source = side.RELEASES / job["commit"]
    sys.path.insert(0, str(source / "src"))
    from malpdf.extraction import uri_head_eval_job

    directory = jobs.job_directory(job_id)
    rows = uri_head_eval_job.load_rows(Path(jobs.config()["data_root"]), source_root=source)
    selection = parse_json(side.bounded_read(directory / "selection.json", 4 * 1024**2))
    if selection != {"job_id": job_id, "rows": rows, "selection_sha256": jobs.sha(jobs.encoded(rows))}:
        raise ValueError("manifest_unavailable")
    result = jobs.validate_result(parse_json(side.bounded_read(directory / "result.json", 1024**2)), job)
    if result["status"] not in {"passed", "partial", "failed", "interrupted"}:
        raise ValueError("report_invalid")

    eval_dir = directory / "uri_eval"
    records = []
    for index, row in enumerate(rows):
        identity = row["pdf_sha256"]
        cohort = row["cohort"]
        eval_path = eval_dir / f"{index:04d}.json"
        record = {
            "index": index,
            "sha256": identity,
            "cohort": cohort,
            "eval_status": "missing",
            "max_prob": 0.0,
            "tier": "benign",
            "scored_url_count": 0,
            "allowlisted_url_count": 0,
            "filtered_xml_xmp_count": 0,
            "vector_counts": {},
            "top_url_vector": None,
            "heuristic_phishing": False,
            "password_locked": False,
        }
        if eval_path.exists():
            try:
                raw = parse_json(side.bounded_read(jobs.trusted_path(eval_path), 65536))
                if (
                    raw.get("sha256") != identity
                    or raw.get("cohort") != cohort
                    or raw.get("index") != index
                    or raw.get("eval_status") not in uri_head_eval_job.EVAL_STATUSES
                    or raw.get("tier") not in uri_head_eval_job.TIERS
                ):
                    raise ValueError("invalid")
                record = {
                    "index": index,
                    "sha256": identity,
                    "cohort": cohort,
                    "eval_status": str(raw["eval_status"]),
                    "max_prob": round(float(raw["max_prob"]), 6),
                    "tier": str(raw["tier"]),
                    "scored_url_count": int(raw["scored_url_count"]),
                    "allowlisted_url_count": int(raw["allowlisted_url_count"]),
                    "filtered_xml_xmp_count": int(raw["filtered_xml_xmp_count"]),
                    "vector_counts": {str(k): int(v) for k, v in (raw.get("vector_counts") or {}).items()},
                    "top_url_vector": str(raw["top_url_vector"]) if raw.get("top_url_vector") else None,
                    "heuristic_phishing": bool(raw["heuristic_phishing"]),
                    "password_locked": bool(raw["password_locked"]),
                }
            except (OSError, ValueError, TypeError, KeyError):
                record["eval_status"] = "invalid"
        records.append(record)

    return {
        "schema_version": 1,
        "job_id": job_id,
        "selection_sha256": selection["selection_sha256"],
        "cohort": uri_head_eval_job.contract(),
        "runner_status": result["status"],
        "eval_status_counts": dict(Counter(record["eval_status"] for record in records)),
        "cohort_summary": _cohort_metrics(records),
        "records": records,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("job_id")
    args = parser.parse_args()
    report = jobs.encoded(export_eval(args.job_id))
    if len(report) > 8 * 1024**2:
        raise ValueError("report_invalid")
    sys.stdout.buffer.write(report + b"\n")


if __name__ == "__main__":
    main()
