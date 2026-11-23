from __future__ import annotations

import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import gzip
from hashlib import file_digest, sha256
import json
from pathlib import Path
import re


POOL_SHA256 = "24a202d8307ec4f52798d09e3a2cc6ad60ce6c774175a058ea7342c394e14bf2"
CIC_SHA256 = "25db2059d59207d2040c5a999838514579ed4667b2b7fa39f2398dee484caf65"
LAB_TABLE_SHA256 = "6ca22c2cedc0afc02468576e62c44c4e519c96540713dc33b3033e3a559e59a6"
ACQUISITION_SHA256 = "c4e59ad6040dbd6b2ebeba9142d68979a789c2c8d3ecb5f9c27616c72f7dc6f8"
HEX256 = re.compile(r"[a-f0-9]{64}\Z")
COMPARE = {"PdfSize": "raw_size_bytes", "Obj": "lexical_obj", "Endobj": "lexical_endobj",
           "Stream": "lexical_stream", "Endstream": "lexical_endstream", "JS": "lexical_JS",
           "Javascript": "lexical_JavaScript", "Pages": "canonical_pages", "PageNo": "lexical_page_command"}


def digest(path):
    with path.open("rb") as source:
        return file_digest(source, "sha256").hexdigest()


def require_digest(path, expected):
    if digest(path) != expected:
        raise ValueError(f"audit_input_changed:{path.name}")


def historical_scan_evidence(report):
    if not isinstance(report, dict):
        return None
    target = report.get("sha256")
    positives, total, date = (report.get(key) for key in ("positives", "total", "scan_date"))
    scans = report.get("scans")
    if (not isinstance(target, str) or not HEX256.fullmatch(target.lower()) or report.get("response_code") != 1
            or type(total) is not int or type(positives) is not int or not 0 <= positives <= total
            or not isinstance(scans, dict) or len(scans) != total or not isinstance(date, str)):
        return None
    if not all(isinstance(vote, dict) and type(vote.get("detected")) is bool for vote in scans.values()):
        return None
    if sum(vote["detected"] for vote in scans.values()) != positives:
        return None
    try:
        datetime.strptime(date, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    return target.lower(), positives, total, date


def resolve_training_label(label, source, historical_positive):
    if source == "cic_protocol_g_verified":
        return None, "cic_identity_review"
    if historical_positive and label == 0:
        return None, "conflicting_source_evidence"
    if historical_positive and label is None:
        return 1, "zenodo2017_exact_historical_consensus"
    return label, source


def collect_zenodo(root):
    root = root.resolve(strict=True)
    acquisition = root / "manifest.csv"
    require_digest(acquisition, ACQUISITION_SHA256)
    with acquisition.open(newline="", encoding="utf-8") as handle:
        members = [row for row in csv.DictReader(handle)
                   if row["source"] == "zenodo_3464032_malware_2017" and row["filename"].lower().endswith(".json")]
    if len(members) != 2261:
        raise ValueError("unexpected_zenodo_metadata_population")
    fact_rows, rejected = [], Counter()
    for row in members:
        path = (root / row["stored_relpath"]).resolve(strict=True)
        if not path.is_relative_to(root):
            raise ValueError("zenodo_metadata_path_outside_acquisition")
        with path.open("rb") as source:
            body = source.read(2_000_001)
        if len(body) > 2_000_000 or sha256(body).hexdigest() != row["sha256"]:
            raise ValueError("zenodo_metadata_member_identity")
        try:
            fact = historical_scan_evidence(json.loads(body))
        except (ValueError, RecursionError):
            fact = None
        if fact is None:
            rejected["missing_or_inconsistent_verdict"] += 1
            continue
        target, positives, total, date = fact
        fact_rows.append({"report_sha256": row["sha256"], "pdf_sha256": target, "positive_engines": positives,
                          "total_engines": total, "scan_date": date})
    return {"acquisition_sha256": ACQUISITION_SHA256, "members": len(members),
            "rejected": dict(rejected), "facts": fact_rows}


def compare_cic(cic_path, observed_path):
    import numpy as np
    import pandas as pd

    require_digest(cic_path, CIC_SHA256)
    require_digest(observed_path, LAB_TABLE_SHA256)
    cic = pd.read_parquet(cic_path, columns=["FileName", *COMPARE])
    with gzip.open(observed_path, "rt", encoding="utf-8") as stream:
        observed = pd.DataFrame([{"FileName": row["sha256"], **{f"lab_{k}": row["features"].get(v, {}).get("value")
                    for k, v in COMPARE.items()}} for row in map(json.loads, stream)])
    matched = observed.merge(cic, on="FileName", validate="one_to_one")
    if len(matched) != len(observed) or len(matched) != 1452:
        raise ValueError("unexpected_cic_exact_match_count")
    summary = {}
    for key in COMPARE:
        pairs = matched[[key, f"lab_{key}"]].apply(pd.to_numeric, errors="coerce").dropna()
        cic_values, lab_values = (pairs[column] for column in pairs.columns)
        if key == "PdfSize":
            lab_values = np.floor(lab_values / 1000)
        summary[key] = {"pairs": len(pairs), "equal": int((cic_values == lab_values).sum()),
                        "pearson": float(cic_values.corr(lab_values)),
                        "spearman": float(cic_values.corr(lab_values, method="spearman"))}
    return {"pairs_by_sha256": len(matched), "features": summary, "PdfSize_units": "floor(measured_bytes / 1000)"}


def build_view(pool, evidence, destination):
    strong, conflicting = set(), set()
    by_target = {}
    for row in evidence["facts"]:
        target, votes, total = (row[k] for k in ("pdf_sha256", "positive_engines", "total_engines"))
        by_target.setdefault(target, []).append((votes, total))
    for target, reports in by_target.items():
        if any(total >= 20 and votes >= 5 for votes, total in reports):
            (conflicting if any(total >= 20 and votes == 0 for votes, total in reports) else strong).add(target)
    require_digest(pool, POOL_SHA256)
    counts, eligible, transitions, historical_matches = Counter(), Counter(), Counter(), Counter()
    seen = set()
    with gzip.open(pool, "rt", encoding="ascii") as stream, destination.open("x", encoding="ascii", newline="\n") as out:
        header = json.loads(next(stream))
        out.write(json.dumps({"schema_version": 1, "pool_sha256": POOL_SHA256, "feature_names": header["features"]}) + "\n")
        for sha, old, source, status, fields, graph in map(json.loads, stream):
            if sha in seen or not HEX256.fullmatch(sha) or old not in (0, 1, None):
                raise ValueError("unexpected_pool_identity_or_label")
            seen.add(sha)
            if sha in by_target:
                historical_matches["exact_pool_matches"] += 1
                historical_matches["consensus_positive_matches"] += int(sha in strong)
                historical_matches["inconsistent_report_matches"] += int(sha in conflicting)
            label, updated_source = resolve_training_label(old, source, sha in strong)
            if sha in conflicting and source != "cic_protocol_g_verified":
                label, updated_source = None, "conflicting_historical_reports"
            counts[str(label)] += 1
            eligible["ssl_table"] += int(label is None and any(value is not None for value in fields))
            eligible["ssl_graph"] += int(label is None and graph is not None)
            eligible["supervised_graph"] += int(label is not None and graph is not None)
            if updated_source != source:
                transitions[updated_source] += 1
            out.write(json.dumps({"sha256": sha, "label": label, "label_source": updated_source,
                                  "status": status, "graph_available": graph is not None}, separators=(",", ":")) + "\n")
    if len(seen) != 41727 or transitions["cic_identity_review"] != 1452:
        raise ValueError("unexpected_supervised_cohort")
    return {"pdfs": len(seen), "label_counts": dict(counts), "eligible": dict(eligible),
            "label_transitions": dict(transitions), "historical_report_matches": dict(historical_matches),
            "unique_report_targets": len(by_target), "view_sha256": digest(destination)}


def main():
    parser = argparse.ArgumentParser(description="Audit pinned, local label evidence for the common PDF pool")
    commands = parser.add_subparsers(dest="command", required=True)
    remote = commands.add_parser("zenodo-reports")
    remote.add_argument("--bulk-root", type=Path, required=True)
    local = commands.add_parser("audit")
    for name in ("pool", "cic", "lab-table", "history", "run-directory", "label-view"):
        local.add_argument(f"--{name}", required=True, type=Path)
    args = parser.parse_args()
    if args.command == "zenodo-reports":
        print(json.dumps(collect_zenodo(args.bulk_root), separators=(",", ":")))
        return
    historical = json.loads(args.history.read_text(encoding="utf-8-sig"))
    if historical["acquisition_sha256"] != ACQUISITION_SHA256 or historical["members"] != 2261:
        raise ValueError("unexpected_lab_metadata_evidence")
    qa = compare_cic(args.cic, args.lab_table)
    out = args.run_directory
    out.mkdir(parents=True, exist_ok=False)
    inputs = [args.pool, args.cic, args.lab_table, args.history, Path(__file__)]
    (out / "locked_methodology.json").write_text(json.dumps({
        "started_utc": datetime.now(timezone.utc).isoformat(), "input_sha256": {p.name: digest(p) for p in inputs},
        "historical_positive_policy": {"min_engines": 20, "min_positive_engines": 5, "exact_sha256": True},
        "known_review": "Quarantine the 1452 CIC manifest labels in this training view",
        "remote_reputation_queries": 0,
    }, indent=2) + "\n", encoding="utf-8")
    result = {"cic_alignment": qa, "zenodo_metadata_members": historical["members"],
              "zenodo_valid_reports": len(historical["facts"]), "zenodo_rejected_reports": historical["rejected"],
              "label_view": build_view(args.pool, historical, args.label_view)}
    (out / "metrics.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
