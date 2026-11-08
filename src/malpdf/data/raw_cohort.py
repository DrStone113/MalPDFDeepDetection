"""Authorized raw-PDF inventory, isolated static features, and a new locked split."""

from collections import Counter
import csv
import hashlib
import io
import json
import math
import multiprocessing
import os
from pathlib import Path
import time

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

from malpdf.data.manifest_validator import validate_sha256
from malpdf.data.rit_pdfmal_split import build_duplicate_group_ids
from malpdf.provenance.research_runs import ResearchRun, write_json
from malpdf.reproducibility import set_random_seed
from malpdf.static.obfuscation import count_escaped_pdf_names
from malpdf.static.raw_scan import scan_raw_pdf_tokens
from malpdf.static.rit_reference import inspect_rit_reference_features
from malpdf.static.safety import read_bounded_bytes, StaticInspectionLimits
from malpdf.static.schema import RIT_FEATURES

RAW_FEATURES = (*RIT_FEATURES, "script_ratio", "ObfuscationCount")


def read_acquired_inventory(root: Path, inputs: list[dict], expected_count: int) -> pd.DataFrame:
    rows, seen = [], set()
    for locked in inputs:
        content = read_bounded_bytes(root / locked["path"], boundary=root / "artifacts/raw_downloads", max_bytes=32 * 1024 * 1024)
        if hashlib.sha256(content).hexdigest() != validate_sha256(locked["sha256"]):
            raise ValueError("Acquisition manifest differs from its checksum lock")
        reader = csv.DictReader(io.StringIO(content.decode("utf-8")))
        for row in reader:
            digest = validate_sha256(row["pdf_sha256"])
            if (None in row or row["sample_id"] != "public_pdf:" + digest or digest in seen
                    or row["Label"] not in {"", "0", "1"} or row["magic_verified"] != "True"):
                raise ValueError("Invalid or repeated acquisition identity/label")
            path = root / row["pdf_relative_path"]
            content = read_bounded_bytes(path, boundary=root / "data/raw", max_bytes=10 * 1024 * 1024)
            if content[:5] != b"%PDF-" or hashlib.sha256(content).hexdigest() != digest or len(content) != int(row["bytes"]):
                raise ValueError("Acquired PDF changed or fails magic/size/checksum")
            seen.add(digest)
            source = row["source"]


            related = "cve_t4pdf_repository" if source.startswith("cve_t4pdf_") else (
                source if source.startswith("contagio_s3_") else "pdf:" + digest)
            rows.append({**row, "related_group_id": related})
    if len(rows) != expected_count or not rows:
        raise ValueError("Acquired inventory count differs from the declared lock")
    return pd.DataFrame(rows).sort_values("sample_id", kind="stable").reset_index(drop=True)


def _feature_child(connection, path, boundary, digest, limits, cpu_seconds, memory_bytes):
    """Only JSON travels back across the parser boundary, never pickled objects."""
    import resource

    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        with open(os.devnull, "wb") as null:
            os.dup2(null.fileno(), 1)
            os.dup2(null.fileno(), 2)
        content = read_bounded_bytes(Path(path), boundary=Path(boundary), max_bytes=limits.max_file_size_bytes)
        if content[:5] != b"%PDF-" or hashlib.sha256(content).hexdigest() != digest:
            raise ValueError("Raw source differs from the preparation lock")
        reference = inspect_rit_reference_features(content, len(content), limits)
        features = {**scan_raw_pdf_tokens(content), **reference.features,
                    "ObfuscationCount": count_escaped_pdf_names(content)}
        features["script_ratio"] = (features["JS"] + features["JavaScript"]) / (1 + features["obj"])
        complete = (reference.success and set(features) == set(RAW_FEATURES)
                    and all(type(v) in (int, float) and math.isfinite(v) for v in features.values())
                    and not any(e.fatal for e in reference.errors))
        connection.send_bytes(json.dumps({"features": features, "complete": complete,
                "errors": [e.code for e in reference.errors], "warnings": [e.code for e in reference.warnings]}, allow_nan=False).encode())
    except BaseException as error:
        connection.send_bytes(json.dumps({"features": {}, "complete": False, "errors": [type(error).__name__], "warnings": []}).encode())
    finally:
        connection.close()


def isolated_features(inventory: pd.DataFrame, root: Path, *, workers=2, wall_seconds=12,
                      cpu_seconds=8, memory_bytes=2 * 1024**3, progress=lambda **counts: None):
    if (not 1 <= workers <= 2 or not 1 <= cpu_seconds <= wall_seconds <= 60
            or not 256 * 1024**2 <= memory_bytes <= 4 * 1024**3):
        raise ValueError("Invalid parser process resource caps")


    context, active, next_row, finished, last = multiprocessing.get_context("fork"), {}, 0, 0, time.monotonic()
    limits = StaticInspectionLimits(max_file_size_bytes=10 * 1024**2)
    try:
        while finished < len(inventory):
            while len(active) < workers and next_row < len(inventory):
                row = inventory.iloc[next_row]
                reader, writer = context.Pipe(duplex=False)
                process = context.Process(target=_feature_child, args=(writer, str(root / row.pdf_relative_path), str(root / "data/raw"), row.pdf_sha256, limits, cpu_seconds, memory_bytes))
                process.start()
                writer.close()
                active[next_row] = (process, reader, time.monotonic())
                next_row += 1
            for position, (process, reader, started) in list(active.items()):
                value = None
                if reader.poll():
                    try:
                        value = json.loads(reader.recv_bytes(maxlength=64 * 1024))
                    except (OSError, EOFError, ValueError):
                        value = {"features": {}, "complete": False, "errors": ["invalid_worker_response"], "warnings": []}
                elif not process.is_alive() or time.monotonic() - started >= wall_seconds:
                    value = {"features": {}, "complete": False, "errors": ["parser_exit_or_timeout"], "warnings": []}
                if value is None:
                    continue
                if process.is_alive():
                    process.terminate()
                process.join(timeout=1)
                if process.is_alive():
                    process.kill()
                    process.join()
                reader.close()
                del active[position]
                if (not isinstance(value, dict) or set(value) != {"features", "complete", "errors", "warnings"}
                        or not isinstance(value["features"], dict) or set(value["features"]) - set(RAW_FEATURES)
                        or any(v is not None and (type(v) not in (int, float) or not math.isfinite(v)) for v in value["features"].values())
                        or type(value["complete"]) is not bool
                        or any(not isinstance(value[k], list) or len(value[k]) > 128 or any(not isinstance(v, str) or len(v) > 128 for v in value[k]) for k in ("errors", "warnings"))
                        or (value["complete"] and (set(value["features"]) != set(RAW_FEATURES) or any(v is None for v in value["features"].values())))):
                    raise ValueError("Parser result violates the bounded feature contract")
                finished += 1
                yield position, value
            if time.monotonic() - last >= 10:
                progress(processed=finished, total=len(inventory))
                last = time.monotonic()
            time.sleep(0.002)
    finally:
        for process, reader, _ in active.values():
            if process.is_alive():
                process.kill()
            process.join()
            reader.close()


def locked_raw_split(table: pd.DataFrame, source: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Group identical vectors, exact PDF identities and known related sources."""
    set_random_seed(42)
    if not table.sample_id.is_unique or set(table.Label) != {0, 1} or set(table.sample_id) != set(source.sample_id):
        raise ValueError("Split inputs must be complete, aligned, binary and unique")
    values = table.loc[:, [*RAW_FEATURES, "Label"]]
    vector_groups = build_duplicate_group_ids(values)
    parent = list(range(len(table)))
    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    indexed = source.set_index("sample_id").loc[table.sample_id]
    for tokens in (vector_groups, indexed.pdf_sha256, indexed.related_group_id):
        first = {}
        for i, token in enumerate(tokens):
            if token in first:
                parent[find(i)] = find(first[token])
            else:
                first[token] = i
    components = {}
    for i in range(len(table)):
        components.setdefault(find(i), []).append(i)
    grouped = np.empty(len(table), dtype=object)
    for positions in components.values():
        group = "component_" + hashlib.sha256("\n".join(sorted(table.iloc[positions].sample_id)).encode()).hexdigest()
        grouped[positions] = group


    held = list(StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42).split(values, table.Label, grouped))
    splits = np.full(len(table), "train", dtype=object)
    splits[held[0][1]], splits[held[1][1]] = "test", "validation"
    manifest = pd.DataFrame({"sample_id": table.sample_id, "duplicate_group_id": grouped,
                             "split": splits, "Label": table.Label.to_numpy()})
    assert_group_partitions(manifest)
    if any(set(manifest.loc[manifest.split.eq(p)].Label) != {0, 1} for p in ("train", "validation", "test")):
        raise ValueError("Every split must contain both binary classes")
    summary = {"seed": 42, "requested_proportions": {"train": 0.6, "validation": 0.2, "test": 0.2},
               "actual_counts": manifest.split.value_counts().to_dict(), "groups": len(components),
               "mixed_label_groups": int(manifest.groupby("duplicate_group_id").Label.nunique().gt(1).sum()),
               "zero_group_overlap": True, "zero_pdf_overlap": True, "zero_related_overlap": True,
               "zero_feature_vector_overlap": True, "scope": "New acquired raw cohort; historical RIT split unchanged"}
    return manifest, summary


def assert_group_partitions(manifest):
    if (not manifest.sample_id.is_unique or manifest.duplicate_group_id.isna().any()
            or not manifest.split.isin(["train", "validation", "test"]).all()
            or manifest.groupby("duplicate_group_id").split.nunique().max() != 1):
        raise ValueError("Saved cohort split is incomplete or leaks a component")


def prepare_raw_cohort(root: Path, config: dict, *, run_id=None):
    with ResearchRun(root, "raw_pdf_cohort", {"configuration": config,
            "policy": "Capped static byte/metadata reads; parser process per file, bounded JSON result, no rendering, action execution or uploads",
            "features": list(RAW_FEATURES), "obfuscation": "raw escaped-name token count; no stream inflation or intent claim",
            "split": "New group-aware Protocol G seed 42; existing RIT split is never regenerated",
            "unavailable_features": "Keep nulls and errors; never impute security features; incomplete rows remain inventoried and require referral"}, run_id=run_id) as run:
        if (not isinstance(config, dict) or set(config) != {"seed", "inputs", "expected_samples", "parser"}
                or config["seed"] != 42 or type(config["expected_samples"]) is not int or not 1 <= config["expected_samples"] <= 100000
                or not isinstance(config["inputs"], list) or not 1 <= len(config["inputs"]) <= 20):
            raise ValueError("Preparation requires an explicit seed-42 bounded inventory configuration")
        inventory = read_acquired_inventory(root, config["inputs"], config["expected_samples"])
        processed = root / "data/processed/raw_pdf_cohort" / run.identifier
        if any(p.is_symlink() for p in (processed, *processed.parents)):
            raise ValueError("Derived path contains a symbolic link")
        processed.mkdir(parents=True, exist_ok=False)
        source_path = processed / "source_pdf_manifest.csv"
        with source_path.open("x", newline="", encoding="utf-8") as f:
            inventory.to_csv(f, index=False)
        source_lock = {"cohort_type": "public_raw_pdf_v1", "status": "completed", "cohort": {
                "path": str(processed.relative_to(root)), "manifest_path": str(source_path.relative_to(root)),
                "manifest_sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(), "sample_count": len(inventory),
                "labels": {"malicious": int(inventory.Label.eq("1").sum()), "benign": int(inventory.Label.eq("0").sum()), "unlabeled": int(inventory.Label.eq("").sum())}},
                "source_inventory": [{"path": row.pdf_relative_path, "sha256": row.pdf_sha256} for row in inventory.itertuples()]}
        write_json(run.artifacts / "source_preparation_report.json", source_lock)
        run.state["source_manifest"] = source_lock["cohort"]["manifest_path"]
        run.state["source_manifest_sha256"] = source_lock["cohort"]["manifest_sha256"]
        run.state["preparation_report"] = str((run.artifacts / "source_preparation_report.json").relative_to(root))
        run.progress("inventory_locked", samples=len(inventory), labeled=int(inventory.Label.isin(["0", "1"]).sum()), unlabeled=int(inventory.Label.eq("").sum()))
        results, failures, reasons = {}, [], Counter()
        partial = processed / "raw_features.csv"
        with partial.open("x", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, fieldnames=["sample_id", "Label", *RAW_FEATURES, "feature_complete"])
            writer.writeheader()
            for position, result in isolated_features(inventory, root, **config["parser"], progress=lambda **c: run.progress("feature_progress", **c)):
                row = inventory.iloc[position]
                record = {"sample_id": row.sample_id, "Label": row.Label, **{k: result["features"].get(k) for k in RAW_FEATURES}, "feature_complete": result["complete"]}
                writer.writerow(record)
                output.flush()
                results[position] = record
                if not result["complete"]:
                    failures.append({"sample_id": row.sample_id, **result})
                    reasons.update(result["errors"] or ["incomplete_reference_features"])
        frame = pd.DataFrame([results[i] for i in sorted(results)])
        eligible = frame.loc[frame.feature_complete & frame.Label.isin(["0", "1"])].drop(columns="feature_complete").copy()
        eligible["Label"] = eligible.Label.astype(int)
        cohort_sources = inventory.set_index("sample_id").loc[eligible.sample_id].reset_index()
        dataset = processed / "complete_labeled_features.csv"
        with dataset.open("x", newline="", encoding="utf-8") as f: eligible.to_csv(f, index=False)
        manifest, split = locked_raw_split(eligible, cohort_sources)
        split_path = processed / "protocol_g_seed42_split_manifest.csv"
        with split_path.open("x", newline="", encoding="utf-8") as f:manifest.to_csv(f, index=False)
        write_json(run.artifacts / "parser_failures.json", failures)
        audit = {"inventory_samples": len(inventory), "complete_features": int(frame.feature_complete.sum()),
                 "labeled_samples": int(frame.Label.isin(["0", "1"]).sum()), "supervised_eligible": len(eligible),
                 "unlabeled": int(frame.Label.eq("").sum()), "parser_incomplete": len(failures),
                 "failure_reasons": dict(reasons), "eligible_label_counts": eligible.Label.value_counts().to_dict(),
                 "raw_features": str(partial.relative_to(root)), "full_feature_schema": list(RAW_FEATURES),
                 "partial_feature_rows_retained": True, "imputed_values": 0, "split": split}
        write_json(run.report / "feature_audit.json", audit)
        run.state.update(audit)
        run.state["inputs"] = {name: {"path": str(path.relative_to(root)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                               for name, path in (("dataset", dataset), ("split_manifest", split_path), ("source_manifest", source_path))}
        run.state["notes"] = "No model evaluation; all raw PDFs inventoried; incomplete features are retained without imputation; supervised eligibility fixed before splitting."
        run.progress("preparation_completed", eligible=len(eligible), incomplete=len(failures), counts=split["actual_counts"])
    return run.state


def finalize_raw_supervised(root: Path, preparation: dict, *, run_id=None):
    """Create a new all-labeled cohort under the user's missing-feature policy.

    Preserve the first preparation and its complete-case split. This new cohort
    explicitly includes missing metadata; later imputation is fitted separately
    on each training fold, and parser failures force referral at inference.
    """
    with ResearchRun(root, "raw_pdf_cohort", {"policy": "Explicit user choice: retain all 19958 labeled samples; training-only imputation and missingness indicators; mandatory referral on parser failures",
            "source_preparation": preparation["report_path"], "features": list(RAW_FEATURES),
            "raw_feature_policy": "Actual lexical/security/obfuscation measurements only; unavailable metadata stays null",
            "split_policy": "New full labeled cohort; no established subset or RIT split regenerated"}, run_id=run_id) as run:
        if preparation["status"] != "completed":
            raise ValueError("Completed static preparation is required")
        frame_bytes = read_bounded_bytes(root / preparation["raw_features"], boundary=root / "data/processed", max_bytes=32 * 1024**2)
        frame = pd.read_csv(io.BytesIO(frame_bytes))
        source = pd.read_csv(root / preparation["source_manifest"], keep_default_na=False)
        if (hashlib.sha256((root / preparation["source_manifest"]).read_bytes()).hexdigest() != preparation["source_manifest_sha256"]
                or not frame.sample_id.is_unique or set(frame.sample_id) != set(source.sample_id)):
            raise ValueError("Static preparation identity/checksum lock differs")
        source = source.set_index("sample_id").loc[frame.sample_id].reset_index()
        if not all((str(int(y)) if pd.notna(y) else "") == s for y, s in zip(frame.Label, source.Label)):
            raise ValueError("Static features contradict original source labels")
        for i, row in source.iterrows():
            content = read_bounded_bytes(root / row.pdf_relative_path, boundary=root / "data/raw", max_bytes=10 * 1024**2)
            if hashlib.sha256(content).hexdigest() != row.pdf_sha256:
                raise ValueError("Raw PDF changed after feature preparation")
            actual = {**scan_raw_pdf_tokens(content), "ObfuscationCount": count_escaped_pdf_names(content)}
            actual["script_ratio"] = (actual["JS"] + actual["JavaScript"]) / (1 + actual["obj"])
            for name, value in actual.items():
                stored = frame.loc[i, name]
                matches = (np.isclose(stored, value, rtol=1e-14, atol=1e-15)
                           if name == "script_ratio" else stored == value)
                if pd.notna(stored) and not matches:
                    raise ValueError("Saved raw security feature differs from actual bytes")
                frame.loc[i, name] = value
            if i % 1000 == 0:
                run.progress("security_measurements_verified", processed=i + 1, total=len(source))
        frame["parser_failed"] = ~frame.feature_complete.astype(bool)
        frame = frame.drop(columns="feature_complete")
        if (np.isinf(frame.loc[:, RAW_FEATURES].to_numpy(dtype=float)).any()
                or frame.ObfuscationCount.isna().any() or frame.script_ratio.isna().any()):
            raise ValueError("Measured security interactions are unavailable/non-finite")
        processed = root / "data/processed/raw_pdf_cohort" / run.identifier
        processed.mkdir(parents=True, exist_ok=False)
        all_features, source_path = processed / "all_raw_features.csv", processed / "source_pdf_manifest.csv"
        with all_features.open("x", newline="", encoding="utf-8") as f:frame.to_csv(f, index=False)
        with source_path.open("x", newline="", encoding="utf-8") as f:source.to_csv(f, index=False)
        labeled = frame.loc[frame.Label.notna()].copy()
        labeled["Label"] = labeled.Label.astype(int)
        dataset = processed / "labeled_features.csv"
        with dataset.open("x", newline="", encoding="utf-8") as f:labeled.to_csv(f, index=False)
        manifest, split = locked_raw_split(labeled, source.loc[source.Label.isin(["0", "1"])])
        split_path = processed / "protocol_g_seed42_split_manifest.csv"
        with split_path.open("x", newline="", encoding="utf-8") as f:manifest.to_csv(f, index=False)
        run.state.update({"inputs": {name: {"path": str(path.relative_to(root)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                        for name, path in (("dataset", dataset), ("split_manifest", split_path), ("source_manifest", source_path), ("all_features", all_features))},
                        "supervised_rows": len(labeled), "unlabeled_rows": int(frame.Label.isna().sum()),
                        "parser_failed_rows": int(frame.parser_failed.sum()), "split": split,
                        "source_raw_features_sha256": hashlib.sha256(frame_bytes).hexdigest(),
                        "notes": "All labeled rows retained; raw metadata missing values preserved. No imputation before split; actual ObfuscationCount verified from source bytes. Parser errors force referral; RIT unchanged."})
        write_json(run.report / "data_provenance.json", run.state["inputs"])
        run.progress("full_supervised_cohort_locked", labeled=len(labeled), unlabeled=int(frame.Label.isna().sum()), counts=split["actual_counts"])
    return run.state
