"""Static VM extraction over saved, group-consistent Protocol G partitions."""

from collections import Counter, defaultdict
import csv
from dataclasses import asdict
import hashlib
import io
import json
from pathlib import Path
import re
from typing import Any
from itertools import chain

import numpy as np
import yaml

from malpdf.extraction.batch import extract_pdfs
from malpdf.extraction.jobs import MANIFESTS, fingerprint
from malpdf.extraction.orchestrator import processed_output_root
from malpdf.experiments.cic_static_benchmark import verify_label_provenance
from malpdf.provenance.research_runs import ResearchRun, write_json
from malpdf.reproducibility import set_random_seed
from malpdf.static.code_inspector import VMInspectionLimits
from malpdf.static.execution import UNLIMITED, available_cpus
from malpdf.static.safety import read_bounded_bytes
from malpdf.extraction.resume import resume_records, write_sample


def read_manifest(root: Path, spec: dict) -> list[dict]:
    content = read_bounded_bytes(root / spec["path"], boundary=root / "data/processed", max_bytes=UNLIMITED)
    if hashlib.sha256(content).hexdigest() != spec["sha256"]:
        raise ValueError("Saved manifest checksum changed")
    return list(csv.DictReader(io.StringIO(content.decode("utf-8"))))


def select_manifest_rows(manifest: list[dict], sources: list[dict], *,
                         partitions: list[str], cohort: str, boundary: Path) -> list[dict]:
    indexed = {row["sample_id"]: row for row in sources}
    if len(indexed) != len(sources) or len({row["sample_id"] for row in manifest}) != len(manifest):
        raise ValueError("Repeated manifest identity")
    assignments = defaultdict(set)
    labels = defaultdict(set)
    chosen = []
    for row in manifest:
        source = indexed.get(row["sample_id"])
        if source is None or source["Label"] != row["Label"] or row["Label"] not in {"0", "1"}:
            raise ValueError("Manifest/source labels invalid")
        if row["split"] not in {"train", "validation", "test"}:
            raise ValueError("Manifest split invalid")
        groups = {"duplicate_group_id": row["duplicate_group_id"],
                  **{key: source[key] for key in ("pdf_sha256", "related_group_id")}}
        for key, value in groups.items():
            if not value:
                raise ValueError("Missing saved group identity")
            assignments[key, value].add(row["split"])
            if key == "pdf_sha256":
                labels[value].add(row["Label"])
        if row["cohort"] != cohort or row["split"] not in partitions:
            continue
        path = Path(source["pdf_relative_path"])
        if path.is_absolute() or ".." in path.parts or not path.is_relative_to(boundary):
            raise ValueError("PDF path outside its raw boundary")
        if re.fullmatch(r"[a-f0-9]{64}", source["pdf_sha256"]) is None:
            raise ValueError("Invalid saved PDF identity")
        chosen.append({**row, **{key: source[key] for key in
            ("pdf_relative_path", "pdf_sha256", "related_group_id")}})
    if any(len(values) != 1 for values in assignments.values()):
        raise ValueError("Saved file or related/equivalent group crosses partitions")
    if any(len(values) != 1 for values in labels.values()):
        raise ValueError("Saved group has conflicting labels")
    if not chosen:
        raise ValueError("No raw PDF rows in the requested saved partitions")
    return chosen


def load_vm_configuration(root: Path, config: Path) -> tuple[dict, dict, list[dict], VMInspectionLimits]:
    content = read_bounded_bytes(config, boundary=root, max_bytes=UNLIMITED)
    cfg = yaml.safe_load(content)
    required = {"execution_mode", "cohort_config", "cohort", "raw_boundary", "output_root",
                "profile", "seed", "workers", "partitions", "limits"}
    if not isinstance(cfg, dict) or not required <= cfg.keys() or cfg.keys() - required - {"arlington_lock"}:
        raise ValueError("Invalid VM extraction configuration")
    if cfg["execution_mode"] != "vm" or type(cfg["seed"]) is not int or cfg["seed"] != 42:
        raise ValueError("VM extraction requires saved Protocol G seed 42")
    if cfg["profile"] not in {"fast-static", "deep-static"}:
        raise ValueError("VM extraction supports static profiles only")
    partitions = cfg["partitions"]
    if (not isinstance(partitions, list) or not partitions or
            any(value not in {"train", "validation", "test"} for value in partitions) or
            len(set(partitions)) != len(partitions)):
        raise ValueError("Select explicit saved partitions")
    if cfg["workers"] != "auto" and (type(cfg["workers"]) is not int or cfg["workers"] < 1):
        raise ValueError("workers must be a positive integer or auto")
    boundary = Path(cfg["raw_boundary"])
    if boundary.is_absolute() or ".." in boundary.parts or not boundary.is_relative_to("data/raw"):
        raise ValueError("VM raw boundary must be under data/raw")
    processed_output_root(root, root / cfg["output_root"])
    if not isinstance(cfg["limits"], dict):
        raise ValueError("Invalid VM parser capacities")
    limits = VMInspectionLimits(**cfg["limits"])
    cohort_content = read_bounded_bytes(root / cfg["cohort_config"], boundary=root, max_bytes=UNLIMITED)
    cohort_cfg = yaml.safe_load(cohort_content)
    if cohort_cfg["seed"] != 42:
        raise ValueError("Saved cohort seed changed")
    rows = select_manifest_rows(read_manifest(root, cohort_cfg["split_manifest"]),
        read_manifest(root, cohort_cfg["source_manifest"]), partitions=partitions,
        cohort=cfg["cohort"], boundary=boundary)
    verify_label_provenance(rows, read_manifest(root, cohort_cfg["normalization_manifest"]))
    return cfg, cohort_cfg, rows, limits


def run_vm_job(root: Path, config: Path, *, resume_from: str | None = None,
               workers: int | None = None) -> dict[str, Any]:
    from malpdf.extraction.lab import require_lab_isolation
    require_lab_isolation()
    root = Path(root).absolute()
    cfg, cohort, rows, limits = load_vm_configuration(root, Path(config).absolute())
    from malpdf.extraction.environment import environment_metadata
    requested_workers = cfg["workers"] if workers is None else workers
    if requested_workers != "auto" and (type(requested_workers) is not int or requested_workers < 1):
        raise ValueError("workers must be a positive integer or auto")
    effective_workers = min(available_cpus(), len(rows),
        available_cpus() if requested_workers == "auto" else requested_workers)
    code_fingerprint = fingerprint(root, limits, cfg.get("arlington_lock"))
    selection_sha256 = hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()
    cached, resume = resume_records(root, cfg, rows, code_fingerprint, selection_sha256, resume_from)
    methodology = {"protocol": "saved Protocol G static VM extraction", "configuration": cfg,
        "manifest_provenance": {key: cohort[key] for key in MANIFESTS},
        "selection_sha256": selection_sha256, "fingerprint": code_fingerprint,
        "resume": resume, "requested_workers": requested_workers,
        "execution_mode": "vm", "effective_workers": effective_workers,
        "requested_capacities": asdict(limits), "test_access": "test" in cfg["partitions"],
        "fitting": False, "model_evaluation": False}
    with ResearchRun(root, "pdf_extraction_vm", methodology, maintenance=True) as run:
        write_json(run.report / "runtime_environment.json", environment_metadata())
        destination = root / cfg["output_root"] / run.identifier
        destination.mkdir(parents=True, exist_ok=False, mode=0o700)
        write_json(destination / "selection.json", rows)
        set_random_seed(cfg["seed"])
        pending_indices = [index for index in range(len(rows)) if index not in cached]
        statuses, timings, memory = Counter(), [], []
        completed = reused = 0
        run.progress("run_started", planned=len(rows), workers=effective_workers,
                     resume=resume, output_path=str(destination.relative_to(root)))
        def progress(event: dict) -> None:
            run.progress(event["event"], **{key: value for key, value in event.items() if key != "event"},
                         completed=completed, planned=len(rows), reused=reused)
        results = extract_pdfs((root / rows[index]["pdf_relative_path"] for index in pending_indices),
            boundary=root / cfg["raw_boundary"], workers=effective_workers,
            expected_hashes={index: row["pdf_sha256"] for index, row in enumerate(rows)},
            raw_artifact_root=destination / "streams" if cfg["profile"] == "deep-static" else None,
            input_indices=iter(pending_indices), progress=progress,
            limits=limits, profile=cfg["profile"], arlington_lock=cfg.get("arlington_lock"), repository_root=root)
        def restored():
            for index, (path, entry) in sorted(cached.items()):
                content = read_bounded_bytes(path, boundary=root / cfg["output_root"], max_bytes=UNLIMITED)
                if hashlib.sha256(content).hexdigest() != entry["record_sha256"]:
                    pending_indices.append(index)
                    continue
                bundle = json.loads(content)["bundle"]
                bundle["coverage_report"]["provenance"]["reused_from"] = {
                    "run_id": resume_from, "record_path": str(path.relative_to(root)),
                    "record_sha256": entry["record_sha256"]}
                yield index, bundle
        try:
            for index, bundle in chain(restored(), results):
                provenance = bundle["coverage_report"]["provenance"]
                restored_sample = "reused_from" in provenance
                if restored_sample:
                    reused += 1
                    provenance["resumed_by"] = {"commit": run.commit, "worktree": run.state["code_worktree"]}
                else:
                    provenance.update(generating_commit=run.commit, worktree=run.state["code_worktree"])
                row = rows[index]
                write_sample(destination, index, {
                    "sample_id": row["sample_id"], "split": row["split"], "Label": int(row["Label"]),
                    "bundle": bundle})
                statuses[bundle["status"]] += 1
                worker = bundle["coverage_report"]["worker"]
                if not restored_sample and type(worker.get("worker_seconds")) in (float, int):
                    timings.append(worker["worker_seconds"])
                if not restored_sample and type(worker.get("peak_rss_bytes")) is int:
                    memory.append(worker["peak_rss_bytes"])
                completed += 1
                run.progress("sample_finished", input_index=index, completed=completed, planned=len(rows),
                             reused=reused, status=bundle["status"])
        finally:
            try:
                results.close()
            finally:
                run.state.update(rows=completed, reused=reused, planned=len(rows), output_path=str(destination.relative_to(root)),
                    notes="Static VM extraction; saved partitions unchanged; failures retained; model metrics N/A.")
                write_json(run.report / "coverage_summary.json", {"completed": completed, "planned": len(rows),
                    "not_completed": len(rows) - completed, "statuses": dict(statuses),
                    "worker_seconds_median": float(np.median(timings)) if timings else None,
                    "worker_seconds_p99": float(np.percentile(timings, 99)) if timings else None,
                    "peak_worker_rss_bytes": max(memory) if memory else None,
                    "timed_rows": len(timings), "effective_workers": effective_workers,
                    "reused": reused, "newly_extracted": completed - reused, "resume": resume,
                    "test_access": methodology["test_access"], "model_evaluation": False,
                    "pdf_evidence_directory": str(destination.relative_to(root))})
    return run.state
