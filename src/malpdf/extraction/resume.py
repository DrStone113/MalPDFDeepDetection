"""Verify completed VM records and retained blobs before reusing extraction."""

import hashlib
import json
from pathlib import Path
import re

from malpdf.extraction.contracts import validate_bundle
from malpdf.static.execution import UNLIMITED
from malpdf.static.safety import read_bounded_bytes


def read_json(path: Path, boundary: Path) -> dict:
    return json.loads(read_bounded_bytes(path, boundary=boundary, max_bytes=UNLIMITED))


def write_sample(directory: Path, index: int, record: dict) -> dict:
    name = f"sample_{index:08d}.json"
    content = (json.dumps(record, allow_nan=False, separators=(",", ":")) + "\n").encode()
    with (directory / name).open("xb") as output:
        output.write(content)
    entry = {"input_index": index, "sample_id": record["sample_id"], "path": name,
             "record_sha256": hashlib.sha256(content).hexdigest()}
    with (directory / "completed_samples.jsonl").open("a", encoding="utf-8") as journal:
        journal.write(json.dumps(entry, separators=(",", ":")) + "\n")
        journal.flush()
    return entry


def reusable_bundle(bundle: dict) -> bool:
    worker = bundle["coverage_report"]["worker"]
    return (worker.get("worker_result_received") is True and worker.get("worker_cleanup_complete") is True
            and worker.get("status") in {"complete", "partial", "parser_error"})


def verify_blobs(root: Path, directory: Path, index: int, bundle: dict) -> None:
    if bundle["extraction_profile"] != "deep-static":
        return
    actual = bundle["coverage_report"]["provenance"].get("raw_artifact_directory")
    if not isinstance(actual, str):
        raise ValueError("resume_blob_directory_changed")
    expected = Path(actual)
    if (not expected.is_absolute() or ".." in expected.parts
            or expected.name != f"sample_{index:08d}" or expected.parent.name != "streams"
            or expected.parent.parent.parent != directory.parent
            or re.fullmatch(r"run_[A-Za-z0-9_-]{1,100}", expected.parent.parent.name) is None
            or any(path.is_symlink() for path in (expected, *expected.parents))):
        raise ValueError("resume_blob_directory_changed")
    stores = [record["details"]["storage"] for record in bundle["evidence_store"]["records"]
              if record["kind"] == "stream_analysis"]
    if len(stores) != 1 or stores[0].get("unfinished_stream") is not False:
        raise ValueError("resume_blob_ledger_incomplete")
    for record in stores[0]["records"]:
        digest = record["sha256"]
        if record["status"] != "verified" or re.fullmatch(r"[a-f0-9]{64}", digest) is None:
            raise ValueError("resume_blob_unverified")
        content = read_bounded_bytes(expected / (digest + ".bin"), boundary=root / "data/processed", max_bytes=UNLIMITED)
        if len(content) != record["size_bytes"] or hashlib.sha256(content).hexdigest() != digest:
            raise ValueError("resume_blob_checksum_changed")


def resume_records(root: Path, cfg: dict, rows: list[dict], fingerprint: dict,
                   selection_sha256: str, source_run: str | None) -> tuple[dict[int, tuple[Path, dict]], dict]:
    info = {"source_run": source_run, "status": "not_requested", "eligible": 0, "rejected": 0}
    accepted = {}
    if source_run is None:
        return accepted, info
    if re.fullmatch(r"run_[A-Za-z0-9_-]{1,100}", source_run) is None:
        raise ValueError("Invalid VM resume run identifier")
    report = root / "reports/experiments/pdf_extraction_vm" / source_run
    summary = read_json(report / "run_summary.json", root / "reports/experiments")
    method = read_json(report / "locked_methodology.json", root / "reports/experiments")
    if summary["status"] not in {"completed", "interrupted", "failed"}:
        raise ValueError("Resume requires a finished VM invocation")
    if method.get("fingerprint") != fingerprint or method.get("selection_sha256") != selection_sha256:
        info.update(status="incompatible", reason="code_environment_or_selection_changed")
        return accepted, info
    directory = root / summary["output_path"]
    boundary = root / cfg["output_root"]
    if (".." in directory.parts or not directory.is_relative_to(boundary) or
            any(path.is_symlink() for path in (directory, *directory.parents))):
        raise ValueError("Unsafe resume output path")
    if read_json(directory / "selection.json", boundary) != rows:
        raise ValueError("Resume selection differs from the saved manifest")
    journal = directory / "completed_samples.jsonl"
    if not journal.is_file():
        info.update(status="incompatible", reason="completion_journal_unavailable")
        return accepted, info
    seen = set()
    content = read_bounded_bytes(journal, boundary=boundary, max_bytes=UNLIMITED)
    for line in content.splitlines():
        index = None
        try:
            entry = json.loads(line)
            index = entry["input_index"]
            if type(index) is not int or not 0 <= index < len(rows) or index in seen:
                raise ValueError("resume_index_invalid")
            seen.add(index)
            row = rows[index]
            if entry["sample_id"] != row["sample_id"] or entry["path"] != f"sample_{index:08d}.json":
                raise ValueError("resume_occurrence_changed")
            path = directory / entry["path"]
            saved = read_bounded_bytes(path, boundary=boundary, max_bytes=UNLIMITED)
            if hashlib.sha256(saved).hexdigest() != entry["record_sha256"]:
                raise ValueError("resume_record_changed")
            record = json.loads(saved)
            if (record["sample_id"] != row["sample_id"] or record["split"] != row["split"]
                    or type(record["Label"]) is not int or record["Label"] != int(row["Label"])):
                raise ValueError("resume_identity_changed")
            bundle = validate_bundle(record["bundle"])
            if (bundle["sample_sha256"] != row["pdf_sha256"] or bundle["extraction_profile"] != cfg["profile"]
                    or not reusable_bundle(bundle)):
                raise ValueError("resume_worker_unfinished")
            original = read_bounded_bytes(root / row["pdf_relative_path"], boundary=root / cfg["raw_boundary"], max_bytes=UNLIMITED)
            if hashlib.sha256(original).hexdigest() != row["pdf_sha256"]:
                raise ValueError("resume_input_changed")
            verify_blobs(root, directory, index, bundle)
            accepted[index] = (path, entry)
        except (OSError, ValueError, KeyError, TypeError):
            if type(index) is int:
                accepted.pop(index, None)
            info["rejected"] += 1
    info.update(status="verified", eligible=len(accepted))
    return accepted, info
