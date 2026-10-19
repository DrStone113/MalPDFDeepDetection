"""Concurrent coordinators for disposable static parser processes."""

from collections.abc import Iterable, Iterator, Mapping
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from collections.abc import Callable
from pathlib import Path
import threading
import re
from typing import Any

from malpdf.extraction.normalize import normalize_profile
from malpdf.extraction.orchestrator import extract_pdf
from malpdf.static.code_inspector import CodeInspectionLimits
from malpdf.static.execution import available_cpus, is_vm


def extract_pdfs(paths: Iterable[Path], *, boundary: Path, workers: int | None = None,
                 expected_hashes: Mapping[int, str] | None = None,
                 raw_artifact_root: Path | None = None, progress: Callable[[dict], None] | None = None,
                 input_indices: Iterable[int] | None = None, **options: Any) -> Iterator[tuple[int, dict]]:
    from malpdf.extraction.lab import require_extraction_platform
    require_extraction_platform()
    count = 1 if workers is None else workers
    if type(count) is not int or count < 1:
        raise ValueError("workers must be a positive integer or auto")
    count = min(count, available_cpus())
    if "cancellation_event" in options or "raw_artifact_dir" in options or "expected_sha256" in options:
        raise ValueError("Batch extraction owns cancellation, identities and artifact directories")
    if expected_hashes is not None and (not isinstance(expected_hashes, Mapping) or
            any(type(index) is not int or index < 0 or not isinstance(digest, str) or
                re.fullmatch(r"[a-f0-9]{64}", digest) is None for index, digest in expected_hashes.items())):
        raise ValueError("Expected hashes must map input positions to SHA-256 identities")
    options.setdefault("limits", CodeInspectionLimits())
    if options.get("arlington_lock") is not None:
        from malpdf.extraction.arlington_model import load_model, ModelUnavailable
        if options.get("repository_root") is None or options.get("profile", "deep-static") != "deep-static":
            raise ValueError("Arlington requires an explicit repository root and deep-static profile")
        try:
            catalog = load_model(options["repository_root"], options["arlington_lock"])
        except ModelUnavailable:
            pass
        else:
            options.pop("arlington_lock")
            options["arlington_catalog"] = catalog
    cancellation = threading.Event()
    if input_indices is None:
        inputs = iter(enumerate(paths))
    else:
        inputs = iter(zip(input_indices, paths, strict=True))
    submitted = set()
    executor = ThreadPoolExecutor(max_workers=count, thread_name_prefix="pdf-coordinator")
    pending = {}

    def submit() -> bool:
        try:
            index, path = next(inputs)
        except StopIteration:
            return False
        if type(index) is not int or index < 0 or index in submitted:
            raise ValueError("Batch input indices must be unique nonnegative integers")
        if expected_hashes is not None and index not in expected_hashes:
            raise ValueError("Missing expected hash for batch input")
        storage = None if raw_artifact_root is None else Path(raw_artifact_root) / f"sample_{index:08d}"
        future = executor.submit(extract_pdf, path, boundary=boundary,
            expected_sha256=None if expected_hashes is None else expected_hashes.get(index),
            raw_artifact_dir=storage, cancellation_event=cancellation, **options)
        pending[future] = index
        submitted.add(index)
        if progress is not None:
            progress({"event": "sample_started", "input_index": index, "in_flight": len(pending)})
        return True

    try:
        for _ in range(count):
            if not submit():
                break
        while pending:
            completed, _ = wait(pending, timeout=5, return_when=FIRST_COMPLETED)
            if not completed and progress is not None:
                progress({"event": "workers_active", "in_flight": len(pending),
                          "input_indices": sorted(pending.values())})
            for future in completed:
                index = pending.pop(future)
                try:
                    bundle = future.result()
                except Exception as error:
                    bundle = normalize_profile({"status": "worker_error", "errors": [
                        "sample_extraction_failed", type(error).__name__]}, None,
                        options.get("profile", "deep-static"), provenance={"seed": 42,
                            "execution_mode": "vm" if is_vm(options['limits']) else "bounded", "input_index": index})
                submission_error = None
                try:
                    submit()
                except Exception as error:
                    submission_error = error
                yield index, bundle
                if submission_error is not None:
                    raise submission_error
    finally:
        cancellation.set()
        for future in pending:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
