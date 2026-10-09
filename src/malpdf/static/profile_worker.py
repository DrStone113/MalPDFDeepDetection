"""Bounded one-file profiling that reuses the analyzer and JS inspector."""

from dataclasses import asdict
import hashlib
import json
import math
import multiprocessing
import os
from pathlib import Path
import resource
import time

from malpdf.static.code_inspector import (
    CodeInspectionLimits, _apply_code_limits, _stop_code_process, _worker_count,
)
from malpdf.static.profiling import STAGES, StageTimings
from malpdf.static.safety import read_bounded_bytes, StaticInspectionLimits


def _failure(code, status="worker_error"):
    return {"status": status, "errors": [code], "static": None, "code": None,
            "cache_hit": False, "timings": {name: None for name in STAGES}}


def resident_bytes(pid):
    try:
        return next(int(line.split()[1]) * 1024 for line in Path(f"/proc/{pid}/status").read_text().splitlines() if line.startswith("VmRSS:"))
    except (OSError, StopIteration, ValueError):
        return 0


def cached_profile(record, key, digest):
    from malpdf.static.schema import RIT_FEATURES
    value = record["profile"]
    encoded = json.dumps(value, sort_keys=True, allow_nan=False).encode()
    features = value["static"]["features"]
    if (record["key"] != key or record["profile_sha256"] != hashlib.sha256(encoded).hexdigest()
            or value["status"] != "complete" or not value["code"]["complete"]
            or value["static"]["input"]["sha256"] != digest or set(features) != set(RIT_FEATURES)
            or any(v is not None and (type(v) not in (int, float) or not math.isfinite(v)) for v in features.values())):
        return None
    return value


def _profile_child(connection, path, boundary, digest, limits, cache_path, cache_key):
    def event(kind, name, timings):
        connection.send_bytes(json.dumps({"event": kind, "stage": name, "timings": timings}).encode())

    timings = StageTimings(event)
    applied = None
    try:
        applied = _apply_code_limits(limits)
        with open(os.devnull, "wb") as output:
            os.dup2(output.fileno(), 1)
            os.dup2(output.fileno(), 2)
        with timings.stage("read_hash"):
            data = read_bounded_bytes(Path(path), boundary=Path(boundary), max_bytes=limits.max_file_bytes)
            actual = hashlib.sha256(data).hexdigest()
            if actual != digest:
                raise ValueError("input_checksum_mismatch")
            if not data.startswith(b"%PDF-"):
                raise ValueError("not_pdf")
        cached = None
        if cache_path is not None and Path(cache_path).is_file():
            try:
                content = read_bounded_bytes(Path(cache_path), boundary=Path(cache_path).parent, max_bytes=64 * 1024)
                record = json.loads(content)
                cached = cached_profile(record, cache_key, actual)
            except (OSError, ValueError, KeyError, TypeError):
                pass  # Incomplete, malformed or obsolete entries are cache misses.
        if cached is not None:
            result = {**cached, "cache_hit": True}
        else:
            from malpdf.static.analyzer import StaticPDFAnalyzer
            from malpdf.static.code_inspector import _inspect_code_bytes
            static = StaticPDFAnalyzer(StaticInspectionLimits(max_file_size_bytes=limits.max_file_bytes,
                max_objects=limits.max_objects, max_recursion_depth=limits.max_pdf_depth)).inspect(
                    path, snapshot=data, snapshot_sha256=actual, timings=timings)
            code = _inspect_code_bytes(data, limits, timings=timings)
            # Parser exception messages can contain input content; keep only
            # fixed issue codes. Complete private object/source evidence stays
            # in ignored LAB artifacts, never in aggregate Git reports.
            safe = {"input": {key: static.input[key] for key in ("size_bytes", "sha256")},
                    "features": static.features, "parser": static.parser,
                    "errors": [{"code": item.code, "fatal": item.fatal} for item in static.errors],
                    "warnings": [item.code for item in static.warnings]}
            missing_reference = (any(static.features.get(name) == -1 for name in ("images", "contains_text"))
                or static.diagnostics.get("rit_reference_diagnostics", {}).get("page_text_extraction_error_count", 0) > 0)
            good = (static.parser.get("success") and static.parser.get("structural_complete") and not missing_reference
                    and not static.errors and not static.parser.get("resource_limit_reached")
                    and static.protocol_g_drop3constant_gate().passed)
            status = "complete" if good and code["complete"] else "partial"
            if not static.parser.get("success"):
                status = "parser_error"
            issues = {item.code for item in static.errors} | set(code["errors"])
            if missing_reference:
                issues.add("reference_feature_partial")
            result = {"status": status, "errors": sorted(issues),
                      "static": safe, "code": code, "cache_hit": False}
        if not result["cache_hit"] and result["code"] and result["code"]["complete"] and result["code"]["scripts_found"] == 0:
            timings.seconds["js_ast"] = 0.0
            timings.seconds["stream_decode"] = 0.0
        result.update(timings=dict(timings.seconds), resource_limits=applied,
                      peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024)
    except BaseException as error:
        name = str(error) if str(error) in {"input_checksum_mismatch", "not_pdf"} else type(error).__name__
        result = _failure(name, "input_error" if isinstance(error, (OSError, ValueError)) else "worker_error")
        result["timings"] = dict(timings.seconds)
        if applied is not None:
            result["resource_limits"] = applied
            result["peak_rss_bytes"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    try:
        connection.send_bytes(json.dumps({"event": "result", "profile": result}, allow_nan=False).encode())
    finally:
        connection.close()


def profile_pdf(path, *, boundary, digest, limits=None, cache_path=None, cache_key=None):
    """Profile one PDF in a fresh process; preserve completed stages on kill."""
    limits = limits or CodeInspectionLimits(wall_seconds=20, cpu_seconds=12)
    for name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
        os.environ[name] = "1"
    _worker_count(1, limits)
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_profile_child, args=(sender, str(path), str(boundary), digest, limits,
        None if cache_path is None else str(cache_path), cache_key))
    started = time.monotonic()
    result, last, observed, peak, family_peak = None, None, {name: None for name in STAGES}, 0, 0
    try:
        process.start()
        sender.close()
        while result is None:
            try:
                memory = Path(f"/proc/{process.pid}/status").read_text()
                peak = max([peak] + [int(line.split()[1]) * 1024 for line in memory.splitlines() if line.startswith(("VmRSS:", "VmHWM:"))])
                family_peak = max(family_peak, resident_bytes(process.pid) + resident_bytes(os.getpid()))
            except (OSError, ValueError):
                pass
            ready = receiver.poll()
            exited = not process.is_alive() if not ready else False
            if exited:
                ready = receiver.poll()
            if ready:
                try:
                    message = json.loads(receiver.recv_bytes(maxlength=64 * 1024))
                    if message.get("event") == "result":
                        result = message["profile"]
                    elif message.get("event") in {"started", "finished"} and message.get("stage") in STAGES:
                        last, observed = message["stage"], message["timings"]
                    else:
                        raise ValueError("invalid_profile_message")
                except (ValueError, OSError, EOFError, KeyError):
                    result = _failure("invalid_worker_response")
                    process.join(timeout=0.05)
                    if process.exitcode in (-9, -24):
                        result = _failure("worker_signal_" + str(-process.exitcode), "resource_limit_or_signal")
            elif time.monotonic() - started >= limits.wall_seconds:
                result = _failure("wall_timeout", "timeout")
            elif exited:
                result = _failure("worker_exit", "worker_error")
            if result is None:
                time.sleep(0.005)
        if result["status"] in {"worker_error", "timeout", "resource_limit_or_signal"}:
            result["timings"] = observed
        result["last_stage"] = last
        result["worker_exit_code"] = process.exitcode
        result["peak_rss_bytes"] = max(peak, result.get("peak_rss_bytes", 0))
        result["peak_family_rss_sampled_bytes"] = family_peak
        result["rss_quality"] = "kernel_worker_hwm" if "resource_limits" in result else "sampled_lower_bound"
        result["worker_seconds"] = time.monotonic() - started
        return result
    finally:
        if process.pid is not None:
            _stop_code_process(process)
        receiver.close()
        sender.close()
