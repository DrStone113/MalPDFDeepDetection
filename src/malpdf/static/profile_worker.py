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
from malpdf.static.profiling import STAGES, StageTimings, PROFILE_VERSION
from malpdf.static.safety import read_bounded_bytes, StaticInspectionLimits


def _failure(code, status="worker_error"):
    return {"profile_version": PROFILE_VERSION, "status": status, "errors": [code], "reasons": [code], "static": None, "code": None,
            "cache_hit": False, "timings": {name: None for name in STAGES}}


def resident_bytes(pid):
    try:
        return next(int(line.split()[1]) * 1024 for line in Path(f"/proc/{pid}/status").read_text().splitlines() if line.startswith("VmRSS:"))
    except (OSError, StopIteration, ValueError):
        return 0


def current_process_peak_rss():
    # VmHWM describes the current process image. Keep the rusage fallback
    # explicitly identified instead of treating both measurements as equal.
    try:
        value = next(int(line.split()[1]) * 1024 for line in Path("/proc/self/status").read_text().splitlines() if line.startswith("VmHWM:"))
        return value, "proc_vmhwm"
    except (OSError, StopIteration, ValueError):
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024, "rusage_fallback"


def cached_profile(record, key, digest):
    from malpdf.static.schema import RIT_FEATURES
    value = record["profile"]
    encoded = json.dumps(value, sort_keys=True, allow_nan=False).encode()
    features = value["static"]["features"]
    if (record["key"] != key or record["profile_sha256"] != hashlib.sha256(encoded).hexdigest()
            or value["profile_version"] != PROFILE_VERSION or value["status"] != "complete" or not value["code"]["complete"]
            or value["static"]["input"]["sha256"] != digest or set(features) != set(RIT_FEATURES)
            or any(v is not None and (type(v) not in (int, float) or not math.isfinite(v)) for v in features.values())):
        return None
    return value


def _profile_child(connection, path, boundary, digest, limits, cache_path, cache_key, include_v8=False, analysis_version=None):
    v9 = analysis_version == 'v9'
    include_v8 = include_v8 or v9
    output_limit = 6 * 1024**2 if v9 else 2 * 1024**2
    def event(kind, name, timings):
        connection.send_bytes(json.dumps({"event": kind, "stage": name, "timings": timings}).encode())

    timings = StageTimings(event)
    applied = None
    def checkpoint(profile):
        if include_v8:
            payload = json.dumps({'event': 'checkpoint', 'profile': profile}, allow_nan=False).encode()
            if len(payload) > output_limit:
                raise MemoryError('worker_output_limit')
            connection.send_bytes(payload)
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
        if include_v8:
            from malpdf.static.raw_scan import scan_raw_pdf_tokens
            checkpoint({'status': 'partial', 'errors': ['primary_not_finished'], 'static': None, 'code': None,
                        'raw_evidence': {'sha256': actual, 'size_bytes': len(data), 'features': scan_raw_pdf_tokens(data)}})
        cached = None
        if cache_path is not None and Path(cache_path).is_file():
            try:
                content = read_bounded_bytes(Path(cache_path), boundary=Path(cache_path).parent,
                                            max_bytes=output_limit if include_v8 else 64 * 1024)
                record = json.loads(content)
                cached = cached_profile(record, cache_key, actual)
                if include_v8 and cached is not None and cached.get('analysis_v8',{}).get('schema_version') != 'pdf-evidence-v8':
                    cached = None
                if include_v8 and cached is not None and (cached['analysis_v8'].get('status') != 'complete'
                        or cached['analysis_v8'].get('original_bytes_changed') is not False
                        or cached['analysis_v8'].get('active_content_executed') is not False):
                    cached = None
                if v9 and cached is not None and (cached.get('analysis_v9', {}).get('schema_version') != 'pdf-evidence-v9'
                        or not cached['analysis_v9'].get('complete')
                        or cached['analysis_v9'].get('document_sha256') != actual
                        or cached['analysis_v9'].get('original_bytes_changed') is not False
                        or cached['analysis_v9'].get('active_content_executed') is not False):
                    cached = None
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
            # Parser exception messages can contain input content; keep only
            # fixed issue codes. Complete private object/source evidence stays
            # in ignored LAB artifacts, never in aggregate Git reports.
            safe = {"input": {key: static.input[key] for key in ("size_bytes", "sha256")},
                    "features": static.features, "parser": static.parser,
                    "reference_parser_repaired": static.diagnostics.get("rit_reference_diagnostics", {}).get("parser_repaired"),
                    "errors": [{"code": item.code, "fatal": item.fatal} for item in static.errors],
                    "warnings": [item.code for item in static.warnings]}
            checkpoint({'status': 'partial', 'errors': [item.code for item in static.errors] + ['code_not_finished'],
                        'static': safe, 'code': None})
            code = _inspect_code_bytes(data, limits, timings=timings,
                                       **({'evidence_metadata': True} if v9 else {}))
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
            reasons = set(issues)
            if not static.parser.get("structural_complete"):
                reasons.update(item.code for item in static.warnings if item.code.startswith(("structural_", "encrypted_pdf")))
                if not reasons:
                    reasons.add("structural_incomplete")
            if static.parser.get("resource_limit_reached"):
                reasons.add("static_resource_limit")
            if not static.protocol_g_drop3constant_gate().passed:
                reasons.add("feature_gate_failed")
            if not code["complete"] and not code["errors"]:
                reasons.add("code_inspection_incomplete")
            if status != "complete" and not reasons:
                reasons.add("analysis_incomplete")
            result = {"profile_version": PROFILE_VERSION, "status": status, "errors": sorted(issues), "reasons": sorted(reasons),
                      "static": safe, "code": code, "cache_hit": False}
            if include_v8:
                # A crash during the independent backend must not erase primary
                # raw/structure/AST observations already returned by the worker.
                checkpoint(result)
                from malpdf.static.evidence import inspect_evidence
                def legacy_checkpoint(analysis):
                    checkpoint({**result, 'analysis_v8': analysis})
                result['analysis_v8'] = inspect_evidence(data, safe, code, limits, timings=timings,
                    primary_complete=result['status']=='complete',
                    **({'checkpoint': legacy_checkpoint} if v9 else {}))
                if v9:
                    checkpoint(result)
                    from malpdf.static.evidence_v9 import inspect_evidence_v9
                    from malpdf.static.evidence_ipc import WorkerRawSink
                    def evidence_checkpoint(delta):
                        connection.send_bytes(json.dumps({'event': 'evidence_delta', 'delta': delta}, allow_nan=False).encode())
                    result['analysis_v9'] = inspect_evidence_v9(data, safe, code, limits, timings=timings,
                        primary_complete=result['status']=='complete', legacy_analysis=result['analysis_v8'],
                        checkpoint=evidence_checkpoint, raw_sink=WorkerRawSink(connection))
        if not result["cache_hit"] and result["code"] and result["code"]["complete"] and result["code"]["scripts_found"] == 0:
            timings.seconds["js_ast"] = 0.0
            timings.seconds["stream_decode"] = 0.0
        memory, source = current_process_peak_rss()
        result.update(timings=dict(timings.seconds), resource_limits=applied,
                      peak_rss_bytes=memory, rss_source=source)
    except BaseException as error:
        name = str(error) if str(error) in {"input_checksum_mismatch", "not_pdf"} else type(error).__name__
        status = ("resource_limit_or_signal" if include_v8 and isinstance(error,MemoryError) else
                  "input_error" if isinstance(error,(OSError,ValueError)) else "worker_error")
        result = _failure(name,status)
        result["timings"] = dict(timings.seconds)
        if applied is not None:
            result["resource_limits"] = applied
            result["peak_rss_bytes"], result["rss_source"] = current_process_peak_rss()
    try:
        payload = json.dumps({"event": "result", "profile": result}, allow_nan=False).encode()
        if include_v8 and len(payload) > output_limit:
            payload = json.dumps({'event':'result','profile':_failure('worker_output_limit','resource_limit_or_signal')}).encode()
        connection.send_bytes(payload)
    finally:
        connection.close()


def profile_pdf(path, *, boundary, digest, limits=None, cache_path=None, cache_key=None, include_v8=False,
                analysis_version=None, raw_artifact_dir=None):
    """Profile one PDF in a fresh process; preserve completed stages on kill."""
    limits = limits or CodeInspectionLimits(wall_seconds=20, cpu_seconds=12)
    if analysis_version not in (None, 'v8', 'v9'):
        raise ValueError('Unknown evidence analysis version')
    v9 = analysis_version == 'v9'
    include_v8 = include_v8 or analysis_version in {'v8', 'v9'}
    if raw_artifact_dir is not None and not v9:
        raise ValueError('Raw evidence storage requires v9 analysis')
    from malpdf.static.evidence_ipc import EvidenceAccumulator, ParentRawStore
    accumulator = EvidenceAccumulator(digest) if v9 else None
    raw_store = ParentRawStore(raw_artifact_dir) if v9 else None
    for name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
        os.environ[name] = "1"
    _worker_count(1, limits)
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    arguments = (sender, str(path), str(boundary), digest, limits,
        None if cache_path is None else str(cache_path), cache_key, include_v8)
    process = context.Process(target=_profile_child, args=arguments + ((analysis_version,) if v9 else ()))
    started = time.monotonic()
    result, last, observed, peak, family_peak = None, None, {name: None for name in STAGES}, 0, 0
    saved_checkpoint = None
    try:
        process.start()
        sender.close()
        while result is None:
            if time.monotonic() - started >= limits.wall_seconds:
                result = _failure('wall_timeout', 'timeout')
                break
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
                    message = json.loads(receiver.recv_bytes(maxlength=(6 * 1024**2 if v9 else 2 * 1024**2)
                                                             if include_v8 else 64 * 1024))
                    if message.get("event") == "result":
                        result = message["profile"]
                        if v9 and 'analysis_v9' in result:
                            accumulator.merge(result['analysis_v9'])
                            result['analysis_v9'] = accumulator.value
                    elif message.get('event') == 'checkpoint' and include_v8:
                        saved_checkpoint = {**(saved_checkpoint or {}), **message['profile']}
                    elif message.get('event') == 'evidence_delta' and v9:
                        accumulator.merge(message['delta'])
                    elif message.get('event') in {'raw_begin', 'raw_chunk', 'raw_end'} and v9:
                        raw_store.accept(message)
                    elif message.get("event") in {"started", "finished"} and message.get("stage") in STAGES:
                        last, observed = message["stage"], message["timings"]
                    else:
                        raise ValueError("invalid_profile_message")
                except (ValueError, OSError, EOFError, KeyError, TypeError, RecursionError, MemoryError):
                    result = _failure("invalid_worker_response")
                    process.join(timeout=0.05)
                    if process.exitcode in (-9, -24):
                        result = _failure("worker_signal_" + str(-process.exitcode), "resource_limit_or_signal")
            elif time.monotonic() - started >= limits.wall_seconds:
                result = _failure("wall_timeout", "timeout")
            elif exited:
                result = _failure("worker_exit", "worker_error")
            if result is None and not receiver.poll():
                time.sleep(0.005)
        if result["status"] in {"worker_error", "timeout", "resource_limit_or_signal"}:
            result["timings"] = observed
            if saved_checkpoint is not None:
                result.update(static=saved_checkpoint['static'], code=saved_checkpoint['code'],
                    raw_evidence=saved_checkpoint.get('raw_evidence'),
                    primary_status=saved_checkpoint['status'], primary_errors=saved_checkpoint['errors'],
                    analysis_v8={**saved_checkpoint.get('analysis_v8', {}), 'schema_version': 'pdf-evidence-v8',
                        'status': 'resource_limited' if result['status'] in {'timeout','resource_limit_or_signal'} else 'unavailable',
                        'complete': False, 'recovery_success': False, 'errors': result['errors'],
                        'original_bytes_changed': False,
                        'content_redacted': True, 'active_content_executed': False})
            if v9:
                result['analysis_v9'] = accumulator.interrupted(result['errors'])
        if v9:
            result.setdefault('analysis_v9', accumulator.value)
            result['raw_stream_storage'] = {'records': raw_store.records, 'verified_bytes': raw_store.used,
                                           'unfinished_stream': raw_store.active is not None}
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
            if result is not None:
                result['worker_exit_code'] = process.exitcode
                result['worker_cleanup_complete'] = not process.is_alive()
        if raw_store is not None:
            raw_store.close()
        receiver.close()
        sender.close()
