"""Inert PDF JavaScript inspection in disposable, resource-limited processes.

The pypdf parser may internally decode xref/object streams. OS process limits
cover those operations too. This is parser isolation, not a dynamic sandbox.
Only catalog-reachable JavaScript is inspected; no payload is written to disk.
"""

from dataclasses import asdict, dataclass
from collections import Counter
import io
import hashlib
import json
import multiprocessing
import os
import re
from pathlib import Path
import time
import zlib

from malpdf.static.js_ast import CALL_NAMES, CodeInspectionError, inspect_js_syntax
from malpdf.static.safety import read_bounded_bytes

SECURITY_NAMES = frozenset({"/JS", "/JavaScript", "/OpenAction", "/AA", "/Launch",
    "/EmbeddedFile", "/EmbeddedFiles", "/XFA", "/AcroForm", "/JBIG2Decode", "/RichMedia", "/URI"})


@dataclass(frozen=True)
class CodeInspectionLimits:
    max_file_bytes: int = 10 * 1024**2
    max_objects: int = 2000
    max_pdf_depth: int = 64
    max_scripts: int = 64
    max_script_bytes: int = 256 * 1024
    max_decoded_bytes: int = 4 * 1024**2
    max_ast_nodes: int = 20_000
    max_ast_depth: int = 100
    wall_seconds: int = 8
    cpu_seconds: int = 4
    memory_bytes: int = 1024**3

    def __post_init__(self):
        if any(type(value) is not int or value <= 0 for value in asdict(self).values()):
            raise ValueError("Code inspection limits must be positive integers")
        if (self.max_file_bytes > 50 * 1024**2 or self.max_objects > 10_000
                or self.max_pdf_depth > 100 or self.max_scripts > 128
                or self.max_script_bytes > 1024**2 or self.max_decoded_bytes > 8 * 1024**2
                or self.max_ast_nodes > 100_000 or self.max_ast_depth > 200
                or not self.cpu_seconds <= self.wall_seconds <= 60
                or not 512 * 1024**2 <= self.memory_bytes <= 2 * 1024**3):
            raise ValueError("Code inspection exceeds the allowed resource budget")


def _unavailable(code):
    return {"status": "unavailable", "complete": False, "referral_recommended": True,
            "scripts_found": None, "scripts_parsed": None, "ast": None,
            "structural_indicators": None, "errors": [code],
            "scope": "catalog-reachable syntax evidence only",
            "content_redacted": True, "active_content_executed": False}


def _script_text(value, limits):
    from pypdf.generic import ByteStringObject, StreamObject, TextStringObject, NullObject

    if isinstance(value, TextStringObject):
        text = str(value)
    elif isinstance(value, ByteStringObject):
        text = bytes(value).decode("utf-8", errors="strict")
    elif isinstance(value, StreamObject):
        # pypdf 5.x exposes encoded stream bytes here. Do not call get_data().
        data = value._data
        if not isinstance(data, bytes) or len(data) > limits.max_file_bytes:
            raise CodeInspectionError("invalid_script_stream")
        filters = value.get("/Filter", [])
        filters = filters if isinstance(filters, list) else [filters]
        if len(filters) > 3:
            raise CodeInspectionError("stream_filter_limit")
        parms = value.get("/DecodeParms")
        if parms is not None and not isinstance(parms, NullObject):
            raise CodeInspectionError("unsupported_decode_parameters")
        for filter_name in filters:
            if str(filter_name) not in {"/FlateDecode", "/Fl"}:
                raise CodeInspectionError("unsupported_script_filter")
            decoder = zlib.decompressobj()
            data = decoder.decompress(data, limits.max_script_bytes + 1)
            if len(data) > limits.max_script_bytes or decoder.unconsumed_tail:
                raise CodeInspectionError("script_byte_limit")
            if not decoder.eof or decoder.unused_data:
                raise CodeInspectionError("invalid_flate_stream")
        if len(data) > limits.max_script_bytes:
            raise CodeInspectionError("script_byte_limit")
        text = data.decode("utf-8", errors="strict")
    else:
        raise CodeInspectionError("unsupported_script_object")
    if len(text.encode("utf-8")) > limits.max_script_bytes:
        raise CodeInspectionError("script_byte_limit")
    return text


def _inspect_code_bytes(data, limits):
    """Internal parser routine: production access must use inspect_pdf_code(s)."""
    from pypdf import PdfReader
    from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject

    if len(data) > limits.max_file_bytes or not data.startswith(b"%PDF-"):
        return _unavailable("not_pdf_or_byte_limit")
    reader = PdfReader(io.BytesIO(data), strict=True)
    if reader.is_encrypted:
        return _unavailable("encrypted_pdf")
    errors, seen, scripts_seen = set(), set(), set()
    indicators = Counter({name[1:]: 0 for name in sorted(SECURITY_NAMES)})
    nodes, calls = Counter(), Counter({name: 0 for name in sorted(CALL_NAMES)})
    found = parsed = decoded = total_nodes = depth_max = loops = computed = visited = 0

    def resolve(value):
        return value.get_object() if isinstance(value, IndirectObject) else value

    # Iterator frames bound breadth without constructing an untrusted big stack.
    frames = [(iter([reader.trailer.raw_get("/Root")]), 0)]
    while frames:
        iterator, depth = frames[-1]
        try:
            value = next(iterator)
        except StopIteration:
            frames.pop()
            continue
        visited += 1
        if visited > limits.max_objects or depth > limits.max_pdf_depth:
            errors.add("pdf_structure_limit")
            break
        if isinstance(value, IndirectObject):
            key = (value.idnum, value.generation)
            if key in seen:
                continue
            seen.add(key)
        value = resolve(value)
        if isinstance(value, DictionaryObject):
            indicators.update(str(k)[1:] for k in value if str(k) in SECURITY_NAMES)
            for name in ("/S", "/Type", "/Subtype", "/Filter"):
                item = value.get(name)
                items = item if isinstance(item, ArrayObject) else (item,)
                if len(items) > limits.max_objects:
                    errors.add("pdf_structure_limit")
                    break
                indicators.update(str(v)[1:] for v in items if str(v) in SECURITY_NAMES)
            if "/JS" in value:
                script = value.raw_get("/JS")
                key = ((script.idnum, script.generation) if isinstance(script, IndirectObject)
                       else ("direct", id(script)))
                if key not in scripts_seen:
                    scripts_seen.add(key)
                    found += 1
                    if found > limits.max_scripts:
                        errors.add("script_count_limit")
                        break
                    try:
                        text = _script_text(resolve(script), limits)
                        decoded += len(text.encode("utf-8"))
                        if decoded > limits.max_decoded_bytes:
                            raise CodeInspectionError("decoded_byte_limit")
                        ast = inspect_js_syntax(text, max_bytes=limits.max_script_bytes,
                            max_nodes=limits.max_ast_nodes - total_nodes, max_depth=limits.max_ast_depth)
                        parsed += 1
                        total_nodes += ast["node_count"]
                        depth_max = max(depth_max, ast["max_depth"])
                        loops += ast["loops"]
                        computed += ast["computed_members"]
                        nodes.update(ast["node_types"])
                        calls.update(ast["named_calls"])
                    except CodeInspectionError as error:
                        errors.add(str(error))
                        if str(error) in {"decoded_byte_limit", "ast_node_limit"}:
                            break
                    except (UnicodeError, zlib.error):
                        errors.add("script_decode_error")
            frames.append((iter(value.values()), depth + 1))
        elif isinstance(value, ArrayObject):
            frames.append((iter(value), depth + 1))
    return {"status": "partial" if errors else "complete", "complete": not errors,
            "referral_recommended": bool(errors or sum(calls.values()) or indicators["Launch"] or indicators["EmbeddedFile"]),
            "scripts_found": found, "scripts_parsed": parsed,
            "ast": {"node_count": total_nodes, "max_depth": depth_max, "node_types": dict(sorted(nodes.items())),
                    "named_calls": dict(calls), "loops": loops, "computed_members": computed},
            "structural_indicators": dict(indicators), "errors": sorted(errors),
            "scope": "catalog-reachable syntax evidence only", "content_redacted": True,
            "active_content_executed": False}


def _code_child(connection, path, boundary, limits, expected_sha256):
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
        resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))
        resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
        with open(os.devnull, "wb") as null:
            os.dup2(null.fileno(), 1)
            os.dup2(null.fileno(), 2)
        data = read_bounded_bytes(Path(path), boundary=Path(boundary), max_bytes=limits.max_file_bytes)
        if expected_sha256 is not None and hashlib.sha256(data).hexdigest() != expected_sha256:
            result = _unavailable("input_snapshot_mismatch")
        else:
            result = _inspect_code_bytes(data, limits)
    except BaseException as error:
        result = _unavailable("inspection_failed_" + type(error).__name__)
    try:
        connection.send_bytes(json.dumps(result, allow_nan=False).encode())
    finally:
        connection.close()


def _worker_count(requested, limits):
    from malpdf.data.markov_preparation import effective_cpu_count

    if type(requested) is not int or not 1 <= requested <= 16:
        raise ValueError("workers must be an integer between 1 and 16")
    available = next(int(line.split()[1]) * 1024 for line in Path("/proc/meminfo").read_text().splitlines()
                     if line.startswith("MemAvailable:"))
    maximum, current = Path("/sys/fs/cgroup/memory.max"), Path("/sys/fs/cgroup/memory.current")
    if maximum.is_file() and current.is_file() and maximum.read_text().strip() != "max":
        available = min(available, max(0, int(maximum.read_text()) - int(current.read_text())))
    count = min(requested, effective_cpu_count(), max(0, (available - 256 * 1024**2) // limits.memory_bytes))
    if count < 1:
        raise ValueError("Insufficient available RAM for the isolated parser budget")
    return count


def inspect_pdf_codes(paths, *, boundary, limits=None, workers=2, expected_hashes=None):
    """Yield (input position, redacted evidence), with bounded Linux spawn jobs.

    Results may complete out of order. Close the iterator on early termination.
    No child executes sample code; OS limits isolate parser failures only.
    """
    limits = limits or CodeInspectionLimits()
    if expected_hashes is not None and (not isinstance(expected_hashes, dict)
            or any(type(key) is not int or key < 0 or not isinstance(value, str)
                   or re.fullmatch(r"[0-9a-f]{64}", value) is None for key, value in expected_hashes.items())):
        raise ValueError("Expected hashes must map input positions to lowercase SHA-256")
    if os.name != "posix" or not Path("/proc/meminfo").is_file():
        raise ValueError("Resource-limited code inspection requires Linux")
    for name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
        os.environ[name] = "1"
    workers = _worker_count(workers, limits)
    context, active, inputs = multiprocessing.get_context("spawn"), {}, iter(enumerate(paths))
    exhausted = False
    try:
        while not exhausted or active:
            while not exhausted and len(active) < workers:
                try:
                    position, path = next(inputs)
                except StopIteration:
                    exhausted = True
                    break
                receiver, sender = context.Pipe(duplex=False)
                if expected_hashes is not None and position not in expected_hashes:
                    receiver.close()
                    sender.close()
                    raise ValueError("Every input needs its expected SHA-256")
                expected = None if expected_hashes is None else expected_hashes[position]
                process = context.Process(target=_code_child, args=(sender, str(path), str(boundary), limits, expected))
                try:
                    process.start()
                except BaseException:
                    receiver.close()
                    sender.close()
                    raise
                sender.close()
                active[position] = process, receiver, time.monotonic()
            for position, (process, receiver, started) in list(active.items()):
                result = None
                if receiver.poll():
                    try:
                        result = json.loads(receiver.recv_bytes(maxlength=64 * 1024))
                        if (not isinstance(result, dict) or type(result.get("complete")) is not bool
                                or result.get("active_content_executed") is not False
                                or result.get("content_redacted") is not True):
                            raise ValueError("Invalid worker evidence")
                    except (EOFError, OSError, ValueError):
                        result = _unavailable("invalid_worker_response")
                elif time.monotonic() - started >= limits.wall_seconds or not process.is_alive():
                    result = _unavailable("parser_exit_or_timeout")
                if result is None:
                    continue
                if process.is_alive():
                    process.terminate()
                process.join(timeout=1)
                if process.is_alive():
                    process.kill()
                    process.join(timeout=1)
                receiver.close()
                del active[position]
                yield position, result
            if active:
                time.sleep(0.005)
    finally:
        for process, receiver, _ in active.values():
            if process.is_alive():
                process.kill()
            process.join(timeout=1)
            receiver.close()


def inspect_pdf_code(path, *, boundary=None, limits=None, expected_sha256=None):
    """Inspect one explicitly supplied path, using the same disposable boundary."""
    path = Path(path).absolute()
    expected = None if expected_sha256 is None else {0: expected_sha256}
    results = inspect_pdf_codes([path], boundary=boundary or path.parent, limits=limits, workers=1,
                                expected_hashes=expected)
    try:
        return next(results)[1]
    finally:
        results.close()
