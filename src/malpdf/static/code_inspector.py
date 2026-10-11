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
import signal
from pathlib import Path
import time
import zlib
import binascii
import base64
import codecs

from malpdf.static.js_ast import CALL_NAMES, CodeInspectionError, inspect_js_syntax
from malpdf.static.safety import read_bounded_bytes
from malpdf.static.profiling import stage
from malpdf.static.parser_diagnostics import ParserDiagnostics

SECURITY_NAMES = frozenset({"/JS", "/JavaScript", "/OpenAction", "/AA", "/Launch",
    "/EmbeddedFile", "/EmbeddedFiles", "/XFA", "/AcroForm", "/JBIG2Decode", "/RichMedia", "/URI"})
CODE_INSPECTION_SCHEMA_VERSION = "pdf-code-inspection-v7"
# Only fixed PDF vocabulary is exported in paths; untrusted keys remain redacted.
_PATH_NAMES = SECURITY_NAMES | frozenset({"/Root", "/Pages", "/Kids", "/Annots", "/A",
    "/Next", "/Names", "/Fields", "/O", "/C", "/E", "/X", "/D", "/U", "/Fo",
    "/Bl", "/PO", "/PC", "/PV", "/PI", "/K", "/F", "/V"})
_ACTION_PATH_NAMES = frozenset({"/OpenAction", "/AA", "/A", "/Next", "/Names",
    "/JavaScript", "/JS", "/AcroForm", "/XFA", "/Fields", "/Annots"})


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


def _unavailable(code, parser_diagnostics=None):
    return {"schema_version": CODE_INSPECTION_SCHEMA_VERSION,
            "status": "unavailable", "complete": False, "referral_recommended": True,
            "scripts_found": None, "scripts_parsed": None, "ast": None,
            "structural_indicators": None, "errors": [code],
            "parser_diagnostics": parser_diagnostics,
            "traversal_complete": False, "javascript_state": "unavailable",
            "script_extraction_complete": False, "ast_complete": False,
            "parser_recovered": False,
            "observed": None, "script_sources": [],
            "scope": "catalog-reachable PDF actions and declared XFA JavaScript syntax only",
            "content_redacted": True, "active_content_executed": False}


def _decode_script_bytes(data, limits):
    """Decode PDF text-stream bytes, without guessing from leading NULs.

    PDFDocEncoding is the default; Unicode requires a BOM. UTF-16LE is
    accepted as an explicit compatibility form, as in the pypdf backend.
    Both encoded and UTF-8 output sizes remain bounded.
    """
    from pypdf.generic import decode_pdfdocencoding

    if len(data) > limits.max_script_bytes:
        raise CodeInspectionError("script_byte_limit")
    if data.startswith((codecs.BOM_UTF16_BE, codecs.BOM_UTF16_LE)):
        text = data.decode("utf-16", errors="strict")
    elif data.startswith(codecs.BOM_UTF8):
        text = data.decode("utf-8-sig", errors="strict")
    else:
        text = decode_pdfdocencoding(data)
    if len(text.encode("utf-8")) > limits.max_script_bytes:
        raise CodeInspectionError("script_byte_limit")
    return text


def _stream_bytes(value, limits, *, byte_limit=None, overflow="script_byte_limit"):
    """Reuse bounded JS filters for XML; never call backend get_data()."""
    from pypdf.generic import NullObject

    byte_limit = limits.max_script_bytes if byte_limit is None else byte_limit
    data = value._data
    if not isinstance(data, bytes) or len(data) > limits.max_file_bytes:
        raise CodeInspectionError("invalid_script_stream")
    if byte_limit <= 0:
        raise CodeInspectionError(overflow)
    filters = value.get("/Filter", [])
    filters = filters if isinstance(filters, list) else [filters]
    if len(filters) > 3:
        raise CodeInspectionError("stream_filter_limit")
    parms = value.get("/DecodeParms")
    if parms is not None and not isinstance(parms, NullObject):
        raise CodeInspectionError("unsupported_decode_parameters")
    for filter_name in filters:
        if str(filter_name) in {"/ASCIIHexDecode", "/AHx"}:
            compact = re.sub(rb"[\x00\t\n\f\r ]", b"", data)
            if b">" not in compact or compact.split(b">", 1)[1]:
                raise CodeInspectionError("invalid_asciihex_stream")
            digits = compact[:-1]
            if (len(digits) + 1) // 2 > byte_limit:
                raise CodeInspectionError(overflow)
            try:
                data = binascii.unhexlify(digits + (b"0" if len(digits) % 2 else b""))
            except binascii.Error:
                raise CodeInspectionError("invalid_asciihex_stream") from None
            continue
        if str(filter_name) in {"/ASCII85Decode", "/A85"}:
            compact = re.sub(rb"[\x00\t\n\f\r ]", b"", data)
            body = compact[2:] if compact.startswith(b"<~") else compact
            if not body.endswith(b"~>"):
                raise CodeInspectionError("invalid_ascii85_stream")
            body = body[:-2]
            upper = body.count(b"z") * 4 + ((len(body) - body.count(b"z") + 4) // 5) * 4
            if upper > byte_limit:
                raise CodeInspectionError(overflow)
            try:
                data = base64.a85decode(compact, adobe=True, ignorechars=b"\x00\t\n\f\r ")
            except (ValueError, binascii.Error):
                raise CodeInspectionError("invalid_ascii85_stream") from None
            continue
        if str(filter_name) not in {"/FlateDecode", "/Fl"}:
            raise CodeInspectionError("unsupported_script_filter")
        decoder = zlib.decompressobj()
        data = decoder.decompress(data, byte_limit + 1)
        if len(data) > byte_limit or decoder.unconsumed_tail:
            raise CodeInspectionError(overflow)
        if not decoder.eof or decoder.unused_data:
            raise CodeInspectionError("invalid_flate_stream")
    if len(data) > byte_limit:
        raise CodeInspectionError(overflow)
    return data


def _script_text(value, limits):
    from pypdf.generic import ByteStringObject, StreamObject, TextStringObject

    if isinstance(value, TextStringObject):
        original = getattr(value, "_original_bytes", None)
        text = _decode_script_bytes(original, limits) if isinstance(original, bytes) else str(value)
    elif isinstance(value, ByteStringObject):
        text = _decode_script_bytes(bytes(value), limits)
    elif isinstance(value, StreamObject):
        text = _decode_script_bytes(_stream_bytes(value, limits), limits)
    else:
        raise CodeInspectionError("unsupported_script_object")
    if len(text.encode("utf-8")) > limits.max_script_bytes:
        raise CodeInspectionError("script_byte_limit")
    return text


def _inspect_code_bytes(data, limits, *, timings=None, evidence_metadata=False):
    with stage(timings, "parse_pdf"):
        return _inspect_code_bytes_inner(data, limits, timings, evidence_metadata=evidence_metadata)


def _inspect_code_bytes_inner(data, limits, timings, *, supplied_reader=None, evidence_metadata=False):
    """Internal parser routine: production access must use inspect_pdf_code(s)."""
    from pypdf import PdfReader
    from pypdf.errors import PdfReadError
    from pypdf.generic import ArrayObject, ByteStringObject, DictionaryObject, IndirectObject, StreamObject, TextStringObject
    from malpdf.static.xfa_xml import inspect_xfa_xml

    if len(data) > limits.max_file_bytes or not data.startswith(b"%PDF-"):
        return _unavailable("not_pdf_or_byte_limit")
    diagnostic = ParserDiagnostics(strict=True)
    recovered = False
    try:
        with diagnostic.capture_open_notices():
            reader = supplied_reader if supplied_reader is not None else PdfReader(io.BytesIO(data), strict=True)
    except Exception as error:
        diagnostic.failure(error, "open")
        reason = diagnostic.data["failures"][0]["reason"]
        # One bounded retry for known xref failures, in the same capped worker.
        # Reconstructed evidence is partial even when traversal/AST succeeds.
        missing_marker = reason == "startxref_missing" and b"startxref" not in data
        if not isinstance(error, PdfReadError) or (not missing_marker and reason not in {"xref_invalid", "xref_read_failed", "xref_missing"}):
            return _unavailable("pdf_parser_failure", diagnostic.data)
        retry = ParserDiagnostics(strict=False)
        # A fixed in-memory zero-offset marker asks pypdf to rebuild its xref.
        # Original bytes/hash/raw features are untouched. This is reconstructed
        # catalog evidence, never a valid repaired PDF or complete revision view.
        suffix = b"\nstartxref\n0\n%%EOF\n" if missing_marker else b""
        if missing_marker:
            retry.data["reconstruction"] = {"kind": "missing_startxref_marker", "source_bytes_changed": False,
                "parser_buffer_suffix_bytes": len(suffix), "scope": "in-memory catalog reconstruction; revision completeness unknown"}
        try:
            with retry.capture_open_notices():
                reader = PdfReader(io.BytesIO(data + suffix), strict=False)
        except Exception as retry_error:
            retry.failure(retry_error, "open_recovery")
            diagnostic.data["recovery_attempt"] = retry.data
            return _unavailable("pdf_parser_failure", diagnostic.data)
        retry.data["open_success"] = True
        diagnostic.data["recovery_attempt"] = retry.data
        recovered = True
    diagnostic.data["open_success"] = not recovered
    if supplied_reader is not None:
        recovered = True
        diagnostic.data["backend"] = "MuPDF"
        diagnostic.data["recovery_scope"] = "read-only object view; original bytes unchanged; completeness unknown"
    if reader.is_encrypted:
        return _unavailable("encrypted_pdf", diagnostic.data)
    errors, seen, scripts_seen = set(), set(), set()
    if getattr(reader, '_malpdf_xrefstm_failures', []):
        recovered = True
        errors.add('supplemental_xref_unavailable')
    if recovered:
        errors.add("pdf_xref_recovered")
    indicators = Counter({name[1:]: 0 for name in sorted(SECURITY_NAMES)})
    nodes, calls = Counter(), Counter({name: 0 for name in sorted(CALL_NAMES)})
    found = parsed = decoded = total_nodes = depth_max = loops = computed = visited = 0

    def resolve(value):
        references = set()
        while isinstance(value, IndirectObject):
            key = (value.idnum, value.generation)
            if key in references or len(references) >= limits.max_pdf_depth:
                raise CodeInspectionError("pdf_reference_limit")
            references.add(key)
            value = value.get_object()
            if value is None:
                raise CodeInspectionError("pdf_reference_unavailable")
        return value

    sources = []
    traversal_complete = not recovered
    xfa_seen = set()
    xfa_info = {"containers_found": 0, "containers_parsed": 0,
                "xml_nodes_observed": 0, "non_javascript_scripts_observed": 0}

    def start_source(owner, script, path, kind="pdf_javascript"):
        nonlocal found, traversal_complete
        found += 1
        if found > limits.max_scripts:
            traversal_complete = False
            raise CodeInspectionError("script_count_limit")
        source_path = "/" + "/".join(part.lstrip("/") for part in path)
        source = {"container_object": list(owner) if owner else None,
                  "script_object": script, "kind": kind,
                  "path": source_path[:256], "path_truncated": len(source_path) > 256,
                  "extraction_status": "unavailable", "ast_status": "unavailable", "status": "unavailable"}
        sources.append(source)
        return source

    def finish_source(source, text):
        nonlocal parsed, decoded, total_nodes, depth_max, loops, computed, traversal_complete
        decoded += len(text.encode("utf-8"))
        if decoded > limits.max_decoded_bytes:
            source["error"] = "decoded_byte_limit"
            traversal_complete = False
            raise CodeInspectionError("decoded_byte_limit")
        source["extraction_status"] = "complete"
        if evidence_metadata:
            source["decoded_sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
            source["decoded_validated"] = True
        try:
            with stage(timings, "js_ast"):
                ast = inspect_js_syntax(text, max_bytes=limits.max_script_bytes,
                    max_nodes=limits.max_ast_nodes - total_nodes, max_depth=limits.max_ast_depth)
        except CodeInspectionError as error:
            source["error"] = str(error)
            if str(error) == "ast_node_limit":
                traversal_complete = False
            raise
        parsed += 1
        total_nodes += ast["node_count"]
        depth_max = max(depth_max, ast["max_depth"])
        loops += ast["loops"]
        computed += ast["computed_members"]
        nodes.update(ast["node_types"])
        calls.update(ast["named_calls"])
        source["status"] = "parsed"
        source["ast_status"] = "complete"
        if evidence_metadata:
            source["ast_summary"] = ast

    def xfa_problem(code):
        nonlocal traversal_complete
        errors.add(code)
        traversal_complete = False

    def inspect_xfa(raw, owner, path):
        nonlocal decoded
        container = resolve(raw)
        if id(container) in xfa_seen:
            return
        xfa_seen.add(id(container))
        xfa_info["containers_found"] += 1
        if isinstance(container, ArrayObject):
            if not container or len(container) % 2 or len(container) > limits.max_objects:
                raise CodeInspectionError("xfa_packet_array_invalid_or_limit")
            indices = range(1, len(container), 2)
        elif isinstance(container, StreamObject):
            indices = (None,)
        else:
            raise CodeInspectionError("xfa_object_unsupported")

        def chunks():
            nonlocal decoded
            for index in indices:
                if index is not None and not isinstance(resolve(container[index - 1]), (TextStringObject, ByteStringObject)):
                    raise CodeInspectionError("xfa_packet_array_invalid_or_limit")
                raw_stream = raw if index is None else container[index]
                stream = container if index is None else resolve(raw_stream)
                if not isinstance(stream, StreamObject):
                    raise CodeInspectionError("xfa_object_unsupported")
                with stage(timings, "stream_decode"):
                    content = _stream_bytes(stream, limits, byte_limit=limits.max_decoded_bytes - decoded,
                                            overflow="decoded_byte_limit")
                decoded += len(content)
                yield content, {"packet_index": 0 if index is None else index // 2,
                    "stream_object": [raw_stream.idnum, raw_stream.generation] if isinstance(raw_stream, IndirectObject) else None}

        def begin(metadata):
            source = start_source(owner, metadata["stream_object"],
                path + ("/XFA", f"packet[{metadata['packet_index']}]", "script"), "xfa_javascript")
            source.update(xfa_packet_index=metadata["packet_index"], xfa_xml_byte_offset=metadata["xml_byte_offset"])
            return source

        def finish(source, text):
            try:
                finish_source(source, text)
            except CodeInspectionError as error:
                errors.add(str(error))
                if str(error) in {"decoded_byte_limit", "ast_node_limit"}:
                    raise

        def node_observed():
            xfa_info["xml_nodes_observed"] += 1

        stats = inspect_xfa_xml(chunks(), start_script=begin, finish_script=finish, problem=xfa_problem,
            node_observed=node_observed, max_nodes=limits.max_objects - xfa_info["xml_nodes_observed"],
            max_depth=limits.max_pdf_depth, max_script_bytes=limits.max_script_bytes)
        xfa_info["containers_parsed"] += 1
        xfa_info["non_javascript_scripts_observed"] += stats["non_javascript_scripts"]

    try:
        root = reader.trailer.raw_get("/Root")
    except Exception as error:
        diagnostic.failure(error, "root")
        return _unavailable("pdf_root_unavailable", diagnostic.data)

    def dictionary_children(items, parent_path, parent_owner):
        # Two lazy passes prioritize action routes before large page/resource
        # branches, without copying an untrusted dictionary or raising caps.
        for preferred in (True, False):
            for name, child in items:
                if (str(name) in _ACTION_PATH_NAMES) == preferred:
                    yield child, parent_path + (str(name) if str(name) in _PATH_NAMES else "{key}",), parent_owner

    def array_children(items, parent_path, parent_owner):
        for index, child in enumerate(items):
            yield child, parent_path + (f"[{index}]",), parent_owner

    # Iterator frames bound breadth without constructing an untrusted big stack.
    frames = [(iter([(root, ("/Root",), None)]), 0)]
    while frames:
        iterator, depth = frames[-1]
        try:
            value, path, owner = next(iterator)
        except StopIteration:
            frames.pop()
            continue
        visited += 1
        if visited > limits.max_objects or depth > limits.max_pdf_depth:
            errors.add("pdf_structure_limit")
            traversal_complete = False
            break
        if isinstance(value, IndirectObject):
            key = (value.idnum, value.generation)
            if key in seen:
                continue
            seen.add(key)
            owner = key
        try:
            value = resolve(value)
        except Exception as error:
            diagnostic.failure(error, "reference")
            errors.add("pdf_reference_unavailable")
            traversal_complete = False
            continue
        if depth == 0 and not isinstance(value, DictionaryObject):
            return _unavailable("invalid_pdf_root")
        if isinstance(value, DictionaryObject):
            indicators.update(str(k)[1:] for k in value if str(k) in SECURITY_NAMES)
            for name in ("/S", "/Type", "/Subtype", "/Filter"):
                item = value.get(name)
                items = item if isinstance(item, ArrayObject) else (item,)
                if len(items) > limits.max_objects:
                    errors.add("pdf_structure_limit")
                    traversal_complete = False
                    break
                indicators.update(str(v)[1:] for v in items if str(v) in SECURITY_NAMES)
            if "/XFA" in value:
                try:
                    inspect_xfa(value.raw_get("/XFA"), owner, path)
                except CodeInspectionError as error:
                    xfa_problem(str(error))
                except (UnicodeError, zlib.error):
                    xfa_problem("xfa_decode_error")
                except Exception:
                    xfa_problem("xfa_read_error")
                if errors & {"decoded_byte_limit", "ast_node_limit", "script_count_limit", "xfa_xml_node_limit"}:
                    break
            if "/JS" in value or str(value.get("/S")) == "/JavaScript":
                missing_script = "/JS" not in value
                script = None if missing_script else value.raw_get("/JS")
                key = ((script.idnum, script.generation) if isinstance(script, IndirectObject)
                       else ("missing", id(value)) if missing_script else ("direct", id(script)))
                if key not in scripts_seen:
                    scripts_seen.add(key)
                    source = None
                    try:
                        source = start_source(owner, [script.idnum, script.generation] if isinstance(script, IndirectObject) else None,
                                              path + ("/JS",))
                        if missing_script:
                            raise CodeInspectionError("javascript_payload_missing")
                        payload = resolve(script)
                        if evidence_metadata:
                            raw = payload._data if isinstance(payload, StreamObject) else bytes(payload) if isinstance(payload, ByteStringObject) else None
                            if raw is not None:
                                source["raw_sha256"] = hashlib.sha256(raw).hexdigest()
                        if isinstance(payload, StreamObject):
                            with stage(timings, "stream_decode"):
                                text = _script_text(payload, limits)
                        else:
                            text = _script_text(payload, limits)
                        finish_source(source, text)
                    except CodeInspectionError as error:
                        errors.add(str(error))
                        if source is not None:
                            source["error"] = str(error)
                        if str(error) in {"decoded_byte_limit", "ast_node_limit", "script_count_limit"}:
                            traversal_complete = False
                            break
                    except (UnicodeError, zlib.error):
                        errors.add("script_decode_error")
                        source["error"] = "script_decode_error"
                    except Exception:
                        errors.add("script_read_error")
                        source["error"] = "script_read_error"
            # Iterators capture each frame's path/owner without copying children.
            frames.append((dictionary_children(value.items(), path, owner), depth + 1))
        elif isinstance(value, ArrayObject):
            frames.append((array_children(value, path, owner), depth + 1))
    ast_summary = {"node_count": total_nodes, "max_depth": depth_max, "node_types": dict(sorted(nodes.items())),
                   "named_calls": dict(calls), "loops": loops, "computed_members": computed}
    complete_ast = traversal_complete and parsed == found
    extraction_complete = traversal_complete and all(source["extraction_status"] == "complete" for source in sources)
    return {"schema_version": CODE_INSPECTION_SCHEMA_VERSION,
            "status": "partial" if errors else "complete", "complete": not errors,
            "referral_recommended": bool(errors or sum(calls.values()) or indicators["Launch"] or indicators["EmbeddedFile"]),
            "traversal_complete": traversal_complete,
            "script_extraction_complete": extraction_complete, "ast_complete": complete_ast,
            "javascript_state": ("partial" if not traversal_complete else "absent" if found == 0 else
                                 "extracted" if complete_ast else "extracted_ast_failed" if extraction_complete else "present_unavailable"),
            "scripts_found": found if traversal_complete else None, "scripts_parsed": parsed,
            "ast": ast_summary if complete_ast else None,
            "structural_indicators": dict(indicators) if traversal_complete else None,
            "observed": {"scripts_found": found, "ast": ast_summary if parsed or complete_ast else None,
                         "structural_indicators": dict(indicators)},
            "script_sources": sources, "errors": sorted(errors), "xfa_observed": xfa_info,
            "parser_diagnostics": diagnostic.data,
            "parser_recovered": recovered,
            "budget_usage": {"decoded_bytes": decoded, "ast_nodes": total_nodes},
            "scope": "catalog-reachable PDF actions and declared XFA JavaScript syntax only", "content_redacted": True,
            "active_content_executed": False}


def _apply_code_limits(limits):
    """Apply OS caps before reading input or importing a PDF/JS parser."""
    import resource

    os.setsid()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))
    resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds))
    return {"address_space_bytes": list(resource.getrlimit(resource.RLIMIT_AS)),
            "cpu_seconds": list(resource.getrlimit(resource.RLIMIT_CPU)),
            "wall_seconds": limits.wall_seconds, "disposable_process_group": os.getpgrp() == os.getpid()}


def _code_child(connection, path, boundary, limits, expected_sha256):
    applied = None
    try:
        applied = _apply_code_limits(limits)
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
    result["resource_limits"] = applied
    try:
        connection.send_bytes(json.dumps(result, allow_nan=False).encode())
    finally:
        connection.close()


def worker_memory_budget(limits):
    """Report the existing admission budget without opening any sample."""
    available = next(int(line.split()[1]) * 1024 for line in Path("/proc/meminfo").read_text().splitlines()
                     if line.startswith("MemAvailable:"))
    maximum, current = Path("/sys/fs/cgroup/memory.max"), Path("/sys/fs/cgroup/memory.current")
    if maximum.is_file() and current.is_file() and maximum.read_text().strip() != "max":
        available = min(available, max(0, int(maximum.read_text()) - int(current.read_text())))
    return {"available_bytes": available, "worker_bytes": limits.memory_bytes,
            "reserve_bytes": 256 * 1024**2}


def _worker_count(requested, limits):
    from malpdf.data.markov_preparation import effective_cpu_count

    if type(requested) is not int or not 1 <= requested <= 16:
        raise ValueError("workers must be an integer between 1 and 16")
    memory = worker_memory_budget(limits)
    count = min(requested, effective_cpu_count(), max(0,
        (memory["available_bytes"] - memory["reserve_bytes"]) // memory["worker_bytes"]))
    if count < 1:
        raise ValueError("Insufficient available RAM for the isolated parser budget: "
            f"available={memory['available_bytes']} bytes; "
            f"required={memory['worker_bytes'] + memory['reserve_bytes']} bytes for one worker")
    return count


def _stop_code_process(process):
    """Kill the disposable session, including descendants, then reap its worker."""
    try:
        # setsid() makes the worker PID its group ID. Never signal our own group.
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        if process.is_alive():
            process.kill()
    process.join(timeout=1)
    if process.is_alive():
        process.kill()
        process.join(timeout=1)


def inspect_pdf_codes(paths, *, boundary, limits=None, workers=1, expected_hashes=None):
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
                ready = receiver.poll()
                exited = not process.is_alive() if not ready else False
                if exited:
                    # The worker can send and exit between poll() and the
                    # liveness check. Drain its final reply before declaring loss.
                    ready = receiver.poll()
                if ready:
                    try:
                        result = json.loads(receiver.recv_bytes(maxlength=64 * 1024))
                        if (not isinstance(result, dict) or type(result.get("complete")) is not bool
                                or result.get("active_content_executed") is not False
                                or result.get("content_redacted") is not True):
                            raise ValueError("Invalid worker evidence")
                    except (EOFError, OSError, ValueError):
                        result = _unavailable("invalid_worker_response")
                elif time.monotonic() - started >= limits.wall_seconds or exited:
                    result = _unavailable("parser_exit_or_timeout")
                if result is None:
                    continue
                _stop_code_process(process)
                receiver.close()
                del active[position]
                yield position, result
            if active:
                time.sleep(0.005)
    finally:
        for process, receiver, _ in active.values():
            _stop_code_process(process)
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
