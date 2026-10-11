"""Bounded, additive PDF evidence identities and verified action relationships.

This module is an internal worker routine, not an unrestricted PDF entry point.
It reads original bytes and inert syntax only. Original content never appears in
its JSON graph; a caller may retain capped raw streams through the parent sink.
Latest catalog reachability does not establish historical revision completeness.
"""

from collections import defaultdict
from dataclasses import replace
import hashlib
import io
import json
import re
from xml.parsers import expat
import zlib

from pypdf import PdfReader
from pypdf.generic import (ArrayObject, ByteStringObject, DictionaryObject,
                          IndirectObject, NameObject, StreamObject, TextStringObject)

from malpdf.static.code_inspector import _decode_script_bytes, _stream_bytes
from malpdf.static.js_ast import CodeInspectionError, inspect_js_syntax
from malpdf.static.parser_diagnostics import ParserDiagnostics
from malpdf.static.profiling import stage
from malpdf.static.recovery import MuPDFObjectReader, projected_object

EVIDENCE_SCHEMA = "pdf-evidence-v9"
MAX_METADATA_BYTES = 2 * 1024**2
MAX_RETAINED_RAW_BYTES = 10 * 1024**2
CAPABILITIES = ("catalog", "actions", "scripts", "xfa", "embedded")
ACTION_NAMES = frozenset({"/JavaScript", "/Launch", "/GoToE", "/URI", "/GoToR",
                          "/SubmitForm", "/ImportData", "/Named", "/GoTo"})
_VOCABULARY = frozenset({"/Root", "/Pages", "/Kids", "/Annots", "/Fields", "/AcroForm",
    "/XFA", "/OpenAction", "/AA", "/A", "/Next", "/Names", "/JavaScript", "/JS",
    "/EF", "/F", "/UF", "/Win", "/Type", "/Subtype", "/S", "/FT", "/Filter",
    "/O", "/C", "/E", "/X", "/D", "/U", "/Fo", "/Bl", "/PO", "/PC",
    "/PV", "/PI", "/K", "/V", "/WC", "/WS", "/DS", "/WP", "/DP"})
_AA_EVENTS = {"catalog": {"/WC", "/WS", "/DS", "/WP", "/DP"},
              "page": {"/O", "/C"},
              "annotation": {"/E", "/X", "/D", "/U", "/Fo", "/Bl", "/PO", "/PC", "/PV", "/PI"},
              "field": {"/K", "/F", "/V", "/C"}}
_XFA_EVENTS = frozenset({"initialize", "calculate", "validate", "ready", "enter", "exit",
    "change", "click", "mouseEnter", "mouseExit", "mouseDown", "mouseUp", "preOpen",
    "postOpen", "prePrint", "postPrint", "preSave", "postSave", "preSubmit", "postSubmit",
    "docReady", "docClose", "indexChange", "full"})


def _digest(value):
    return hashlib.sha256(value).hexdigest()


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _payload_magic(content):
    """Recognize bounded executable headers without loading or executing them."""
    if content.startswith(b"MZ") and len(content) >= 64:
        offset = int.from_bytes(content[60:64], "little")
        if 64 <= offset <= len(content) - 24 and content[offset:offset + 4] == b"PE\0\0":
            return "pe"
    if content.startswith(b"\x7fELF") and len(content) >= 16:
        elf_class, encoding, version = content[4:7]
        if elf_class in (1, 2) and encoding in (1, 2) and version == 1:
            size = 52 if elf_class == 1 else 64
            if len(content) >= size:
                return "elf"
    return next((kind for prefix, kind in [(b"%PDF-", "pdf"), (b"PK\x03\x04", "zip"),
        (b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpeg")]
        if content.startswith(prefix)), "other")


def merge_evidence_delta(target, delta):
    """Merge immutable checkpoint entries without silently replacing evidence."""
    if delta.get("schema_version", EVIDENCE_SCHEMA) != EVIDENCE_SCHEMA:
        raise ValueError("Invalid evidence checkpoint schema")
    for key in ("observations", "edges", "capability_checks", "conflicts", "backend_results"):
        entries = target.setdefault(key, [])
        indexed = {item["id"]: item for item in entries}
        for item in delta.get(key, []):
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                raise ValueError("Invalid evidence checkpoint identity")
            old = indexed.get(item["id"])
            if old is not None and old != item:
                raise ValueError("Evidence checkpoint would overwrite an observation")
            if old is None:
                entries.append(item)
                indexed[item["id"]] = item
    for key in ("schema_version", "document_sha256", "status", "complete", "primary_profile_complete",
                "original_bytes_changed", "active_content_executed", "content_redacted", "budget_usage",
                "witnesses", "feature_provenance", "scope", "recovery_attempted"):
        if key in delta:
            target[key] = delta[key]
    return target


class _Store:
    def __init__(self, digest, checkpoint, raw_sink):
        self.digest, self.checkpoint, self.raw_sink = digest, checkpoint, raw_sink
        self.result = {"schema_version": EVIDENCE_SCHEMA, "document_sha256": digest,
                       "observations": [], "edges": [], "capability_checks": [],
                       "conflicts": [], "backend_results": [], "status": "partial",
                       "complete": False, "content_redacted": True,
                       "original_bytes_changed": False, "active_content_executed": False}
        self.index, self.metadata_bytes, self.raw_bytes, self.raw_hashes = {}, 0, 0, {}

    def identifier(self, backend, locator, kind):
        return "v9:" + _digest((self.digest + "|" + backend + "|" + locator + "|" + kind).encode())

    def append(self, key, item):
        identity = (key, item["id"])
        if identity in self.index:
            if self.index[identity] != item:
                raise CodeInspectionError("evidence_identity_collision")
            return item["id"]
        size = len(_json_bytes(item)) + 2
        # Reserve room for the complete frozen feature ledger and bounded
        # derived witness paths, which are serialized at final checkpoint.
        reserve = max(16384, min(768 * 1024, MAX_METADATA_BYTES // 3))
        # A full object graph must still checkpoint its localized failure and
        # terminal checks. This small allowance is inside the existing reserve,
        # not another graph budget; ordinary observations cannot spend it.
        terminal = (key in {"backend_results", "capability_checks", "conflicts"}
                    or key == "observations" and item.get("kind") == "stage_failure")
        ceiling = MAX_METADATA_BYTES - reserve + (min(64 * 1024, reserve // 2) if terminal else 0)
        if self.metadata_bytes + size > ceiling:
            raise CodeInspectionError("evidence_metadata_limit")
        self.metadata_bytes += size
        self.index[identity] = item
        self.result[key].append(item)
        if self.checkpoint:
            self.checkpoint({"schema_version": EVIDENCE_SCHEMA, "document_sha256": self.digest,
                             key: [item], "status": "partial", "complete": False,
                             "original_bytes_changed": False, "active_content_executed": False,
                             "content_redacted": True})
        return item["id"]

    def observation(self, backend, locator, kind, *, number=None, generation=None, offset="unknown", **fields):
        item = {"id": self.identifier(backend, locator, kind), "kind": kind, "backend": backend,
                "document_sha256": self.digest, "object_number": number, "generation": generation,
                "locator": locator, "revision": "unknown", "offset": offset,
                "raw_sha256": None, "decoded_sha256": None,
                "status": "observed", "reason_codes": [], **fields}
        return self.append("observations", item)

    def edge(self, source, target, kind, *, route=None, status="verified", reason_codes=()):
        locator = source + "|" + kind + "|" + target + "|" + (route or "")
        item = {"id": self.identifier("graph", locator, "edge"), "source": source, "target": target,
                "kind": kind, "route": route, "status": status, "reason_codes": list(reason_codes)}
        return self.append("edges", item)

    def raw(self, content):
        digest = _digest(content)
        if digest in self.raw_hashes:
            return digest, self.raw_hashes[digest]
        if self.raw_bytes + len(content) > MAX_RETAINED_RAW_BYTES:
            state = {"status": "unavailable", "reason_code": "raw_retention_byte_limit"}
        elif self.raw_sink is None:
            state = {"status": "not_retained", "reason_code": "raw_sink_unavailable"}
        else:
            state = self.raw_sink(content)
            if not isinstance(state, dict) or state.get("sha256") != digest:
                raise CodeInspectionError("raw_sink_hash_mismatch")
            if state.get("status") == "retained":
                self.raw_bytes += len(content)
        self.raw_hashes[digest] = state
        return digest, state


class _Budget:
    def __init__(self, limits, code, legacy):
        self.limits = limits
        decoded = code.get("budget_usage", {}).get("decoded_bytes", 0)
        self.ast_used = code.get("budget_usage", {}).get("ast_nodes", 0)
        prior_code = [code]
        for view in (legacy or {}).get("backends", []):
            if view.get("backend") != "pypdf":
                recovered = view.get("code") or {}
                prior_code.append(recovered)
                self.ast_used += recovered.get("budget_usage", {}).get("ast_nodes", 0)
        self.ast_exhausted = any("ast_node_limit" in view.get("errors", []) for view in prior_code)
        self.script_exhausted = any("script_count_limit" in view.get("errors", []) for view in prior_code)
        self.scripts_prior = sum((view.get("observed") or {}).get("scripts_found", len(view.get("script_sources", [])))
                                 or 0 for view in prior_code)
        self.decoded_remaining = max(0, limits.max_decoded_bytes - decoded)
        if legacy is not None:
            self.decoded_remaining = min(self.decoded_remaining, max(0, legacy.get("decoded_bytes_remaining", 0)))
        if "decoded_byte_limit" in code.get("errors", []):
            self.decoded_remaining = 0
        self.initial_decoded_remaining = self.decoded_remaining
        self.failed_decode_debit = 0
        self.ast_initial = self.ast_used
        self.scripts, self.objects = 0, 0
        self.new_script_hashes = set()
        self.xml_nodes = sum(view.get("xfa_observed", {}).get("xml_nodes_observed", 0) for view in prior_code)
        self.ast_cache, self.decoded_cache = {}, {}
        sources = list(code.get("script_sources", []))
        for view in (legacy or {}).get("backends", []):
            sources.extend((view.get("code") or {}).get("script_sources", []))
        for source in sources:
            summary, digest = source.get("ast_summary"), source.get("decoded_sha256")
            if (source.get("ast_status") == "complete" and source.get("decoded_validated") is True
                    and isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{64}", digest)
                    and isinstance(summary, dict) and type(summary.get("node_count")) is int
                    and 0 <= summary["node_count"] <= limits.max_ast_nodes):
                # Only exact decoded identities with completed per-script AST
                # metadata can reuse earlier work. File-level sums cannot.
                previous = self.ast_cache.get(digest)
                if previous is None or previous == summary:
                    self.ast_cache[digest] = summary

    def decode(self, value, role, store):
        if isinstance(value, StreamObject):
            raw = value._data
            if not isinstance(raw, bytes):
                raise CodeInspectionError("invalid_script_stream")
            raw_hash, retained = store.raw(raw)
            key = (raw_hash, _digest(_json_bytes(projected_object(value))))
            if key in self.decoded_cache:
                return self.decoded_cache[key], raw_hash, retained
            maximum = min(self.decoded_remaining, self.limits.max_script_bytes) if role == "script" else self.decoded_remaining
            try:
                decoded = _stream_bytes(value, self.limits, byte_limit=maximum, overflow="decoded_byte_limit")
            except CodeInspectionError as error:
                if str(error) == "decoded_byte_limit":
                    self.failed_decode_debit += self.decoded_remaining
                    self.decoded_remaining = 0
                elif str(error) == "invalid_flate_stream":
                    # The strict helper deliberately discards unverified
                    # decoded prefixes. Charge its bounded upper allowance;
                    # failed streams never obtain a fresh budget on fallback.
                    self.decoded_remaining -= maximum
                    self.failed_decode_debit += maximum
                raise
            except zlib.error:
                self.decoded_remaining -= maximum
                self.failed_decode_debit += maximum
                raise CodeInspectionError("invalid_flate_stream") from None
            self.decoded_remaining -= len(decoded)
            self.decoded_cache[key] = decoded
            return decoded, raw_hash, retained
        if isinstance(value, TextStringObject):
            raw = getattr(value, "_original_bytes", None)
            if not isinstance(raw, bytes):
                try:
                    raw = value.original_bytes
                except (AttributeError, ValueError):
                    raw = str(value).encode("utf-8")
            decoded = str(value).encode("utf-8")
        elif isinstance(value, ByteStringObject):
            raw = bytes(value)
            decoded = _decode_script_bytes(raw, self.limits).encode("utf-8")
        else:
            raise CodeInspectionError("unsupported_script_object")
        key = ("text", _digest(raw), _digest(decoded))
        if key not in self.decoded_cache:
            if len(decoded) > self.limits.max_script_bytes:
                raise CodeInspectionError("script_byte_limit")
            if len(decoded) > self.decoded_remaining:
                raise CodeInspectionError("decoded_byte_limit")
            self.decoded_remaining -= len(decoded)
            self.decoded_cache[key] = decoded
        return decoded, _digest(raw), {"status": "original_snapshot", "reason_code": None}

    def ast(self, text, timings):
        key = _digest(text.encode("utf-8"))
        if key in self.ast_cache:
            return self.ast_cache[key]
        if key not in self.new_script_hashes:
            if self.script_exhausted or self.scripts_prior + len(self.new_script_hashes) >= self.limits.max_scripts:
                self.script_exhausted = True
                raise CodeInspectionError("script_count_limit")
            self.new_script_hashes.add(key)
        remaining = self.limits.max_ast_nodes - self.ast_used
        if self.ast_exhausted or remaining <= 0:
            raise CodeInspectionError("ast_node_limit")
        with stage(timings, "js_ast"):
            try:
                summary = inspect_js_syntax(text, max_bytes=self.limits.max_script_bytes,
                    max_nodes=remaining, max_depth=self.limits.max_ast_depth)
            except CodeInspectionError as error:
                if str(error) == "ast_node_limit":
                    self.ast_exhausted = True
                raise
        self.ast_used += summary["node_count"]
        self.ast_cache[key] = summary
        return summary


def _route(key):
    value = str(key)
    return value if value in _VOCABULARY else "{key:" + _digest(value.encode())[:16] + "}"


def _reason(error, fallback):
    return str(error) if isinstance(error, CodeInspectionError) else fallback


class _Graph:
    def __init__(self, reader, backend, data, store, budget, timings):
        self.reader, self.backend, self.data = reader, backend, data
        self.store, self.budget, self.limits, self.timings = store, budget, budget.limits, timings
        self.seen, self.values, self.locators, self.errors, self.scope = {}, {}, {}, defaultdict(set), []
        self.direct_nodes, self.walked, self.failure_scopes = {}, set(), defaultdict(set)
        self.script_nodes, self.payload_nodes, self.projections, self.action_ids = {}, {}, {}, set()
        self.xfa_containers = set()

    def problem(self, capability, reason, affected=()):
        self.errors[capability].add(reason)
        self.failure_scopes[capability].update(affected)
        locator = capability + "|" + reason + "|" + "|".join(sorted(affected))
        self.store.observation(self.backend, locator, "stage_failure", status="unavailable",
                               reason_codes=[reason], capability=capability, affected_ids=list(affected))

    def resolve_name(self, value):
        chain = set()
        while isinstance(value, IndirectObject):
            key = (value.idnum, value.generation)
            if key in chain or len(chain) >= self.limits.max_pdf_depth:
                raise CodeInspectionError("graph_name_reference_limit")
            chain.add(key)
            value = value.get_object()
        return str(value) if isinstance(value, NameObject) else None

    def kind(self, value):
        if isinstance(value, DictionaryObject):
            action = self.resolve_name(value.get("/S"))
            if action in ACTION_NAMES:
                return "action", {"action_kind": action}
            object_type = self.resolve_name(value.get("/Type"))
            if object_type == "/EmbeddedFile":
                return "embedded_stream", {}
            if object_type in {"/Catalog", "/Page", "/Pages", "/Annot", "/Filespec"}:
                return {"/Catalog": "catalog", "/Page": "page", "/Pages": "pages",
                        "/Annot": "annotation", "/Filespec": "filespec"}[object_type], {}
            if "/FT" in value:
                return "field", {}
            if "/XFA" in value or "/Fields" in value:
                return "form", {}
            if "/EF" in value:
                return "filespec", {}
        return ("stream" if isinstance(value, StreamObject) else "array" if isinstance(value, ArrayObject)
                else "pdf_object"), {}

    def node(self, value, locator, depth):
        if depth > self.limits.max_pdf_depth:
            raise CodeInspectionError("graph_depth_limit")
        number = generation = None
        offset = "unknown"
        reference = isinstance(value, IndirectObject)
        if reference:
            number, generation = value.idnum, value.generation
            locator = f"object:{number}:{generation}"
            key = (number, generation)
            if key in self.seen:
                return self.seen[key], self.values.get(self.seen[key]), False
            self.budget.objects += 1
            if self.budget.objects > self.limits.max_objects:
                raise CodeInspectionError("graph_object_limit")
            requested = value
            try:
                value = value.get_object()
                if value is None:
                    raise CodeInspectionError("graph_reference_unavailable")
            except Exception as error:
                identity = self.store.observation(self.backend, locator, "unresolved_reference", number=number,
                    generation=generation, status="unavailable", reason_codes=[_reason(error, "graph_reference_failure")])
                self.seen[key] = identity
                self.scope.append(identity)
                self.locators[identity], self.values[identity] = locator, None
                self.problem("catalog", _reason(error, "graph_reference_failure"), [identity])
                return identity, None, False
            if self.backend == "pypdf":
                candidate = getattr(self.reader, "xref", {}).get(generation, {}).get(number)
                if type(candidate) is int and 0 <= candidate < len(self.data):
                    header = re.match(rb"(\d+)\s+(\d+)\s+obj(?:\s|[<\[/])", self.data[candidate:candidate + 128])
                    if header and (int(header[1]), int(header[2])) == (requested.idnum, requested.generation):
                        offset = candidate
        else:
            if locator in self.direct_nodes:
                identity = self.direct_nodes[locator]
                return identity, self.values[identity], False
            self.budget.objects += 1
            if self.budget.objects > self.limits.max_objects:
                raise CodeInspectionError("graph_object_limit")
        kind, fields = self.kind(value)
        projection = projected_object(value)
        fields["projection"] = projection
        if isinstance(value, StreamObject):
            raw = value._data
            if isinstance(raw, bytes):
                fields["raw_sha256"], fields["raw_retention"] = self.store.raw(raw)
                fields["raw_bytes"] = len(raw)
        identity = self.store.observation(self.backend, locator, kind, number=number, generation=generation,
                                          offset=offset, **fields)
        if reference:
            self.seen[(number, generation)] = identity
            self.projections[(number, generation)] = (identity, projection)
        else:
            self.direct_nodes[locator] = identity
        self.values[identity], self.locators[identity] = value, locator
        self.scope.append(identity)
        if not projection["projection_complete"]:
            self.problem("catalog", "object_projection_limit", [identity])
        if kind == "action":
            self.action_ids.add(identity)
        return identity, value, True

    def child(self, parent, value, route, depth):
        identifier, resolved, fresh = self.node(value, self.locators[parent] + route, depth)
        self.store.edge(parent, identifier, "indirect_reference" if isinstance(value, IndirectObject) else "contains",
                        route=route, status="verified" if resolved is not None else "unresolved",
                        reason_codes=[] if resolved is not None else ["graph_reference_unavailable"])
        return identifier, resolved, fresh

    def script(self, node_id, value):
        if node_id in self.script_nodes:
            return self.script_nodes[node_id]
        self.budget.scripts += 1
        fields = {"status": "unavailable", "extraction_status": "unavailable", "ast_status": "unavailable",
                  "decoded_validated": False, "ast_summary": None, "source_object_id": node_id}
        locator = self.locators[node_id] + "|javascript"
        script_id = self.store.identifier(self.backend, locator, "script")
        self.script_nodes[node_id] = script_id
        try:
            decoded, raw_hash, retained = self.budget.decode(value, "script", self.store)
            text = _decode_script_bytes(decoded, self.limits) if isinstance(value, StreamObject) else decoded.decode("utf-8")
            fields.update(raw_sha256=raw_hash, decoded_sha256=_digest(text.encode("utf-8")),
                          extraction_status="complete", decoded_validated=True, raw_retention=retained)
            extraction = self.store.observation(self.backend, locator + "|extraction", "script_extraction",
                source_object_id=node_id, extraction_status="complete", decoded_validated=True,
                raw_sha256=raw_hash, decoded_sha256=fields["decoded_sha256"])
            fields["extraction_evidence_id"] = extraction
            fields.update(ast_summary=self.budget.ast(text, self.timings), ast_status="complete", status="observed")
        except Exception as error:
            reason = _reason(error, "script_ast_attribute_error" if isinstance(error, AttributeError) else "script_analysis_failure")
            fields["reason_codes"] = [reason]
            raw_hash = getattr(value, "_data", None)
            if isinstance(raw_hash, bytes):
                fields["raw_sha256"] = _digest(raw_hash)
            self.problem("scripts", reason, [node_id] + ([fields["extraction_evidence_id"]]
                         if "extraction_evidence_id" in fields else []))
        self.store.observation(self.backend, locator, "script", **fields)
        self.store.edge(node_id, script_id, "script_content")
        return script_id

    def payload(self, node_id, value):
        if node_id in self.payload_nodes:
            return self.payload_nodes[node_id]
        locator = self.locators[node_id] + "|payload"
        fields = {"source_object_id": node_id, "extraction_status": "unavailable", "decoded_validated": False,
                  "magic": "unknown", "magic_verified": False, "status": "unavailable"}
        try:
            if not isinstance(value, StreamObject):
                raise CodeInspectionError("embedded_stream_unavailable")
            decoded, raw_hash, retained = self.budget.decode(value, "payload", self.store)
            magic = _payload_magic(decoded)
            fields.update(raw_sha256=raw_hash, decoded_sha256=_digest(decoded), raw_retention=retained,
                extraction_status="complete", decoded_validated=True, status="observed",
                decoded_bytes=len(decoded), magic=magic, magic_verified=True)
        except Exception as error:
            reason = _reason(error, "embedded_decode_failure")
            fields["reason_codes"] = [reason]
            raw = getattr(value, "_data", None)
            if isinstance(raw, bytes):
                fields["raw_sha256"] = _digest(raw)
            self.problem("embedded", reason, [node_id])
        identity = self.store.observation(self.backend, locator, "payload", **fields)
        self.payload_nodes[node_id] = identity
        self.store.edge(node_id, identity, "payload_content")
        return identity

    def action(self, node_id, value, depth):
        kind = self.resolve_name(value.get("/S"))
        if kind == "/JavaScript":
            if "/JS" not in value:
                self.problem("scripts", "javascript_payload_missing", [node_id])
            else:
                target, payload, _ = self.child(node_id, value.raw_get("/JS"), "/JS", depth + 1)
                if payload is not None:
                    self.store.edge(node_id, self.script(target, payload), "action_JS", route="/JS")
        if "/Next" in value:
            target, following, fresh = self.child(node_id, value.raw_get("/Next"), "/Next", depth + 1)
            if isinstance(following, ArrayObject):
                for index, item in enumerate(following):
                    child, resolved, child_fresh = self.child(target, item, f"[{index}]", depth + 2)
                    if isinstance(resolved, DictionaryObject) and self.resolve_name(resolved.get("/S")) in ACTION_NAMES:
                        self.store.edge(node_id, child, "action_Next", route=f"/Next[{index}]")
                    else:
                        self.problem("actions", "action_next_invalid", [node_id, child])
                    self.walk(child, resolved, depth + 2)
            else:
                if isinstance(following, DictionaryObject) and self.resolve_name(following.get("/S")) in ACTION_NAMES:
                    self.store.edge(node_id, target, "action_Next", route="/Next")
                else:
                    self.problem("actions", "action_next_invalid", [node_id, target])
                self.walk(target, following, depth + 1)
        if kind == "/Launch" and "/F" in value:
            filespec, resolved, _ = self.child(node_id, value.raw_get("/F"), "/F", depth + 1)
            if isinstance(resolved, DictionaryObject) and "/EF" in resolved:
                self.store.edge(node_id, filespec, "Launch_filespec", route="/F")
                ef, mapping, _ = self.child(filespec, resolved.raw_get("/EF"), "/EF", depth + 2)
                if isinstance(mapping, DictionaryObject):
                    for key in ("/F", "/UF"):
                        if key in mapping:
                            child, stream, _ = self.child(ef, mapping.raw_get(key), key, depth + 3)
                            if stream is not None:
                                self.store.edge(filespec, self.payload(child, stream), "filespec_EF", route="/EF" + key)
                else:
                    self.problem("embedded", "embedded_filespec_invalid", [filespec, ef])

    def attach_actions(self, node_id, value, kind, depth):
        routes = ("/OpenAction",) if kind == "catalog" else ("/A",) if kind in {"annotation", "field"} else ()
        for route in routes:
            if route in value:
                child, action, _ = self.child(node_id, value.raw_get(route), route, depth + 1)
                if isinstance(action, DictionaryObject) and self.resolve_name(action.get("/S")) in ACTION_NAMES:
                    self.store.edge(node_id, child, kind + "_action", route=route)
        if "/AA" in value and kind in _AA_EVENTS:
            aa_id, aa, _ = self.child(node_id, value.raw_get("/AA"), "/AA", depth + 1)
            if isinstance(aa, DictionaryObject):
                for event in sorted(_AA_EVENTS[kind]):
                    if event in aa:
                        child, action, _ = self.child(aa_id, aa.raw_get(event), event, depth + 2)
                        if isinstance(action, DictionaryObject) and self.resolve_name(action.get("/S")) in ACTION_NAMES:
                            self.store.edge(node_id, child, kind + "_action", route="/AA" + event)
            else:
                self.problem("actions", "additional_actions_invalid", [node_id, aa_id])

    def walk(self, node_id, value, depth):
        if value is None or node_id in self.walked:
            return
        self.walked.add(node_id)
        kind, _ = self.kind(value)
        if isinstance(value, DictionaryObject):
            self.attach_actions(node_id, value, kind, depth)
            if kind == "action":
                self.action(node_id, value, depth)
            if kind == "embedded_stream":
                self.payload(node_id, value)
            if kind in {"form", "catalog"} and "/XFA" in value:
                self.xfa(node_id, value.raw_get("/XFA"), depth)
            priority = ("/OpenAction", "/AA", "/A", "/Next", "/JS", "/AcroForm", "/XFA", "/Names")
            for preferred in (True, False):
                for key, raw in value.items():
                    if (str(key) in priority) != preferred:
                        continue
                    route = _route(key)
                    try:
                        child, resolved, fresh = self.child(node_id, raw, route, depth + 1)
                        if kind == "catalog" and str(key) == "/AcroForm" and isinstance(resolved, DictionaryObject):
                            self.store.edge(node_id, child, "document_acroform", route=route)
                        self.walk(child, resolved, depth + 1)
                    except Exception as error:
                        reason = _reason(error, "graph_object_attribute_error" if isinstance(error, AttributeError) else "graph_object_failure")
                        self.problem("catalog", reason, [node_id])
                        if reason in {"graph_object_limit", "evidence_metadata_limit"}:
                            raise
        elif isinstance(value, ArrayObject):
            for index, raw in enumerate(value):
                child, resolved, fresh = self.child(node_id, raw, f"[{index}]", depth + 1)
                self.walk(child, resolved, depth + 1)

    def xfa(self, owner, raw, depth):
        container, value, _ = self.child(owner, raw, "/XFA", depth + 1)
        if container in self.xfa_containers:
            return
        self.xfa_containers.add(container)
        self.store.edge(owner, container, "acroform_xfa", route="/XFA")
        parts, sources = [], []
        try:
            if isinstance(value, ArrayObject):
                if not value or len(value) % 2 or len(value) > self.limits.max_objects:
                    raise CodeInspectionError("xfa_packet_array_invalid_or_limit")
                entries = [(i // 2, value[i]) for i in range(1, len(value), 2)]
            elif isinstance(value, StreamObject):
                entries = [(0, raw)]
            else:
                raise CodeInspectionError("xfa_object_unsupported")
            for index, entry in entries:
                stream_id, stream, _ = self.child(container, entry, f"packet[{index}]", depth + 2)
                if not isinstance(stream, StreamObject):
                    raise CodeInspectionError("xfa_object_unsupported")
                decoded, raw_hash, _ = self.budget.decode(stream, "xfa", self.store)
                packet = self.store.observation(self.backend, self.locators[stream_id] + f"|xfa:{index}", "xfa_packet",
                    raw_sha256=raw_hash, decoded_sha256=_digest(decoded), extraction_status="complete", decoded_validated=True,
                    packet_index=index, source_object_id=stream_id)
                self.store.edge(container, packet, "xfa_packet", route=f"packet[{index}]")
                sources.append((sum(map(len, parts)), packet))
                parts.append(decoded)
            self.xfa_xml(container, b"".join(parts), sources)
        except Exception as error:
            self.problem("xfa", _reason(error, "xfa_analysis_failure"), [container])

    def xfa_xml(self, container, data, sources):
        parser = expat.ParserCreate(namespace_separator="}")
        parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
        stack, active = [], None
        def reject(*args):
            raise CodeInspectionError("xfa_xml_dtd_unsupported")
        def start(name, attributes):
            nonlocal active
            local = name.rsplit("}", 1)[-1]
            self.budget.xml_nodes += 1
            if self.budget.xml_nodes > self.limits.max_objects:
                raise CodeInspectionError("xfa_xml_node_limit")
            if len(stack) >= self.limits.max_pdf_depth:
                raise CodeInspectionError("xfa_xml_depth_limit")
            if active is not None:
                raise CodeInspectionError("xfa_script_markup_unsupported")
            referenced = any(key.rsplit("}", 1)[-1] in {"use", "usehref", "href"} for key in attributes)
            inherited_bad = referenced or any(item[2] for item in stack)
            event = None
            if local == "event" and attributes.get("activity") in _XFA_EVENTS and not inherited_bad:
                packet = next((identity for offset, identity in reversed(sources) if offset <= parser.CurrentByteIndex), sources[0][1])
                event = self.store.observation(self.backend, container + f"|event:{parser.CurrentByteIndex}", "xfa_event",
                    event_activity=attributes["activity"], xml_byte_offset=parser.CurrentByteIndex)
                self.store.edge(packet, event, "XFA_event")
                # Container edge proves the complete ordered packet context.
                self.store.edge(container, event, "XFA_event")
            stack.append((local, event, inherited_bad))
            if local == "script" and attributes.get("contentType") == "application/x-javascript":
                parent_event = next((item[1] for item in reversed(stack[:-1]) if item[1]), None)
                active = [parser.CurrentByteIndex, parent_event, [], 0, inherited_bad]
            elif local == "script" and attributes.get("contentType", "application/x-formcalc") != "application/x-formcalc":
                self.problem("xfa", "xfa_script_language_unsupported", [container])
            if referenced:
                self.problem("xfa", "xfa_reference_unsupported", [container])
        def text(value):
            if active is not None:
                active[3] += len(value.encode("utf-8"))
                if active[3] > self.limits.max_script_bytes:
                    raise CodeInspectionError("script_byte_limit")
                active[2].append(value)
        def end(name):
            nonlocal active
            if active is not None and name.rsplit("}", 1)[-1] == "script":
                offset, event, parts, _, bad = active
                body = "".join(parts)
                locator = container + f"|xml_script:{offset}"
                object_id = self.store.observation(self.backend, locator, "xfa_script_source",
                    raw_sha256=_digest(body.encode("utf-8")), source_object_id=container,
                    xml_byte_offset=offset, event_declared=event is not None)
                self.locators[object_id] = locator
                if not bad:
                    script = self.script(object_id, TextStringObject(body))
                    if event is not None:
                        self.store.edge(event, script, "event_script")
                else:
                    self.problem("xfa", "xfa_reference_unsupported", [object_id])
                active = None
            stack.pop()
        parser.StartElementHandler, parser.EndElementHandler = start, end
        parser.CharacterDataHandler = text
        parser.StartDoctypeDeclHandler = parser.EntityDeclHandler = parser.ExternalEntityRefHandler = reject
        try:
            for index in range(0, len(data), 8192):
                parser.Parse(data[index:index + 8192], False)
            parser.Parse(b"", True)
        except expat.ExpatError:
            raise CodeInspectionError("xfa_xml_parse_error") from None

    def run(self, document):
        for failure in getattr(self.reader, '_malpdf_xrefstm_failures', []):
            offset = failure.get('offset', 'unknown')
            identifier = self.store.observation(self.backend, f'xfailure:{offset}', 'xref_check',
                offset=offset, status='unavailable', reason_codes=['supplemental_xref_unavailable'])
            self.problem('catalog', 'supplemental_xref_unavailable', [identifier])
        root, value, fresh = self.node(self.reader.trailer.raw_get("/Root"), "/Root", 0)
        if not isinstance(value, DictionaryObject) or self.resolve_name(value.get("/Type")) != "/Catalog":
            raise CodeInspectionError("graph_catalog_invalid")
        self.store.edge(document, root, "document_catalog", route="/Root")
        if fresh:
            self.walk(root, value, 0)
        self.bind_structural(root, value)
        return root

    def bind_structural(self, root, catalog):
        """Validate legal owner paths instead of trusting dictionary co-occurrence."""
        def children(parent, mapping, key):
            if key not in mapping:
                return []
            identifier, container, _ = self.child(parent, mapping.raw_get(key), key, 1)
            if isinstance(container, ArrayObject):
                return [self.child(identifier, value, f"[{index}]", 2)[:2]
                        for index, value in enumerate(container)]
            return [(identifier, container)]
        pending = []
        if "/Pages" in catalog:
            identifier, value, _ = self.child(root, catalog.raw_get("/Pages"), "/Pages", 1)
            if isinstance(value, DictionaryObject) and self.resolve_name(value.get("/Type")) == "/Pages":
                self.store.edge(root, identifier, "catalog_pages", route="/Pages")
                pending.append((identifier, value))
        seen = set()
        while pending:
            parent, mapping = pending.pop()
            if parent in seen:
                continue
            seen.add(parent)
            for identifier, value in children(parent, mapping, "/Kids"):
                if not isinstance(value, DictionaryObject):
                    continue
                kind = self.resolve_name(value.get("/Type"))
                if kind not in {"/Page", "/Pages"}:
                    continue
                self.store.edge(parent, identifier, "pages_child", route="/Kids")
                if kind == "/Pages":
                    pending.append((identifier, value))
                else:
                    for annotation, item in children(identifier, value, "/Annots"):
                        if isinstance(item, DictionaryObject) and self.kind(item)[0] == "annotation":
                            self.store.edge(identifier, annotation, "page_annotation", route="/Annots")
        if "/AcroForm" in catalog:
            form, mapping, _ = self.child(root, catalog.raw_get("/AcroForm"), "/AcroForm", 1)
            if isinstance(mapping, DictionaryObject):
                self.store.edge(root, form, "document_acroform", route="/AcroForm")
                pending = [(form, mapping, "/Fields")]
                seen = set()
                while pending:
                    parent, mapping, key = pending.pop()
                    if parent in seen:
                        continue
                    seen.add(parent)
                    for identifier, value in children(parent, mapping, key):
                        if isinstance(value, DictionaryObject):
                            self.store.edge(parent, identifier, "form_field", route=key)
                            pending.append((identifier, value, "/Kids"))
        if "/Names" in catalog:
            names, mapping, _ = self.child(root, catalog.raw_get("/Names"), "/Names", 1)
            if isinstance(mapping, DictionaryObject) and "/JavaScript" in mapping:
                tree, value, _ = self.child(names, mapping.raw_get("/JavaScript"), "/JavaScript", 2)
                pending, seen = [(tree, value)], set()
                while pending:
                    parent, mapping = pending.pop()
                    if parent in seen or not isinstance(mapping, DictionaryObject):
                        continue
                    seen.add(parent)
                    if "/Names" in mapping:
                        array, values, _ = self.child(parent, mapping.raw_get("/Names"), "/Names", 3)
                        if isinstance(values, ArrayObject) and len(values) % 2 == 0:
                            for index in range(0, len(values), 2):
                                if not isinstance(values[index], (TextStringObject, ByteStringObject)):
                                    continue
                                action, item, _ = self.child(array, values[index + 1], f"[{index + 1}]", 4)
                                if isinstance(item, DictionaryObject) and self.resolve_name(item.get("/S")) == "/JavaScript":
                                    self.store.edge(root, action, "catalog_action", route=f"/Names/JavaScript/Names[{index + 1}]")
                    pending.extend(children(parent, mapping, "/Kids"))


def _witnesses(result):
    """Find eligible linked evidence; the decision policy validates it again."""
    nodes = {item["id"]: item for item in result["observations"]}
    adjacency = defaultdict(list)
    for edge in result["edges"]:
        if edge["status"] == "verified":
            adjacency[edge["source"]].append(edge)
    witnesses = []
    # Object reachability is verified only through actual graph edges. Semantic
    # owner/action edges separately constrain executable PDF action placement.
    for document in (item for item in nodes.values() if item["kind"] == "document"):
        pending, reachable = [(document["id"], [document["id"]])], {}
        while pending:
            identity, path = pending.pop()
            if identity in reachable:
                continue
            reachable[identity] = path
            for edge in adjacency[identity]:
                if edge["kind"] in {"document_catalog", "catalog_pages", "pages_child", "page_annotation",
                                    "document_acroform", "form_field", "acroform_xfa", "xfa_packet"}:
                    pending.append((edge["target"], path + [edge["id"], edge["target"]]))
        action_paths = []
        for owner, path in reachable.items():
            for edge in adjacency[owner]:
                if edge["kind"] in {"catalog_action", "page_action", "annotation_action", "field_action", "form_action"}:
                    action_paths.append((edge["target"], path + [edge["id"], edge["target"]]))
            for edge in adjacency[owner]:
                if edge["kind"] == "XFA_event":
                    for script_edge in adjacency[edge["target"]]:
                        script = nodes.get(script_edge["target"], {})
                        if script_edge["kind"] == "event_script" and script.get("extraction_status") == "complete" and script.get("ast_status") == "complete":
                            witnesses.append({"family": "xfa_javascript", "status": "verified", "terminal_id": script["id"],
                                "supporting_ids": path + [edge["id"], edge["target"], script_edge["id"], script["id"]]})
        seen_actions = set()
        while action_paths:
            action, path = action_paths.pop()
            if action in seen_actions:
                continue
            seen_actions.add(action)
            for edge in adjacency[action]:
                target = nodes.get(edge["target"], {})
                if edge["kind"] == "action_Next":
                    action_paths.append((edge["target"], path + [edge["id"], edge["target"]]))
                elif edge["kind"] == "action_JS" and target.get("extraction_status") == "complete" and target.get("ast_status") == "complete":
                    witnesses.append({"family": "pdf_javascript", "status": "verified", "terminal_id": target["id"],
                        "supporting_ids": path + [edge["id"], target["id"]]})
                elif edge["kind"] == "Launch_filespec":
                    for payload_edge in adjacency[edge["target"]]:
                        payload = nodes.get(payload_edge["target"], {})
                        if payload_edge["kind"] == "filespec_EF" and payload.get("extraction_status") == "complete" and payload.get("magic") in {"pe", "elf"}:
                            witnesses.append({"family": "embedded_launch", "status": "verified", "terminal_id": payload["id"],
                                "supporting_ids": path + [edge["id"], edge["target"], payload_edge["id"], payload["id"]]})
    unique = {(w["family"], w["terminal_id"]): w for w in witnesses}
    return list(unique.values())


def inspect_evidence_v9(data, static, code, limits, *, timings=None, primary_complete=False,
                        checkpoint=None, raw_sink=None, legacy_analysis=None):
    """Inspect immutable bytes inside the existing capped worker and emit deltas.

    Legacy v8 is measured first; remaining decoded-byte and AST budgets are
    carried into this pass. Backend-local identities never alias generations or
    unverified revisions. Secondary failure leaves primary checkpoints intact.
    """
    if not isinstance(data, bytes) or not data.startswith(b"%PDF-") or len(data) > limits.max_file_bytes:
        raise CodeInspectionError("not_pdf_or_byte_limit")
    store = _Store(_digest(data), checkpoint, raw_sink)
    result = store.result
    result["primary_profile_complete"] = bool(primary_complete)
    result["recovery_attempted"] = not primary_complete
    result["scope"] = "latest catalog/actions/declared XFA/embedded; historical revisions and orphan objects unverified"
    document = store.observation("original", "original", "document", raw_sha256=store.digest,
                                  size_bytes=len(data), immutable=True)
    input_digest = (static.get("input") or {}).get("sha256")
    input_verified = input_digest == store.digest
    measurements = store.observation("legacy", "primary_model_inputs", "primary_model_inputs",
        status="verified" if input_verified else "unavailable",
        reason_codes=[] if input_verified else ["primary_input_identity_unverified"],
        source_object_id=document, primary_complete=bool(primary_complete),
        measurement_sha256=_digest(_json_bytes({"static": static, "code": code, "analysis_v8": legacy_analysis})))
    budget = _Budget(limits, code or {}, legacy_analysis)
    graphs = []
    for backend in (["pypdf"] if primary_complete else ["pypdf", "MuPDF"]):
        reader, graph, failure = None, None, None
        diagnostic = ParserDiagnostics(strict=False)
        try:
            with stage(timings, "parse_pdf"), diagnostic.capture_open_notices():
                reader = PdfReader(io.BytesIO(data), strict=False) if backend == "pypdf" else MuPDFObjectReader(data, limits)
                if reader.is_encrypted:
                    raise CodeInspectionError("encrypted_pdf")
                graph = _Graph(reader, backend, data, store, budget, timings)
                graph.run(document)
        except Exception as error:
            failure = _reason(error, "graph_backend_attribute_error" if isinstance(error, AttributeError) else "graph_backend_failure")
            if graph is not None:
                try:
                    graph.problem("catalog", failure, graph.scope[-1:])
                except CodeInspectionError:
                    pass
        finally:
            if reader is not None and backend == "MuPDF":
                reader.close()
        if graph is not None:
            graphs.append(graph)
        for capability in CAPABILITIES:
            errors = set(graph.errors.get(capability, [])) if graph else {failure or "backend_unavailable"}
            # Unfinished catalog enumeration makes absence/completion unknown.
            if failure or (graph and graph.errors.get("catalog")):
                errors.add(failure or "catalog_enumeration_incomplete")
            if backend == "MuPDF":
                errors.add("recovered_scope_not_complete")
            check = {"id": store.identifier(backend, capability, "capability_check"), "backend": backend,
                "capability": capability, "status": "complete" if not errors else "partial",
                "scope_ids": sorted(graph.failure_scopes.get(capability, set()) |
                                    graph.failure_scopes.get("catalog", set())) if graph and errors else [],
                "required_ids": list(graph.scope) if graph and not errors else [],
                "reason_codes": sorted(errors)}
            try:
                store.append("capability_checks", check)
            except CodeInspectionError:
                # Oversized enumeration cannot become a complete check. Keep
                # its backend/catalog owner and emit the partial check through
                # the same bounded checkpoint path as every other entry.
                affected = graph.scope[:1] if graph else []
                if graph is not None:
                    graph.problem("catalog", "evidence_metadata_limit", affected)
                check.update(status="partial", scope_ids=affected, required_ids=[],
                             reason_codes=["evidence_metadata_limit"])
                store.append("capability_checks", check)
        # Capability serialization can itself hit the metadata allowance. Its
        # localized failure must be included in the immutable backend summary.
        reasons = sorted(set([failure] if failure else []) | set().union(*(graph.errors.values() if graph else [])))
        state = {"id": store.identifier(backend, "backend_result", "backend_result"), "backend": backend,
                 "status": "error" if failure and graph is None else "partial" if reasons or backend == "MuPDF" else "observed",
                 "reason_codes": reasons, "completed_observations": len(graph.scope) if graph else 0,
                 "stage": "open" if graph is None else "graph_or_script", "revision_completeness": "unknown"}
        store.append("backend_results", state)
    if len(graphs) == 2:
        for key in sorted(graphs[0].projections.keys() & graphs[1].projections.keys()):
            left, right = graphs[0].projections[key], graphs[1].projections[key]
            if left[1] != right[1]:
                item = {"id": store.identifier("comparison", f"{key[0]}:{key[1]}", "conflict"),
                    "affected_ids": [left[0], right[0]], "fields": ["projection"], "localized": False,
                    "reason_code": "backend_projection_conflict_revision_unverified",
                    "resolution": "separate observations; revision identity unknown"}
                store.append("conflicts", item)
    primary_checks = [c for c in result["capability_checks"] if c.get("backend") == "pypdf"]
    result["complete"] = bool(primary_complete and len(primary_checks) == len(CAPABILITIES)
                              and all(c["status"] == "complete" for c in primary_checks) and not result["conflicts"])
    result["status"] = "complete" if result["complete"] else "partial" if any(g.scope for g in graphs) else "unavailable"
    result["witnesses"] = _witnesses(result)
    from malpdf.inference.evidence_policy_v9 import derive_feature_provenance
    result["feature_provenance"] = derive_feature_provenance(
        {"static": static, "code": code, "analysis_v8": legacy_analysis, "pdf_sha256": store.digest}, result)
    result["budget_usage"] = {"decoded_bytes_prior": limits.max_decoded_bytes - budget.initial_decoded_remaining,
        "decoded_bytes_v9": budget.initial_decoded_remaining - budget.decoded_remaining,
        "decoded_bytes_failed_upper_bound_debit": budget.failed_decode_debit,
        "decoded_bytes_remaining": budget.decoded_remaining, "ast_nodes_prior": budget.ast_initial,
        "ast_nodes_v9": budget.ast_used - budget.ast_initial, "raw_bytes_retained": store.raw_bytes,
        "graph_metadata_bytes": store.metadata_bytes, "objects_visited": budget.objects,
        "scripts_inspected": budget.scripts, "xml_nodes": budget.xml_nodes}
    result["budget_usage"].update(scripts_prior=budget.scripts_prior,
                                   new_scripts_analyzed=len(budget.new_script_hashes))
    if checkpoint:
        checkpoint({key: value for key, value in result.items() if key not in {
            "observations", "edges", "capability_checks", "conflicts", "backend_results"}})
    return result
