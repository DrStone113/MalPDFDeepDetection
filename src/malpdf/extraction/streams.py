"""Supplement v9 with bounded per-filter evidence on its discovered streams."""

from dataclasses import asdict
from copy import deepcopy
import hashlib
import json

from malpdf.extraction.filters import DecodeBudget, FilterLimits, decode_filters
from malpdf.static.execution import capacity, UNLIMITED, is_vm
from malpdf.extraction.checkpointing import CheckpointScheduler

MAX_STREAMS = 128
MAX_METADATA_BYTES = 512 * 1024


class StreamCollector:
    """Keep v9 observations unchanged; decode only after v9 spends its budget.

    The collector operates in the same disposable worker. It does not enumerate
    a new parser view, call get_data() or enumerate orphan/object streams. An
    optional sink routes completed bytes to the separately bounded carver; the
    collector does not claim complete PDF stream coverage.
    """

    def __init__(self, digest, limits, *, retain=None, checkpoint=None, artifact_sink=None, plugins=None):
        self.sources, self.retain, self.checkpoint = [], retain, checkpoint
        self.artifact_sink = artifact_sink
        self.plugins=plugins
        self.enhanced = is_vm(limits)
        self.limit = min(capacity(limits, MAX_STREAMS), limits.max_objects)
        self.metadata_limit = capacity(limits, MAX_METADATA_BYTES)
        self.checkpoints = CheckpointScheduler(limits)
        self.limits = FilterLimits(max_input_bytes=limits.max_file_bytes,
            max_stage_bytes=min(capacity(limits, 1024**2), limits.max_decoded_bytes),
            max_total_bytes=limits.max_decoded_bytes, max_filters=capacity(limits, 8))
        self.resolution_limit = limits.max_objects
        self.value = {"schema_version": "pdf-stream-analysis-v1", "document_sha256": digest,
            "status": "not_run", "complete": False, "scope": "v9 catalog-discovered streams; orphan/history coverage unverified",
            "records": [], "active_stream": None, "discovered_streams": 0, "retained_sources": 0,
            "parameter_reference_reads": 0,
            "source_limit_reached": False, "reason_codes": [], "limits": asdict(self.limits),
            "decoded_bytes_available": None, "decoded_bytes_used": 0, "decoded_bytes_remaining": None}

    def observe(self, value, *, backend, source_id, object_number, generation, offset):
        """Capture references only, without taking bytes from v9's decode budget."""
        self.value["discovered_streams"] += 1
        if len(self.sources) == self.limit:
            self.value["source_limit_reached"] = True
            return
        from pypdf.generic import NameObject, NumberObject
        context = {}
        object_type, subtype = value.get('/Type'), value.get('/Subtype')
        if isinstance(object_type, NameObject) and str(object_type) == '/ObjStm':
            context['hint'] = 'object_stream'
            for key, name in (('/N', 'objects'), ('/First', 'first')):
                item = value.raw_get(key) if key in value else None
                context[name] = int(item) if isinstance(item, NumberObject) else None
        elif isinstance(subtype, NameObject) and str(subtype) == '/Image':
            context['hint'] = 'image_data'
            for key, name in (('/Width', 'width'), ('/Height', 'height'), ('/BitsPerComponent', 'bits_per_component')):
                item = value.raw_get(key) if key in value else None
                if isinstance(item, NumberObject):
                    context[name] = int(item)
            color = value.raw_get('/ColorSpace') if '/ColorSpace' in value else None
            if isinstance(color, NameObject) and str(color) in {'/DeviceGray', '/DeviceRGB', '/DeviceCMYK'}:
                context['components'] = {'/DeviceGray': 1, '/DeviceRGB': 3, '/DeviceCMYK': 4}[str(color)]
        self.sources.append((value, {"source_id": source_id, "backend": backend,
            "object_number": object_number, "generation": generation, "offset": offset, 'artifact_context': context}))
        self.value["retained_sources"] = len(self.sources)

    def _metadata(self, stream):
        from pypdf.errors import LimitReachedError
        from pypdf.generic import ArrayObject, BooleanObject, DictionaryObject, IndirectObject, NameObject, NullObject, NumberObject
        from malpdf.static.js_ast import CodeInspectionError

        def resolve(value):
            seen = set()
            while isinstance(value, IndirectObject):
                key = (value.idnum, value.generation)
                if key in seen or len(seen) == 16 or self.value["parameter_reference_reads"] >= self.resolution_limit:
                    raise ValueError("stream_parameter_reference_limit")
                seen.add(key)
                self.value["parameter_reference_reads"] += 1
                try:
                    value = value.get_object()
                except MemoryError:
                    raise
                except Exception as error:
                    if isinstance(error, LimitReachedError) or isinstance(error, CodeInspectionError) and "limit" in str(error):
                        raise ValueError("stream_parameter_reference_limit") from None
                    if isinstance(error, CodeInspectionError) and "unsupported" in str(error):
                        raise ValueError("stream_parameter_reference_unsupported") from None
                    raise ValueError("stream_parameter_reference_unavailable") from None
                if value is None:
                    raise ValueError("stream_parameter_reference_unavailable")
            return value

        filters = resolve(stream.raw_get("/Filter")) if "/Filter" in stream else []
        filters = [] if isinstance(filters, NullObject) else list(filters) if isinstance(filters, (ArrayObject, list)) else [filters]
        if len(filters) > self.limits.max_filters:
            raise ValueError("stream_filter_count_limit")
        names = []
        for value in filters:
            value = resolve(value)
            if not isinstance(value, NameObject) or len(str(value)) > 256:
                raise ValueError("invalid_stream_filter_metadata")
            names.append(str(value))
        parameters = resolve(stream.raw_get("/DecodeParms")) if "/DecodeParms" in stream else None
        parameters = None if isinstance(parameters, NullObject) else parameters
        def project(value):
            value = resolve(value)
            if value is None or isinstance(value, NullObject):
                return None
            if not isinstance(value, DictionaryObject) or len(value) > 16:
                raise ValueError("invalid_stream_decode_parameters")
            output = {}
            for key, item in value.items():
                extra={key for spec in self.plugins.select('decoder') for key in spec.parameter_keys} if self.plugins is not None else set()
                if str(key) not in {"/Predictor", "/Columns", "/Colors", "/BitsPerComponent", "/EarlyChange", "/Name", "/Type", "/ColorTransform",
                    '/K', '/Rows', '/EndOfLine', '/EncodedByteAlign', '/EndOfBlock', '/BlackIs1', '/DamagedRowsBeforeError'}|extra:
                    raise ValueError("unsupported_decode_parameter")
                item = resolve(item)
                if isinstance(item, NumberObject):
                    output[str(key)] = int(item)
                elif isinstance(item, BooleanObject):
                    output[str(key)] = item.value
                elif isinstance(item, NameObject) and str(key) in {"/Name", "/Type"}:
                    output[str(key)] = str(item)
                else:
                    raise ValueError("invalid_stream_decode_parameter_value")
            return output
        if isinstance(parameters, ArrayObject):
            if len(parameters) != len(names):
                raise ValueError("filter_parameter_alignment")
            parameters = [project(value) for value in parameters]
        elif parameters is not None:
            parameters = project(parameters)
        return names, parameters

    def _emit(self, *, force=False):
        if self.metadata_limit != UNLIMITED and len(json.dumps(self.value, allow_nan=False, separators=(",", ":")).encode()) > self.metadata_limit:
            raise ValueError("stream_metadata_limit")
        if not self.checkpoints.due(force=force):
            return
        if self.checkpoint:
            self.checkpoint(deepcopy(self.value))
        self.checkpoints.completed()

    def finish(self, remaining):
        if type(remaining) is not int or not 0 <= remaining <= self.limits.max_total_bytes:
            raise ValueError("Invalid v9 remaining decoded-byte budget")
        budget = DecodeBudget(remaining)
        self.value.update(status="partial", decoded_bytes_available=remaining, decoded_bytes_remaining=remaining)
        self._emit()
        reasons = set()
        if self.value["source_limit_reached"]:
            reasons.add("stream_source_limit")
        for stream, source in self.sources:
            decoded = None
            raw = getattr(stream, "_data", None)
            entry = {**source, "id": "stream:" + hashlib.sha256(source["source_id"].encode()).hexdigest(),
                "filters": None, "decode": None, "status": "partial", "reason_codes": [],
                "declared_length": None, "length_comparison_status": "not_run",
                "length_limitation": "original_declared_length_not_verified_in_this_view"}
            self.value['active_stream'] = deepcopy(entry)
            self._emit()
            try:
                names, parameters = self._metadata(stream)
                entry["filters"] = names
                def filter_checkpoint(metadata):
                    previous = self.value['active_stream']
                    self.value['active_stream'] = {**entry, 'decode': metadata, 'status': metadata['status'],
                                                   'reason_codes': metadata['reason_codes']}
                    self.value.update(decoded_bytes_used=remaining - budget.remaining, decoded_bytes_remaining=budget.remaining)
                    try:
                        self._emit()
                    except Exception:
                        self.value['active_stream'] = previous
                        raise
                decoded = decode_filters(raw, names, decode_parms=parameters,
                    limits=self.limits, budget=budget, retain=self.retain, checkpoint=filter_checkpoint,plugins=self.plugins,
                    recover_trailing=self.enhanced, media_codecs=self.enhanced, image_context=source['artifact_context'])
                entry.update(decode=decoded.metadata, status=decoded.metadata["status"],
                             reason_codes=decoded.metadata["reason_codes"])
            except Exception as error:


                internal = str(error) if isinstance(error, ValueError) else ""
                code = internal if internal in {"stream_parameter_reference_limit", "stream_filter_count_limit", "stream_parameter_reference_unavailable", "stream_parameter_reference_unsupported", "stream_metadata_limit",
                    "invalid_stream_filter_metadata", "invalid_stream_decode_parameters", "unsupported_decode_parameter",
                    "invalid_stream_decode_parameter_value", "filter_parameter_alignment"} else "stream_decode_failure"
                if isinstance(error, MemoryError):
                    code = "stream_memory_limit"
                    budget.remaining = 0
                status = ("resource_limit" if "limit" in code else "partial" if code == "stream_parameter_reference_unavailable"
                          else "unsupported" if "unsupported" in code else "decode_error")
                active = self.value.get('active_stream') or {}
                if active.get('decode'):
                    entry['decode'] = deepcopy(active['decode'])
                entry.update(status=status, reason_codes=[code])
            reasons.update(entry["reason_codes"])
            if self.metadata_limit != UNLIMITED:
                proposed = {**self.value, "records": self.value["records"] + [entry], 'active_stream': None}
                reserve = max(4096, min(128 * 1024, self.metadata_limit // 4))
                if len(json.dumps(proposed, allow_nan=False, separators=(",", ":")).encode()) > self.metadata_limit - reserve:
                    reasons.add("stream_metadata_limit")
                    break
            self.value["records"].append(entry)
            self.value['active_stream'] = None
            self.value.update(decoded_bytes_used=remaining - budget.remaining, decoded_bytes_remaining=budget.remaining,
                              reason_codes=sorted(reasons))
            self._emit()
            if decoded is not None and ((entry.get('decode') or {}).get('output_complete') or (entry.get('decode') or {}).get('complete')) and self.artifact_sink is not None:
                try:
                    self.artifact_sink(decoded.data, entry)
                except Exception:


                    reasons.add('artifact_routing_failed')
                    self.value.setdefault('artifact_routing_failures', []).append(entry['id'])
            if decoded is not None and self.artifact_sink is not None:
                for filter_index, suffix in decoded.trailing_spans:
                    suffix_entry = {**entry, 'id': entry['id'] + ':filter:' + str(filter_index),
                        'artifact_context': {'origin': 'encoded_filter_trailing_bytes'},
                        'decode': {'decoded_sha256': hashlib.sha256(suffix).hexdigest(), 'complete': False,
                                   'reason_codes': ['filter_trailing_data_preserved']}}
                    try:
                        self.artifact_sink(suffix, suffix_entry)
                    except Exception:
                        reasons.add('artifact_routing_failed')
                        self.value.setdefault('artifact_routing_failures', []).append(suffix_entry['id'])
        self.value.update(status="observed" if not reasons else "partial", complete=not reasons,
            decoded_bytes_used=remaining - budget.remaining, decoded_bytes_remaining=budget.remaining, reason_codes=sorted(reasons))
        self._emit(force=True)
        return self.value
