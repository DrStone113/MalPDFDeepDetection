"""Bounded, non-executing recursion over verified decoded artifacts.

Input comes from completed filters, never from failed decoder prefixes. Children
share the original worker, output-byte/AST/script/retention budgets, and lineage.
Archive names are metadata only: no extraction API or external tool is invoked.
"""

from collections import deque
from copy import deepcopy
from dataclasses import asdict, dataclass, replace
import hashlib
import io
import json
import re
import stat
import struct
import zipfile
import zlib

from malpdf.extraction.filters import DecodeBudget, _Stopped, _flate
from malpdf.static.code_inspector import _decode_script_bytes
from malpdf.static.js_ast import CodeInspectionError, inspect_js_syntax
from malpdf.static.profiling import stage
from malpdf.static.execution import capacity, expand_limits, valid_capacity, is_vm
from malpdf.static.execution import UNLIMITED
from malpdf.extraction.checkpointing import CheckpointScheduler


@dataclass(frozen=True)
class CarvingLimits:
    max_depth: int = 4
    max_artifacts: int = 64
    max_artifact_bytes: int = 1024**2
    max_queued_bytes: int = 4 * 1024**2
    max_archive_members: int = 64
    max_expansion_ratio: int = 100
    max_pdf_children: int = 8
    max_child_streams: int = 128
    max_metadata_bytes: int = 1024**2

    def __post_init__(self):
        if any(type(value) is not int or value <= 0 for value in asdict(self).values()):
            raise ValueError('Carving limits must be positive integers')
        if any(not valid_capacity(value, ceiling) for value, ceiling in zip(asdict(self).values(),
                (8, 128, 8 * 1024**2, 8 * 1024**2, 128, 1000, 16, 256, 2 * 1024**2))):
            raise ValueError('Carving limits exceed the static resource budget')
        if self.max_metadata_bytes < 2048:
            raise ValueError('Carving metadata needs terminal status space')


class _CarveIssue(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def artifact_kind(data, hint=None):
    """Classify magic/context, without asserting validity or exploit coverage."""
    signatures = ((b'%PDF-', 'pdf'), (b'PK\x03\x04', 'zip'), (b'PK\x05\x06', 'zip'),
        (b'\x89PNG\r\n\x1a\n', 'png'), (b'\xff\xd8\xff', 'jpeg'),
        (b'\x00\x00\x00\x0cjP  \r\n\x87\n', 'jpx'), (b'\xff\x4f\xff\x51', 'jpx'),
        (b'\x97JB2\r\n\x1a\n', 'jbig2'),
        (b'\x00\x01\x00\x00', 'sfnt_font'), (b'OTTO', 'sfnt_font'), (b'true', 'sfnt_font'), (b'typ1', 'sfnt_font'),
        (b'wOFF', 'woff_font'), (b'wOF2', 'woff_font'),
        (b'%!PS-AdobeFont', 'font_data'), (b'%!FontType1', 'font_data'), (b'\x80\x01', 'font_data'),
        (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'ole'), (b'FWS', 'flash'), (b'CWS', 'flash'), (b'ZWS', 'flash'),
        (b'Rar!\x1a\x07', 'rar'), (b'7z\xbc\xaf\x27\x1c', '7z'), (b'MZ', 'pe_candidate'), (b'\x7fELF', 'elf_candidate'))
    for signature, kind in signatures:
        if data.startswith(signature):
            return kind
    return hint if hint in {'javascript', 'xfa_xml', 'object_stream', 'image_data', 'font_data',
                             'javascript_candidate', 'xml_candidate', 'content_stream'} else 'unknown'


class RecursiveCarver:
    def __init__(self, root_sha256, code_limits, *, limits=None, retain=None, checkpoint=None, plugins=None):
        self.limits = limits or expand_limits(CarvingLimits(
            max_artifact_bytes=min(1024**2, code_limits.max_file_bytes),
            max_queued_bytes=min(4 * 1024**2, code_limits.max_decoded_bytes)), code_limits)
        self.code_limits, self.retain, self.checkpoint = code_limits, retain, checkpoint
        self.checkpoints = CheckpointScheduler(code_limits)
        self.plugins=plugins
        self.queue, self.seen, self.index, self.contexts, self.script_cache = deque(), {}, {}, {}, {}
        self.queued_bytes = self.pdf_children = self.child_streams = 0
        self.object_allowance = self.xml_remaining = code_limits.max_objects
        self.ast_remaining, self.scripts_remaining = code_limits.max_ast_nodes, code_limits.max_scripts
        self.budget = None
        self._saved = None
        self._pdf_budget_pending = False
        self.value = {'schema_version': 'pdf-recursive-artifacts-v1', 'document_sha256': root_sha256,
            'status': 'not_run', 'complete': False, 'records': [], 'analyses': {}, 'active_artifact_id': None,
            'unclassified_inputs': [], 'inputs_seen': 0, 'reason_codes': [], 'limits': asdict(self.limits),
            'decoded_bytes_available': None, 'decoded_bytes_used': 0, 'decoded_bytes_remaining': None,
            'ast_nodes_remaining': self.ast_remaining, 'scripts_remaining': self.scripts_remaining,
            'per_pass_object_allowance_remaining': self.object_allowance, 'xml_nodes_remaining': self.xml_remaining}
        self._saved = deepcopy(self.value)

    def register_context(self, analysis):
        """Use verified v9 source relationships, not names/extensions as proof."""
        for node in analysis.get('observations', []):
            source = node.get('source_object_id')
            if node.get('kind') in {'script', 'script_extraction'} and node.get('extraction_status') == 'complete':
                self.contexts[source] = 'javascript'
            elif node.get('kind') == 'xfa_packet':
                self.contexts[source] = 'xfa_xml'
            if (node.get('kind') == 'script' and node.get('ast_status') == 'complete'
                    and node.get('decoded_validated') is True and isinstance(node.get('ast_summary'), dict)):
                self.script_cache[node['decoded_sha256']] = (node['ast_summary'], node['id'])

    def _blob(self, data):
        result = {'sha256': _digest(data), 'size_bytes': len(data), 'status': 'not_retained'}
        if self.retain is not None:
            result = self.retain(data)
            if not isinstance(result, dict) or result.get('sha256') != _digest(data) or result.get('size_bytes') != len(data):
                raise ValueError('artifact_retention_identity_mismatch')
        return result

    def _emit(self, *, force=False):
        if self.budget is not None:
            self.value.update(decoded_bytes_used=self.value['decoded_bytes_available'] - self.budget.remaining,
                              decoded_bytes_remaining=self.budget.remaining)
        self.value.update(ast_nodes_remaining=self.ast_remaining, scripts_remaining=self.scripts_remaining,
            per_pass_object_allowance_remaining=self.object_allowance, xml_nodes_remaining=self.xml_remaining)

        if not self.checkpoints.due(force=force):
            return
        if self.limits.max_metadata_bytes != UNLIMITED and len(json.dumps(self.value, allow_nan=False, separators=(',', ':')).encode()) > self.limits.max_metadata_bytes - 256:
            raise _CarveIssue('resource_limit', 'artifact_metadata_limit')
        if self.checkpoint:
            self.checkpoint(deepcopy(self.value))
        self._saved = deepcopy(self.value)
        self.checkpoints.completed()

    def add(self, data, *, parent_id, decoded_sha256, source_document_sha256=None,
            slot='stream', container_id=None, hint=None, metadata=None, repaired=False, force=False):
        """Admit a complete, hash-verified body; preserve each incoming lineage."""
        if not isinstance(data, bytes) or _digest(data) != decoded_sha256:
            raise ValueError('artifact_source_identity_mismatch')
        self.value['inputs_seen'] += 1
        hint = self.contexts.get((metadata or {}).get('source_id'), hint)
        kind = artifact_kind(data, hint)
        if kind == 'unknown' and not force:
            if len(self.value['unclassified_inputs']) < self.limits.max_artifacts:
                self.value['unclassified_inputs'].append({'parent_id': parent_id, 'sha256': decoded_sha256,
                                                        'size_bytes': len(data)})
            else:
                self.value['reason_codes'] = sorted(set(self.value['reason_codes']) | {'unclassified_input_limit'})
            return None
        if container_id is not None and container_id not in self.index:
            raise ValueError('artifact_container_identity_unavailable')
        parent = self.index.get(container_id)
        depth = 1 if parent is None else parent['depth'] + 1
        ancestors = (self.value['document_sha256'],) if parent is None else tuple(parent['ancestors']) + (parent['sha256'],)
        identity = 'artifact:' + _digest((self.value['document_sha256'] + '|' + parent_id + '|' + str(slot)).encode())
        if identity in self.index:
            if self.index[identity]['sha256'] != decoded_sha256:
                raise ValueError('artifact_occurrence_identity_collision')
            return identity
        if len(self.value['records']) >= self.limits.max_artifacts:
            self.value['reason_codes'] = sorted(set(self.value['reason_codes']) | {'artifact_count_limit'})
            return None
        if not data and force:
            kind = 'empty'
        entry = {'id': identity, 'parent_id': parent_id, 'container_id': container_id,
            'source_document_sha256': source_document_sha256, 'sha256': decoded_sha256, 'size_bytes': len(data),
            'kind': kind, 'declared_hint': hint, 'depth': depth, 'ancestors': list(ancestors),
            'status': 'not_run', 'reason_codes': [], 'reused_from_id': None,
            'is_synthetic_repaired': bool(repaired or parent and parent['is_synthetic_repaired']),
            'source_metadata': metadata or {}, 'retention': self._blob(data)}
        self.index[identity] = entry
        self.value['records'].append(entry)
        if decoded_sha256 in ancestors:
            entry.update(status='partial', reason_codes=['artifact_ancestor_cycle'])
        elif depth > self.limits.max_depth:
            entry.update(status='resource_limit', reason_codes=['artifact_depth_limit'])
        elif len(data) > self.limits.max_artifact_bytes or self.queued_bytes + len(data) > self.limits.max_queued_bytes:
            entry.update(status='resource_limit', reason_codes=['artifact_input_byte_limit'])
        elif (decoded_sha256, kind) in self.seen:
            entry['reused_from_id'] = self.seen[(decoded_sha256, kind)]
        else:
            self.seen[(decoded_sha256, kind)] = identity
            self.queued_bytes += len(data)
            self.queue.append((identity, data))
        return identity

    def stream_sink(self, *, container_id=None, document_sha256=None):
        def accept(data, entry):
            context = entry.get('artifact_context') or {}
            return self.add(data, parent_id=entry['id'], decoded_sha256=entry['decode']['decoded_sha256'],
                source_document_sha256=document_sha256 or self.value['document_sha256'], container_id=container_id,
                hint=context.get('hint'), metadata={**context, 'source_id': entry['source_id'],
                    'source_decode_complete': entry['decode']['complete'],
                    'source_decode_reason_codes': entry['decode']['reason_codes']},
                repaired=entry['backend'] == 'MuPDF')
        return accept

    def _script(self, data, source_id=None, *, text=None, utf8=False):
        if text is None:
            text = data.decode('utf-8-sig', errors='strict') if utf8 else _decode_script_bytes(data, self.code_limits)
        if len(text.encode('utf-8')) > self.code_limits.max_script_bytes:
            raise _CarveIssue('resource_limit', 'artifact_script_byte_limit')
        digest = _digest(text.encode('utf-8'))
        if digest in self.script_cache:
            summary, source_id = self.script_cache[digest]
            return {'decoded_script_sha256': digest, 'ast': summary, 'reused_from_evidence_id': source_id}
        if self.ast_remaining <= 0 or self.scripts_remaining <= 0:
            raise _CarveIssue('resource_limit', 'artifact_ast_or_script_limit')
        self.scripts_remaining -= 1
        try:
            with stage(getattr(self,'timings',None),'js_ast'):
                summary = inspect_js_syntax(text, max_bytes=self.code_limits.max_script_bytes,
                    max_nodes=self.ast_remaining, max_depth=self.code_limits.max_ast_depth)
        except CodeInspectionError as error:
            if 'limit' in str(error):
                self.ast_remaining = 0
                raise _CarveIssue('resource_limit', 'artifact_ast_limit') from None
            raise _CarveIssue('decode_error', 'artifact_javascript_parse_error') from None
        self.ast_remaining -= summary['node_count']
        if source_id is not None:
            self.script_cache[digest] = (summary, source_id)
        return {'decoded_script_sha256': digest, 'ast': summary, 'execution_performed': False}

    def _xml(self, data, entry):
        from malpdf.static.xfa_xml import inspect_xfa_xml
        scripts, problems, count = [], set(), 0
        def node_observed():
            nonlocal count
            if self.xml_remaining == 0:
                raise CodeInspectionError('xfa_xml_node_limit')
            self.xml_remaining -= 1
            count += 1
        def start_script(location):
            item = {'id': entry['id'] + ':xml-script:' + str(len(scripts)),
                    'location': location, 'status': 'partial', 'analysis': None}
            scripts.append(item)
            return item
        def finish_script(item, text):
            try:
                item.update(analysis=self._script(b'', item['id'], text=text), status='observed')
            except _CarveIssue as error:
                item.update(status=error.status, reason_codes=[error.code])
                problems.add(error.code)
            self.value['analyses'][entry['id']] = {'xml_nodes_observed': count, 'scripts': scripts, 'limitations': sorted(problems)}
            self._emit()
        result = None
        try:
            result = inspect_xfa_xml([(data, {'packet_index': 0})], start_script=start_script,
                finish_script=finish_script, problem=problems.add, node_observed=node_observed,
                max_nodes=self.xml_remaining, max_depth=self.code_limits.max_pdf_depth,
                max_script_bytes=self.code_limits.max_script_bytes)
        except CodeInspectionError as error:
            problems.add(str(error))
        return {'xml_nodes_observed': count, 'scripts': scripts, 'limitations': sorted(problems), 'inspection': result}

    def _objects(self, data, entry):
        from pypdf.generic import StreamObject, DictionaryObject, NameObject, TextStringObject, ByteStringObject, read_object
        from malpdf.static.recovery import projected_object
        metadata = entry['source_metadata']
        declared, first = metadata.get('objects'), metadata.get('first')
        if type(declared) is not int or type(first) is not int:
            raise _CarveIssue('unsupported', 'object_stream_parameters_unavailable')
        if declared < 0 or not 0 <= first <= len(data):
            raise _CarveIssue('decode_error', 'object_stream_header_invalid')
        if declared > min(self.object_allowance, self.limits.max_artifacts):
            raise _CarveIssue('resource_limit', 'object_stream_count_limit')
        pairs = []
        for token in re.finditer(rb'\S+', data[:first]):
            if len(pairs) >= declared * 2 or not re.fullmatch(rb'\d{1,10}', token.group()):
                raise _CarveIssue('decode_error', 'object_stream_header_invalid')
            pairs.append(int(token.group()))
        if len(pairs) != declared * 2:
            raise _CarveIssue('decode_error', 'object_stream_header_invalid')
        if declared == 0 and first < len(data):
            raise _CarveIssue('decode_error', 'object_stream_body_unassigned')
        ids, offsets = pairs[::2], pairs[1::2]
        if any(number == 0 for number in ids) or offsets != sorted(offsets) or any(first + offset >= len(data) for offset in offsets):
            raise _CarveIssue('decode_error', 'object_stream_offsets_invalid')
        class OpaqueReader:
            strict = True
            def get_object(self, reference):
                raise CodeInspectionError('object_stream_reference_not_resolved')
        members = []
        for index, (number, offset) in enumerate(zip(ids, offsets)):
            self.object_allowance -= 1
            end = first + offsets[index + 1] if index + 1 < len(offsets) else len(data)
            try:
                body = io.BytesIO(data[first + offset:end])
                value = read_object(body, OpaqueReader())
                if isinstance(value, StreamObject):
                    raise ValueError('compressed_stream_object')
                tail = re.sub(rb'%[^\r\n]*(?:\r\n|\r|\n|$)', b'', body.read())
                trailing = bool(tail.strip(b'\x00\t\n\x0c\r '))
                projection = projected_object(value)
                member = {'id': entry['id'] + ':object:' + str(index), 'object_number': number,
                          'generation': 0, 'decoded_offset': first + offset, 'projection': projection,
                          'status': 'observed' if projection['projection_complete'] and not trailing else 'partial',
                          'reason_codes': ['object_stream_member_trailing_data'] if trailing else []}
                if isinstance(value, DictionaryObject) and value.get('/S') == NameObject('/JavaScript') and '/JS' in value:
                    script = value.raw_get('/JS')
                    if isinstance(script, (TextStringObject, ByteStringObject)):
                        body = str(script).encode('utf-8') if isinstance(script, TextStringObject) else bytes(script)
                        try:
                            member['script'] = {'status': 'observed', 'analysis': self._script(body, member['id'],
                                text=str(script) if isinstance(script, TextStringObject) else None)}
                        except _CarveIssue as error:
                            member['script'] = {'status': error.status, 'reason_codes': [error.code]}
                members.append(member)
            except RecursionError:
                members.append({'object_number': number, 'generation': 0, 'status': 'resource_limit'})
            except Exception:
                members.append({'object_number': number, 'generation': 0, 'status': 'partial',
                                'reason_codes': ['object_stream_member_unavailable']})
            self.value['analyses'][entry['id']] = {'members': members, 'duplicate_object_numbers': len(ids) != len(set(ids))}
            self._emit()
        return {'members': members, 'duplicate_object_numbers': len(ids) != len(set(ids)),
                'scope': 'compressed-object syntax/projections; references are opaque; no execution graph inferred'}

    def _zip_directory(self, data):

        end, position = len(data), -1
        for attempt in range(16):
            candidate = data.rfind(b'PK\x05\x06', max(0, len(data) - 65557), end)
            if candidate < 0:
                break
            if candidate + 22 <= len(data):
                values = struct.unpack_from('<4s4H2IH', data, candidate)
                if candidate + 22 + values[-1] == len(data):
                    position = candidate
                    break
            end = candidate
        if position < 0:
            raise _CarveIssue('partial', 'zip_end_record_unavailable')
        _, disk, central_disk, here, total, size, offset, comment = values
        if disk or central_disk or here != total:
            raise _CarveIssue('unsupported', 'zip_multidisk_unsupported')
        if total == 65535 or size == 0xFFFFFFFF or offset == 0xFFFFFFFF:
            raise _CarveIssue('unsupported', 'zip64_unsupported')
        if total > self.limits.max_archive_members:
            raise _CarveIssue('resource_limit', 'zip_member_count_limit')
        if offset + size != position or offset < 0:
            raise _CarveIssue('unsupported', 'zip_central_layout_unsupported')
        cursor, count = offset, 0
        while cursor < position:
            if count == self.limits.max_archive_members:
                raise _CarveIssue('resource_limit', 'zip_member_count_limit')
            if cursor + 46 > position or data[cursor:cursor + 4] != b'PK\x01\x02':
                raise _CarveIssue('decode_error', 'zip_central_directory_invalid')
            if struct.unpack_from('<H', data, cursor + 6)[0] & 255 > zipfile.MAX_EXTRACT_VERSION:
                raise _CarveIssue('unsupported', 'zip_version_unsupported')
            name, extra, note = struct.unpack_from('<3H', data, cursor + 28)
            cursor += 46 + name + extra + note
            count += 1
        if cursor != position or count != total:
            raise _CarveIssue('decode_error', 'zip_central_directory_invalid')
        return offset, count

    def _member(self, data, info, directory):
        offset = info.header_offset
        if offset < 0 or offset + 30 > directory or data[offset:offset + 4] != b'PK\x03\x04':
            raise _CarveIssue('decode_error', 'zip_local_header_invalid')
        _, version, flags, method, clock, day, crc, packed, size, name, extra = struct.unpack_from('<4s5H3I2H', data, offset)
        start, end = offset + 30 + name + extra, offset + 30 + name + extra + info.compress_size
        if end > directory or start > end or flags != info.flag_bits or method != info.compress_type:
            raise _CarveIssue('decode_error', 'zip_local_central_mismatch')
        if flags & (1 | 64) or info.flag_bits & (1 | 64):
            raise _CarveIssue('encrypted', 'zip_member_encrypted')
        if method not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise _CarveIssue('unsupported', 'zip_compression_unsupported')
        if flags & (32 | 8192):
            raise _CarveIssue('unsupported', 'zip_flag_feature_unsupported')
        if packed == 0xFFFFFFFF or size == 0xFFFFFFFF:
            raise _CarveIssue('unsupported', 'zip64_unsupported')
        local_name = data[offset + 30:offset + 30 + name].decode('utf-8' if flags & 2048 else 'cp437')
        if local_name != info.orig_filename:
            raise _CarveIssue('decode_error', 'zip_local_central_name_mismatch')
        if not flags & 8 and (crc != info.CRC or packed != info.compress_size or size != info.file_size):
            raise _CarveIssue('decode_error', 'zip_local_central_mismatch')
        if flags & 8:
            descriptor = end + (4 if data[end:end + 4] == b'PK\x07\x08' else 0)
            if descriptor + 12 > directory or struct.unpack_from('<3I', data, descriptor) != (info.CRC, info.compress_size, info.file_size):
                raise _CarveIssue('decode_error', 'zip_descriptor_mismatch')
        encoded = data[start:end]
        cap = min(self.limits.max_artifact_bytes, self.budget.remaining, len(encoded) * self.limits.max_expansion_ratio)
        output, status, reasons = None, 'observed', []
        try:
            if method == zipfile.ZIP_STORED:
                if len(encoded) > cap:
                    raise _Stopped('resource_limit', 'zip_member_byte_limit', encoded[:cap])
                output = encoded
            else:
                output = _flate(encoded, cap, wbits=-zlib.MAX_WBITS)
            if len(output) != info.file_size or zlib.crc32(output) & 0xFFFFFFFF != info.CRC:
                raise _Stopped('decode_error', 'zip_member_integrity_mismatch', output)
        except _Stopped as error:
            output, status, reasons = error.prefix, error.status, [error.code]
        self.budget.remaining -= len(output) if output is not None else 0
        return output, status, reasons, (start, end)

    def _archive(self, data, entry):
        directory, count = self._zip_directory(data)
        rows, ranges = [], []
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if len(archive.infolist()) != count or archive.start_dir != directory:
                raise _CarveIssue('partial', 'zip_backend_directory_disagreement')
            for index, info in enumerate(archive.infolist()):
                if len(self.value['records']) >= self.limits.max_artifacts:
                    rows.append({'index': index, 'status': 'resource_limit', 'reason_codes': ['artifact_count_limit']})
                    break
                meta = {'index': index, 'name_sha256': _digest(info.orig_filename.encode('utf-8', 'surrogatepass')),
                    'declared_size': info.file_size, 'compressed_bytes': info.compress_size,
                    'unsafe_path': bool(info.filename.startswith(('/', '\\')) or '\0' in info.orig_filename
                        or re.match(r'^[A-Za-z]:', info.filename) or '..' in re.split(r'[/\\]', info.filename))}
                if info.is_dir():
                    rows.append({**meta, 'status': 'not_run', 'reason_codes': ['zip_directory_not_an_artifact']})
                    continue
                try:
                    if stat.S_ISLNK(info.external_attr >> 16):
                        raise _CarveIssue('unsupported', 'zip_symlink_not_followed')
                    if entry['depth'] >= self.limits.max_depth:
                        raise _CarveIssue('resource_limit', 'artifact_depth_limit')
                    body, status, reasons, extent = self._member(data, info, directory)
                    if any(max(extent[0], old[0]) < min(extent[1], old[1]) for old in ranges):
                        status, reasons = 'partial', ['zip_member_data_overlap']
                    ranges.append(extent)
                    row = {**meta, 'status': status, 'reason_codes': reasons, 'artifact_id': None,
                           'compressed_byte_start': extent[0], 'compressed_byte_end': extent[1],
                           'observed_prefix_bytes': len(body) if body is not None else None,
                           'retention': self._blob(body) if body is not None else None}
                    if status == 'observed':
                        suffix = info.filename.rsplit('.', 1)[-1].lower()
                        hint = 'javascript_candidate' if suffix == 'js' else 'xml_candidate' if suffix in {'xml', 'xfa'} else None
                        row['artifact_id'] = self.add(body, parent_id=entry['id'], decoded_sha256=_digest(body),
                            container_id=entry['id'], slot='zip:' + str(index), hint=hint, force=True,
                            metadata={'zip_member': meta})
                    rows.append(row)
                except _CarveIssue as error:
                    rows.append({**meta, 'status': error.status, 'reason_codes': [error.code], 'artifact_id': None})
                self.value['analyses'][entry['id']] = {'zip_members': rows}
                self._emit()
        return {'zip_members': rows, 'scope': 'stored/deflated ZIP members; names never used as output paths'}

    def _pdf(self, data, entry, timings):
        from malpdf.extraction.raw import inspect_raw_layout
        from malpdf.extraction.streams import StreamCollector
        from malpdf.static.analyzer import StaticPDFAnalyzer
        from malpdf.static.code_inspector import _inspect_code_bytes, _unavailable
        from malpdf.static.evidence_ipc import EvidenceAccumulator
        from malpdf.static.evidence_v9 import inspect_evidence_v9
        from malpdf.static.safety import StaticInspectionLimits

        result = {'layout': inspect_raw_layout(data), 'static': None, 'code': None, 'analysis_v9': None, 'stream_analysis': None}
        self.value['analyses'][entry['id']] = result
        self._emit()
        self._pdf_budget_pending = False
        if self.pdf_children >= self.limits.max_pdf_children or not min(self.object_allowance, self.xml_remaining, self.budget.remaining):
            raise _CarveIssue('resource_limit', 'child_pdf_budget_limit')
        self.pdf_children += 1
        quota = min(capacity(self.code_limits, 256), self.object_allowance, self.xml_remaining)
        if not is_vm(self.code_limits):
            self.object_allowance -= quota
        self._pdf_budget_pending = True
        allocated_bytes, allocated_ast, allocated_scripts = self.budget.remaining, self.ast_remaining, self.scripts_remaining
        limits = replace(self.code_limits, max_file_bytes=self.limits.max_artifact_bytes, max_objects=quota,
            max_decoded_bytes=allocated_bytes, max_ast_nodes=max(1, allocated_ast), max_scripts=max(1, allocated_scripts))
        static = StaticPDFAnalyzer(StaticInspectionLimits(max_file_size_bytes=limits.max_file_bytes,
            max_objects=quota, max_pages=min(capacity(limits, 100), quota), max_recursion_depth=limits.max_pdf_depth)).inspect_snapshot(
                data, expected_sha256=entry['sha256'], timings=timings)
        result['static'] = {'input': {key: static.input[key] for key in ('size_bytes', 'sha256')},
            'features': static.features, 'parser': static.parser,
            'errors': [{'code': item.code, 'fatal': item.fatal} for item in static.errors],
            'warnings': [item.code for item in static.warnings],
            'reference_parser_repaired': static.diagnostics.get('rit_reference_diagnostics', {}).get('parser_repaired')}
        self._emit()
        if allocated_ast and allocated_scripts:
            code = _inspect_code_bytes(data, limits, timings=timings, evidence_metadata=True)
        else:
            code = _unavailable('ast_node_limit' if not allocated_ast else 'script_count_limit')
        result['code'] = code
        self._emit()
        collector = StreamCollector(entry['sha256'], limits, retain=self.retain,plugins=self.plugins, artifact_sink=self.stream_sink(
            container_id=entry['id'], document_sha256=entry['sha256']))
        collector.limit = min(collector.limit, self.limits.max_child_streams - self.child_streams)
        accumulator = EvidenceAccumulator(entry['sha256'], max_bytes=256 * 1024)
        def checkpoint(delta):
            accumulator.merge(delta)
            result['analysis_v9'] = accumulator.value
            self._emit()
        missing = any(static.features.get(key) == -1 for key in ('images', 'contains_text')) or static.diagnostics.get(
            'rit_reference_diagnostics', {}).get('page_text_extraction_error_count', 0) > 0
        primary = bool(static.parser.get('success') and static.parser.get('structural_complete') and not static.errors
            and not missing and not static.parser.get('resource_limit_reached') and static.protocol_g_drop3constant_gate().passed and code['complete'])
        try:
            analysis = inspect_evidence_v9(data, result['static'], code, limits, primary_complete=primary,
                checkpoint=checkpoint, raw_sink=self.retain, stream_sink=collector.observe)
            result['analysis_v9'] = analysis
            self.register_context(analysis)
            self.budget.remaining = analysis['budget_usage']['decoded_bytes_remaining']
            ast = analysis['budget_usage']['ast_nodes_prior'] + analysis['budget_usage']['ast_nodes_v9']
            issue_codes = code.get('errors', []) + [reason for item in analysis['observations'] for reason in item.get('reason_codes', [])]
            exhausted = 'ast_node_limit' in issue_codes
            self.ast_remaining = 0 if exhausted else max(0, allocated_ast - ast)
            scripts = analysis['budget_usage']['scripts_prior'] + analysis['budget_usage']['new_scripts_analyzed']
            self.scripts_remaining = 0 if 'script_count_limit' in issue_codes else max(0, allocated_scripts - scripts)
            self.xml_remaining = max(0, self.xml_remaining - analysis['budget_usage']['xml_nodes'])
            self.child_streams += len(collector.sources)
            collector.checkpoint = lambda value: (result.update(stream_analysis=value), self._emit())
            result['stream_analysis'] = collector.finish(self.budget.remaining)
            self.budget.remaining = result['stream_analysis']['decoded_bytes_remaining']
            result.update(status='complete' if primary else 'partial', errors=[], primary_profile_complete=primary)
            self._pdf_budget_pending = False
            return result
        except BaseException:

            self.budget.remaining = self.ast_remaining = self.scripts_remaining = 0
            raise

    def finish(self, remaining, *, root_analysis=None, prior_code=(), timings=None):
        self.timings = timings
        self.budget = DecodeBudget(remaining)
        self.value.update(status='partial', decoded_bytes_available=remaining, decoded_bytes_remaining=remaining)
        if root_analysis:
            self.register_context(root_analysis)
            usage = root_analysis.get('budget_usage', {})
            self.ast_remaining = max(0, self.ast_remaining - usage.get('ast_nodes_prior', 0) - usage.get('ast_nodes_v9', 0))
            self.scripts_remaining = max(0, self.scripts_remaining - usage.get('scripts_prior', 0) - usage.get('new_scripts_analyzed', 0))
            self.xml_remaining = max(0, self.xml_remaining - usage.get('xml_nodes', 0))
            codes = [reason for item in root_analysis.get('observations', []) for reason in item.get('reason_codes', [])]
            codes.extend(reason for code in prior_code for reason in code.get('errors', []))
            if 'ast_node_limit' in codes:
                self.ast_remaining = 0
            if 'script_count_limit' in codes:
                self.scripts_remaining = 0
        try:
            self._emit()
        except _CarveIssue:
            return self._metadata_limited()
        reasons = set(self.value['reason_codes'])
        while self.queue:
            identity, data = self.queue.popleft()
            entry = self.index[identity]
            self.value['active_artifact_id'] = identity
            media_issues = None
            try:
                self._emit()
            except _CarveIssue:
                return self._metadata_limited()
            try:
                if entry['kind'] == 'zip':
                    analysis = self._archive(data, entry)
                    issues = [item for item in analysis['zip_members'] if item['status'] not in {'observed', 'not_run'}]
                elif entry['kind'] == 'pdf':
                    analysis = self._pdf(data, entry, timings)
                    issues = [] if analysis['analysis_v9'].get('complete') and analysis['stream_analysis'].get('complete') else [True]
                elif entry['kind'] in {'javascript', 'javascript_candidate'}:
                    analysis, issues = self._script(data, entry['id'], utf8=entry['kind'] == 'javascript_candidate'), []
                elif entry['kind'] in {'xfa_xml', 'xml_candidate'}:
                    analysis = self._xml(data, entry)
                    issues = analysis['limitations']
                elif entry['kind'] == 'object_stream':
                    analysis = self._objects(data, entry)
                    issues = [item for item in analysis['members'] if item['status'] != 'observed' or item.get('script', {}).get('status', 'observed') != 'observed'] or analysis['duplicate_object_numbers']
                elif entry['kind'] == 'empty':
                    analysis, issues = {'empty_artifact': True}, []
                elif is_vm(self.code_limits) and entry['kind'] in {'jpeg', 'png', 'jpx', 'jbig2', 'image_data', 'sfnt_font', 'woff_font', 'font_data', 'flash', 'content_stream'}:
                    from malpdf.extraction.media import MediaIssue, inspect_image, inspect_font, inspect_flash
                    try:
                        from malpdf.extraction.content_stream import ContentStreamIssue, inspect_content_stream
                    except ImportError:
                        ContentStreamIssue, inspect_content_stream = type('ContentStreamIssue', (Exception,), {}), None
                    try:
                        if entry['kind'] == 'content_stream':
                            if inspect_content_stream is None:
                                raise _CarveIssue('unsupported', 'content_stream_parser_unavailable')
                            box = entry.get('source_metadata', {}).get('boundary_box')
                            analysis = inspect_content_stream(data, boundary_box=box)
                        elif entry['kind'] in {'jpeg', 'png', 'jpx', 'jbig2', 'image_data'}:
                            analysis = inspect_image(data, entry['source_metadata'])
                        elif entry['kind'] in {'sfnt_font', 'font_data'}:
                            if data.startswith((b'%!PS-AdobeFont', b'%!FontType1', b'\x80\x01')):
                                from malpdf.extraction.font_containers import inspect_type1
                                analysis = inspect_type1(data)
                            elif entry['kind'] == 'font_data' and data[:1] == b'\x01':
                                from malpdf.extraction.font_containers import inspect_cff
                                analysis = inspect_cff(data)
                            else:
                                analysis = inspect_font(data)
                        elif entry['kind'] == 'woff_font':
                            from malpdf.extraction.font_containers import inspect_woff
                            analysis = inspect_woff(data, budget=self.budget, max_expansion_ratio=self.limits.max_expansion_ratio)
                        else:
                            analysis = inspect_flash(data, budget=self.budget,
                                max_expansion_ratio=self.limits.max_expansion_ratio, retain=self.retain)
                    except (MediaIssue, ContentStreamIssue) as error:
                        self.value['analyses'][identity] = error.details
                        raise _CarveIssue(error.status if hasattr(error, 'status') else 'partial', error.code) from None
                    issues = analysis['reason_codes']
                    media_issues = issues
                else:
                    raise _CarveIssue('unsupported', 'artifact_format_analysis_unsupported')
                self.value['analyses'][identity] = analysis
                entry.update(status='partial' if issues else 'observed', reason_codes=list(media_issues)
                    if media_issues is not None else ['artifact_analysis_partial'] if issues else [])
            except _CarveIssue as error:
                if error.code == 'artifact_metadata_limit':
                    return self._metadata_limited()
                entry.update(status=error.status, reason_codes=[error.code])
            except MemoryError:
                self.budget.remaining = self.ast_remaining = self.scripts_remaining = 0
                entry.update(status='resource_limit', reason_codes=['artifact_memory_limit'])
            except zipfile.BadZipFile:
                entry.update(status='partial', reason_codes=['zip_metadata_parser_unavailable'])
            except CodeInspectionError as error:
                code = 'artifact_syntax_limit' if 'limit' in str(error) else 'artifact_syntax_unsupported' if 'unsupported' in str(error) else 'artifact_analysis_unavailable'
                entry.update(status='resource_limit' if 'limit' in code else 'unsupported' if 'unsupported' in code else 'partial', reason_codes=[code])
            except Exception:
                entry.update(status='decode_error', reason_codes=['artifact_analysis_failed'])
            finally:
                if self._pdf_budget_pending:
                    self.budget.remaining = self.ast_remaining = self.scripts_remaining = 0
                    self._pdf_budget_pending = False
            reasons.update(entry['reason_codes'])
            self.value['active_artifact_id'] = None
            try:
                self._emit()
            except _CarveIssue:
                reasons.add('artifact_metadata_limit')
                return self._metadata_limited()
        for entry in self.value['records']:
            if entry['reused_from_id']:
                original = self.index[entry['reused_from_id']]
                entry.update(status=original['status'], reason_codes=list(original['reason_codes']))
            reasons.update(entry['reason_codes'])
        reasons.update(self.value['reason_codes'])
        self.value.update(status='observed' if not reasons and not self.queue else 'partial', complete=not reasons and not self.queue,
                          reason_codes=sorted(reasons))
        try:
            self._emit(force=True)
        except _CarveIssue:
            return self._metadata_limited()
        return self.value

    def _metadata_limited(self):
        if self._saved is None:
            raise _CarveIssue('resource_limit', 'artifact_metadata_limit')
        omitted = len(self.value['records']) - len(self._saved['records'])
        self.value = deepcopy(self._saved)
        self.value.update(status='partial', complete=False,
            omitted_artifacts_lower_bound=max(0, omitted),
            reason_codes=sorted(set(self.value['reason_codes']) | {'artifact_metadata_limit'}))


        if self.checkpoint:
            self.checkpoint(deepcopy(self.value))
        return self.value
