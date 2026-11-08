"""V8 evidence graph and independent recovery views inside the capped worker."""

from collections import Counter
from dataclasses import replace
import hashlib
import io
import zlib

from pypdf import PdfReader
from pypdf.errors import PyPdfError
from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, NameObject, StreamObject

from malpdf.static.code_inspector import _inspect_code_bytes_inner, _stream_bytes
from malpdf.static.js_ast import CodeInspectionError
from malpdf.static.parser_diagnostics import ParserDiagnostics, exception_type
from malpdf.static.profiling import stage
from malpdf.static.recovery import MuPDFObjectReader, projected_object

EVIDENCE_SCHEMA = "pdf-evidence-v8"
ACTION_NAMES = frozenset({"/JavaScript", "/Launch", "/URI", "/SubmitForm", "/GoToR", "/GoToE", "/ImportData"})
ROUTES = frozenset({"/Root", "/OpenAction", "/AA", "/Next", "/A", "/Names", "/JavaScript", "/JS",
                    "/AcroForm", "/XFA", "/Fields", "/Annots", "/EF", "/EmbeddedFiles"})


def _children(value, owner):
    if isinstance(value, DictionaryObject):
        for key, child in value.items():
            yield child, owner, str(key) if str(key) in ROUTES else '{key}'
    else:
        for child in value:
            yield child, owner, '[item]'


def fact(name, value, backend, *, complete=False, applicable=True, evidence_ids=()):
    if not applicable:
        value, status = None, "not_applicable"
    elif value is None:
        status = "unknown"
    elif value == 0 or value is False:
        status = "absent_after_complete_check" if complete else "unknown"
        if not complete:
            value = None
    else:
        status = "observed"
    return {"name": name, "value": value, "status": status, "source": backend,
            "recovered": backend == "MuPDF", "complete": complete,
            "absence_scope": "measured feature in the checked latest-catalog/raw-byte scope; historical revisions unverified",
            "evidence_ids": list(evidence_ids), "confidence": "measured" if status == "observed" else "scope_limited"}


def _graph(reader, backend, limits, decoded_remaining):
    """Catalog graph only, with redacted action edges and bounded attachments."""
    seen, objects, actions, edges, attachments, errors = set(), {}, [], [], [], set()
    if getattr(reader, '_malpdf_xrefstm_failures', []):
        errors.add('supplemental_xref_unavailable')
    counts, used, visited = Counter(), 0, 0
    def name_value(value):
        nonlocal visited
        chain = set()
        try:
            while isinstance(value,IndirectObject):
                key=(value.idnum,value.generation)
                visited+=1
                if key in chain or len(chain)>=limits.max_pdf_depth or visited>limits.max_objects:
                    raise CodeInspectionError('graph_name_reference_limit')
                chain.add(key)
                value=value.get_object()
                if value is None:
                    raise CodeInspectionError('graph_name_reference_unavailable')
        except (CodeInspectionError,ValueError,TypeError,AttributeError,KeyError,OSError,RuntimeError,RecursionError,PyPdfError) as error:
            errors.add(str(error) if isinstance(error,CodeInspectionError) else 'graph_name_reference_failure')
            return None
        return str(value) if isinstance(value,NameObject) else None

    stack = [(iter([(reader.trailer.raw_get('/Root'), None, '/Root')]), 0)]
    while stack:
        iterator, depth = stack[-1]
        try:
            value, parent, route = next(iterator)
        except StopIteration:
            stack.pop()
            continue
        visited += 1
        if visited > limits.max_objects or depth > limits.max_pdf_depth:
            errors.add('graph_object_or_depth_limit')
            break
        owner = parent
        try:
            chain = set()
            while isinstance(value, IndirectObject):
                key = (value.idnum, value.generation)
                identifier = f'{backend}:{key[0]}:{key[1]}'
                edges.append({'parent': parent, 'child': identifier, 'route': route})
                if key in chain or len(chain) >= limits.max_pdf_depth:
                    raise CodeInspectionError('graph_reference_cycle_or_depth')
                if key in seen:
                    value = None
                    break
                chain.add(key); seen.add(key); owner = identifier
                value = value.get_object()
                if value is None:
                    raise CodeInspectionError('graph_reference_unavailable')
                objects[identifier] = projected_object(value)
                if not objects[identifier]['projection_complete']:
                    errors.add('object_projection_limit')
            if value is None:
                continue
            if depth == 0 and not isinstance(value, DictionaryObject):
                raise CodeInspectionError('graph_root_invalid')
            if isinstance(value, DictionaryObject):
                action = name_value(value.get('/S'))
                if action in ACTION_NAMES:
                    identity = owner or f'{backend}:direct:{visited}'
                    actions.append({'evidence_id': identity, 'kind': action, 'incoming_route': route,
                                    'parent': parent, 'backend': backend})
                    counts[action[1:]] += 1
                if name_value(value.get('/Type')) == '/EmbeddedFile':
                    entry = {'evidence_id': owner or f'{backend}:direct:{visited}', 'backend': backend,
                             'status': 'unknown', 'mime': None, 'magic': None, 'sha256': None, 'bytes': None}
                    mime = name_value(value.get('/Subtype'))
                    if mime in {'/application/pdf', '/application/octet-stream', '/application/x-dosexec', '/image/png', '/image/jpeg'}:
                        entry['mime'] = mime[1:]
                    try:
                        if not isinstance(value, StreamObject):
                            raise CodeInspectionError('embedded_stream_unavailable')
                        content = _stream_bytes(value, limits, byte_limit=decoded_remaining-used, overflow='decoded_byte_limit')
                        used += len(content)
                        magic = next((kind for prefix, kind in [(b'%PDF-', 'pdf'), (b'MZ', 'pe'), (b'\x7fELF', 'elf'),
                            (b'PK\x03\x04', 'zip'), (b'\x89PNG\r\n\x1a\n', 'png'), (b'\xff\xd8\xff', 'jpeg')]
                                      if content.startswith(prefix)), 'other')
                        entry.update(status='observed', magic=magic, sha256=hashlib.sha256(content).hexdigest(), bytes=len(content))
                    except CodeInspectionError as error:
                        entry['error'] = str(error); errors.add(str(error))
                    except (ValueError, UnicodeError, OSError, PyPdfError, zlib.error):
                        entry['error'] = 'embedded_decode_failure'; errors.add('embedded_decode_failure')
                    attachments.append(entry)
                stack.append((_children(value, owner), depth+1))
            elif isinstance(value, ArrayObject):
                stack.append((_children(value, owner), depth+1))
        except (CodeInspectionError, ValueError, TypeError, AttributeError, KeyError, OSError, RecursionError, PyPdfError) as error:
            errors.add(str(error) if isinstance(error, CodeInspectionError) else 'graph_reference_failure')
    return {'backend': backend, 'objects': objects, 'actions': actions, 'edges': edges, 'embedded': attachments,
            'errors': sorted(errors), 'complete': not errors, 'decoded_bytes': used,
            'action_counts': dict(counts), 'scope': 'latest catalog-reachable objects; historical/orphan objects unverified'}


def inspect_evidence(data, static, code, limits, *, timings=None, primary_complete=None, checkpoint=None):
    """Keep v7 measurements intact and add a separately versioned v8 view."""
    result = {'schema_version': EVIDENCE_SCHEMA, 'status': 'partial', 'primary_errors': list(code['errors']),
              'preflight': {'eof_markers': data.count(b'%%EOF'), 'startxref_markers': data.count(b'startxref'),
                            'revision_history_complete': False},
              'backends': [], 'conflicts': [], 'features': [], 'content_redacted': True,
              'active_content_executed': False, 'original_bytes_changed': False,
              'resource_limits_reached': bool(static['parser'].get('resource_limit_reached')),
              'primary_profile_complete': primary_complete,
              'recovery_attempted': False, 'recovery_success': False}
    remaining = max(0, limits.max_decoded_bytes - code.get('budget_usage', {}).get('decoded_bytes', 0))
    if 'decoded_byte_limit' in code['errors']:
        remaining = 0
    from malpdf.static.raw_scan import RAW_DIRECT_TOKENS
    for name, value in static.get('features', {}).items():

        value = None if value == -1 else value
        source = 'raw_scanner' if name in RAW_DIRECT_TOKENS or name in {'obj','endobj','stream','endstream','xref','startxref','page_command'} else 'rit_reference'
        result['features'].append(fact('canonical_'+name, value, source, complete=value is not None,
                                      evidence_ids=[source+':'+name] if value is not None else []))
    graphs = []
    diagnostic = ParserDiagnostics(strict=False)
    try:
        with stage(timings, 'parse_pdf'), diagnostic.capture_open_notices():
            reader = PdfReader(io.BytesIO(data), strict=False)
            if reader.is_encrypted:
                raise CodeInspectionError('encrypted_pdf')
            graph = _graph(reader, 'pypdf', limits, remaining)
        remaining -= graph['decoded_bytes']; graphs.append(graph)
        if 'decoded_byte_limit' in graph['errors']:
            remaining = 0
        result['backends'].append({'backend': 'pypdf', 'status': 'partial' if graph['errors'] else 'observed',
                                   'diagnostics': diagnostic.data, 'graph': graph, 'code': code})
        if checkpoint is not None:
            checkpoint({**result, 'decoded_bytes_remaining': remaining})
    except (CodeInspectionError, ValueError, TypeError, AttributeError, OSError, KeyError, RecursionError, PyPdfError) as error:
        diagnostic.failure(error, 'object_graph')
        result['backends'].append({'backend': 'pypdf', 'status': 'error', 'error_code':
            str(error) if isinstance(error, CodeInspectionError) else
            'graph_backend_attribute_error' if isinstance(error, AttributeError) else 'graph_open_failure',
            'diagnostics': diagnostic.data})
    primary_ok = bool(static['parser'].get('success') and static['parser'].get('structural_complete')
                      and not static['errors'] and code['complete'] and graphs and graphs[0]['complete']
                      and primary_complete is not False)
    if not primary_ok:
        result['recovery_attempted'] = True
        alternate = None
        try:
            with stage(timings, 'parse_pdf'):
                alternate = MuPDFObjectReader(data, limits)
                graph = _graph(alternate, 'MuPDF', limits, remaining)
            remaining -= graph['decoded_bytes']; graphs.append(graph)
            if 'decoded_byte_limit' in graph['errors']:
                remaining = 0
            nodes = limits.max_ast_nodes - code.get('budget_usage', {}).get('ast_nodes', 0)
            if 'ast_node_limit' in code['errors']:
                nodes = 0
            recovered_code = None
            if checkpoint is not None:
                checkpoint({**result, 'decoded_bytes_remaining': remaining,
                    'backends': [*result['backends'], {'backend': 'MuPDF', 'status': 'partial',
                        'graph': graph, 'code': None, 'code_unavailable_reason': 'ast_not_finished'}]})
            if remaining > 0 and nodes > 0:
                available = replace(limits, max_decoded_bytes=remaining, max_ast_nodes=nodes)
                with stage(timings, 'parse_pdf'):
                    recovered_code = _inspect_code_bytes_inner(data, available, timings, supplied_reader=alternate,
                        **({'evidence_metadata': True} if checkpoint is not None else {}))
                remaining = max(0, remaining-recovered_code.get('budget_usage', {}).get('decoded_bytes', 0))
            result['recovery_success'] = bool(graph['objects'])
            result['backends'].append({'backend': 'MuPDF', 'status': 'partial', 'is_repaired': alternate.repaired,
                'warning_count': alternate.warning_count,
                'graph': graph, 'code': recovered_code, 'revision_completeness': 'unknown',
                'code_unavailable_reason': 'shared_code_budget_exhausted' if recovered_code is None else None,
                'reason': 'independent read-only recovered view; primary warnings retained'})
        except (CodeInspectionError, ValueError, TypeError, AttributeError, OSError, KeyError, RecursionError, RuntimeError, PyPdfError) as error:
            result['backends'].append({'backend': 'MuPDF', 'status': 'error', 'error_code':
                str(error) if isinstance(error, CodeInspectionError) else
                'recovery_backend_attribute_error' if isinstance(error, AttributeError) else 'recovery_backend_failure',
                'exception_type': exception_type(error)})
        finally:
            if alternate is not None:
                alternate.close()
    for graph in graphs:
        complete = primary_ok and graph['backend'] == 'pypdf'
        for kind in sorted(ACTION_NAMES):
            ids = [a['evidence_id'] for a in graph['actions'] if a['kind'] == kind]
            result['features'].append(fact('action_'+kind[1:], len(ids), graph['backend'], complete=complete, evidence_ids=ids))
        for magic in ['pdf', 'pe', 'elf', 'zip', 'png', 'jpeg', 'other']:
            ids = [e['evidence_id'] for e in graph['embedded'] if e['magic'] == magic]
            result['features'].append(fact('embedded_'+magic, len(ids), graph['backend'],
                complete=complete and all(e['status']=='observed' for e in graph['embedded']), evidence_ids=ids))
    if len(graphs) == 2:
        def keyed(g): return {k.split(':', 1)[1]: v for k,v in g['objects'].items()}
        primary, fallback = map(keyed, graphs)
        for key in sorted(primary.keys() & fallback.keys()):
            if primary[key] != fallback[key]:
                result['conflicts'].append({'object': key, 'backends': ['pypdf', 'MuPDF'],
                    'scope': 'bounded dictionary/array/scalar/reference projection and raw-stream digest', 'resolution': 'separate evidence; no merge'})
    result['decoded_bytes_remaining'] = remaining
    result['status'] = 'complete' if primary_ok and not result['conflicts'] else 'partial'
    if not static['parser'].get('success') and not result['recovery_success']:
        result['status'] = 'parser_error'
    result['complete'] = result['status'] == 'complete'
    result['scope'] = 'v8 overlay; canonical RIT and v7 C0/C1/P0/P1/P2 measurements retained'
    return result
