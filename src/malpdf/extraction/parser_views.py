"""Independent xref/object inventories and conservative parser comparison.

This internal worker pass never saves a PDF, renders, executes content, or calls
native decoded-stream APIs. Current xref selection is not revision history.
"""

from copy import deepcopy
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import io
import json
import logging
import re

from pypdf import PdfReader
from pypdf.generic import IndirectObject, StreamObject

from malpdf.extraction.qpdf_adapter import QPDFReader
from malpdf.extraction.mupdf_adapter import MuPDFReader as _MuPDFView
from malpdf.static.js_ast import CodeInspectionError
from malpdf.static.parser_diagnostics import ParserDiagnostics
from malpdf.static.recovery import projected_object
from malpdf.static.execution import capacity, UNLIMITED
from malpdf.extraction.checkpointing import CheckpointScheduler


def _hash(value):
    return hashlib.sha256(value).hexdigest()


def _json_size(value):
    return len(json.dumps(value, allow_nan=False, separators=(',', ':')))


@dataclass
class _RawBudget:
    remaining: int


class _PyPDFView:
    repaired = False
    def __init__(self, data, limits):
        import pypdf
        self.data, self.limits = data, limits
        self.warning_count = 0
        self.diagnostic = ParserDiagnostics(strict=False)
        with self._notices(), self.diagnostic.capture_open_notices():
            self.document = PdfReader(io.BytesIO(data), strict=False)
        if self.document.is_encrypted:
            raise CodeInspectionError('inventory_encrypted_pdf')
        self.repaired = bool(self.diagnostic.data['recovery_notice_codes'])
        self.version = {'pypdf': pypdf.__version__}

    @contextmanager
    def _notices(self):
        owner = self
        class Counter(logging.Handler):
            def emit(self,record):
                owner.warning_count += 1
        logger = logging.getLogger('pypdf')
        handler = Counter(level=logging.WARNING)
        previous = logger.level
        logger.setLevel(logging.WARNING)
        logger.addHandler(handler)
        try:
            yield
        finally:
            logger.removeHandler(handler)
            logger.setLevel(previous)

    def candidates(self):
        seen = set()
        for generation, entries in self.document.xref.items():
            for number, offset in entries.items():
                if number == 0 or (number,generation) in seen:
                    continue
                seen.add((number,generation))
                header = re.match(rb'(\d+)\s+(\d+)\s+obj(?:\s|[<\[/])', self.data[offset:offset + 128]) if type(offset) is int and 0 <= offset < len(self.data) else None
                yield {'number':number,'generation':generation,'offset':offset if header and (int(header[1]),int(header[2])) == (number,generation) else None}
        for number, (stream, index) in self.document.xref_objStm.items():
            if (number,0) not in seen:
                yield {'number':number,'generation':0,'offset':None,'object_stream_number':stream,'object_stream_index':index}

    def object(self, candidate, raw_budget):
        before = self.warning_count
        with self._notices():
            value = self.document.get_object(IndirectObject(candidate['number'],candidate['generation'],self.document))
        if isinstance(value, StreamObject):
            size = len(value._data)
            if size > raw_budget.remaining:
                return value, False, ['inventory_raw_byte_limit']
            raw_budget.remaining -= size
        notices = self.warning_count != before
        return value, not notices, ['inventory_parser_notices'] if notices else []

    def warnings(self):
        codes = self.diagnostic.data['recovery_notice_codes']
        return {'count':self.warning_count,'codes':sorted(set(codes) | ({'pypdf_parser_warning'} if self.warning_count else set()))}

    def close(self):
        self.document.close()


def _failure(error):
    name = type(error).__name__
    fixed = str(error) if isinstance(error,CodeInspectionError) else ''
    if name in {'PasswordError','FileNotDecryptedError'} or 'encrypted' in fixed:
        return 'encrypted','inventory_encrypted_pdf'
    if isinstance(error,(MemoryError,RecursionError)) or 'limit' in fixed:
        return 'resource_limit','inventory_resource_limit'
    if isinstance(error,(ImportError,ModuleNotFoundError)):
        return 'unsupported','inventory_dependency_unavailable'
    if isinstance(error,ValueError) and str(error) == 'inventory_retention_identity_mismatch':
        return 'partial','inventory_retention_identity_mismatch'
    return 'partial','inventory_parser_unavailable'


def merge_views(views, *, max_comparisons=2048):
    """Preserve disagreements; no parser wins and missing is never zero.

    Matches are projection equality within engine-exposed xref views. Even known
    objgen pairs have no verified historical revision identity in this pass.
    """
    comparisons = []
    for left_index,left in enumerate(views):
        for right in views[left_index + 1:]:
            left_nodes, right_nodes = {}, {}
            for view, grouped in ((left,left_nodes),(right,right_nodes)):
                for node in view['records']:
                    grouped.setdefault(node['object_number'],[]).append(node)
            for number in sorted(left_nodes.keys() | right_nodes.keys()):
                lnodes,rnodes = left_nodes.get(number,[]),right_nodes.get(number,[])
                pairs = []
                remaining = list(rnodes)


                for ln in lnodes:
                    match = next((rn for rn in remaining if ln['generation'] is not None and ln['generation'] == rn['generation']),None)
                    if match is None and len(lnodes) == len(rnodes) == 1:
                        match = remaining[0] if remaining else None
                    if match is not None:
                        remaining.remove(match)
                    pairs.append((ln,match))
                pairs.extend((None,rn) for rn in remaining)
                for ln,rn in pairs:
                    if len(comparisons) == max_comparisons:
                        return comparisons, False
                    identity = 'parser-comparison:' + _hash((left['backend']+'|'+right['backend']+'|'+str(number)+'|'+str((ln or {}).get('generation'))+'|'+str((rn or {}).get('generation'))).encode())
                    item = {'id':identity,'object_number':number,'left_backend':left['backend'],'right_backend':right['backend'],
                        'left_id':ln['id'] if ln else None,'right_id':rn['id'] if rn else None,
                        'identity_scope':'engine-exposed xref interpretations; revision identity unverified',
                        'generation_verified':bool(ln and rn and ln['generation'] is not None and rn['generation'] is not None),
                        'key_differences':[],'projection_equal':None,'raw_stream_equal':None}
                    if ln is None or rn is None:
                        absent_view = left if ln is None else right
                        item['result'] = 'only_in_enumerated_view' if absent_view['complete'] else 'not_observed_in_partial_view'
                    elif ln['generation'] is not None and rn['generation'] is not None and ln['generation'] != rn['generation']:
                        item['result'] = 'generation_selection_conflict'
                    elif not ln.get('projection') or not rn.get('projection'):
                        item['result'] = 'projection_unavailable'
                    else:
                        lp,rp = ln['projection'],rn['projection']
                        if lp['projection_complete'] and rp['projection_complete']:
                            item['projection_equal'] = lp['projected_values_sha256'] == rp['projected_values_sha256']
                        if lp['stream_sha256'] is not None and rp['stream_sha256'] is not None:
                            item['raw_stream_equal'] = lp['stream_sha256'] == rp['stream_sha256']
                        lkeys = {key['key_sha256']:key for key in lp.get('key_projections',[])}
                        rkeys = {key['key_sha256']:key for key in rp.get('key_projections',[])}
                        for key in sorted(lkeys.keys() | rkeys.keys()):
                            lv,rv = lkeys.get(key),rkeys.get(key)
                            if lv is None or rv is None:
                                missing = lp if lv is None else rp
                                if missing.get('key_enumeration_complete'):
                                    item['key_differences'].append({'key_sha256':key,'difference':'key_not_in_view'})
                            elif lv['complete'] and rv['complete'] and lv['value_sha256'] != rv['value_sha256']:
                                item['key_differences'].append({'key_sha256':key,'difference':'value_projection_conflict'})
                        differing = item['projection_equal'] is False or item['raw_stream_equal'] is False or bool(item['key_differences'])
                        item['result'] = ('value_projection_conflict' if item['generation_verified'] else 'projection_difference_identity_unverified') if differing else (
                            'projection_equal' if item['projection_equal'] is True else 'projection_unavailable')
                    comparisons.append(item)
    return comparisons, True


def inspect_parser_views(data, limits, *, retain=None, checkpoint=None, max_metadata_bytes=1024**2,plugins=None):
    """Run all three native views on original bytes, after prior checkpoints."""
    if not isinstance(data,bytes) or not data.startswith(b'%PDF-') or len(data) > limits.max_file_bytes:
        raise ValueError('inventory_input_invalid')
    max_metadata_bytes = capacity(limits, max_metadata_bytes)
    if not 2048 <= max_metadata_bytes <= 2*1024**2 and max_metadata_bytes != UNLIMITED:
        raise ValueError('inventory_metadata_cap_invalid')
    if plugins is not None:
        from malpdf.extraction.plugins import PluginRegistry
        if type(plugins) is not PluginRegistry:raise ValueError('plugin_registry_required')
    digest = _hash(data)
    result = {'schema_version':'pdf-parser-inventory-v1','document_sha256':digest,'status':'partial','complete':False,
        'views':[],'comparisons':[],'comparisons_complete':False,'reason_codes':[],
        'limits':{'objects_per_view':limits.max_objects,'raw_bytes_total':limits.max_file_bytes,'metadata_bytes':max_metadata_bytes,
                  'projection_nodes_per_object':capacity(limits,1024),'projection_depth':8,
                  'key_details_per_object':capacity(limits,64)},
        'raw_bytes_used':0,'scope':'native xref interpretations; raw forensic/history/orphan proof remains unverified'}
    raw_budget = _RawBudget(limits.max_file_bytes)
    snapshots = CheckpointScheduler(limits)
    list_bytes = view_header_bytes = 0

    def emit(*, force=False, view=None, new_view=False, node=None, comparison=None, **updates):
        nonlocal list_bytes, view_header_bytes
        views, comparisons = result['views'], result['comparisons']
        updates['raw_bytes_used'] = limits.max_file_bytes - raw_budget.remaining
        if max_metadata_bytes != UNLIMITED:
            # Count array entries and their separators once; the headers below contain empty arrays.
            growth = 0
            if view is not None:
                header_bytes = _json_size(dict(view, records=[]))
                growth = header_bytes + bool(views) if new_view else header_bytes - view_header_bytes
            elif node is not None:
                growth = _json_size(node) + bool(views[-1]['records'])
            elif comparison is not None:
                growth = _json_size(comparison) + bool(comparisons)
            root_bytes = _json_size({**result, **updates, 'views': [], 'comparisons': []})
            if root_bytes + list_bytes + growth > max_metadata_bytes - 512:
                raise CodeInspectionError('inventory_metadata_limit')
            list_bytes += growth
            if view is not None:
                view_header_bytes = header_bytes
        result.update(updates)
        if new_view:
            views.append(dict(deepcopy(view), records=[]))
        elif view is not None:
            views[-1].update(deepcopy(view))
        elif node is not None:
            views[-1]['records'].append(node)
        elif comparison is not None:
            comparisons.append(comparison)
        if checkpoint and snapshots.due(force=force):
            checkpoint(deepcopy(result))
            snapshots.completed()
    try:
        emit()
        factories=[('pypdf',_PyPDFView,None),('QPDF',QPDFReader,None),('MuPDF',_MuPDFView,None)]
        if plugins is not None:
            from malpdf.extraction.plugins import ParserReader
            factories.extend(('plugin:'+spec.plugin_id,None,spec) for spec in plugins.select('parser'))
        for backend,factory,spec in factories:
            view = {'backend':backend,'version':{},'status':'not_run','complete':False,
                    'reason_codes':[],'warnings':{'count':0,'codes':[]},'generation_available':backend != 'MuPDF',
                    'enumeration_complete':False,'repair_requested':backend != 'QPDF'}
            view['selection_scope'] = {'pypdf':'exposed xref map, including retained generations; active/revision identity unverified',
                'QPDF':'QPDF selected xref entries; historical revisions unverified',
                'MuPDF':'number-addressed current xref slots; generation unavailable, free/null slots may fail'}.get(backend,
                    'operator-selected plugin candidates; physical membership/history unverified')
            if spec is not None:
                view.update(plugin=spec.describe(),version=spec.describe(),generation_available=False,repair_requested=None)
            emit(view=view,new_view=True)
            records = result['views'][-1]['records']
            reader = None
            try:
                reader = ParserReader(spec,data,limits) if spec is not None else factory(data,limits)
                view.update(version=reader.version,status='partial')
                emit(view=view)
                for index,candidate in enumerate(reader.candidates()):
                    if index == limits.max_objects:
                        view['reason_codes'].append('inventory_object_limit')
                        break
                    number,generation = candidate['number'],candidate['generation']
                    node = {'id':'parser-object:'+_hash((digest+'|'+backend+'|'+str(number)+':'+str(generation)).encode()),
                        'object_number':number,'generation':generation,'byte_offset':candidate['offset'],
                        'xref':candidate,'projection':None,'status':'partial','reason_codes':[],
                        'raw_retention':None,'is_synthetic_repaired':backend == 'MuPDF' or reader.repaired}
                    try:
                        value,complete,reasons = reader.object(candidate,raw_budget)
                        projection = projected_object(value,include_fields=True,limits=limits)
                        if not complete:
                            projection['projection_complete'] = False
                            if set(reasons) & {'inventory_projection_limit', 'inventory_scalar_encoding_unavailable'}:
                                projection['key_enumeration_complete'] = False
                                for key in projection['key_projections']:
                                    key['complete'] = False
                            if isinstance(value,StreamObject) and 'inventory_raw_byte_limit' in reasons:
                                projection['stream_sha256'] = None
                        node['projection'] = projection
                        node['reason_codes'] = reasons + ([] if projection['projection_complete'] else ['inventory_projection_incomplete'])
                        if isinstance(value,StreamObject) and projection['stream_sha256'] is not None:
                            raw = value._data
                            state = retain(raw) if retain else {'sha256':_hash(raw),'size_bytes':len(raw),'status':'not_retained'}
                            if state.get('sha256') != _hash(raw) or state.get('size_bytes') != len(raw):
                                raise ValueError('inventory_retention_identity_mismatch')
                            node['raw_retention'] = state
                        node['status'] = 'observed' if not node['reason_codes'] else 'partial'
                    except Exception as error:
                        status,reason = _failure(error)
                        node.update(status=status,reason_codes=[reason])
                    emit(node=node)
                else:
                    view['enumeration_complete'] = True
                view['complete'] = bool(view['enumeration_complete'] and all(node['status'] == 'observed' for node in records))
                view['status'] = 'observed' if view['complete'] else 'partial'
                view['reason_codes'] = sorted(set(view['reason_codes']) | {code for node in records for code in node['reason_codes']})
                view['warnings'] = reader.warnings()
                if view['warnings']['count']:
                    view['complete'] = False
                    view['status'] = 'partial'
                    view['reason_codes'].append('inventory_parser_notices')
            except CodeInspectionError as error:
                if str(error) == 'inventory_metadata_limit':
                    raise
                view['status'],reason = _failure(error)
                view['reason_codes'].append(reason)
            except Exception as error:
                view['status'],reason = _failure(error)
                view['reason_codes'].append(reason)
            finally:
                if reader is not None:
                    try:
                        reader.close()
                    except Exception:
                        view.update(status='partial',complete=False)
                        view['reason_codes'].append('inventory_parser_close_failed' if spec is None else 'plugin_parser_close_failed')
            emit(force=True,view=view)
        comparisons, complete = merge_views(result['views'], max_comparisons=capacity(limits,2048))


        for comparison in comparisons:
            comparison['id'] += ':'+digest
            emit(comparison=comparison)
        reasons = {code for view in result['views'] for code in view['reason_codes']}
        if any(not view['complete'] for view in result['views']):
            reasons.add('inventory_view_incomplete')
        if not complete:
            reasons.add('inventory_comparison_limit')
        emit(force=True,comparisons_complete=complete,complete=not reasons,
             status='observed' if not reasons else 'partial',reason_codes=sorted(reasons))
    except CodeInspectionError as error:
        if str(error) != 'inventory_metadata_limit':
            raise
        result.update(complete=False,status='partial',reason_codes=sorted(set(result['reason_codes']) | {'inventory_metadata_limit'}))
        if checkpoint:
            checkpoint(deepcopy(result))
    return result
