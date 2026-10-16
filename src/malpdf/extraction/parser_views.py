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
from malpdf.static.js_ast import CodeInspectionError
from malpdf.static.parser_diagnostics import ParserDiagnostics
from malpdf.static.recovery import MuPDFObjectReader, projected_object


def _hash(value):
    return hashlib.sha256(value).hexdigest()


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


class _MuPDFView:
    def __init__(self, data, limits):
        import pymupdf
        self.reader = MuPDFObjectReader(data, limits)
        self.repaired = self.reader.repaired
        self.version = {'PyMuPDF':pymupdf.VersionBind,'MuPDF':pymupdf.VersionFitz}

    def candidates(self):
        for number in range(1,self.reader.document.xref_length()):
            # Public MuPDF xref APIs select by number. Generation remains
            # unknown even when the canonical object text contains references.
            yield {'number':number,'generation':None,'offset':None}

    def object(self, candidate, raw_budget):
        self.reader.raw_stream_allowance = lambda:raw_budget.remaining
        value = self.reader.get_object(IndirectObject(candidate['number'],0,self.reader))
        if isinstance(value,StreamObject):
            if len(value._data) > raw_budget.remaining:
                return value, False, ['inventory_raw_byte_limit']
            raw_budget.remaining -= len(value._data)
        return value, True, []

    def warnings(self):
        import pymupdf
        count = self.reader.warning_count + len(pymupdf.TOOLS.mupdf_warnings(reset=True).splitlines())
        return {'count':count,'codes':['mupdf_parser_warning'] if count else []}

    def close(self):
        self.reader.close()


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
                # Exact known generation matches take priority. Unknown
                # generations are paired only when the number is unambiguous.
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
    if not 2048 <= max_metadata_bytes <= 2*1024**2:
        raise ValueError('inventory_metadata_cap_invalid')
    if plugins is not None:
        from malpdf.extraction.plugins import PluginRegistry
        if type(plugins) is not PluginRegistry:raise ValueError('plugin_registry_required')
    digest = _hash(data)
    result = {'schema_version':'pdf-parser-inventory-v1','document_sha256':digest,'status':'partial','complete':False,
        'views':[],'comparisons':[],'comparisons_complete':False,'reason_codes':[],
        'limits':{'objects_per_view':limits.max_objects,'raw_bytes_total':limits.max_file_bytes,'metadata_bytes':max_metadata_bytes,
                  'projection_nodes_per_object':1024,'projection_depth':8,'key_details_per_object':64},
        'raw_bytes_used':0,'scope':'native xref interpretations; raw forensic/history/orphan proof remains unverified'}
    raw_budget = _RawBudget(limits.max_file_bytes)
    saved = deepcopy(result)
    def emit():
        nonlocal saved
        result['raw_bytes_used'] = limits.max_file_bytes - raw_budget.remaining
        if len(json.dumps(result,allow_nan=False,separators=(',',':')).encode()) > max_metadata_bytes - 512:
            raise CodeInspectionError('inventory_metadata_limit')
        if checkpoint:
            checkpoint(deepcopy(result))
        saved = deepcopy(result)
    try:
        emit()
        factories=[('pypdf',_PyPDFView,None),('QPDF',QPDFReader,None),('MuPDF',_MuPDFView,None)]
        if plugins is not None:
            from malpdf.extraction.plugins import ParserReader
            factories.extend(('plugin:'+spec.plugin_id,None,spec) for spec in plugins.select('parser'))
        for backend,factory,spec in factories:
            view = {'backend':backend,'version':{},'status':'not_run','complete':False,'records':[],
                    'reason_codes':[],'warnings':{'count':0,'codes':[]},'generation_available':backend != 'MuPDF',
                    'enumeration_complete':False,'repair_requested':backend != 'QPDF'}
            view['selection_scope'] = {'pypdf':'exposed xref map, including retained generations; active/revision identity unverified',
                'QPDF':'QPDF selected xref entries; historical revisions unverified',
                'MuPDF':'number-addressed current xref slots; generation unavailable, free/null slots may fail'}.get(backend,
                    'operator-selected plugin candidates; physical membership/history unverified')
            if spec is not None:
                view.update(plugin=spec.describe(),version=spec.describe(),generation_available=False,repair_requested=None)
            result['views'].append(view)
            emit()
            reader = None
            try:
                reader = ParserReader(spec,data,limits) if spec is not None else factory(data,limits)
                view.update(version=reader.version,status='partial')
                emit()
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
                        projection = projected_object(value,include_fields=True)
                        if not complete:
                            projection['projection_complete'] = False
                            if 'inventory_projection_limit' in reasons:
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
                    view['records'].append(node)
                    emit()
                else:
                    view['enumeration_complete'] = True
                view['complete'] = bool(view['enumeration_complete'] and all(node['status'] == 'observed' for node in view['records']))
                view['status'] = 'observed' if view['complete'] else 'partial'
                view['reason_codes'] = sorted(set(view['reason_codes']) | {code for node in view['records'] for code in node['reason_codes']})
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
                    if spec is None:reader.close()
                    else:
                        try:reader.close()
                        except Exception:
                            view.update(status='partial',complete=False)
                            view['reason_codes'].append('plugin_parser_close_failed')
            emit()
        comparisons, complete = merge_views(result['views'])
        # Append comparison checkpoints independently: an oversized final union
        # cannot erase completed inventories or prior localized conflicts.
        for comparison in comparisons:
            comparison['id'] += ':'+digest
            result['comparisons'].append(comparison)
            emit()
        result['comparisons_complete'] = complete
        reasons = {code for view in result['views'] for code in view['reason_codes']}
        if any(not view['complete'] for view in result['views']):
            reasons.add('inventory_view_incomplete')
        if not complete:
            reasons.add('inventory_comparison_limit')
        result.update(complete=not reasons,status='observed' if not reasons else 'partial',reason_codes=sorted(reasons))
        emit()
    except CodeInspectionError as error:
        if str(error) != 'inventory_metadata_limit':
            raise
        result = saved
        result.update(complete=False,status='partial',reason_codes=sorted(set(result['reason_codes']) | {'inventory_metadata_limit'}))
        if checkpoint:
            checkpoint(deepcopy(result))
    return result
