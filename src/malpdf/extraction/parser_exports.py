"""Export additive parser inventories without replacing primary measurements."""

from collections import Counter
from copy import deepcopy
import hashlib

from malpdf.extraction.contracts import feature


def append_parser_views(profile, digest, records, features, edges):
    from malpdf.extraction.normalize import _record
    inventory = profile.get('parser_analysis') or {}
    if not inventory:
        return []
    if inventory.get('document_sha256') != digest:
        raise ValueError('parser_inventory_document_mismatch')
    summary_id = 'parser-inventory:' + digest
    summary = {key:value for key,value in inventory.items() if key not in {'views','comparisons'}}
    records.append(_record(summary_id,'parser_inventory','native_inventory',inventory['status'],details=summary))
    ids = {record['evidence_id'] for record in records}
    storage = {row['sha256']:row for row in (profile.get('raw_stream_storage') or {}).get('records',[])}
    views, conflicts = {}, []
    for view in inventory['views']:
        if view['backend'] in views:
            raise ValueError('duplicate_parser_view')
        view_id = 'parser-view:' + hashlib.sha256((digest+'|'+view['backend']).encode()).hexdigest()
        views[view['backend']] = view_id
        records.append(_record(view_id,'parser_view',view['backend'],view['status'],
                               details={key:value for key,value in view.items() if key != 'records'}))
        ids.add(view_id)
        edges.append({'id':view_id+':document','source':'original:'+digest,'target':view_id,
                      'kind':'original_parser_view','status':'verified'})
        for node in view['records']:
            if node['id'] in ids:
                raise ValueError('duplicate_parser_object_identity')
            ids.add(node['id'])
            details = deepcopy(node)
            retention = details.get('raw_retention')
            if retention:
                parent = storage.get(retention['sha256'])
                retention['parent_verification_status'] = parent['status'] if parent else 'unverified'
            records.append(_record(node['id'],'parser_object',view['backend'],node['status'],details=details,
                object_number=node['object_number'],generation=node['generation'],byte_offset_start=node['byte_offset'],
                is_synthetic_repaired=node['is_synthetic_repaired']))
            edges.append({'id':node['id']+':view','source':view_id,'target':node['id'],
                          'kind':'selected_parser_object','status':'verified'})
        features.append(feature('inventory_object_candidates_'+view['backend'],'parser_coverage',len(view['records']),
            'partial',[view_id],'native xref candidates, including failed reads; no historical/whole-file absence claim'))
        for name in ('observed','partial','encrypted','unsupported','resource_limit'):
            features.append(feature('inventory_object_status_'+view['backend']+'_'+name,'parser_coverage',
                sum(node['status'] == name for node in view['records']),'partial',[view_id],
                'count/lower bound within this native inventory; all failed reads retained'))
    for comparison in inventory['comparisons']:
        if comparison['left_backend'] not in views or comparison['right_backend'] not in views:
            raise ValueError('parser_comparison_view_missing')
        sources = [comparison.get('left_id'),comparison.get('right_id')]
        if any(source is not None and source not in ids for source in sources):
            raise ValueError('parser_comparison_source_missing')
        records.append(_record(comparison['id'],'parser_comparison','differential_merger','partial',details=comparison,
                               object_number=comparison['object_number']))
        for index,source in enumerate(sources):
            source = source or views[comparison['left_backend'] if index == 0 else comparison['right_backend']]
            edges.append({'id':comparison['id']+':source:'+str(index),'source':source,'target':comparison['id'],
                          'kind':'parser_comparison_source','status':'verified'})
        if comparison['result'] in {'value_projection_conflict','projection_difference_identity_unverified','generation_selection_conflict'}:
            fields = deepcopy(comparison['key_differences'])
            if comparison['raw_stream_equal'] is False:
                fields.append({'difference':'raw_stream_identity_conflict'})
            if comparison['result'] == 'generation_selection_conflict':
                fields.append({'difference':'selected_generation_conflict'})
            if comparison['projection_equal'] is False and not comparison['key_differences']:
                fields.append({'difference':'root_projection_conflict_not_localized'})
            conflicts.append({'id':comparison['id']+':conflict','affected_ids':[source for source in sources if source],
                'comparison_evidence_id':comparison['id'],'reason_code':comparison['result'],
                'fields':fields,'resolution':'unresolved; separate original parser interpretations'})
    counts = Counter(comparison['result'] for comparison in inventory['comparisons'])
    for name in ('projection_equal','value_projection_conflict','projection_difference_identity_unverified',
                 'generation_selection_conflict','only_in_enumerated_view','not_observed_in_partial_view','projection_unavailable'):
        features.append(feature('inventory_comparison_'+name,'parser_coverage',counts[name],'partial',[summary_id],
            'observed parser-selection comparison count/lower bound; equality is not file/revision identity'))
    return conflicts
