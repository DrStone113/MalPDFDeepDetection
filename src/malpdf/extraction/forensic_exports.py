"""Evidence-linked original-byte syntax/history; never promote it to execution."""

from collections import Counter
from copy import deepcopy

from malpdf.extraction.contracts import feature


def append_forensic(profile,digest,records,features,edges):
    from malpdf.extraction.normalize import _record
    forensic=profile.get('raw_forensic') or {}
    if not forensic:
        return []
    if forensic.get('document_sha256')!=digest:
        raise ValueError('forensic_export_document_mismatch')
    storage={item['sha256']:item for item in (profile.get('raw_stream_storage') or {}).get('records',[])}
    def retention(value):
        if isinstance(value,dict):
            if 'sha256' in value and 'size_bytes' in value and 'status' in value:
                parent=storage.get(value['sha256'])
                value['parent_verification_status']=parent['status'] if parent else 'unverified'
            for child in list(value.values()):
                if isinstance(child,(dict,list)):
                    retention(child)
        elif isinstance(value,list):
            for child in value:
                retention(child)
    summary_id='forensic-analysis:'+digest
    omit={'objects','partial_declarations','active_declaration','syntax_nodes','edges','xref_blocks','revisions','markers','structural_streams','active_decode','references','synthetic_nodes','comparisons'}
    records.append(_record(summary_id,'raw_forensic_analysis','raw_forensic',forensic['status'],
                           details={key:value for key,value in forensic.items() if key not in omit}))
    ids={record['evidence_id'] for record in records}
    def append(identity,kind,details,status='observed',**locator):
        if identity in ids:
            raise ValueError('forensic_duplicate_evidence_identity')
        ids.add(identity)
        copy=deepcopy(details);retention(copy)
        records.append(_record(identity,kind,'raw_forensic',status,details=copy,**locator))
    for item in forensic['objects']:
        kind='forensic_object_candidate' if item['source_space']=='original' and not item['top_level_confirmed'] else 'forensic_object_declaration'
        append(item['id'],kind,item,item['status'],object_number=item['object_number'],generation=item['generation'],
            byte_offset_start=item['byte_start'],byte_offset_end=item['byte_end'])
        edges.append({'id':item['id']+':document','source':'original:'+digest,'target':item['id'],'kind':'forensic_byte_declaration','status':'verified' if item['source_space']=='original' else 'derived'})
    partials=list(forensic.get('partial_declarations',[]))
    if forensic.get('active_declaration'):
        partials.append(forensic['active_declaration'])
    for item in partials:
        append(item['id'],'forensic_partial_declaration',item,'partial',object_number=item['object_number'],generation=item['generation'],
               byte_offset_start=item['byte_start'],byte_offset_end=item['byte_end'])
        if item.get('root_node_id'):
            edges.append({'id':item['id']+':partial-root','source':item['id'],'target':item['root_node_id'],
                          'kind':'forensic_partial_object_value','status':'verified'})
    for item in forensic['syntax_nodes']:
        original=item['source_space']=='original'
        append(item['id'],'forensic_syntax_'+item['kind'],item,item['status'],
            byte_offset_start=item['start'] if original else None,byte_offset_end=item['end'] if original else None)
    for item in forensic['synthetic_nodes']:
        append(item['id'],'forensic_synthetic_reference',item,'partial')
    for block in forensic['xref_blocks']:
        append(block['id'],'forensic_xref', {key:value for key,value in block.items() if key!='entries'},block['status'],
               byte_offset_start=block['offset'],byte_offset_end=block['end'])
        for entry in block['entries']:
            append(entry['id'],'forensic_xref_entry',entry,'partial' if entry['reason_codes'] else 'observed',
                   object_number=entry['object_number'],generation=entry['generation'])
            edges.append({'id':entry['id']+':block','source':block['id'],'target':entry['id'],'kind':'forensic_xref_membership','status':'verified'})
        if block['trailer_node_id']:
            edges.append({'id':block['id']+':trailer','source':block['id'],'target':block['trailer_node_id'],'kind':'forensic_trailer_dictionary','status':'verified'})
    by_offset={block['offset']:block['id'] for block in forensic['xref_blocks']}
    for block in forensic['xref_blocks']:
        for name in ('prev','supplement'):
            if block[name] is not None and block[name] in by_offset:
                edges.append({'id':block['id']+':'+name,'source':block['id'],'target':by_offset[block[name]],
                              'kind':'forensic_xref_'+name,'status':'verified'})
    for revision in forensic['revisions']:
        append(revision['id'],'forensic_revision_context',revision,'partial',revision=revision.get('revision_ordinal'))
        edges.append({'id':revision['id']+':xref','source':revision['id'],'target':revision['xref_id'],'kind':'forensic_revision_xref','status':'verified'})
    for marker in forensic['markers']:
        identity='forensic-marker:'+digest+':'+str(marker['offset'])
        append(identity,'forensic_'+marker['kind'],marker,byte_offset_start=marker['offset'],byte_offset_end=marker['end'])
    for item in forensic['structural_streams']+([forensic['active_decode']] if forensic.get('active_decode') else []):
        identity=item.get('id',item['source_id']+':structural-decode')
        append(identity,'forensic_structural_decode',item,item.get('status','partial'))
        edges.append({'id':identity+':source','source':item['source_id'],'target':identity,'kind':'forensic_decode_source','status':'verified'})
    for item in forensic['references']:
        append(item['id'],'forensic_reference_resolution',item,'observed' if item['resolved'] else 'partial')
        for index,key in enumerate(('source_id','target_id')):
            edges.append({'id':item['id']+':'+str(index),'source':item[key],'target':item['id'],'kind':'forensic_static_reference','status':'verified' if item['resolved'] else 'unresolved'})
    edges.extend({**edge,'status':'verified'} for edge in forensic['edges'])
    conflicts=[]
    native_views={view['backend']:next((record['evidence_id'] for record in records if record['kind']=='parser_view' and record['backend']==view['backend']),None)
                  for view in (profile.get('parser_analysis') or {}).get('views',[])}
    for item in forensic['comparisons']:
        append(item['id'],'forensic_parser_comparison',item,'partial',object_number=item['object_number'])
        for index,key in enumerate(('left_id','right_id')):
            source=item[key] or (summary_id if index==0 else native_views.get(item['right_backend']))
            if source is None or source not in ids:
                raise ValueError('forensic_comparison_source_missing')
            edges.append({'id':item['id']+':'+str(index),'source':source,'target':item['id'],'kind':'forensic_parser_comparison_source','status':'verified'})
        if item['result'] in {'value_projection_conflict','projection_difference_identity_unverified','generation_selection_conflict'}:
            conflicts.append({'id':item['id']+':conflict','affected_ids':[ref for ref in (item['left_id'],item['right_id']) if ref],
                'comparison_evidence_id':item['id'],'reason_code':item['result'],'fields':item['key_differences'],
                'raw_stream_equal':item['raw_stream_equal'],'resolution':'unresolved; original-byte and native views remain separate'})
    for edge in edges:
        if edge['source'] not in ids or edge['target'] not in ids:
            raise ValueError('forensic_export_reference_missing')
    for name,key in (('object_occurrences','objects'),('xref_blocks','xref_blocks'),('revision_contexts','revisions'),
                     ('synthetic_missing_targets','synthetic_nodes'),('syntax_nodes','syntax_nodes')):
        features.append(feature('forensic_observed_'+name,'xref_history' if key in {'xref_blocks','revisions'} else 'object_graph',
            len(forensic[key]),'partial',[summary_id],'observed original-byte/decoded syntax scope; no whole-file absence or execution claim'))
    memberships=Counter(item['xref_membership'] for item in forensic['objects'])
    for membership in ('selected_by_examined_latest_xref','listed_in_examined_history','unlisted_in_examined_xrefs','unknown'):
        features.append(feature('forensic_membership_'+membership,'xref_history',memberships[membership],'partial',[summary_id],
            'declaration membership under examined xrefs; unlisted is not proof of malicious or catalog-unreachable content'))
    for item in forensic['objects']:
        stream=item.get('stream')
        if stream is not None:
            match=stream['declared_endpoint_matches']
            features.append(feature(item['id']+':declared_endpoint_matches','streams_filters',match,'observed' if type(match) is bool else 'partial',
                [item['id']],'terminator verification at the authored/resolved length endpoint; does not infer an unknown actual stream length',complete=type(match) is bool))
    return conflicts
