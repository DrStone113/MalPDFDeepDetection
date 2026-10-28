"""Evidence-linked rule candidate outcomes, preserving unsupported coverage."""

from collections import Counter

from malpdf.extraction.contracts import feature


def append_arlington(profile,digest,records,features,edges):
    from malpdf.extraction.normalize import _record
    analysis=profile.get('arlington_analysis') or {}
    if not analysis: return
    if analysis.get('document_sha256')!=digest:
        raise ValueError('arlington_export_document_mismatch')
    identity='arlington-analysis:'+str(digest)
    omit={'bindings','checks','binding_reuses'}
    records.append(_record(identity,'arlington_analysis','Arlington',analysis['status'],
        details={key:value for key,value in analysis.items() if key not in omit}))
    ids={record['evidence_id'] for record in records}
    for collection,kind in (('bindings','arlington_schema_candidate'),('checks','arlington_rule_check')):
        for item in analysis.get(collection,[]):
            if item['id'] in ids: raise ValueError('arlington_duplicate_identity')
            if any(ref not in ids for ref in item['source_refs']):
                raise ValueError('arlington_unknown_source_reference')
            status='unsupported' if item['outcome']=='indeterminate' and any('unsupported' in reason for reason in item.get('reason_codes',[])) else 'partial'
            records.append(_record(item['id'],kind,'Arlington',status,details=item))
            ids.add(item['id'])
            for index,source in enumerate(item['source_refs']):
                edges.append({'id':item['id']+':source:'+str(index),'source':source,'target':item['id'],
                              'kind':'arlington_static_rule_source','status':'derived'})
    for item in analysis.get('binding_reuses',[]):
        if item['id'] in ids or item['target_binding_id'] not in ids:
            raise ValueError('arlington_reuse_binding_identity')
        if any(ref not in ids for ref in item['source_refs']):
            raise ValueError('arlington_unknown_source_reference')
        records.append(_record(item['id'],'arlington_binding_reuse','Arlington','partial',details=item))
        ids.add(item['id'])
        for index,source in enumerate(item['source_refs']):
            edges.append({'id':item['id']+':source:'+str(index),'source':source,'target':item['id'],
                          'kind':'arlington_static_rule_source','status':'derived'})
        edges.append({'id':item['id']+':binding','source':item['id'],'target':item['target_binding_id'],
                      'kind':'arlington_completed_binding_reuse','status':'derived'})
    counts=Counter(check['outcome'] for check in analysis.get('checks',[]))
    count_scope=('stored candidate-scoped rule counts; shared bindings counted once; alternative failures are not document violations'
                 if 'binding_reuses' in analysis else 'candidate-scoped rule counts; alternative failures are not document violations')
    for name in ('pass','fail','indeterminate','not_applicable'):
        features.append(feature('arlington_candidate_checks_'+name,'parser_coverage',
            counts[name] if analysis.get('checks') else None,'partial' if analysis.get('checks') else 'not_run',
            [identity],count_scope,
            analysis.get('reason_codes',[])))
    if 'binding_reuses' in analysis:
        features.append(feature('arlington_reused_schema_bindings','parser_coverage',len(analysis['binding_reuses']),
            'partial',[identity],'incoming links to completed schema evaluations within one document/version/xref and verified ancestor/depth context',
            analysis.get('reason_codes',[])))
    if 'total_violations' in analysis:
        features.append(feature('arlington_total_violations','parser_coverage',int(analysis['total_violations']),
            'observed',[identity],'total Arlington specification violations across all objects',
            analysis.get('reason_codes',[]),complete=True))
