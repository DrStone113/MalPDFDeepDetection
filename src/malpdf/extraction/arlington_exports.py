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
    omit={'bindings','checks'}
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
    counts=Counter(check['outcome'] for check in analysis.get('checks',[]))
    for name in ('pass','fail','indeterminate','not_applicable'):
        features.append(feature('arlington_candidate_checks_'+name,'parser_coverage',
            counts[name] if analysis.get('checks') else None,'partial' if analysis.get('checks') else 'not_run',
            [identity],'candidate-scoped rule counts; alternative failures are not document violations',
            analysis.get('reason_codes',[])))
