"""Transactional feature extensions after the built-in extraction checkpoints."""

from collections import Counter
from copy import deepcopy
import json

from malpdf.extraction.contracts import validate_bundle
from malpdf.extraction.plugins import FeatureContext,PluginContribution


def _candidate(base,batch):
    value=deepcopy(base)
    value['evidence_store']['records'].extend(deepcopy(batch['evidence']))
    value['evidence_store']['edges'].extend(deepcopy(batch['edges']))
    value['feature_store']['records'].extend(deepcopy(batch['features']))
    counts=Counter(row['feature_group'] for row in value['feature_store']['records'])
    for group,entry in value['coverage_report']['groups'].items():entry['feature_count']=counts[group]
    value['coverage_report']['observation_status_counts']=dict(Counter(row['observation_status'] for row in value['feature_store']['records']))
    return validate_bundle(value)


def run_feature_plugins(data,profile,digest,code_limits,plugins,*,buffers=None,checkpoint=None):
    from malpdf.extraction.normalize import normalize_profile
    limits=plugins.limits
    value={'schema_version':'pdf-plugin-features-v1','document_sha256':digest,'status':'partial','complete':False,
        'runs':[],'active_plugin':None,'active_method_invoked':False,'reason_codes':[],
        'scope':'operator-selected static feature contributions; no format-wide completeness'}
    saved=deepcopy(value)
    def emit():
        nonlocal saved
        if len(json.dumps(value,allow_nan=False,separators=(',',':')).encode())>limits.max_metadata_bytes-4096:
            raise ValueError('plugin_feature_metadata_limit')
        if checkpoint:checkpoint(deepcopy(value))
        saved=deepcopy(value)
    try:
        emit()
        base=normalize_profile(profile,digest,'deep-static')
        used={'evidence':0,'features':0,'edges':0}
        caps={'evidence':limits.max_evidence,'features':limits.max_features,'edges':limits.max_edges}
        for spec in plugins.select('feature'):
            value['active_plugin']=spec.plugin_id;emit()
            run={'plugin':spec.describe(),'status':'partial','reason_codes':[],'method_invoked':False,'evidence':[],'features':[],'edges':[]}
            try:
                if len(json.dumps(base,allow_nan=False,separators=(',',':')).encode())>limits.max_context_bytes:
                    raise ValueError('plugin_feature_context_limit')
                context=FeatureContext(data,base,spec,code_limits,plugins.seed,buffers or {})
                namespace=context.namespace+':'
                implementation=spec.build();run['method_invoked']=True
                value['active_method_invoked']=True;emit()
                output=implementation.extract(context)
                if type(output) is not PluginContribution:raise ValueError('plugin_feature_result_shape')
                batch={key:deepcopy(getattr(output,key)) for key in used}
                if any(type(batch[key]) not in (tuple,list) for key in used):raise ValueError('plugin_feature_result_shape')
                batch={key:list(rows) for key,rows in batch.items()}
                if any(used[key]+len(batch[key])>caps[key] for key in used):raise ValueError('plugin_feature_item_limit')
                ids={row['evidence_id']:row for row in base['evidence_store']['records']}
                ids.update({row['evidence_id']:row for row in batch['evidence']})
                new_ids={row['evidence_id'] for row in batch['evidence']}
                for row in batch['evidence']:
                    if not row['evidence_id'].startswith(namespace) or row['backend']!='plugin:'+spec.plugin_id:
                        raise ValueError('plugin_feature_namespace')
                    source=row['details'].get('plugin_source_ref');cursor=source;seen={row['evidence_id']}
                    repaired=row['is_synthetic_repaired']
                    if type(repaired) is not bool:raise ValueError('plugin_feature_repair_flag')
                    while True:
                        if cursor not in ids or cursor in seen:raise ValueError('plugin_feature_source')
                        parent=ids[cursor]
                        if type(parent['is_synthetic_repaired']) is not bool:raise ValueError('plugin_feature_repair_flag')
                        repaired=repaired or parent['is_synthetic_repaired']
                        if cursor not in new_ids:break
                        seen.add(cursor);cursor=parent['details'].get('plugin_source_ref')
                    row['is_synthetic_repaired']=repaired
                    batch['edges'].append({'id':row['evidence_id']+':source','source':source,'target':row['evidence_id'],
                        'kind':'plugin_source','status':'derived'})
                if used['edges']+len(batch['edges'])>caps['edges']:raise ValueError('plugin_feature_item_limit')
                if (any(not row['feature_name'].startswith(namespace) for row in batch['features'])
                        or any(not row['id'].startswith(namespace) for row in batch['edges'])):
                    raise ValueError('plugin_feature_namespace')
                candidate=_candidate(base,batch)
                run.update(batch,status='observed')
                proposed={**value,'runs':value['runs']+[run],'active_plugin':None}
                if len(json.dumps(proposed,allow_nan=False,separators=(',',':')).encode())>limits.max_metadata_bytes-4096:
                    raise ValueError('plugin_feature_metadata_limit')
                base=candidate
                for key in used:used[key]+=len(batch[key])
            except Exception as error:
                code=str(error) if isinstance(error,ValueError) and str(error).startswith('plugin_') and str(error).isidentifier() else (
                    'plugin_feature_resource_limit' if isinstance(error,(MemoryError,RecursionError)) else 'plugin_feature_failed')
                run.update(status='resource_limit' if 'limit' in code else 'partial',reason_codes=[code])
                run.update(evidence=[],features=[],edges=[])
                value['reason_codes']=sorted(set(value['reason_codes'])|{code})
            value['runs'].append(run);value['active_plugin']=None;value['active_method_invoked']=False;emit()
        value['complete']=not value['reason_codes'];value['status']='observed' if value['complete'] else 'partial';emit()
    except (ValueError,MemoryError,RecursionError):
        value=deepcopy(saved)
        value.update(status='partial',complete=False,counters_are_interrupted_lower_bounds=True,
            reason_codes=sorted(set(value['reason_codes'])|{'plugin_feature_metadata_or_context_limit'}))
        if checkpoint:checkpoint(deepcopy(value))
    return value


def append_plugin_features(profile,digest,records,features,edges):
    from malpdf.extraction.normalize import _record
    value=profile.get('plugin_features') or {}
    if not value:return
    if value.get('document_sha256')!=digest:raise ValueError('plugin_feature_document_mismatch')
    for run in value.get('runs',[]):
        spec=run['plugin'];identity='plugin-run:'+spec['plugin_id']+':'+digest
        records.append(_record(identity,'plugin_feature_run','plugin:'+spec['plugin_id'],run['status'],
            details={key:deepcopy(v) for key,v in run.items() if key not in {'evidence','features','edges'}}))
        records.extend(deepcopy(run['evidence']));features.extend(deepcopy(run['features']));edges.extend(deepcopy(run['edges']))


def plugin_backends(profile):
    registry=profile.get('plugin_registry') or {}
    result={}
    for spec in registry.get('specs',[]):
        if spec['kind']=='parser' and any(v['backend']=='plugin:'+spec['plugin_id'] for v in (profile.get('parser_analysis') or {}).get('views',[])):
            continue
        codes=[];statuses=[]
        if spec['kind']=='feature':
            for run in (profile.get('plugin_features') or {}).get('runs',[]):
                if run['plugin']['plugin_id']==spec['plugin_id']:
                    statuses.append(run['status']);codes.extend(run['reason_codes'])
            if (profile.get('plugin_features') or {}).get('active_plugin')==spec['plugin_id']:
                statuses.append('partial');codes.append('plugin_feature_interrupted')
        else:
            def stream_states(analysis):
                records=list((analysis or {}).get('records',[]))
                if (analysis or {}).get('active_stream'):records.append(analysis['active_stream'])
                for row in records:
                    for step in (row.get('decode') or {}).get('steps',[]):
                        if (step.get('plugin') or {}).get('plugin_id')==spec['plugin_id']:
                            statuses.append(step['status']);codes.extend(step['reason_codes'])
            stream_states(profile.get('stream_analysis'))
            for child in (profile.get('carving') or {}).get('analyses',{}).values():stream_states(child.get('stream_analysis'))
            raw=profile.get('raw_forensic') or {}
            stream_states({'records':raw.get('structural_streams',[]),'active_stream':raw.get('active_decode')})
        status='not_run' if not statuses else 'observed' if all(s=='observed' for s in statuses) else 'partial'
        if profile.get('status') in {'timeout','worker_error','resource_limit_or_signal'} and statuses:
            status='partial';codes.append('plugin_worker_interrupted')
        result['plugin:'+spec['plugin_id']]={'observation_status':status,'limitations':sorted(set(codes)) or ([] if statuses else ['plugin_not_invoked']),
            'version':spec,'scope':'attempted '+spec['kind']+' plugin operations only; registration is not coverage'}
    return result
