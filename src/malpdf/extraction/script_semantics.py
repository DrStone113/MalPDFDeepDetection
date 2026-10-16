"""Reuse validated script ASTs in one disposable worker, then export provenance."""

from copy import deepcopy
from dataclasses import asdict
import hashlib
import json

from malpdf.static.js_semantics import SemanticLimits,SemanticBudget,SemanticLimit,analyze_js_tree


class ScriptSemantics:
    def __init__(self,digest,code_limits,*,limits=None,checkpoint=None):
        self.code=code_limits;self.limits=limits or SemanticLimits(
            max_nodes=code_limits.max_ast_nodes,max_depth=code_limits.max_ast_depth)
        if self.limits.max_nodes>code_limits.max_ast_nodes or self.limits.max_depth>code_limits.max_ast_depth:
            raise ValueError('js_semantics_exceeds_worker_ast_allowance')
        self.budget=SemanticBudget(self.limits);self.checkpoint=checkpoint
        self.trees={};self.captured_nodes=0;self.source_bytes=0;self.capture_failures=0;self.duplicates=0
        self.captured_unique=0
        self.saved=None;self.output_halted=False;self.finished=False
        self.value={'schema_version':'pdf-script-semantics-v1','document_sha256':digest,
            'status':'partial','complete':False,'scripts':[],'reason_codes':[],
            'limits':asdict(self.limits),'additional_ast_parses':0,'javascript_executed':False,
            'scope':'successfully captured existing syntax trees only; independent per-script entry contexts',
            'capture_failures':0,'captured_unique_sources':0,'capture_duplicate_observations':0,
            'captured_ast_nodes':0,'captured_utf8_source_bytes':0,'processed_scripts':0}

    def capture(self,source,tree,summary):
        """A bounded optional observer must not fail the primary syntax pass."""
        try:
            data=source.encode('utf-8');digest=hashlib.sha256(data).hexdigest()
            if digest in self.trees:
                self.duplicates+=1;return
            count=summary['node_count']
            if (type(count) is not int or count<1 or len(data)>self.code.max_script_bytes
                    or self.source_bytes+len(data)>self.code.max_decoded_bytes
                    or len(self.trees)>=self.code.max_scripts
                    or self.captured_nodes+count>self.limits.max_nodes):
                raise SemanticLimit('js_tree_capture_limit')
            self.trees[digest]=(tree,len(source));self.captured_nodes+=count;self.source_bytes+=len(data)
            self.captured_unique+=1
        except Exception:
            self.capture_failures+=1

    def emit(self):
        self.value.update(capture_failures=self.capture_failures,captured_unique_sources=self.captured_unique,
            capture_duplicate_observations=self.duplicates,captured_ast_nodes=self.captured_nodes,
            captured_utf8_source_bytes=self.source_bytes,budget_usage=dict(self.budget.used))
        if self.capture_failures:
            self.value['reason_codes']=sorted(set(self.value['reason_codes'])|{'js_tree_capture_unavailable'})
        encoded=lambda value:len(json.dumps(value,ensure_ascii=True,separators=(',',':')).encode())
        if not self.output_halted and encoded(self.value)>self.limits.max_metadata_bytes-1024:
            self.value=deepcopy(self.saved) if self.saved is not None else {
                **self.value,'scripts':[],'reason_codes':[]}
            self.output_halted=True
            self.value.update(complete=False,counters_are_interrupted_lower_bounds=True)
            self.value['reason_codes']=sorted(set(self.value['reason_codes'])|{'js_semantic_output_limit'})
        if encoded(self.value)>self.limits.max_metadata_bytes:
            raise SemanticLimit('js_semantic_output_limit')
        self.saved=deepcopy(self.value)
        if self.checkpoint: self.checkpoint(deepcopy(self.value))

    def finish(self):
        if self.finished: return self.value
        self.finished=True
        self.emit()
        if self.output_halted:
            self.trees.clear();return self.value
        try:
            for digest,(tree,characters) in self.trees.items():
                analysis=analyze_js_tree(tree,digest,budget=self.budget)
                analysis['decoded_source_codepoints']=characters
                size=len(json.dumps(analysis,ensure_ascii=True,separators=(',',':')).encode())
                current=len(json.dumps(self.value,ensure_ascii=True,separators=(',',':')).encode())
                if current+size>self.limits.max_metadata_bytes-2048:
                    dropped=0
                    for collection in ('facts','calls','bindings','functions','scopes'):
                        while analysis[collection] and current+len(json.dumps(analysis,ensure_ascii=True,separators=(',',':')).encode())>self.limits.max_metadata_bytes-2048:
                            analysis[collection].pop();dropped+=1
                    analysis.update(complete=False,counters_are_interrupted_lower_bounds=True,
                        omitted_records_lower_bound=dropped,
                        reason_codes=sorted(set(analysis['reason_codes'])|{'js_semantic_combined_metadata_limit'}))
                    if current+len(json.dumps(analysis,ensure_ascii=True,separators=(',',':')).encode())>self.limits.max_metadata_bytes-1024:
                        raise SemanticLimit('js_semantic_combined_metadata_limit')
                self.value['scripts'].append(analysis);self.value['processed_scripts']+=1
                self.value['reason_codes']=sorted(set(self.value['reason_codes'])|set(analysis['reason_codes']))
                self.emit()
                if self.output_halted: raise SemanticLimit('js_semantic_output_limit')
                if not analysis['complete']:
                    raise SemanticLimit('js_semantic_script_interrupted')
            self.value['complete']=self.capture_failures==0
        except (SemanticLimit,MemoryError,RecursionError) as error:
            code=str(error) if isinstance(error,SemanticLimit) else 'js_semantic_memory_or_recursion_limit'
            self.value.update(complete=False,counters_are_interrupted_lower_bounds=True)
            self.value['reason_codes']=sorted(set(self.value['reason_codes'])|{code})
        finally:
            self.trees.clear()
        self.emit()
        return self.value


def _script_hashes(value,*,repaired=False):
    """Only explicit successful per-script metadata can support an AST source."""
    pending=[(value,repaired)]
    found={}
    while pending:
        item,recovered=pending.pop()
        if isinstance(item,dict):
            recovered=recovered or item.get('backend')=='MuPDF' or item.get('is_synthetic_repaired') is True or item.get('is_repaired') is True
            if (item.get('ast_status')=='complete' and item.get('decoded_validated') is True
                    and isinstance(item.get('ast_summary'),dict)):
                digest=item.get('decoded_sha256')
                if isinstance(digest,str): found[digest]=found.get(digest,frozenset())|{recovered}
            if isinstance(item.get('ast'),dict):
                digest=item.get('decoded_script_sha256')
                if isinstance(digest,str): found[digest]=found.get(digest,frozenset())|{recovered}
            pending.extend((value,recovered) for value in item.values() if isinstance(value,(dict,list)))
        elif isinstance(item,list): pending.extend((value,recovered) for value in item)
    return found


def append_script_semantics(profile,digest,records,features,edges):
    from malpdf.extraction.normalize import _record
    from malpdf.extraction.contracts import feature
    analysis=profile.get('script_semantics') or {}
    if not analysis: return
    if analysis.get('document_sha256')!=digest:
        raise ValueError('script_semantic_document_mismatch')
    sources={}
    for record in records:
        if record['kind'] not in {'script','primary_checkpoint','artifact','artifact_xml_script','object_stream_member'}: continue
        for script,origins in _script_hashes(record.get('details',{}),repaired=record['is_synthetic_repaired']).items():
            references=sources.setdefault(script,{})
            references[record['evidence_id']]=references.get(record['evidence_id'],frozenset())|origins
    identity='script-semantics:'+str(digest)
    summary={key:deepcopy(value) for key,value in analysis.items() if key!='scripts'}
    summary['matched_script_sources']=sum(script['decoded_script_sha256'] in sources for script in analysis.get('scripts',[]))
    summary['unmatched_script_sources']=len(analysis.get('scripts',[]))-summary['matched_script_sources']
    summary['source_metadata_without_semantic_tree']=len(set(sources)-{s['decoded_script_sha256'] for s in analysis.get('scripts',[])})
    records.append(_record(identity,'script_semantic_analysis','static_ast','partial',details=summary))
    ids={record['evidence_id'] for record in records}
    total_calls=0;candidate_calls=0;unknown_calls=0
    for script in analysis.get('scripts',[]):
        sha=script['decoded_script_sha256'];refs=sorted(sources.get(sha,{}))
        if not refs: continue  # Never publish an AST fact without a retained source.
        prefix=identity+':'+sha
        root=prefix+':script'
        recovered=any(True in origin for origin in sources[sha].values())
        records.append(_record(root,'script_static_semantics','static_ast','partial',details={
            **{key:value for key,value in script.items() if key not in {'scopes','bindings','functions','facts','calls'}},
            'source_provenance':{'source_refs':refs,'includes_recovered_view':recovered,
                'all_sources_recovered':all(origin=={True} for origin in sources[sha].values()),
                'source_view_origins':{ref:('original_and_recovered' if len(origin)==2 else 'recovered_only' if True in origin else 'original_interpretation')
                                       for ref,origin in sources[sha].items()}}},is_synthetic_repaired=recovered))
        ids.add(root)
        for index,ref in enumerate(refs):
            edges.append({'id':root+':source:'+str(index),'source':ref,'target':root,
                'kind':'same_decoded_script_static_analysis','status':'derived'})
        elements={item['id']:prefix+':'+item['id'] for name in ('scopes','bindings','functions','facts','calls') for item in script.get(name,[])}
        api_ids={}
        for name,kind in (('scopes','script_lexical_scope'),('bindings','script_normalized_binding'),
                          ('functions','script_function_candidate'),('facts','script_abstract_fact'),('calls','script_static_call')):
            for item in script.get(name,[]):
                target=elements[item['id']]
                if target in ids: raise ValueError('script_semantic_duplicate_identity')
                details=deepcopy(item);details['decoded_script_sha256']=sha
                details['source_range_unit']=script['source_range_unit']
                records.append(_record(target,kind,'static_ast','partial',details=details,is_synthetic_repaired=recovered));ids.add(target)
                edges.append({'id':target+':script','source':root,'target':target,'kind':'script_ast_fact','status':'derived'})
                if name=='calls':
                    total_calls+=1;candidate_calls+=bool(item['known_api_candidates'])
                    unknown_calls+=item['resolution_status']=='unknown'
                    caller=elements.get(item['source_function']) if item['source_function']!='program' else elements.get('scope_0')
                    if caller is not None:
                        edges.append({'id':target+':caller','source':caller,'target':target,
                            'kind':'potential_static_call_site','status':'derived'})
                    api_names=set(item['known_api_candidates'])
                    if item.get('syntactic_api_name'): api_names.add(item['syntactic_api_name'])
                    for api_name in sorted(api_names):
                        api_id=api_ids.get(api_name)
                        if api_id is None:
                            api_id=prefix+':api:'+hashlib.sha256(api_name.encode()).hexdigest();api_ids[api_name]=api_id
                            records.append(_record(api_id,'script_api_candidate','static_ast','partial',details={
                                'api_name':api_name,'scope':'name candidate; shadowing/host identity/dispatch/execution unverified'},
                                is_synthetic_repaired=recovered));ids.add(api_id)
                        edges.append({'id':target+':api:'+api_name,'source':target,'target':api_id,
                            'kind':'potential_api_reference' if api_name in item['known_api_candidates'] else 'syntactic_api_spelling',
                            'status':'derived'})
                    for local in item['possible_local_functions']:
                        if local in elements:
                            edges.append({'id':target+':callee:'+local,'source':target,'target':elements[local],
                                'kind':'potential_local_function_call','status':'derived'})
                elif name=='bindings' and item['scope_id'] in elements:
                    edges.append({'id':target+':scope','source':elements[item['scope_id']],'target':target,
                                  'kind':'lexical_binding','status':'derived'})
        finite=sum(fact.get('value',{}).get('status')=='finite' for fact in script.get('facts',[]))
        unknown=sum(fact.get('value',{}).get('status')=='unknown' for fact in script.get('facts',[]))
        for name,count in (('bindings',len(script.get('bindings',[]))),('finite_facts',finite),('unknown_facts',unknown)):
            features.append(feature(prefix+':'+name,'javascript_xfa',count,'partial',[root],
                'one matched script static abstraction; no behavioral equivalence, activation or execution claim',
                script.get('reason_codes',[])))
    for name,count in (('call_sites',total_calls),('api_candidates',candidate_calls),('unknown_calls',unknown_calls)):
        features.append(feature('script_semantic_'+name,'javascript_xfa',count,'partial',[identity],
            'lower bound in matched captured ASTs; syntax/static candidates, never runtime or exploit evidence',
            analysis.get('reason_codes',[])))
