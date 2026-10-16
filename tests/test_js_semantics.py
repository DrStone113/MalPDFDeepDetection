"""Generated inert JS/AST/PDF fixtures; no runtime, dataset or network."""

from copy import deepcopy
from dataclasses import replace
import hashlib
import io
import json

import pytest
from pypdf import PdfWriter
from pypdf.generic import DictionaryObject,NameObject,TextStringObject

from malpdf.extraction.contracts import validate_bundle
from malpdf.extraction.normalize import normalize_profile
from malpdf.extraction.orchestrator import extract_pdf
from malpdf.extraction.raw import inspect_raw_layout
from malpdf.extraction.script_semantics import ScriptSemantics
from malpdf.static.code_inspector import CodeInspectionLimits
from malpdf.static.js_ast import inspect_js_syntax,set_tree_observer,reset_tree_observer
from malpdf.static.js_abstract import (Atom,Value,one,top,join,literal,boolean,binary,
                                     unary,describe,units)
from malpdf.static.js_semantics import SemanticLimits,SemanticBudget,analyze_js_tree


def sha(data): return hashlib.sha256(data).hexdigest()


def capture(source,*,limits=None,code=None):
    collector=ScriptSemantics('a'*64,code or CodeInspectionLimits(),limits=limits)
    token=set_tree_observer(collector)
    try: summary=inspect_js_syntax(source)
    finally: reset_tree_observer(token)
    return collector,summary


def analyze(source,**kwargs):
    collector,_=capture(source,**kwargs)
    return collector.finish()['scripts'][0]


def value_of(text): return describe(one('string',text))


@pytest.mark.parametrize(('operator','a','b','kind','expected'),[
    ('+',one('string','a'),one('string','b'),'string','ab'),
    ('+',one('number',1),one('number',2),'number',3),
    ('-',one('number',1),one('number',2),'number',-1),
    ('*',one('number',3),one('number',2),'number',6),
    ('/',one('number',6),one('number',2),'number',3),
    ('%',one('number',-5),one('number',2),'number',-1),
    ('===',one('boolean',True),one('number',1),'boolean',False),
    ('!==',one('string','a'),one('string','b'),'boolean',True),
    ('<',one('number',1),one('number',2),'boolean',True),
])
def test_finite_primitive_transfers(operator,a,b,kind,expected):
    assert binary(operator,a,b)==one(kind,expected)


@pytest.mark.parametrize(('operator','a','b'),[
    ('+',one('string','x'),one('number',1)),('==',one('string','1'),one('number',1)),
    ('/',one('number',1),one('number',3)),('/',one('number',1),one('number',0)),
    ('*',one('number',0),one('number',-1)),('%',one('number',-2),one('number',2)),
    ('+',one('number',2**53-1),one('number',1)),('+',top('unknown'),one('number',1)),
])
def test_unsupported_coercion_precision_and_opaque_values_stay_unknown(operator,a,b):
    result=binary(operator,a,b)
    assert result.unknown
    with pytest.raises(TypeError): bool(result)


def test_utf16_units_finite_sets_and_unknown_dominance():
    assert units('a\U0001f600')==3
    assert len(join([one('string','a'),one('string','b')]).atoms)==2
    assert join([one('number',i) for i in range(5)]).unknown
    assert join([one('number',1),top('unknown')]).unknown
    assert unary('-',one('number',0)).unknown
    assert unary('!',one('undefined'))==one('boolean',True)
    assert boolean(top('unknown')) is None


def test_equal_utf16_sequences_and_surrogate_concatenation_have_equal_values():
    astral=one('string','\U0001f600');pair=one('string','\ud83d\ude00')
    assert astral==pair
    assert binary('+',one('string','\ud83d'),one('string','\ude00'))==astral
    assert one('string','\u00e9')!=one('string','e\u0301')
    result=analyze('if("\U0001f600"==="\\ud83d\\ude00"){eval("inert");}')
    assert result['calls'][0]['flow_status']!='excluded_within_modeled_scope'
    assert analyze('const a="\U0001f600";')['normalized_ast_sha256']==analyze('const b="\\ud83d\\ude00";')['normalized_ast_sha256']


def test_decoded_script_ranges_are_codepoints_while_strings_use_utf16_units():
    source='const text="\U0001f600";eval(text);'
    result=analyze(source);call=result['calls'][0]
    start,end=call['source_range']
    assert source[start:end]=='eval(text)'
    assert call['arguments'][0]['alternatives'][0]['utf16_units']==2


def test_this_api_syntax_is_preserved_without_assuming_its_dynamic_receiver():
    result=analyze('this.getField("inert");')
    assert result['calls'][0]['syntactic_api_name']=='this.getField'
    assert result['calls'][0]['known_api_candidates']==[]


def test_observer_reuses_tree_without_changing_legacy_summary_or_reparsing(monkeypatch):
    import esprima
    source='var privateName="pri"+"ntf"; util[privateName]("private canary");'
    baseline=inspect_js_syntax(source)
    collector,observed=capture(source)
    assert observed==baseline
    def forbidden(*args,**kwargs): pytest.fail('Semantic pass must reuse the existing AST')
    monkeypatch.setattr(esprima,'parseScript',forbidden)
    result=collector.finish()
    assert result['complete'] and result['additional_ast_parses']==0
    assert 'private canary' not in json.dumps(result) and 'privateName' not in json.dumps(result)


@pytest.mark.parametrize(('first','second'),[
    ('var apple=1; function f(banana){let carrot=banana+1;return carrot;} f(apple);',
     'var x=1; function g(y){let z=y+1;return z;} g(x);'),
    ('let apple=1;{let apple=2;apple++;}apple++;','let x=1;{let x=2;x++;}x++;'),
    ('var a=function named(p){return named;};','var b=function other(q){return other;};'),
])
def test_alpha_normalization_respects_lexical_binding_identities(first,second):
    a,b=analyze(first),analyze(second)
    assert a['normalized_ast_sha256']==b['normalized_ast_sha256']
    assert a['bindings'] and all('name' not in binding for binding in a['bindings'])


@pytest.mark.parametrize(('first','second'),[
    ('var a=1;freeA(a);','var a=1;freeB(a);'),
    ('var a=1;({a:a});','var b=1;({b:b});'),
    ('var a={};a.left;','var b={};b.right;'),
])
def test_free_names_and_public_property_keys_are_not_alpha_renamed(first,second):
    assert analyze(first)['normalized_ast_sha256']!=analyze(second)['normalized_ast_sha256']


@pytest.mark.parametrize('source',[
    'const method="launch"+"URL";app[method]("inert");',
    'var host=app;var method="launch"+"URL";host[method]("inert");',
    'app["launch"+"URL"]("inert");',
])
def test_computed_constant_and_alias_api_candidates_are_explicitly_potential(source):
    result=analyze(source);call=result['calls'][0]
    assert call['known_api_candidates']==['app.launchURL']
    assert call['execution_status']=='not_executed' and result['functions_invoked'] is False
    assert result['javascript_executed'] is False


@pytest.mark.parametrize('source',[
    'app.launchURL("x");var app;',
    'function f(app){app.launchURL("x");}',
    '{let app=1;app.launchURL("x");}',
    '{function app(){}} app.launchURL("x");',
    'let app;app.launchURL("x");',
])
def test_shadowed_and_ambiguous_host_names_never_become_host_api_proof(source):
    result=analyze(source)
    assert all(not call['known_api_candidates'] for call in result['calls'])
    assert any(call['syntactic_api_name']=='app.launchURL' for call in result['calls'])


def test_unknown_conditions_join_values_and_opaque_effects_widen_mutable_state():
    result=analyze('var choice;if(flag){choice="a";}else{choice="b";}var result=choice+"c";')
    facts=[fact for fact in result['facts'] if fact['kind']=='binary_transfer']
    assert facts[-1]['value']==describe(join([one('string','ac'),one('string','bc')]))
    opaque=analyze('var x=1;unknown();var y=x+1;')
    assert [f for f in opaque['facts'] if f['kind']=='binary_transfer'][-1]['value']['status']=='unknown'
    stable=analyze('const x="a";unknown();var y=x+"b";')
    assert [f for f in stable['facts'] if f['kind']=='binary_transfer'][-1]['value']==value_of('ab')


@pytest.mark.parametrize('operation',['a+=1','a++'])
def test_opaque_update_or_compound_coercion_cannot_leave_other_mutable_values_known(operation):
    result=analyze('var a=opaqueObject;var x=1;'+operation+';var y=x+1;')
    last=next(f for f in reversed(result['facts']) if f['kind']=='binary_transfer')
    assert last['value']['status']=='unknown'
    assert 'object_coercion_unsupported' in result['reason_codes']


def test_program_entry_var_is_unknown_while_function_local_var_is_undefined():
    program=analyze('var x;if(x){app.launchURL("x");}')
    assert program['calls'][0]['flow_status']!='excluded_within_modeled_scope'
    function=analyze('function f(){var x;if(x){app.launchURL("x");}}')
    assert function['calls'][0]['flow_status']=='excluded_within_modeled_scope'


def test_tdz_assignment_does_not_invent_a_known_value():
    result=analyze('x=1;if(x){app.launchURL("x");}let x;')
    assignment=next(f for f in result['facts'] if f['kind']=='assignment_transfer')
    assert assignment['value']['status']=='unknown'
    assert 'lexical_tdz_or_entry_context_unverified' in result['reason_codes']


def test_local_function_alias_graph_does_not_invoke_or_propagate_returns():
    result=analyze('function f(x){return "private-return";}var g=f;var r=g(1);var z=r+"x";')
    call=result['calls'][0]
    assert call['possible_local_functions']==['function_0'] and call['known_api_candidates']==[]
    assert next(f for f in result['facts'] if f['kind']=='binary_transfer')['value']['status']=='unknown'
    assert 'private-return' not in json.dumps(result)


@pytest.mark.parametrize('source',[
    'if(false){eval("inert");}', 'false && eval("inert");','true || eval("inert");',
    'while(false){eval("inert");}','for(;false;eval("inert")){}',
    'function f(){do{return 1;}while(eval("inert"));}',
])
def test_constant_short_circuits_keep_excluded_call_sites_without_running_them(source):
    result=analyze(source)
    assert result['calls'] and all(c['flow_status']=='excluded_within_modeled_scope' for c in result['calls'])


def test_loop_widening_has_zero_concrete_iterations_and_does_not_claim_final_values():
    result=analyze('var x=0;while(flag){x++;}var y=x+1;')
    assert any(f['kind']=='loop_widening' and f['concrete_iterations_performed']==0 for f in result['facts'])
    assert next(f for f in reversed(result['facts']) if f['kind']=='binary_transfer')['value']['status']=='unknown'


@pytest.mark.parametrize('source',[
    'with(obj){eval("inert");}', 'try{eval("inert");}catch(e){}',
    'class C{method(){return 1;}}', 'var x={a:1};var y=x.a;',
    'var x=1.5+2;', 'var x=String.fromCharCode(65);eval(x);',
])
def test_unsupported_constructs_stay_partial_and_never_invoke_js(source):
    result=analyze(source)
    assert result['status']=='partial' and not result['javascript_executed']
    assert not result['functions_invoked']
    assert result['reason_codes']


@pytest.mark.parametrize(('override','reason'),[
    ({'max_steps':2},'js_semantic_steps_limit'),({'max_nodes':2},'js_tree_capture_unavailable'),
    ({'max_scopes':1},'js_semantic_scopes_limit'),({'max_bindings':1},'js_semantic_bindings_limit'),
    ({'max_facts':1},'js_semantic_facts_limit'),
])
def test_global_resource_caps_preserve_partial_results(override,reason):
    collector,_=capture('var a=1;var b=2;function f(){return a+b;}f();',limits=replace(SemanticLimits(),**override))
    result=collector.finish()
    assert not result['complete'] and reason in result['reason_codes']


def test_duplicate_capture_is_reused_and_ast_budget_is_shared_between_scripts():
    collector=ScriptSemantics('a'*64,CodeInspectionLimits(),limits=replace(SemanticLimits(),max_nodes=12))
    token=set_tree_observer(collector)
    try:
        first=inspect_js_syntax('var a=1;');again=inspect_js_syntax('var a=1;')
        inspect_js_syntax('var b=2;')
        inspect_js_syntax('var c=3;')
    finally: reset_tree_observer(token)
    result=collector.finish()
    assert first==again
    assert result['capture_duplicate_observations']==1
    assert result['captured_ast_nodes']<=12 and result['capture_failures']>0


def test_small_metadata_caps_remain_bounded_and_mark_omissions():
    collector,_=capture(''.join('var a%d=%d;'%(i,i) for i in range(20)),limits=replace(SemanticLimits(),max_metadata_bytes=8192))
    result=collector.finish()
    assert not result['complete']
    assert len(json.dumps(result,separators=(',',':')).encode())<=8192


def test_final_output_guard_restores_last_bounded_checkpoint_before_ipc():
    checkpoints=[]
    collector,_=capture('var a=1;',limits=replace(SemanticLimits(),max_metadata_bytes=8192))
    collector.checkpoint=lambda value:checkpoints.append(value)
    collector.emit()
    # Simulate unexpected downstream metadata growth beyond the record ledger.
    collector.value['scripts']=[{'unexpected_metadata':'x'*10000}]
    collector.emit()
    assert not collector.value['complete'] and collector.output_halted
    assert 'js_semantic_output_limit' in collector.value['reason_codes']
    assert collector.value['scripts']==[] and collector.value['captured_unique_sources']==1
    assert all(len(json.dumps(value,separators=(',',':')).encode())<=8192 for value in checkpoints)


def test_repeated_finish_cannot_resume_a_limit_or_turn_partial_into_success():
    collector,_=capture('var a=1;',limits=replace(SemanticLimits(),max_steps=2))
    first=deepcopy(collector.finish());second=collector.finish()
    assert second==first and second['complete'] is False


def fixture_pdf(source,*,closing=False):
    writer=PdfWriter();writer.add_blank_page(72,72)
    action=DictionaryObject({
        NameObject('/S'):NameObject('/JavaScript'),NameObject('/JS'):TextStringObject(source)})
    if closing: writer.root_object[NameObject('/AA')]=DictionaryObject({NameObject('/WC'):action})
    else: writer.root_object[NameObject('/OpenAction')]=action
    output=io.BytesIO();writer.write(output);return output.getvalue()


def save_bundle(bundle,tmp_path):
    path=tmp_path/'semantics_bundle.json'
    path.write_text(json.dumps(bundle,allow_nan=False))
    validate_bundle(json.loads(path.read_bytes()))


def test_worker_integration_sources_parity_and_no_script_plaintext(tmp_path):
    from malpdf.static.profile_worker import profile_pdf
    source='const privateBinding="launch"+"URL";app[privateBinding]("private-fixture-text");'
    data=fixture_pdf(source);path=tmp_path/'synthetic.pdf';path.write_bytes(data)
    limits=CodeInspectionLimits(wall_seconds=20,cpu_seconds=12)
    baseline=profile_pdf(path,boundary=tmp_path,digest=sha(data),analysis_version='v9',limits=limits)
    result=extract_pdf(path,boundary=tmp_path,limits=limits)
    validate_bundle(result)
    save_bundle(result,tmp_path)
    primary=next(r for r in result['evidence_store']['records'] if r['evidence_id']=='primary:'+sha(data))
    assert primary['details']['features']==baseline['static']['features']
    assert primary['details']['source_profile']['code']==baseline['code']
    assert primary['details']['source_profile']['analysis_v8']==baseline['analysis_v8']
    calls=[r for r in result['evidence_store']['records'] if r['kind']=='script_static_call']
    assert calls and any(r['details']['known_api_candidates']==['app.launchURL'] for r in calls)
    assert any(e['kind']=='same_decoded_script_static_analysis' for e in result['evidence_store']['edges'])
    assert any(e['kind']=='potential_static_call_site' for e in result['evidence_store']['edges'])
    assert any(e['kind']=='potential_api_reference' for e in result['evidence_store']['edges'])
    assert 'privateBinding' not in json.dumps(result) and 'private-fixture-text' not in json.dumps(result)
    assert path.read_bytes()==data and result['coverage_report']['worker']['worker_cleanup_complete']


def test_unmatched_ast_does_not_publish_facts_without_source_provenance():
    collector,_=capture('const x=1;eval("inert");')
    result=collector.finish();data=b'%PDF-1.7\n%%EOF\n';digest=sha(data)
    result['document_sha256']=digest
    bundle=normalize_profile({'status':'complete','raw_layout':inspect_raw_layout(data),
        'script_semantics':result},digest,'deep-static')
    validate_bundle(bundle)
    assert not any(r['kind']=='script_static_call' for r in bundle['evidence_store']['records'])
    summary=next(r for r in bundle['evidence_store']['records'] if r['kind']=='script_semantic_analysis')
    assert summary['details']['unmatched_script_sources']==1


def test_recovered_source_provenance_remains_flagged_for_all_new_facts():
    from malpdf.extraction.script_semantics import append_script_semantics
    from malpdf.extraction.normalize import _record
    source='const value="a"+"b";eval(value);'
    collector,summary=capture(source);result=collector.finish()
    records=[_record('recovered-script','script','MuPDF',is_synthetic_repaired=True,details={
        'ast_status':'complete','decoded_validated':True,'decoded_sha256':sha(source.encode()),'ast_summary':summary})]
    features=[];edges=[]
    append_script_semantics({'script_semantics':result},'a'*64,records,features,edges)
    facts=[record for record in records if record['kind'] in {'script_static_semantics','script_abstract_fact','script_static_call'}]
    assert facts and all(record['is_synthetic_repaired'] for record in facts)
    root=next(record for record in facts if record['kind']=='script_static_semantics')
    assert root['details']['source_provenance']['all_sources_recovered'] is True


def test_primary_checkpoint_with_mixed_views_retains_both_source_origins():
    from malpdf.extraction.script_semantics import append_script_semantics
    from malpdf.extraction.normalize import _record
    source='const x=1;eval(x);';collector,summary=capture(source)
    metadata={'ast_status':'complete','decoded_validated':True,'decoded_sha256':sha(source.encode()),'ast_summary':summary}
    code={'script_sources':[metadata]}
    records=[_record('primary','primary_checkpoint','legacy',details={'source_profile':{
        'code':code,'analysis_v8':{'backends':[{'backend':'MuPDF','code':deepcopy(code)}]}}})]
    append_script_semantics({'script_semantics':collector.finish()},'a'*64,records,[],[])
    root=next(r for r in records if r['kind']=='script_static_semantics')
    origins=root['details']['source_provenance']
    assert origins['includes_recovered_view'] is True and origins['all_sources_recovered'] is False
    assert origins['source_view_origins']['primary']=='original_and_recovered'


def test_every_call_has_a_caller_and_counts_after_first_api_candidate():
    from malpdf.extraction.script_semantics import append_script_semantics
    from malpdf.extraction.normalize import _record
    source='eval();unescape();app.launchURL("inert");'
    collector,summary=capture(source)
    records=[_record('source','script','pypdf',details={'ast_status':'complete','decoded_validated':True,
        'decoded_sha256':sha(source.encode()),'ast_summary':summary})]
    features=[];edges=[]
    append_script_semantics({'script_semantics':collector.finish()},'a'*64,records,features,edges)
    assert next(f for f in features if f['feature_name']=='script_semantic_call_sites')['value']==3
    assert len([e for e in edges if e['kind']=='potential_static_call_site'])==3
    assert {r['details']['api_name'] for r in records if r['kind']=='script_api_candidate'}=={'eval','unescape','app.launchURL'}
    ids={r['evidence_id'] for r in records}
    assert all(e['source'] in ids and e['target'] in ids for e in edges)


def test_nested_pdf_script_keeps_child_sources_and_one_shared_ast_analysis(tmp_path):
    from pypdf.generic import DecodedStreamObject
    source='const childMethod="launchURL";app[childMethod]("private child canary");'
    child=fixture_pdf(source)
    writer=PdfWriter();writer.add_blank_page(72,72)
    stream=DecodedStreamObject();stream.set_data(child)
    writer.root_object[NameObject('/PrivateChild')]=writer._add_object(stream)
    output=io.BytesIO();writer.write(output);data=output.getvalue()
    path=tmp_path/'nested_benign.pdf';path.write_bytes(data)
    result=extract_pdf(path,boundary=tmp_path)
    validate_bundle(result)
    save_bundle(result,tmp_path)
    roots=[r for r in result['evidence_store']['records'] if r['kind']=='script_static_semantics']
    assert len(roots)==1 and roots[0]['details']['decoded_script_sha256']==sha(source.encode())
    sources=roots[0]['details']['source_provenance']['source_refs']
    assert 'primary:'+sha(child) in sources and 'primary:'+sha(data) not in sources
    assert 'private child canary' not in json.dumps(result)
    assert any(r['kind']=='script_static_call' for r in result['evidence_store']['records'])


def xfa_fixture(source):
    from pypdf.generic import DecodedStreamObject
    writer=PdfWriter();writer.add_blank_page(72,72)
    xml=('<template><script contentType="application/x-javascript"><![CDATA['+source+']]></script></template>').encode()
    stream=DecodedStreamObject();stream.set_data(xml)
    writer.root_object[NameObject('/AcroForm')]=DictionaryObject({NameObject('/XFA'):writer._add_object(stream)})
    out=io.BytesIO();writer.write(out);return out.getvalue()


def test_xfa_worker_links_semantics_to_kept_script_sources(tmp_path):
    source='const x="pri"+"ntf";util[x]("private XFA canary");'
    data=xfa_fixture(source);path=tmp_path/'synthetic_xfa.pdf';path.write_bytes(data)
    result=extract_pdf(path,boundary=tmp_path)
    validate_bundle(result)
    save_bundle(result,tmp_path)
    calls=[r for r in result['evidence_store']['records'] if r['kind']=='script_static_call']
    assert calls and any('util.printf' in r['details']['known_api_candidates'] for r in calls)
    assert 'private XFA canary' not in json.dumps(result)
    assert result['coverage_report']['worker']['worker_cleanup_complete']


def test_javascript_token_alone_does_not_merge_activation_routes_or_api_candidates(tmp_path):
    bundles=[]
    for index,(source,closing) in enumerate((('app.launchURL("inert");',False),('util.printf("inert");',True))):
        data=fixture_pdf(source,closing=closing);path=tmp_path/f'benign_{index}.pdf';path.write_bytes(data)
        bundle=extract_pdf(path,boundary=tmp_path);validate_bundle(bundle);bundles.append(bundle)
    routes=[{event['pdf_route'] for event in b['trigger_plan']['events']} for b in bundles]
    names=[{name for r in b['evidence_store']['records'] if r['kind']=='script_static_call'
            for name in r['details']['known_api_candidates']} for b in bundles]
    assert '/OpenAction' in routes[0] and '/AA/WC' in routes[1] and routes[0]!=routes[1]
    assert 'app.launchURL' in names[0] and 'util.printf' in names[1] and names[0]!=names[1]
    assert all(b['trigger_plan']['dynamic_execution_status']=='not_run' for b in bundles)


def _semantic_checkpoint_then_stall(connection,path,boundary,digest,limits,*args):
    import os,time
    os.setsid()
    source='const method="launchURL";app[method]("inert");'
    collector,_=capture(source);analysis=collector.finish();analysis['document_sha256']=digest
    data=fixture_pdf(source)
    metadata={'ast_status':'complete','decoded_validated':True,'decoded_sha256':sha(source.encode()),
              'ast_summary':{'node_count':1}}
    connection.send_bytes(json.dumps({'event':'checkpoint','profile':{'status':'complete','errors':[],
        'static':{'input':{'sha256':digest},'features':{'canary':7}},
        'code':{'script_sources':[metadata]},'raw_layout':inspect_raw_layout(data),'script_semantics':analysis}}).encode())
    time.sleep(30)


def test_worker_timeout_keeps_completed_semantics_and_primary(tmp_path,monkeypatch):
    import multiprocessing
    from malpdf.static import profile_worker
    context=multiprocessing.get_context('fork')
    monkeypatch.setattr(profile_worker.multiprocessing,'get_context',lambda *args:context)
    monkeypatch.setattr(profile_worker,'_profile_child',_semantic_checkpoint_then_stall)
    monkeypatch.setattr(profile_worker,'_worker_count',lambda *args:1)
    source='const method="launchURL";app[method]("inert");';data=fixture_pdf(source)
    result=profile_worker.profile_pdf(tmp_path/'unused.pdf',boundary=tmp_path,digest=sha(data),analysis_version='v9',
        extraction_profile='deep-static',limits=CodeInspectionLimits(wall_seconds=2,cpu_seconds=1))
    assert result['script_semantics']['scripts'] and not result['script_semantics']['complete']
    assert result['static']['features']=={'canary':7} and result['worker_cleanup_complete']
    validate_bundle(normalize_profile(result,sha(data),'deep-static'))


@pytest.mark.parametrize('values',[{'max_nodes':0},{'max_steps':True},{'max_metadata_bytes':1},{'max_scopes':513}])
def test_invalid_limits_are_rejected(values):
    with pytest.raises(ValueError): SemanticLimits(**values)
