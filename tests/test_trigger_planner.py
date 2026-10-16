"""Static plans from generated benign PDFs or synthetic exported evidence only."""

from copy import deepcopy
from dataclasses import replace
import hashlib
from io import BytesIO
import json

import pytest
from pypdf import PdfWriter
from pypdf.generic import DictionaryObject,NameObject,TextStringObject,ArrayObject,DecodedStreamObject

from malpdf.extraction.contracts import validate_bundle
from malpdf.extraction.normalize import normalize_profile,_record
from malpdf.extraction.raw import inspect_raw_layout
from malpdf.extraction.raw_forensic import inspect_raw_forensic
from malpdf.extraction.triggers import TriggerLimits,plan_triggers
from malpdf.static.code_inspector import CodeInspectionLimits,_inspect_code_bytes


def sha(data):return hashlib.sha256(data).hexdigest()
def obj(**keys):return DictionaryObject({NameObject('/'+k):v for k,v in keys.items()})
def name(value):return NameObject('/'+value)


def serialize(writer):
    stream=BytesIO();writer.write(stream);return stream.getvalue()


def raw_bundle(data):
    raw=inspect_raw_forensic(data,CodeInspectionLimits(),remaining=1024**2)
    assert raw['selection_context_verified'] and raw['xref_chain_complete']
    return normalize_profile({'status':'complete','raw_layout':inspect_raw_layout(data),'raw_forensic':raw},sha(data),'deep-static')


def native_bundle(data):
    from malpdf.static.evidence_v9 import inspect_evidence_v9
    limits=CodeInspectionLimits();static={'input':{'sha256':sha(data)},'features':{},'parser':{}}
    code=_inspect_code_bytes(data,limits)
    analysis=inspect_evidence_v9(data,static,code,limits,primary_complete=True)
    return normalize_profile({'status':'complete','static':static,'code':code,'raw_layout':inspect_raw_layout(data),
        'analysis_v9':analysis},sha(data),'deep-static')


def graph_bundle(kind='catalog',route='/OpenAction',chain=()):
    data=b'%PDF-1.7\n benign graph fixture\n';value=normalize_profile({'status':'complete','raw_layout':inspect_raw_layout(data)},sha(data),'deep-static')
    records=value['evidence_store']['records'];edges=value['evidence_store']['edges']
    def node(identity,kind,**details):records.append(_record(identity,kind,'pypdf',details=details));return identity
    def edge(source,target,kind,**details):
        edges.append({'id':'edge:'+str(len(edges)),'source':source,'target':target,'kind':kind,'status':'verified',**details})
    root='original:'+sha(data);node('catalog','catalog');edge(root,'catalog','document_catalog')
    if kind=='catalog':owner='catalog'
    elif kind in {'page','annotation'}:
        node('pages','pages');node('page','page');edge('catalog','pages','catalog_pages');edge('pages','page','pages_child');owner='page'
        if kind=='annotation':node('annotation','annotation');edge('page','annotation','page_annotation');owner='annotation'
    else:
        node('form','form');node('field','field');edge('catalog','form','document_acroform');edge('form','field','form_field');owner='field'
    for identity in ['action','second','third']:node(identity,'action',action_kind='/JavaScript')
    edge(owner,'action',kind+'_action',route=route)
    for source,target in chain:edge(source,target,'action_Next',route='/Next')
    return validate_bundle(value)


def assert_plan_sources(bundle,plan):
    nodes={n['evidence_id']:n for n in bundle['evidence_store']['records']};ids=set(nodes)|{e['id'] for e in bundle['evidence_store']['edges']}
    for event in plan['events']:
        assert event['execution_status']=='not_run' and event['runtime_feasibility']=='unverified'
        assert event['owner_id'] in nodes and (event['action_id'] is None or event['action_id'] in nodes)
        assert event['supporting_ids'] and all(ref in ids for ref in event['supporting_ids'])
        root=nodes[event['supporting_ids'][0]]
        assert root['kind']=='document' and root['backend']=='original' and root['details'].get('immutable') is True
        assert bundle['sample_sha256'] in (root['details'].get('sha256'),root['details'].get('raw_sha256'))
        assert all(n['evidence_id'] in nodes for n in event['action_chain'])
    assert not plan['forced_execution'] and plan['dynamic_execution_status']=='not_run'
    assert len({e['id'] for e in plan['events']})==len(plan['events'])
    assert len(json.dumps(plan,separators=(',',':')).encode())<=plan['limits']['max_metadata_bytes']


@pytest.mark.parametrize('kind,route,event',[
    ('catalog','/OpenAction','open_document'),('catalog','/AA/WC','close_document'),
    ('catalog','/AA/DC','close_document'),('catalog','/AA/WS','will_save_document'),
    ('catalog','/AA/DS','did_save_document'),('catalog','/AA/WP','will_print_document'),
    ('catalog','/AA/DP','did_print_document'),('page','/AA/O','open_page'),('page','/AA/C','close_page'),
    ('annotation','/A','activate_annotation'),('annotation','/AA/E','pointer_enter'),
    ('annotation','/AA/X','pointer_exit'),('annotation','/AA/D','pointer_down'),('annotation','/AA/U','pointer_up'),
    ('annotation','/AA/Fo','focus_annotation'),('annotation','/AA/Bl','blur_annotation'),
    ('annotation','/AA/PO','open_annotation_page'),('annotation','/AA/PC','close_annotation_page'),
    ('annotation','/AA/PV','show_annotation_page'),('annotation','/AA/PI','hide_annotation_page'),
    ('field','/AA/K','field_keystroke'),('field','/AA/F','format_field'),
    ('field','/AA/V','validate_field'),('field','/AA/C','calculate_field')])
def test_maps_owner_specific_event_families(kind,route,event):
    bundle=graph_bundle(kind,route);plan=plan_triggers(bundle)
    assert event in plan['family_counts'];assert_plan_sources(bundle,plan)
    if kind in {'page','annotation'}:assert plan['family_counts']['visit_page']==1


def test_next_graph_distinguishes_shared_dag_from_actual_cross_branch_cycle():
    dag=[('action','second'),('action','third'),('second','third')]
    value=graph_bundle(chain=dag);before=deepcopy(value)
    plan=plan_triggers(value);event=plan['events'][0]
    assert len(event['action_chain'])==3 and not event['cycle_observed']
    assert value==before;assert_plan_sources(value,plan)
    cycle=graph_bundle(chain=dag+[('third','second')]);event=plan_triggers(cycle)['events'][0]
    assert event['cycle_observed'] and len(event['action_chain'])==3


def test_chain_and_event_limits_keep_completed_prefix():
    bundle=graph_bundle(chain=[('action','second'),('second','third')])
    limited=plan_triggers(bundle,max_chain=1)
    assert limited['events'][0]['chain_limited'] and len(limited['events'][0]['action_chain'])==1
    assert not limited['traversal_complete'] and 'trigger_action_chain_limit' in limited['reason_codes']
    edges=bundle['evidence_store']['edges'];edges.append({'id':'second-root','source':'catalog','target':'second',
        'kind':'catalog_action','route':'/AA/WC','status':'verified'})
    limited=plan_triggers(bundle,max_events=1)
    assert len(limited['events'])==1 and limited['event_limit_reached']
    assert_plan_sources(bundle,limited)


@pytest.mark.parametrize('limits,reason',[
    (TriggerLimits(max_nodes=1),'trigger_node_index_limit'),(TriggerLimits(max_edges=1),'trigger_edge_index_limit'),
    (TriggerLimits(max_steps=1),'trigger_step_limit'),(TriggerLimits(max_path_ids=1),'trigger_path_limit'),
    (TriggerLimits(max_metadata_bytes=4096),'trigger_metadata_limit')])
def test_all_plan_budgets_are_explicit_and_fail_closed(limits,reason):
    bundle=graph_bundle();plan=plan_triggers(bundle,limits=limits)
    assert reason in plan['reason_codes'] and not plan['traversal_complete']
    assert_plan_sources(bundle,plan)


@pytest.mark.parametrize('override',[{'max_events':0},{'max_chain':True},{'max_nodes':65537},{'max_metadata_bytes':2000}])
def test_invalid_budget_configuration_is_refused(override):
    with pytest.raises(ValueError):TriggerLimits(**override)


def test_bad_owner_paths_and_backend_crossings_cannot_activate_an_action():
    value=graph_bundle();edges=value['evidence_store']['edges'];edges[-1]['kind']='field_action'
    assert not plan_triggers(value)['events']
    edges[-1]['kind']='catalog_action'
    next(n for n in value['evidence_store']['records'] if n['evidence_id']=='action')['backend']='MuPDF'
    assert not plan_triggers(value)['events']


def test_malformed_opaque_route_is_not_copied_or_interpreted():
    value=graph_bundle();value['evidence_store']['edges'][-1]['route']={'untrusted':'metadata'}
    plan=plan_triggers(value)
    assert not plan['events'] and plan['reason_codes']==['trigger_route_unverified']


def outline_pdf(*,cycle=False,bad_parent=False,both=False):
    writer=PdfWriter();writer.add_blank_page(72,72)
    outline=obj(Type=name('Outlines'));outline_ref=writer._add_object(outline)
    action=obj(S=name('URI'),URI=TextStringObject('https://never-follow.invalid/private-canary'))
    action_ref=writer._add_object(action)
    first=obj(Title=TextStringObject('private bookmark title'),Parent=outline_ref,A=action_ref)
    first_ref=writer._add_object(first)
    child=obj(Title=TextStringObject('private child title'),Parent=first_ref,Dest=TextStringObject('private-named-destination'))
    child_ref=writer._add_object(child);first[name('First')]=child_ref;first[name('Last')]=child_ref
    outline[name('First')]=first_ref;outline[name('Last')]=first_ref
    if bad_parent:first[name('Parent')]=first_ref
    if both:first[name('Dest')]=ArrayObject([writer.pages[0].indirect_reference,name('Fit')])
    if cycle:first[name('Next')]=first_ref
    writer.root_object[name('Outlines')]=outline_ref
    writer.root_object[name('Private')]=obj(Title=TextStringObject('forged outside outline'),A=action_ref)
    return serialize(writer)


def test_bookmarks_use_selected_raw_ir_and_redact_titles_urls_and_named_destinations():
    value=raw_bundle(outline_pdf());before=deepcopy(value);plan=plan_triggers(value)
    events=plan['events'];assert len(events)==2 and all(e['event']=='activate_bookmark' for e in events)
    assert any(e['action_chain'][0]['action_kind']=='/URI' for e in events if e['action_chain'])
    assert any(e.get('destination_id') and e['destination_resolution']=='unverified' for e in events)
    assert 'private' not in json.dumps(plan) and 'never-follow' not in json.dumps(plan)
    assert value==before;assert_plan_sources(value,plan)
    assert any('root-reference' in ref for e in events for ref in e['supporting_ids'])


@pytest.mark.parametrize('kwargs,reason',[
    ({'cycle':True},'trigger_outline_cycle_or_reuse'),({'bad_parent':True},'trigger_outline_parent_unverified'),
    ({'both':True},'trigger_outline_action_destination_conflict')])
def test_outline_malformations_are_preserved_as_incomplete(kwargs,reason):
    value=raw_bundle(outline_pdf(**kwargs));plan=plan_triggers(value)
    assert reason in plan['reason_codes'] and not plan['traversal_complete'];assert_plan_sources(value,plan)
    if kwargs.get('bad_parent'):assert not plan['events']


def test_raw_reference_or_selection_drift_never_becomes_a_bookmark_event():
    value=raw_bundle(outline_pdf())
    summary=next(n for n in value['evidence_store']['records'] if n['evidence_id']=='forensic-analysis:'+value['sample_sha256'])
    summary['details']['selection_context_verified']=False
    plan=plan_triggers(value);assert not plan['events'] and 'trigger_raw_xref_context_unverified' in plan['reason_codes']


def test_raw_next_chain_keeps_sources_and_cycles():
    writer=PdfWriter();writer.add_blank_page(72,72)
    outline=obj(Type=name('Outlines'));outref=writer._add_object(outline)
    a=obj(S=name('JavaScript'),JS=TextStringObject('var benign = 1;'));b=obj(S=name('Named'),N=name('NextPage'))
    ar,br=writer._add_object(a),writer._add_object(b);a[name('Next')]=br;b[name('Next')]=ar
    item=writer._add_object(obj(Title=TextStringObject('inert'),Parent=outref,A=ar));outline[name('First')]=item;outline[name('Last')]=item
    writer.root_object[name('Outlines')]=outref
    value=raw_bundle(serialize(writer));plan=plan_triggers(value)
    assert plan['events'][0]['cycle_observed'] and len(plan['events'][0]['action_chain'])==2
    assert_plan_sources(value,plan)


def test_destination_openaction_and_link_need_no_script_or_uri_execution():
    writer=PdfWriter();writer.add_blank_page(72,72);dest=ArrayObject([writer.pages[0].indirect_reference,name('Fit')])
    writer.root_object[name('OpenAction')]=dest
    link=writer._add_object(obj(Type=name('Annot'),Subtype=name('Link'),Dest=dest))
    writer.pages[0][name('Annots')]=ArrayObject([link])
    value=raw_bundle(serialize(writer));plan=plan_triggers(value)
    assert plan['family_counts']=={'open_document':1,'activate_link':1}
    assert all(e['action_id'] is None and e['destination_resolution']=='unverified' for e in plan['events'])
    assert_plan_sources(value,plan)


def test_acroform_field_candidates_keep_type_inheritance_and_skip_signatures():
    writer=PdfWriter();writer.add_blank_page(72,72)
    child=writer._add_object(obj(T=TextStringObject('private field')))
    parent=writer._add_object(obj(FT=name('Tx'),Kids=ArrayObject([child])))
    choice=writer._add_object(obj(FT=name('Ch'),T=TextStringObject('private choice')))
    signature=writer._add_object(obj(FT=name('Sig'),T=TextStringObject('private signature')))
    writer.root_object[name('AcroForm')]=obj(Fields=ArrayObject([parent,choice,signature]))
    value=raw_bundle(serialize(writer));plan=plan_triggers(value)
    assert len(plan['events'])==3 and all(e['event']=='fill_form_field' for e in plan['events'])
    assert {e['field_type'] for e in plan['events']}=={'/Tx','/Ch'}
    assert 'ancestor_candidate_unverified' in {e['field_type_status'] for e in plan['events']}
    assert all(e['input_proposal']['selector_status']=='evidence_id_only' for e in plan['events'])
    assert 'private' not in json.dumps(plan);assert_plan_sources(value,plan)


def test_real_name_tree_graph_is_an_open_document_candidate():
    writer=PdfWriter();writer.add_blank_page(72,72)
    action=writer._add_object(obj(S=name('JavaScript'),JS=TextStringObject('var benign = 1;')))
    tree=writer._add_object(obj(Names=ArrayObject([TextStringObject('private script name'),action])))
    writer.root_object[name('Names')]=obj(JavaScript=tree)
    value=native_bundle(serialize(writer));plan=plan_triggers(value)
    assert plan['events'] and all(e['activation']=='document_javascript' and e['event']=='open_document' for e in plan['events'])
    assert 'private' not in json.dumps(plan);assert_plan_sources(value,plan)


def test_xfa_event_graph_preserves_distinct_equal_activity_declarations():
    writer=PdfWriter();writer.add_blank_page(72,72)
    xml=b'<template><event activity="initialize"><script contentType="application/x-javascript">var benign=1;</script></event><event activity="initialize"><script contentType="application/x-javascript">var other=2;</script></event></template>'
    stream=DecodedStreamObject();stream.set_data(xml)
    writer.root_object[name('AcroForm')]=obj(XFA=writer._add_object(stream))
    value=native_bundle(serialize(writer));plan=plan_triggers(value)
    events=[e for e in plan['events'] if e['event']=='xfa_event']
    assert len(events)==2 and all(e['xfa_activity']=='initialize' for e in events)
    assert all(e['input_proposal']['selector_status']=='unavailable' for e in events)
    assert_plan_sources(value,plan)


def test_planning_does_not_parse_decode_open_files_or_connect_network(monkeypatch):
    import builtins,socket
    from pathlib import Path
    from malpdf.extraction import trigger_ir,raw_forensic,filters
    value=raw_bundle(outline_pdf())
    def fail(*a,**k):pytest.fail('Planner must use exported metadata only')
    monkeypatch.setattr(builtins,'open',fail);monkeypatch.setattr(Path,'open',fail)
    monkeypatch.setattr(socket,'socket',fail);monkeypatch.setattr(raw_forensic._Document,'object_at',fail)
    monkeypatch.setattr(filters,'decode_filters',fail)
    import pypdf
    monkeypatch.setattr(pypdf,'PdfReader',fail)
    plan=plan_triggers(value);assert len(plan['events'])==2;assert_plan_sources(value,plan)


def test_compressed_objects_binary_xref_and_duplicate_consistent_root_evidence():
    import pikepdf
    output=BytesIO()
    with pikepdf.Pdf.open(BytesIO(outline_pdf())) as pdf:
        pdf.save(output,object_stream_mode=pikepdf.ObjectStreamMode.generate)
    value=raw_bundle(output.getvalue());plan=plan_triggers(value)
    assert len(plan['events'])==2 and all(e['event']=='activate_bookmark' for e in plan['events'])
    assert_plan_sources(value,plan)


def test_conflicting_latest_reference_evidence_and_stale_selected_objects_are_refused():
    value=raw_bundle(outline_pdf());nodes=value['evidence_store']['records']
    root=next(n for n in nodes if n['kind']=='forensic_reference_resolution' and n['evidence_id'].endswith(':root-reference'))
    forged=deepcopy(root);forged['evidence_id']+=':conflicting';forged['details']['id']=forged['evidence_id']
    forged['details']['resolved']=False;nodes.append(forged)
    plan=plan_triggers(value)
    assert not plan['events'] and 'trigger_raw_reference_unresolved' in plan['reason_codes']
    nodes.pop()
    selected=next(n for n in nodes if n['evidence_id']==root['details']['target_id'])
    selected['details']['xref_membership']='listed_in_examined_history'
    plan=plan_triggers(value)
    assert not plan['events'] and 'trigger_raw_selected_target_unverified' in plan['reason_codes']


def test_repaired_origin_and_parent_aliases_remain_visible():
    value=graph_bundle();next(n for n in value['evidence_store']['records'] if n['evidence_id']=='action')['is_synthetic_repaired']=True
    plan=plan_triggers(value)
    assert plan['events'][0]['is_synthetic_repaired'] and plan['events'][0]['runtime_feasibility']=='unverified'
    assert_plan_sources(value,plan)


def test_verified_edge_without_semantic_kind_is_unavailable():
    value=graph_bundle();value['evidence_store']['edges'][-1].pop('kind')
    plan=plan_triggers(value)
    assert not plan['events'] and plan['reason_codes']==['trigger_edge_kind_unverified']


def test_malformed_array_index_does_not_select_an_alternative_bookmark_path():
    writer=PdfWriter();writer.add_blank_page(72,72)
    field=writer._add_object(obj(FT=name('Tx'),T=TextStringObject('benign')))
    writer.root_object[name('AcroForm')]=obj(Fields=ArrayObject([field]))
    value=raw_bundle(serialize(writer))
    for edge in value['evidence_store']['edges']:
        if edge.get('kind')=='forensic_array_item':edge['index']=None
    plan=plan_triggers(value)
    assert not plan['events'] and 'trigger_raw_array_index_unverified' in plan['reason_codes']


def test_worker_plans_all_new_families_and_preserves_primary(tmp_path):
    from malpdf.extraction.orchestrator import extract_pdf
    from malpdf.static.profile_worker import profile_pdf
    writer=PdfWriter(clone_from=BytesIO(outline_pdf()))
    script=writer._add_object(obj(S=name('JavaScript'),JS=TextStringObject('var benign=1;')))
    tree=writer._add_object(obj(Names=ArrayObject([TextStringObject('fixture'),script])))
    writer.root_object[name('Names')]=obj(JavaScript=tree)
    writer.root_object[name('AA')]=obj(DC=script)
    stream=DecodedStreamObject();stream.set_data(b'<template><event activity="initialize"><script contentType="application/x-javascript">var benign=1;</script></event></template>')
    field=writer._add_object(obj(FT=name('Tx'),T=TextStringObject('private field')))
    writer.root_object[name('AcroForm')]=obj(XFA=writer._add_object(stream),Fields=ArrayObject([field]))
    data=serialize(writer);path=tmp_path/'benign.pdf';path.write_bytes(data)
    limits=CodeInspectionLimits(wall_seconds=30,cpu_seconds=12)
    baseline=profile_pdf(path,boundary=tmp_path,digest=sha(data),analysis_version='v9',limits=limits)
    value=extract_pdf(path,boundary=tmp_path,limits=limits);validate_bundle(value)
    primary=next(r['details'] for r in value['evidence_store']['records'] if r['kind']=='primary_checkpoint')
    assert primary['features']==baseline['static']['features'] and primary['source_profile']['code']==baseline['code']
    assert primary['source_profile']['analysis_v8']==baseline['analysis_v8']
    plan=value['trigger_plan'];assert_plan_sources(value,plan)
    assert {'activate_bookmark','xfa_event','open_document','close_document','fill_form_field'}<=set(plan['family_counts'])
    assert any(e['activation']=='document_javascript' for e in plan['events'] if e.get('activation'))
    assert all(e['execution_status']=='not_run' for e in plan['events'])
    assert path.read_bytes()==data and all(v is False for v in value['safety'].values())
    assert value['coverage_report']['worker']['worker_cleanup_complete']
    (tmp_path/'triggers_bundle.json').write_text(json.dumps(value,allow_nan=False))
