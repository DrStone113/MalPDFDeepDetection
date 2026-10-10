"""Benign generated PDFs and synthetic decisions only; no external corpus."""

from dataclasses import replace
import hashlib
import io
import json
import os
from types import SimpleNamespace
import time
import zlib

import numpy as np
import pytest
from pypdf import PdfWriter
from pypdf.generic import (ArrayObject, DictionaryObject, IndirectObject, NameObject,
                          EncodedStreamObject, DecodedStreamObject, TextStringObject)

from malpdf.static.code_inspector import CodeInspectionLimits, _inspect_code_bytes, _inspect_code_bytes_inner
from malpdf.static.evidence import inspect_evidence, fact, _graph
from malpdf.static.recovery import MuPDFObjectReader
from malpdf.static.js_ast import CodeInspectionError
from malpdf.inference.evidence_policy import evidence_decision
from malpdf.experiments.cic_v8 import decision_metrics, fit_c1_v8, failure_inventory


def pdf(*, broken_marker=False, attachment=None, bad_attachment=False, action_cycle=False,indirect_action=False,bad_mime_ref=False):
    writer=PdfWriter(); writer.add_blank_page(72,72)
    action=DictionaryObject({NameObject('/S'):NameObject('/JavaScript'),
                             NameObject('/JS'):TextStringObject('var benign = 1;')})
    if indirect_action:
        action[NameObject('/S')]=writer._add_object(NameObject('/JavaScript'))
    ref=writer._add_object(action); writer._root_object[NameObject('/OpenAction')]=ref
    if action_cycle:
        other=writer._add_object(DictionaryObject({NameObject('/S'):NameObject('/SubmitForm'),
            NameObject('/F'):TextStringObject('https://synthetic.invalid/private'),NameObject('/Next'):ref}))
        action[NameObject('/Next')]=other
    if attachment is not None:
        stream=EncodedStreamObject() if bad_attachment else DecodedStreamObject()
        stream._data=attachment
        stream[NameObject('/Type')]=NameObject('/EmbeddedFile')
        if bad_mime_ref:stream[NameObject('/Subtype')]=IndirectObject(9999,0,writer)
        if bad_attachment: stream[NameObject('/Filter')]=NameObject('/FlateDecode')
        writer._root_object[NameObject('/Names')]=DictionaryObject({NameObject('/EmbeddedFiles'):ArrayObject([writer._add_object(stream)])})
    out=io.BytesIO(); writer.write(out); data=out.getvalue()
    return data[:data.rfind(b'startxref')] if broken_marker else data


def static(success=True):
    return {'parser':{'success':success,'structural_complete':success},'errors':[],'features':{}}


@pytest.mark.parametrize('value,complete,status,expected',[(None,True,'unknown',None),(0,False,'unknown',None),
    (0,True,'absent_after_complete_check',0),(3,False,'observed',3)])
def test_missing_evidence_never_becomes_zero(value,complete,status,expected):
    result=fact('count',value,'pypdf',complete=complete)
    assert result['status']==status and result['value']==expected
    assert fact('ignored',1,'pypdf',applicable=False)['status']=='not_applicable'


def test_readonly_mupdf_adapter_preserves_scripts_and_original_bytes():
    data=pdf(); before=hashlib.sha256(data).hexdigest(); limits=CodeInspectionLimits()
    reader=MuPDFObjectReader(data,limits)
    try:
        result=_inspect_code_bytes_inner(data,limits,None,supplied_reader=reader)
        assert result['scripts_parsed']==1 and result['parser_recovered']
        assert not result['complete'] and result['ast'] is None
        assert result['observed']['ast']['node_count']>0
        with pytest.raises(CodeInspectionError,match='generation_unsupported'):
            reader.get_object(IndirectObject(reader.trailer.raw_get('/Root').idnum,1,reader))
    finally: reader.close()
    assert hashlib.sha256(data).hexdigest()==before


def test_missing_startxref_recovery_stays_partial_with_primary_failure():
    data=pdf(broken_marker=True); limits=CodeInspectionLimits()
    code=_inspect_code_bytes(data,limits)
    result=inspect_evidence(data,static(False),code,limits)
    assert result['status']=='partial' and result['recovery_attempted'] and result['recovery_success']
    assert result['primary_errors']==code['errors'] and result['original_bytes_changed'] is False
    assert next(b for b in result['backends'] if b['backend']=='MuPDF')['code']['scripts_parsed']==1


def test_action_cycles_submitform_and_redaction():
    data=pdf(action_cycle=True); limits=CodeInspectionLimits(); code=_inspect_code_bytes(data,limits)
    result=inspect_evidence(data,static(),code,limits)
    actions=result['backends'][0]['graph']['actions']
    assert {a['kind'] for a in actions}=={'/JavaScript','/SubmitForm'}
    assert 'synthetic.invalid' not in json.dumps(result) and 'var benign' not in json.dumps(result)
    assert len(result['backends'][0]['graph']['edges'])<30


@pytest.mark.parametrize('bad',[False,True])
def test_embedded_bytes_are_hashed_without_export_and_failures_keep_other_actions(bad):
    content=b'PK\x03\x04synthetic benign container'
    data=pdf(attachment=content,bad_attachment=bad); limits=CodeInspectionLimits(); code=_inspect_code_bytes(data,limits)
    result=inspect_evidence(data,static(),code,limits)
    graph=result['backends'][0]['graph']; assert graph['actions'][0]['kind']=='/JavaScript'
    entry=graph['embedded'][0]
    if bad:
        assert entry['status']=='unknown' and graph['errors'] and result['status']=='partial'
    else:
        assert entry['magic']=='zip' and entry['sha256']==hashlib.sha256(content).hexdigest()
    assert 'synthetic benign container' not in json.dumps(result)


def test_embedded_budget_is_shared_with_javascript():
    limits=replace(CodeInspectionLimits(),max_decoded_bytes=16)
    data=pdf(attachment=b'benign'*30); code=_inspect_code_bytes(data,limits)
    result=inspect_evidence(data,static(),code,limits)
    assert result['decoded_bytes_remaining']>=0
    assert result['backends'][0]['graph']['embedded'][0]['error']=='decoded_byte_limit'


def test_graph_limit_does_not_claim_absence_or_completeness():
    data=pdf(); limits=replace(CodeInspectionLimits(),max_objects=2)
    code=_inspect_code_bytes(data,limits); result=inspect_evidence(data,static(False),code,limits)
    assert result['status']!='complete'
    assert all(f['status']!='absent_after_complete_check' for f in result['features'])


@pytest.mark.parametrize('probability',[None,float('nan'),-0.1,1.1])
def test_invalid_scores_abstain_without_a_fabricated_label(probability):
    decision=evidence_decision(probability,{'schema_version':'pdf-evidence-v8','status':'complete'},input_available=True)
    assert decision['decision']=='Inconclusive' and decision['predicted_label'] is None
    assert decision['operational_action']=='quarantine' and decision['malicious_probability'] is None


def contextual(status='partial'):
    return {'schema_version':'pdf-evidence-v8','status':status,'conflicts':[],
        'features':[fact('action_JavaScript',1,'pypdf',evidence_ids=['pypdf:1:0'])],
        'backends':[{'backend':'pypdf','status':'observed','graph':{'actions':[{'kind':'/JavaScript'}]},
                    'code':{'script_sources':[{'ast_status':'complete'}]}}]}


def test_partial_negative_and_conflicting_positive_are_inconclusive():
    assert evidence_decision(0.2,contextual(),input_available=True)['decision']=='Inconclusive'
    conflicting={**contextual(),'conflicts':[{'object':'1:0'}]}
    assert evidence_decision(0.9,conflicting,input_available=True)['decision']=='Inconclusive'
    assert evidence_decision(0.9,contextual(),input_available=False)['decision']=='Inconclusive'
    assert evidence_decision(0.9,{'schema_version':'pdf-evidence-v8','status':'partial'},input_available=True)['decision']=='Inconclusive'


def test_contextual_partial_positive_needs_model_score_and_complete_negative_can_allow():
    positive=evidence_decision(0.9,contextual(),input_available=True)
    assert positive['decision']=='Malicious' and positive['evidence_ids']==['pypdf:1:0']
    negative=evidence_decision(0.2,contextual('complete'),input_available=True)
    assert negative['decision']=='Benign' and negative['operational_action']=='allow'


def test_metrics_preserve_all_class_and_abstention_denominators():
    decisions=[]
    for label,p,status in [(1,0.9,'complete'),(1,0.2,'partial'),(0,0.9,'complete'),(0,0.2,'complete')]:
        decisions.append({**evidence_decision(p,contextual(status),input_available=True),'Label':label})
    scores=decision_metrics(decisions)
    assert scores['planned']==4 and scores['classified']==3 and scores['inconclusive']==1
    assert scores['conditional_recall']==1 and scores['end_to_end_detected_fraction']==0.5
    assert scores['malicious_coverage']==0.5 and scores['benign_coverage']==1
    assert scores['quarantine_malicious_fraction']==1 and scores['quarantine_benign_fraction']==0.5


def test_c1_train_only_missing_indicator_fitting_and_split_leakage_refusal():
    from malpdf.static.schema import RIT_FEATURES
    records=[]
    for partition in ['train','validation']:
        for number in range(6):
            features={name:0 for name in RIT_FEATURES}; features.update(pdfsize=number+(1000 if partition=='validation' else 1),pdf_ver=1.7)
            records.append({'sample_id':f'{partition}{number}','pdf_sha256':hashlib.sha256(f'{partition}{number}'.encode()).hexdigest(),
                'split':partition,'Label':number%2,'cache_mode':'cold','status':'partial','timings':{'read_hash':0.1,'raw_scan':0.1},
                'static':{'features':features,'input':{'size_bytes':1000},'parser':{}},'code':None,'analysis_v8':contextual()})
    config={'rf':{'n_estimators':3,'max_depth':3,'min_samples_leaf':1,'class_weight':'balanced'},'limits':{'max_file_bytes':10000}}
    model,decisions,names,count=fit_c1_v8(records,config)
    assert count==6 and len(decisions)==6
    assert model.named_steps['simpleimputer'].statistics_[names.index('pdfsize')]==3.5
    records[6]['static']['features']=dict(records[0]['static']['features'])
    with pytest.raises(ValueError,match='cross locked partitions'): fit_c1_v8(records,config)


def checkpoint_crash(connection,*args):
    os.setsid()
    connection.send_bytes(json.dumps({'event':'checkpoint','profile':{'status':'partial','errors':['primary_error'],
        'static':{'features':{'JS':1}},'code':{'complete':False}}}).encode())
    connection.close(); os._exit(7)


def test_backend_crash_preserves_primary_evidence_and_reports_unknown(tmp_path,monkeypatch):
    import multiprocessing
    from malpdf.static import profile_worker
    # The simulated crash must not include unrelated spawn import latency.
    # Real spawn and OS caps are exercised by the disposable-worker test below.
    context=multiprocessing.get_context('fork')
    monkeypatch.setattr(profile_worker.multiprocessing,'get_context',lambda *args:context)
    monkeypatch.setattr(profile_worker,'_profile_child',checkpoint_crash)
    monkeypatch.setattr(profile_worker,'_worker_count',lambda *args: 1)
    result=profile_worker.profile_pdf(tmp_path/'unused.pdf',boundary=tmp_path,digest='0'*64,
                                    include_v8=True,limits=CodeInspectionLimits(wall_seconds=8,cpu_seconds=4))
    assert result['status']=='worker_error' and result['static']['features']['JS']==1
    assert result['primary_errors']==['primary_error'] and result['analysis_v8']['status']=='unavailable'


def test_actual_disposable_v8_worker_never_rewrites_benign_input(tmp_path,monkeypatch):
    from malpdf.static import profile_worker
    # Admission is tested separately; this fixture must not depend on host RAM.
    # The actual subprocess still receives its hard address-space/CPU limits.
    monkeypatch.setattr(profile_worker,'_worker_count',lambda *args: 1)
    data=pdf(broken_marker=True); path=tmp_path/'benign.pdf';path.write_bytes(data)
    result=profile_worker.profile_pdf(path,boundary=tmp_path,digest=hashlib.sha256(data).hexdigest(),include_v8=True,
                       limits=CodeInspectionLimits(wall_seconds=20,cpu_seconds=12))
    assert result['analysis_v8']['status']=='partial' and result['analysis_v8']['recovery_success']
    assert result['status']=='parser_error' and result['errors']
    assert path.read_bytes()==data and result['resource_limits']['address_space_bytes'][0]==1024**3


def test_compressed_attachment_bomb_remains_bounded_and_partial():
    data=pdf(attachment=zlib.compress(b'A'*100000),bad_attachment=True)
    limits=replace(CodeInspectionLimits(),max_decoded_bytes=1000)
    reader=__import__('pypdf').PdfReader(io.BytesIO(data))
    graph=_graph(reader,'pypdf',limits,1000)
    assert not graph['complete'] and graph['decoded_bytes']<=1000
    assert graph['embedded'][0]['sha256'] is None
    assert 'decoded_byte_limit' in graph['errors']
    assert graph['action_counts']['JavaScript']==1


def test_object_projection_detects_content_and_reference_disagreement_without_export():
    from malpdf.static.recovery import projected_object
    a=DictionaryObject({NameObject('/JS'):TextStringObject('private first script')})
    b=DictionaryObject({NameObject('/JS'):TextStringObject('private second script')})
    assert projected_object(a)!=projected_object(b)
    assert 'private' not in json.dumps(projected_object(a))
    array=ArrayObject([NameObject('/inert')]*2000)
    assert not projected_object(array)['projection_complete']


def test_final_benchmark_attempt_is_atomic_and_not_reusable(tmp_path):
    from malpdf.experiments.cic_v8 import claim_v8_attempt
    prepared='run_synthetic'
    directory=tmp_path/'artifacts/cic_static_prepare'/prepared; directory.mkdir(parents=True)
    claim_v8_attempt(tmp_path,prepared)
    original=(directory/'v8_attempt.json').read_bytes()
    with pytest.raises(ValueError,match='already attempted'): claim_v8_attempt(tmp_path,prepared)
    assert (directory/'v8_attempt.json').read_bytes()==original
    with pytest.raises(ValueError,match='Unsafe'): claim_v8_attempt(tmp_path,'../../escape')


def oversized_backend(connection,*args):
    os.setsid()
    connection.send_bytes(json.dumps({'event':'checkpoint','profile':{'status':'partial','errors':[],
        'static':{'features':{'JS':1}},'code':None}}).encode())
    connection.send_bytes(b'A'*(3*1024**2));connection.close()


def stalled_backend(connection,*args):
    os.setsid()
    connection.send_bytes(json.dumps({'event':'checkpoint','profile':{'status':'partial','errors':[],
        'static':{'features':{'JS':1}},'code':None}}).encode())
    time.sleep(30)


@pytest.mark.parametrize('child,expected',[(oversized_backend,'worker_error'),(stalled_backend,'timeout')])
def test_output_cap_and_deadline_preserve_checkpoint_and_reap_worker(tmp_path,monkeypatch,child,expected):
    import multiprocessing
    from malpdf.static import profile_worker
    context=multiprocessing.get_context('fork')
    monkeypatch.setattr(profile_worker.multiprocessing,'get_context',lambda *args:context)
    monkeypatch.setattr(profile_worker,'_profile_child',child)
    monkeypatch.setattr(profile_worker,'_worker_count',lambda *args:1)
    before={p.pid for p in multiprocessing.active_children()}
    result=profile_worker.profile_pdf(tmp_path/'unused.pdf',boundary=tmp_path,digest='0'*64,
                                    include_v8=True,limits=CodeInspectionLimits(wall_seconds=2,cpu_seconds=1))
    assert result['status']==expected and result['static']['features']['JS']==1
    assert result['analysis_v8']['complete'] is False
    assert {p.pid for p in multiprocessing.active_children()}==before


def test_matching_readonly_backend_views_do_not_conflict_on_stream_representation():
    data=pdf(attachment=b'%PDF-inert attachment');limits=CodeInspectionLimits()
    primary=__import__('pypdf').PdfReader(io.BytesIO(data))
    alternate=MuPDFObjectReader(data,limits)
    try:
        a=_graph(primary,'pypdf',limits,limits.max_decoded_bytes)
        b=_graph(alternate,'MuPDF',limits,limits.max_decoded_bytes)
        keyed=lambda g:{key.split(':',1)[1]:value for key,value in g['objects'].items()}
        assert keyed(a)==keyed(b)
    finally:alternate.close()


def test_indirect_action_name_is_resolved_instead_of_recorded_absent():
    data=pdf(indirect_action=True)
    graph=_graph(__import__('pypdf').PdfReader(io.BytesIO(data)),'pypdf',CodeInspectionLimits(),10000)
    assert graph['complete'] and graph['action_counts']['JavaScript']==1


def test_recovery_does_not_restart_exhausted_primary_ast_budget(monkeypatch):
    from malpdf.static import evidence
    limits=replace(CodeInspectionLimits(),max_ast_nodes=2)
    data=pdf();code=_inspect_code_bytes(data,limits)
    assert 'ast_node_limit' in code['errors']
    monkeypatch.setattr(evidence,'_inspect_code_bytes_inner',lambda *args,**kwargs:pytest.fail('AST allowance restarted'))
    result=evidence.inspect_evidence(data,static(),code,limits)
    recovered=next(b for b in result['backends'] if b['backend']=='MuPDF')
    assert recovered['code'] is None and recovered['code_unavailable_reason']=='shared_code_budget_exhausted'
    assert result['status']=='partial' and not result['complete']


@pytest.mark.parametrize('code',['ast_node_limit','decoded_byte_limit','graph_object_or_depth_limit','xfa_xml_node_limit','reference_object_limit'])
def test_resource_caps_refuse_even_contextual_positive_predictions(code):
    analysis={**contextual(),'primary_errors':[code]}
    decision=evidence_decision(0.99,analysis,input_available=True)
    assert decision['decision']=='Inconclusive' and decision['predicted_label'] is None
    assert decision['resource_error_codes']==[code] and 'analysis_resource_limited' in decision['reasons']
    assert decision['operational_action']=='quarantine'


def test_invalid_mime_reference_preserves_attachment_bytes_and_valid_js_sibling():
    data=pdf(attachment=b'%PDF-inert',bad_mime_ref=True)
    graph=_graph(__import__('pypdf').PdfReader(io.BytesIO(data)),'pypdf',CodeInspectionLimits(),10000)
    assert not graph['complete'] and 'graph_name_reference_unavailable' in graph['errors']
    assert graph['embedded'][0]['sha256']==hashlib.sha256(b'%PDF-inert').hexdigest()
    assert graph['embedded'][0]['mime'] is None and graph['action_counts']['JavaScript']==1


def test_incomplete_primary_feature_gate_never_becomes_complete_or_benign():
    data=pdf();limits=CodeInspectionLimits();code=_inspect_code_bytes(data,limits)
    assert code['complete']
    analysis=inspect_evidence(data,static(),code,limits,primary_complete=False)
    assert analysis['status']=='partial' and not analysis['complete']
    assert analysis['primary_profile_complete'] is False
    decision=evidence_decision(0.1,analysis,input_available=True)
    assert decision['decision']=='Inconclusive' and 'incomplete_negative' in decision['reasons']


def paired_run_fixture(tmp_path,monkeypatch):
    from malpdf.experiments import cic_v8
    from malpdf.static.schema import RIT_FEATURES
    old=[];new=[]
    for partition in ('train','validation'):
        for number in range(32):
            features={name:0 for name in RIT_FEATURES}
            features.update(pdfsize=number+(1000 if partition=='validation' else 1),pdf_ver=1.7)
            row={'sample_id':f'{partition}{number}','pdf_sha256':hashlib.sha256(f'{partition}{number}'.encode()).hexdigest(),
                'split':partition,'Label':str(number%2),'cache_mode':'cold','status':'partial','errors':['synthetic_partial'],
                'timings':{'read_hash':0.1,'raw_scan':0.1},'total_seconds':0.1,
                'static':{'features':features,'input':{'size_bytes':1000},'parser':{}},'code':None}
            old.append(row);new.append({**row,'analysis_v8':{**contextual('complete'),
                'original_bytes_changed':False,'active_content_executed':False}})
    cfg={'rf':{'n_estimators':3,'max_depth':3,'min_samples_leaf':1,'class_weight':'balanced'},'limits':{'max_file_bytes':10000}}
    lock={'baseline_run':cic_v8.V7_RUN,'subset_sha256':'synthetic-manifest','configuration':cfg,'fingerprint':{'backends':{'synthetic':'1'}}}
    monkeypatch.setattr(cic_v8,'baseline_records',lambda root: (old,{},lock))
    artifacts=tmp_path/'artifacts/cic_static_profile/run_synthetic';artifacts.mkdir(parents=True)
    report=tmp_path/'reports/experiments/cic_static_profile/run_synthetic';report.mkdir(parents=True)
    run=SimpleNamespace(root=tmp_path,report=report,artifacts=artifacts,state={'metrics':{},'code_commit':'synthetic'})
    saved=tmp_path/'artifacts/cic_static_profile'/cic_v8.V7_RUN;saved.mkdir(parents=True)
    predictions={'sample_ids':[r['sample_id'] for r in old if r['split']=='validation'],
                 'probabilities':{name:[0.2]*32 for name in ('P0_rit41_fallback','P1_observed_static','P2_observed_plus_status')}}
    (saved/'observed_development_predictions.json').write_text(json.dumps(predictions))
    changed=json.loads(json.dumps(predictions));changed['probabilities']['P0_rit41_fallback'][1]=0.9
    (artifacts/'observed_development_predictions.json').write_text(json.dumps(changed))
    return run,new,lock


def test_final_comparison_preserves_denominators_and_blocks_unresolved_regression(tmp_path,monkeypatch):
    from malpdf.experiments.cic_v8 import compare_v8_run
    run,records,lock=paired_run_fixture(tmp_path,monkeypatch)
    compare_v8_run(run,records,lock)
    summary=json.loads((run.report/'v7_v8_comparison.json').read_text())
    assert summary['paired_samples']==64 and summary['c1']['planned']==32
    assert summary['acceptance']=='blocked' and summary['p0_p1_p2_prediction_changes']==1
    inventory=json.loads((run.artifacts/'failure_inventory.json').read_text())
    analysis=json.loads((run.artifacts/'c1_error_analysis.json').read_text())
    assert len(inventory)==64 and len(analysis)==32
    assert records[0]['pdf_sha256'] not in ''.join(p.read_text() for p in run.report.glob('*.json'))
    manifest=json.loads((run.report/'C1_v8_manifest.json').read_text())
    assert manifest['artifact_sha256']==hashlib.sha256((run.artifacts/'C1_v8.joblib').read_bytes()).hexdigest()
    assert not manifest['calibration_fitted']


@pytest.mark.parametrize('change',['hash','label','partition','duplicate'])
def test_v8_refuses_identity_label_partition_or_duplicate_change_before_fit(tmp_path,monkeypatch,change):
    from malpdf.experiments.cic_v8 import compare_v8_run
    run,records,lock=paired_run_fixture(tmp_path,monkeypatch)
    if change=='hash':records[0]['pdf_sha256']='f'*64
    elif change=='label':records[0]['Label']='1'
    elif change=='partition':records[0]['split']='validation'
    else:records[0]['sample_id']=records[1]['sample_id']
    with pytest.raises(ValueError,match='identit|retain'): compare_v8_run(run,records,lock)
    assert not (run.artifacts/'C1_v8.joblib').exists()
