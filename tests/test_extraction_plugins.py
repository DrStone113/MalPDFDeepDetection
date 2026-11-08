"""Trusted synthetic plugins; never download plugins, samples or execute PDF JS."""

from copy import deepcopy
from dataclasses import replace
from io import BytesIO
import hashlib
import json
import os
from pathlib import Path
import zlib

import pytest
from pypdf import PdfWriter
from pypdf.generic import EncodedStreamObject,DictionaryObject,NameObject,NumberObject

from malpdf.extraction.plugins import (BaseParserPlugin,BaseDecoderPlugin,BaseFeaturePlugin,PluginSpec,
    PluginRegistry,PluginLimits,PluginContribution,PluginDecodeFailure,BoundedOutput)
from malpdf.extraction.filters import decode_filters,DecodeBudget,FilterLimits
from malpdf.extraction.parser_views import inspect_parser_views
from malpdf.extraction.plugin_features import run_feature_plugins
from malpdf.extraction.orchestrator import extract_pdf
from malpdf.extraction.normalize import normalize_profile
from malpdf.extraction.raw import inspect_raw_layout
from malpdf.extraction.contracts import validate_bundle,feature
from malpdf.static.code_inspector import CodeInspectionLimits




def sha(data):return hashlib.sha256(data).hexdigest()


class ReverseDecoder(BaseDecoderPlugin):
    def __init__(self,shift=0):self.shift=shift
    def decode(self,data,parameters,output):
        shift=parameters.get('/Shift',self.shift)
        output.write(bytes((v-shift)%256 for v in data[::-1]))


class SuppressedOverflow(BaseDecoderPlugin):
    def decode(self,data,parameters,output):
        try:output.write(b'x'*1000)
        except PluginDecodeFailure:pass


class PrefixFailure(BaseDecoderPlugin):
    def decode(self,data,parameters,output):
        output.write(b'inert prefix')
        raise ValueError('must never export this arbitrary text')


class MemoryFailure(BaseDecoderPlugin):
    def decode(self,data,parameters,output):raise MemoryError('synthetic resource failure')


class WrongReturn(BaseDecoderPlugin):
    def decode(self,data,parameters,output):return b'unaccepted return bytes'


class Reader:
    repaired=True
    def candidates(self):yield {'number':77,'generation':0,'offset':0}
    def object(self,candidate,allowance):
        return DictionaryObject({NameObject('/WorkerPID'):NumberObject(os.getpid())}),True,[]
    def warnings(self):return {'count':0,'codes':[]}
    def close(self):pass


class ParserPlugin(BaseParserPlugin):
    def open(self,data,limits):return Reader()


class OversizedReader(Reader):
    def object(self,candidate,allowance):
        value=EncodedStreamObject();value._data=b'x'*(allowance.remaining+1)
        return value,True,[]


class OversizedParser(BaseParserPlugin):
    def open(self,data,limits):return OversizedReader()


class ResetReader(Reader):
    def object(self,candidate,allowance):
        allowance.remaining+=100000
        return super().object(candidate,allowance)


class ResetParser(BaseParserPlugin):
    def open(self,data,limits):return ResetReader()


class CloseReader(Reader):
    def close(self):raise RuntimeError('private implementation message')


class CloseParser(BaseParserPlugin):
    def open(self,data,limits):return CloseReader()


class SnapshotFeature(BaseFeaturePlugin):
    def extract(self,context):
        node=context.observation('probe','snapshot_probe',details={'pid':os.getpid(),'seed':context.seed,
            'import_cpu_limit':_IMPORT_CPU_LIMIT,'import_memory_limit':_IMPORT_MEMORY_LIMIT,
            'cpu_limit':resource.getrlimit(resource.RLIMIT_CPU)[0],
            'memory_limit':resource.getrlimit(resource.RLIMIT_AS)[0]},start=0,end=5)
        value=context.measurement('length','raw_layout',len(context.data),'observed',[node['evidence_id']],
            'verified immutable root bytes',complete=True)
        return PluginContribution(evidence=(node,),features=(value,))


class BadNamespaceFeature(BaseFeaturePlugin):
    def extract(self,context):
        root=context.bundle['evidence_store']['records'][0]['evidence_id']
        return PluginContribution(features=(feature('canonical_JS','objects',0,'observed',[root],'unaccepted overwrite'),))


class MutatingFeature(BaseFeaturePlugin):
    def extract(self,context):
        context.bundle['coverage_report']['whole_document_complete']=True
        context.bundle['feature_store']['records'].clear()
        return SnapshotFeature().extract(context)


class MissingSourceFeature(BaseFeaturePlugin):
    def extract(self,context):
        node=context.observation('probe','probe',source_ref='nonexistent')
        return PluginContribution(evidence=(node,))


class BadRepairFeature(BaseFeaturePlugin):
    def extract(self,context):
        node=context.observation('probe','probe');node['is_synthetic_repaired']=1
        return PluginContribution(evidence=(node,))


class RepairedFeature(BaseFeaturePlugin):
    def extract(self,context):
        parent=next(r['evidence_id'] for r in context.bundle['evidence_store']['records'] if r['is_synthetic_repaired'])
        second=context.observation('second','probe',source_ref=parent)
        first=context.observation('first','probe',source_ref=second['evidence_id'])
        return PluginContribution(evidence=(first,second))


class CycleFeature(BaseFeaturePlugin):
    def extract(self,context):
        a=context.observation('first','probe',source_ref=context.identifier('second'))
        b=context.observation('second','probe',source_ref=a['evidence_id'])
        return PluginContribution(evidence=(a,b))


class StallingFeature(BaseFeaturePlugin):
    def extract(self,context):
        import time
        time.sleep(60)


def spec(cls,id='example',**kwargs):
    return PluginSpec(id,'1.0',cls,**({'filters':('/FixtureReverse',),'parameter_keys':('/Shift',)}
        if issubclass(cls,BaseDecoderPlugin) else {}),**kwargs)


def registry(cls=ReverseDecoder,**kwargs):return PluginRegistry((spec(cls,**kwargs),))


def pdf(body=None,filters=()):
    writer=PdfWriter();writer.add_blank_page(72,72)
    if body is not None:
        from pypdf.generic import ArrayObject
        stream=EncodedStreamObject();stream._data=body
        stream[NameObject('/Filter')]=ArrayObject([NameObject(name) for name in filters])
        writer.root_object[NameObject('/Private')]=writer._add_object(stream)
    out=BytesIO();writer.write(out);return out.getvalue()


def profile(data):
    layout=inspect_raw_layout(data)
    return {'status':'complete','errors':[],'raw_layout':layout,'static':{'input':{'sha256':sha(data)},'features':{'canary':7}},'code':None}


def test_decoder_extends_real_multilayer_dispatch_and_keeps_shared_budget():
    payload=b'benign decoded data';compressed=zlib.compress(payload);raw=compressed[::-1]
    budget=DecodeBudget(1000)
    decoded=decode_filters(raw,['/FixtureReverse','/FlateDecode'],plugins=registry(),budget=budget)
    assert decoded.data==payload and decoded.metadata['complete']
    assert budget.remaining==1000-len(compressed)-len(payload)
    assert decoded.metadata['steps'][0]['plugin_invoked'] and decoded.metadata['steps'][0]['plugin']['source_sha256']
    assert decode_filters(raw,['/FixtureReverse']).metadata['status']=='unsupported'


def test_plugin_numeric_parameters_are_explicit_and_configuration_is_snapshotted():
    config={'shift':1};s=spec(ReverseDecoder,parameters=config);config['shift']=9;s.parameters['shift']=20
    result=decode_filters(b'dcb',['/FixtureReverse'],plugins=PluginRegistry((s,)))
    assert result.data==b'abc' and 'shift' not in json.dumps(s.describe())
    result=decode_filters(b'dcb',['/FixtureReverse'],decode_parms={'/Shift':0},plugins=PluginRegistry((s,)))
    assert result.data==b'bcd'


@pytest.mark.parametrize('parms',[{'/Other':1},{'/Shift':True},{'/Shift':'secret'},[]])
def test_unsupported_parameters_do_not_invoke_plugin_or_become_empty_success(parms):
    result=decode_filters(b'bytes',['/FixtureReverse'],decode_parms=parms,plugins=registry())
    assert not result.metadata['complete'] and result.data is None
    assert not result.metadata['steps'] or not result.metadata['steps'][0].get('plugin_invoked',False)


def test_suppressing_output_exception_cannot_turn_truncation_into_success():
    limits=replace(FilterLimits(),max_stage_bytes=3)
    budget=DecodeBudget(1000)
    result=decode_filters(b'input',['/FixtureReverse','/FlateDecode'],plugins=registry(SuppressedOverflow),limits=limits,budget=budget)
    assert result.data is None and result.partial_data==b'xxx' and budget.remaining==997
    assert result.metadata['steps'][1]['status']=='not_run'


@pytest.mark.parametrize('cls',[PrefixFailure,MemoryFailure,WrongReturn])
def test_decoder_failures_keep_prefix_and_do_not_run_following_filter(cls):
    budget=DecodeBudget(500)
    result=decode_filters(b'input',['/FixtureReverse','/FlateDecode'],plugins=registry(cls),budget=budget)
    assert not result.metadata['complete'] and result.data is None and result.metadata['steps'][1]['status']=='not_run'
    assert 'must never export' not in json.dumps(result.metadata)
    if cls is PrefixFailure:assert result.partial_data==b'inert prefix' and budget.remaining==488
    if cls is MemoryFailure:assert budget.remaining==0 and result.metadata['status']=='resource_limit'


def test_empty_decoder_output_is_real_empty_with_zero_allowance():
    value=decode_filters(b'',['/FixtureReverse'],plugins=registry(),budget=DecodeBudget(0))
    assert value.data==b'' and value.metadata['complete'] and value.metadata['decoded_bytes']==0


@pytest.mark.parametrize('name',['/FlateDecode','/Fl','/Crypt'])
def test_registry_cannot_override_builtin_or_crypt_routes(name):
    with pytest.raises(ValueError,match='override'):PluginSpec('override','1',ReverseDecoder,filters=(name,))


@pytest.mark.parametrize('bad',[{'plugin_id':'../bad'},{'version':''},{'parameters':{'x':float('nan')}},{'parameters':{1:'coercion'}},
                              {'filters':('/Bad Name',)},{'parameter_keys':('/x','/x')}])
def test_registration_shapes_are_fail_closed(bad):
    args={'plugin_id':'good','version':'1','implementation':ReverseDecoder,'filters':('/FixtureReverse',)};args.update(bad)
    with pytest.raises(ValueError):PluginSpec(**args)


def test_registry_rejects_abstract_duplicate_and_ambiguous_routes():
    with pytest.raises(ValueError):PluginSpec('abstract','1',BaseFeaturePlugin)
    with pytest.raises(ValueError):PluginRegistry((spec(ReverseDecoder),spec(SnapshotFeature)))
    with pytest.raises(ValueError):PluginRegistry((spec(ReverseDecoder,id='first'),spec(ReverseDecoder,id='second')))
    with pytest.raises(ValueError):PluginRegistry(specs=[])
    with pytest.raises(ValueError):PluginRegistry(limits=None)


def test_worker_wire_contains_only_json_and_pins_exact_source_and_configuration():
    from malpdf.extraction.plugins import from_wire
    active=PluginRegistry((spec(ReverseDecoder,parameters={'shift':3}),spec(SnapshotFeature,id='facts')))
    payload=json.loads(json.dumps(active.wire(),allow_nan=False))
    restored=from_wire(payload)
    assert restored.describe()==active.describe() and restored.specs[0].parameters_json=='{"shift":3}'
    assert restored.specs[0].build().shift==3


@pytest.mark.parametrize('change',['source_sha256','source_path','module','parameters_json','class','api_version'])
def test_worker_rejects_wire_drift(change):
    from malpdf.extraction.plugins import from_wire
    value=registry().wire();item=value['specs'][0];desc=item['descriptor']
    if change=='parameters_json':item[change]='{"shift":9}'
    elif change=='source_sha256':desc[change]='0'*64
    elif change=='source_path':desc[change]=str(Path(__file__).absolute().with_name('test_stream_filters.py'))
    elif change=='module':desc[change]='malpdf.extraction.plugins'
    elif change=='class':desc[change]='__dict__'
    else:value[change]='unsupported-version'
    with pytest.raises(ValueError):from_wire(value)


def test_source_drift_is_rejected_before_pdf_access(tmp_path,monkeypatch):
    from malpdf.extraction import plugins,orchestrator
    active=registry(SnapshotFeature)
    monkeypatch.setattr(plugins,'_source',lambda *args:'0'*64)
    monkeypatch.setattr(orchestrator,'read_bounded_bytes',lambda *a,**k:pytest.fail('No PDF access before registry verification'))
    with pytest.raises(ValueError,match='source_changed'):extract_pdf(tmp_path/'not-read.pdf',plugins=active)


def test_plugin_profiles_are_explicit_and_default_empty_registry_is_compatible(tmp_path):
    with pytest.raises(ValueError,match='deep-static'):extract_pdf(tmp_path/'not-read.pdf',profile='fast-static',plugins=registry(SnapshotFeature))
    assert not PluginRegistry()
    with pytest.raises(ValueError,match='registry_required'):extract_pdf(tmp_path/'not-read.pdf',plugins='not an import path')


def test_parser_plugin_joins_inventory_merger_with_verified_provenance():
    data=pdf();value=inspect_parser_views(data,CodeInspectionLimits(),plugins=registry(ParserPlugin))
    view=next(v for v in value['views'] if v['backend']=='plugin:example')
    assert view['version']['source_sha256']==spec(ParserPlugin).source_sha256
    node=view['records'][0]
    assert node['object_number']==77 and node['byte_offset'] is None and node['xref']['metadata']['offset_unverified']
    assert node['is_synthetic_repaired'] and any(c['left_backend']=='plugin:example' or c['right_backend']=='plugin:example' for c in value['comparisons'])


@pytest.mark.parametrize('cls',[OversizedParser,ResetParser,CloseParser])
def test_parser_budget_and_close_failures_preserve_native_inventory(cls):
    data=pdf();value=inspect_parser_views(data,CodeInspectionLimits(max_file_bytes=len(data)+1),plugins=registry(cls))
    assert [v['backend'] for v in value['views'][:3]]==['pypdf','QPDF','MuPDF']
    view=value['views'][-1];assert not view['complete'] and view['status']=='partial'
    if cls is OversizedParser:
        assert value['raw_bytes_used']==len(data)+1 and view['records'][0]['projection']['stream_sha256'] is None
    if cls is ResetParser:assert view['records'][0]['projection'] is None
    if cls is CloseParser:assert 'plugin_parser_close_failed' in view['reason_codes']


@pytest.mark.parametrize('cls',[SnapshotFeature,MutatingFeature])
def test_feature_contributions_are_transactional_and_preserve_primary(cls):
    data=pdf();source=profile(data);before=deepcopy(source);active=registry(cls)
    value=run_feature_plugins(data,source,sha(data),CodeInspectionLimits(),active)
    assert value['complete'] and value['runs'][0]['features'] and source==before
    merged=normalize_profile({**source,'plugin_features':value,'plugin_registry':active.describe()},sha(data),'deep-static')
    validate_bundle(merged)
    assert any(f['feature_name'].startswith('plugin:example:') for f in merged['feature_store']['records'])
    assert not merged['coverage_report']['whole_document_complete']


@pytest.mark.parametrize('cls',[BadNamespaceFeature,MissingSourceFeature,BadRepairFeature,CycleFeature])
def test_invalid_feature_output_is_not_published_and_later_plugins_still_run(cls):
    data=pdf();active=PluginRegistry((spec(cls,id='bad'),spec(SnapshotFeature,id='good')))
    value=run_feature_plugins(data,profile(data),sha(data),CodeInspectionLimits(),active)
    assert not value['complete'] and value['runs'][0]['status']=='partial' and not value['runs'][0]['features']
    assert value['runs'][1]['features'] and value['runs'][1]['status']=='observed'


def test_repaired_source_propagates_through_forward_references():
    from malpdf.extraction.normalize import _record
    data=pdf();source=profile(data)

    source['analysis_v9']={'document_sha256':sha(data),'observations':[{'id':'repaired-source','kind':'pdf_object','backend':'MuPDF','status':'observed'}],
        'edges':[],'backend_results':[],'conflicts':[]}
    value=run_feature_plugins(data,source,sha(data),CodeInspectionLimits(),registry(RepairedFeature))
    assert value['complete'] and all(r['is_synthetic_repaired'] for r in value['runs'][0]['evidence'])


@pytest.mark.parametrize('override',[{'max_evidence':0},{'max_context_bytes':5*1024**2},{'max_plugins':True}])
def test_plugin_limit_configuration_is_bounded(override):
    with pytest.raises(ValueError):PluginLimits(**override)


def test_feature_context_and_metadata_limits_keep_primary_and_no_fake_values():
    data=pdf();active=PluginRegistry((spec(SnapshotFeature),),limits=replace(PluginLimits(),max_context_bytes=1))
    value=run_feature_plugins(data,profile(data),sha(data),CodeInspectionLimits(),active)
    assert not value['complete'] and not value['runs'][0]['features'] and not value['runs'][0]['method_invoked']


def test_feature_quota_is_shared_across_plugins_and_batches_are_atomic():
    data=pdf();active=PluginRegistry((spec(SnapshotFeature,id='first'),spec(SnapshotFeature,id='second')),
        limits=replace(PluginLimits(),max_evidence=1))
    value=run_feature_plugins(data,profile(data),sha(data),CodeInspectionLimits(),active)
    assert value['runs'][0]['evidence'] and not value['runs'][1]['evidence'] and not value['runs'][1]['features']
    assert value['runs'][1]['reason_codes']==['plugin_feature_item_limit'] and not value['complete']


def test_decoder_checkpoint_retains_active_invocation_for_structural_timeout():
    from malpdf.extraction.plugin_features import plugin_backends
    snapshots=[];active=registry()
    decode_filters(b'benign',['/FixtureReverse'],plugins=active,checkpoint=snapshots.append)
    started=next(row for row in snapshots if row['steps'] and row['steps'][0].get('plugin_invoked') and not row['complete'])
    assert started['steps'][0]['status']=='partial'
    coverage=plugin_backends({'plugin_registry':active.describe(),'status':'timeout',
        'raw_forensic':{'active_decode':{'decode':started}}})
    assert coverage['plugin:example']['observation_status']=='partial'
    assert 'plugin_worker_interrupted' in coverage['plugin:example']['limitations']


def test_end_to_end_three_plugin_kinds_run_in_worker_and_recursive_decodes_share_pool(tmp_path):
    from malpdf.static.profile_worker import profile_pdf
    leaf=b'benign child bytes';child=pdf(leaf[::-1],('/FixtureReverse',))
    data=pdf(zlib.compress(child)[::-1],('/FixtureReverse','/FlateDecode'));path=tmp_path/'benign.pdf';path.write_bytes(data)
    limits=CodeInspectionLimits(wall_seconds=30,cpu_seconds=12)
    baseline=profile_pdf(path,boundary=tmp_path,digest=sha(data),analysis_version='v9',limits=limits)
    active=PluginRegistry((spec(ParserPlugin,id='parser'),spec(ReverseDecoder,id='decoder'),spec(SnapshotFeature,id='features')))
    result=extract_pdf(path,boundary=tmp_path,limits=limits,plugins=active,raw_artifact_dir=tmp_path/'blobs')
    validate_bundle(result)
    primary=next(r['details'] for r in result['evidence_store']['records'] if r['kind']=='primary_checkpoint')
    assert primary['features']==baseline['static']['features'] and primary['source_profile']['code']==baseline['code']
    assert primary['source_profile']['analysis_v8']==baseline['analysis_v8']
    inventory=next(r['details'] for r in result['evidence_store']['records'] if r['kind']=='parser_view' and r['backend']=='plugin:parser')
    assert inventory['version']['source_sha256']
    probes=[r for r in result['evidence_store']['records'] if r['kind']=='snapshot_probe']
    assert probes and probes[0]['details']['pid']!=os.getpid()
    assert probes[0]['details']['import_cpu_limit']==probes[0]['details']['cpu_limit']==12
    assert probes[0]['details']['import_memory_limit']==probes[0]['details']['memory_limit']==1024**3
    decoded=[r for r in result['evidence_store']['records'] if r['kind']=='stream_decode' and (r['details'].get('decode') or {}).get('decoded_sha256')==sha(child)]
    assert decoded
    assert any(r['kind']=='artifact' and r['details']['kind']=='pdf' for r in result['evidence_store']['records'])
    assert any(r['kind']=='stream_decode' and (r['details'].get('decode') or {}).get('decoded_sha256')==sha(leaf) for r in result['evidence_store']['records'])
    assert (tmp_path/'blobs'/(sha(leaf)+'.bin')).read_bytes()==leaf
    assert result['coverage_report']['backends']['plugin:decoder']['observation_status']=='observed'
    assert result['coverage_report']['worker']['worker_cleanup_complete'] and path.read_bytes()==data
    assert result['coverage_report']['provenance']['plugins']['seed']==42 and all(v is False for v in result['safety'].values())
    (tmp_path/'plugins_bundle.json').write_text(json.dumps(result,allow_nan=False))


def _feature_checkpoint_then_stall(connection,path,boundary,digest,limits,*args):
    from malpdf.extraction.plugins import from_wire
    os.setsid();data=pdf();base=profile(data);active=from_wire(args[-1])
    connection.send_bytes(json.dumps({'event':'checkpoint','profile':base}).encode())
    def checkpoint(value):connection.send_bytes(json.dumps({'event':'checkpoint','profile':{'plugin_features':value}}).encode())
    run_feature_plugins(data,base,digest,limits,active,checkpoint=checkpoint)


def test_timeout_preserves_completed_feature_contribution_and_primary(tmp_path,monkeypatch):
    import multiprocessing
    from malpdf.static import profile_worker
    context=multiprocessing.get_context('fork')
    monkeypatch.setattr(profile_worker.multiprocessing,'get_context',lambda *a:context)
    monkeypatch.setattr(profile_worker,'_profile_child',_feature_checkpoint_then_stall)
    monkeypatch.setattr(profile_worker,'_worker_count',lambda *a:1)
    active=PluginRegistry((spec(SnapshotFeature,id='good'),spec(StallingFeature,id='stall')))
    data=pdf();result=profile_worker.profile_pdf(tmp_path/'not-read.pdf',boundary=tmp_path,digest=sha(data),analysis_version='v9',
        extraction_profile='deep-static',plugins=active,limits=CodeInspectionLimits(wall_seconds=2,cpu_seconds=1))
    assert result['status']=='timeout' and result['static']['features']=={'canary':7}
    assert result['plugin_features']['runs'][0]['features'] and not result['plugin_features']['complete']
    assert result['plugin_features']['active_plugin']=='stall' and result['plugin_features']['active_method_invoked']
    assert result['worker_cleanup_complete']
    bundle=validate_bundle(normalize_profile(result,sha(data),'deep-static'))
    assert bundle['coverage_report']['backends']['plugin:stall']['observation_status']=='partial'
