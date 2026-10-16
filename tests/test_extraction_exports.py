"""Export inert synthetic bundles only; no network, dataset or PDF parsing."""

from copy import deepcopy
from collections import Counter
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import struct
import subprocess

import networkx as nx
import pyarrow as pa
import pyarrow.parquet as pq
import pyarrow.dataset as ds
import pytest
import torch

from malpdf.extraction.contracts import feature,validate_bundle
from malpdf.extraction.exporters import ExportLimits,ExportFailure,export_bundles,export_bundle_files
from malpdf.extraction.graph_exports import node_link_data,graph_tensors
from malpdf.extraction.normalize import normalize_profile,_record
from malpdf.extraction.raw import inspect_raw_layout
from malpdf.extraction.tabular import TABLES,canonical,tables_for_bundle,restore_bundle,schemas


@pytest.fixture
def repository(tmp_path):
    (tmp_path/'.gitignore').write_text('data/processed/**\nartifacts/**\n')
    for args in (['init','-q'],['add','.gitignore'],['-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','Synthetic exporter fixture']):
        subprocess.run(['git','-C',str(tmp_path),*args],check=True,capture_output=True)
    return tmp_path


def bundle():
    data=b'%PDF-1.7\n/JS 1\n%%EOF\n';layout=inspect_raw_layout(data)
    profile={'status':'complete','errors':[],'raw_layout':layout}
    value=normalize_profile(profile,layout['sha256'],'fast-static',provenance={'raw_artifact_directory':'/must/not/be/read'})
    records=value['evidence_store']['records'];root=records[0]['evidence_id']
    records.extend([_record('repaired','object','MuPDF',object_number=7,generation=3,
        byte_offset_start=2**80,byte_offset_end=2**80+9,filter_chain=[],is_synthetic_repaired=True,
        details={'raw_null':None,'sentinel':-1,'id':'reserved id','unicode':'bình thường'}),
        _record('isolated','object','raw',filter_chain=None)])
    value['evidence_store']['edges']=[{'id':name,'source':root,'target':target,'key':'inert reserved attribute'}
        for name,target in [('first','repaired'),('parallel','repaired'),('self',root)]]
    additions=[('int-zero',0,'observed'),('bool-zero',False,'observed'),('float-zero',-0.0,'observed'),
        ('int-max',2**63-1,'observed'),('big-int',2**80,'observed'),('negative',-1,'partial'),
        ('truth',True,'observed'),('absent',0,'absent_within_scope')]
    additions +=[(status,None,status) for status in ('partial','decode_error','unsupported','encrypted','timeout','resource_limit','not_run')]
    for name,raw,status in additions:
        item=feature('test-'+name,'objects',raw,status,[root],'synthetic explicitly checked scope',complete=status=='absent_within_scope')
        item['coverage_ratio']=0 if name=='int-zero' else None
        value['feature_store']['records'].append(item)
    group=value['coverage_report']['groups']['objects'];group['feature_count']+=len(additions);group['observation_status']='partial'
    value['coverage_report']['observation_status_counts']=dict(Counter(r['observation_status'] for r in value['feature_store']['records']))
    value['evidence_store']['capability_checks']=[{'status':'unsupported','data':None}]
    value['evidence_store']['conflicts']=[{'unresolved':True,'backend':'MuPDF'}]
    value['trigger_plan']={'execution_status':'not_run','events':[]}
    value['extension']={'original':True,'nothing':None}
    return validate_bundle(value)


def read_tables(directory,identity='bundle_000000',format='parquet'):
    if format=='parquet':
        return {name:pq.read_table(directory/f'parquet/{name}/{identity}.parquet').to_pylist() for name in TABLES}
    return {name:[json.loads(line) for line in (directory/f'jsonl/{name}/{identity}.jsonl').read_text().splitlines()] for name in TABLES}


def manifest(directory): return json.loads((directory/'export_manifest.json').read_text())


def test_typed_parquet_and_jsonl_roundtrip_preserve_all_nulls_values_and_metadata(repository):
    original=bundle();before=deepcopy(original)
    directory=export_bundles([original],repository/'data/processed/exports',repository_root=repository)
    state=manifest(directory)
    assert state['status']=='completed' and state['completed_inputs']==1 and all(v is False for v in state['safety'].values())
    for fmt in ('parquet','jsonl'):
        tables=read_tables(directory,format=fmt)
        assert canonical(restore_bundle(tables))==canonical(original)
        values={row['feature_name']:row for row in tables['features']}
        assert values['test-int-zero']['value_type']=='int' and type(values['test-int-zero']['value_int64']) is int
        assert values['test-bool-zero']['value_boolean'] is False and values['test-bool-zero']['value_int64'] is None
        assert values['test-float-zero']['value_type']=='float'
        assert struct.pack('>d',values['test-float-zero']['value_float64'])==struct.pack('>d',-0.0)
        assert values['test-big-int']['integer_overflow'] and values['test-big-int']['value_int64'] is None
        assert json.loads(values['test-big-int']['value_json'])==2**80
        assert values['test-absent']['scope_complete'] and values['test-absent']['value_int64']==0
        assert values['test-timeout']['value_type']=='null' and values['test-timeout']['observation_status']=='timeout'
        repaired=next(r for r in tables['evidence'] if r['evidence_id']=='repaired')
        assert repaired['byte_offset_start'] is None and repaired['locator_overflows']==['byte_offset_start','byte_offset_end']
        assert repaired['generation']==3 and repaired['filter_chain']==[] and repaired['is_synthetic_repaired']
        assert next(r for r in tables['evidence'] if r['evidence_id']=='isolated')['filter_chain'] is None
    for entry in state['files']:
        assert entry['status']=='complete' and hashlib.sha256((directory/entry['path']).read_bytes()).hexdigest()==entry['sha256']
    for name,expected in schemas().items():
        actual=pq.read_table(directory/f'parquet/{name}/bundle_000000.parquet').schema
        assert actual.equals(expected,check_metadata=True)
    assert original==before


def test_repeated_hashes_and_failed_documents_are_not_deduplicated_or_dropped(repository):
    value=bundle();failed=normalize_profile({'status':'input_error','errors':['input_read_failed']},None,'deep-static')
    directory=export_bundles([value,value,failed],repository/'data/processed/exports',repository_root=repository)
    state=manifest(directory)
    assert state['completed_inputs']==3 and len({b['bundle_id'] for b in state['bundles']})==3
    assert state['bundles'][0]['sample_sha256']==state['bundles'][1]['sample_sha256']
    assert state['bundles'][2]['sample_sha256'] is None
    combined=ds.dataset(directory/'parquet/documents',format='parquet').to_table()
    assert combined.num_rows==3 and combined['sample_sha256'].null_count==1
    for i,expected in enumerate((value,value,failed)):
        assert canonical(restore_bundle(read_tables(directory,f'bundle_{i:06d}')))==canonical(expected)


def test_empty_tables_have_fixed_arrow_types_and_empty_coo(repository):
    value=normalize_profile({'status':'input_error','errors':['input_read_failed']},None,'fast-static')
    directory=export_bundles([value],repository/'data/processed/exports',repository_root=repository)
    table=pq.read_table(directory/'parquet/edges/bundle_000000.parquet')
    assert table.num_rows==0 and table.schema.equals(schemas()['edges'])
    tensors=graph_tensors(value)
    assert tensors['edge_index'].shape==(2,0) and tensors['edge_index'].dtype==torch.int64
    assert tensors['num_nodes']==len(value['evidence_store']['records'])


def test_networkx_multigraph_and_tensors_keep_parallel_self_and_isolated_nodes():
    value=bundle();before=deepcopy(value);wire=node_link_data(value,bundle_index=8)
    graph=nx.node_link_graph(wire,edges='edges')
    assert isinstance(graph,nx.MultiDiGraph) and graph.number_of_edges()==3
    assert graph.degree('isolated')==0 and graph.nodes['repaired']['record']['details']['id']=='reserved id'
    tensors=graph_tensors(value)
    assert tensors['num_nodes']==graph.number_of_nodes() and tensors['edge_ids']==['first','parallel','self']
    assert tensors['edge_index'].shape==(2,3)
    for i,edge in enumerate(value['evidence_store']['edges']):
        assert [tensors['node_ids'][j] for j in tensors['edge_index'][:,i].tolist()]==[edge['source'],edge['target']]
        assert graph[edge['source']][edge['target']][edge['id']]['record']==edge
    assert value==before


def test_json_object_key_order_does_not_change_table_projection():
    value=bundle();reloaded=json.loads(canonical(value))
    assert canonical(tables_for_bundle(value))==canonical(tables_for_bundle(reloaded))
    assert canonical(restore_bundle(tables_for_bundle(value)))==canonical(value)


def test_separate_exports_have_distinct_occurrence_keys_without_changing_source_identity(repository):
    value=bundle();output=repository/'data/processed/exports'
    first=export_bundles([value],output,repository_root=repository,formats=['parquet'])
    second=export_bundles([value],output,repository_root=repository,formats=['parquet'])
    a=read_tables(first)['documents'][0];b=read_tables(second)['documents'][0]
    assert a['export_id']!=b['export_id'] and a['bundle_sha256']==b['bundle_sha256']
    assert a['sample_sha256']==b['sample_sha256'] and a['bundle_id']==b['bundle_id']
    assert canonical(restore_bundle(read_tables(first)))==canonical(value)
    assert canonical(restore_bundle(read_tables(second)))==canonical(value)


@pytest.mark.parametrize('table,column,value',[('features','value_int64',10),('edges','target_index',900),('evidence','generation',9)])
def test_restore_rejects_projection_tampering(table,column,value):
    tables=tables_for_bundle(bundle());tables[table][0][column]=value
    with pytest.raises(ValueError,match='projection_inconsistent'): restore_bundle(tables)


def test_streamed_file_export_does_not_follow_pdf_blob_or_network_references(repository,monkeypatch):
    from malpdf.extraction import exporters
    import pypdf,pikepdf,pymupdf
    value=bundle();source=repository/'benign_bundle.json';source.write_text(canonical(value))
    read=exporters.read_bounded_bytes;opened=[]
    def restricted(path,**kwargs):
        assert path==source;opened.append(path);return read(path,**kwargs)
    def forbidden(*a,**k): pytest.fail('Metadata export must not parse/render or resolve PDF references')
    monkeypatch.setattr(exporters,'read_bounded_bytes',restricted)
    monkeypatch.setattr(pypdf,'PdfReader',forbidden);monkeypatch.setattr(pikepdf.Pdf,'open',forbidden);monkeypatch.setattr(pymupdf,'open',forbidden)
    directory=export_bundle_files([source],repository/'data/processed/exports',repository_root=repository)
    assert opened==[source] and canonical(restore_bundle(read_tables(directory)))==canonical(value)


@pytest.mark.parametrize('bad',['{"schema_version":1,"schema_version":2}','{"x":NaN}','{"x":Infinity}','not-json'])
def test_invalid_json_is_explicit_failed_export(repository,bad):
    source=repository/'bad.json';source.write_text(bad)
    with pytest.raises(ExportFailure) as failure:
        export_bundle_files([source],repository/'data/processed/exports',repository_root=repository)
    state=manifest(failure.value.directory)
    assert state['status']=='failed' and state['failure_input_index']==0 and state['completed_inputs']==0
    assert state['input_sources'][0]['path']==str(source)


def test_invalid_middle_input_preserves_prefix_and_marks_remaining_not_exported(repository):
    first=repository/'first.json';first.write_text(canonical(bundle()))
    bad=repository/'bad.json';bad.write_text('{}')
    never=repository/'not-read.json'
    with pytest.raises(ExportFailure) as failure:
        export_bundle_files([first,bad,never],repository/'data/processed/exports',repository_root=repository)
    state=manifest(failure.value.directory)
    assert state['expected_inputs']==3 and state['completed_inputs']==1 and state['failure_input_index']==1
    assert len(state['bundles'])==1 and canonical(restore_bundle(read_tables(failure.value.directory)))==canonical(bundle())


@pytest.mark.parametrize('override',[{'max_bundles':0},{'max_bundle_bytes':True},{'max_json_depth':129},{'max_output_bytes':2**32}])
def test_limits_fail_closed(override):
    with pytest.raises(ValueError): ExportLimits(**override)


@pytest.mark.parametrize('override,reason',[({'max_bundle_bytes':8},'bundle_byte_limit'),
    ({'max_rows_per_bundle':1},'row_limit'),({'max_json_depth':1},'structure_limit'),
    ({'max_json_entries':2},'structure_limit'),({'max_output_bytes':1},'output_byte_limit')])
def test_caps_never_publish_a_completed_or_truncated_export(repository,override,reason):
    with pytest.raises(ExportFailure) as failure:
        export_bundles([bundle()],repository/'data/processed/exports',repository_root=repository,limits=ExportLimits(**override))
    state=manifest(failure.value.directory)
    assert state['status']=='failed' and state['completed_inputs']==0 and reason in state['errors'][0]
    if 'max_output_bytes' in override:
        assert state['data_output_bytes']<=override['max_output_bytes']
        assert any(f['status']=='incomplete' for f in state['files'])


@pytest.mark.parametrize('formats',[[],['jsonl','jsonl'],['pickle'],[[]]])
def test_unknown_or_duplicate_formats_refused_before_output(repository,formats):
    output=repository/'data/processed/exports'
    with pytest.raises(ValueError,match='invalid_formats'): export_bundles([bundle()],output,repository_root=repository,formats=formats)
    assert not output.exists()


def test_private_paths_and_collision_do_not_overwrite_prior_exports(repository,monkeypatch):
    from malpdf.extraction import exporters
    with pytest.raises(ValueError,match='under data/processed'):
        export_bundles([bundle()],repository/'reports/exports',repository_root=repository)
    output=repository/'data/processed/exports';monkeypatch.setattr(exporters,'_run_name',lambda commit:'run_fixture')
    directory=export_bundles([bundle()],output,repository_root=repository)
    original=(directory/'export_manifest.json').read_bytes()
    with pytest.raises(FileExistsError): export_bundles([bundle()],output,repository_root=repository)
    assert (directory/'export_manifest.json').read_bytes()==original


def test_output_root_symlink_is_rejected_before_reading_inputs(repository):
    target=repository/'private';target.mkdir()
    link=repository/'data/processed';link.parent.mkdir();link.symlink_to(target,target_is_directory=True)
    with pytest.raises(ValueError,match='symbolic links'):
        export_bundle_files([repository/'not-read.json'],link/'exports',repository_root=repository)
    assert not list(target.iterdir())


@pytest.mark.parametrize('mode',['bytes','rows'])
def test_total_batch_limits_preserve_first_occurrence_and_refuse_second(repository,mode):
    value=bundle();size=len(canonical(value).encode());rows=sum(len(t) for t in tables_for_bundle(value).values())
    limits=ExportLimits(**({'max_input_bytes':size+1} if mode=='bytes' else {'max_total_rows':rows+1}))
    with pytest.raises(ExportFailure) as failure:
        export_bundles([value,value],repository/'data/processed/exports',repository_root=repository,limits=limits)
    state=manifest(failure.value.directory)
    assert state['completed_inputs']==1 and state['failure_input_index']==1 and state['status']=='failed'
    assert canonical(restore_bundle(read_tables(failure.value.directory)))==canonical(value)


def test_interruption_preserves_manifest_and_does_not_claim_completion(repository,monkeypatch):
    from malpdf.extraction import exporters
    def interrupt(*a,**k): raise KeyboardInterrupt()
    monkeypatch.setattr(pq,'write_table',interrupt)
    with pytest.raises(KeyboardInterrupt):
        export_bundles([bundle()],repository/'data/processed/exports',repository_root=repository)
    directory=next((repository/'data/processed/exports').iterdir());state=manifest(directory)
    assert state['status']=='interrupted' and state['completed_inputs']==0
    assert any(f['status']=='complete' for f in state['files']) and any(f['status']=='incomplete' for f in state['files'])


def test_pdf_extension_and_symlink_inputs_are_not_admitted(repository,monkeypatch):
    from malpdf.extraction import exporters
    with monkeypatch.context() as guard:
        guard.setattr(exporters,'read_bounded_bytes',lambda *a,**k:pytest.fail('PDF extension must be refused before read'))
        with pytest.raises(ExportFailure): export_bundle_files([repository/'never.pdf'],repository/'data/processed/exports',repository_root=repository)
    target=repository/'good.json';target.write_text(canonical(bundle()));link=repository/'link.json';link.symlink_to(target)
    with pytest.raises(ExportFailure): export_bundle_files([link],repository/'data/processed/exports',repository_root=repository)


def test_cli_exports_local_bundles_and_returns_failure_directory(repository,monkeypatch,capsys):
    from malpdf import cli
    monkeypatch.setattr(cli,'__file__',str(repository/'src/malpdf/cli.py'))
    path=repository/'bundle.json';path.write_text(canonical(bundle()))
    assert cli.main(['export',str(path),'--output-root',str(repository/'data/processed/exports')])==0
    result=json.loads(capsys.readouterr().out);assert result['pdf_bytes_read'] is False
    assert manifest(Path(result['output_directory']))['completed_inputs']==1
    path.write_text('{}')
    assert cli.main(['export',str(path),'--output-root',str(repository/'data/processed/exports')])==2
    result=json.loads(capsys.readouterr().out);assert manifest(Path(result['output_directory']))['status']=='failed'
