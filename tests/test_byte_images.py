"""Exact byte/pixel/provenance tests using generated benign data only."""

from copy import deepcopy
from dataclasses import replace
from io import BytesIO
import hashlib
import json
from pathlib import Path
import subprocess

import numpy as np
import pikepdf
from PIL import Image
import pytest
from pypdf import PdfWriter
from pypdf.generic import DecodedStreamObject,DictionaryObject,NameObject,TextStringObject

from malpdf.extraction.byte_images import ByteImages,ByteImageLimits,encode_tile,pixel_offset
from malpdf.extraction.contracts import validate_bundle
from malpdf.extraction.normalize import normalize_profile
from malpdf.extraction.orchestrator import extract_pdf,private_artifact_directory
from malpdf.extraction.raw import inspect_raw_layout
from malpdf.extraction.raw_forensic import inspect_raw_forensic
from malpdf.static.code_inspector import CodeInspectionLimits
from malpdf.static.evidence_ipc import WorkerRawSink,ParentRawStore
from malpdf.static.markov import byte_transition_matrix


def sha(data): return hashlib.sha256(data).hexdigest()


class Blobs:
    def __init__(self): self.blobs={}
    def __call__(self,data):
        digest=sha(data);self.blobs[digest]=data
        return {'sha256':digest,'size_bytes':len(data),'status':'retained','reason_code':None}


def pixels(png):
    # Independent decoder from the already declared torchvision/Pillow stack;
    # only our generated bounded PNG fixtures are opened, never input images.
    with Image.open(BytesIO(png)) as image:
        image.load();assert image.mode=='L'
        return image.size,image.tobytes()


def pure(data,*,limits=None,profile=None,store=None):
    store=store or Blobs();worker=ByteImages(sha(data),CodeInspectionLimits(),retain=store,limits=limits)
    return worker.finish(data,profile or {}),store


@pytest.mark.parametrize('length',[1,2,255,256,257,65535,65536])
def test_png_pixels_are_exact_bytes_and_padding_has_an_explicit_mask(length):
    data=(bytes(range(256))*256)[:length]
    png,tile=encode_tile(data)
    size,value=pixels(png)
    assert size==(256,(length+255)//256)
    assert value[:length]==data and value[length:]==b'\0'*tile['padding_pixels']
    assert tile['valid_pixels']==length and sha(value)==tile['pixels_sha256']
    assert sha(value[:length])==tile['valid_bytes_sha256']
    tile['source_byte_start']=123
    assert pixel_offset(tile,(length-1)%256,(length-1)//256)==123+length-1
    if tile['padding_pixels']:
        assert pixel_offset(tile,length%256,length//256) is None


@pytest.mark.parametrize(('data','width','rows'),[
    (b'',256,256),(bytearray(b'x'),256,256),(b'x',0,256),(b'x',True,256),
    (b'x',1025,1),(b'x',256,257),(b'xx',1,1),(b'x',1,0),
])
def test_invalid_raster_requests_do_not_create_an_image(data,width,rows):
    with pytest.raises(ValueError): encode_tile(data,width=width,rows=rows)


@pytest.mark.parametrize(('x','y'),[(-1,0),(256,0),(0,-1),(True,0),(0,2)])
def test_pixel_locator_validates_coordinates(x,y):
    with pytest.raises(ValueError): pixel_offset({'width':256,'height':2,'valid_pixels':257,'source_byte_start':5},x,y)


def test_all_chunks_roundtrip_without_resizing_and_exact_limit_is_not_a_failure():
    data=bytes(range(256))*300
    result,store=pure(data,limits=replace(ByteImageLimits(),max_sources=1,max_tiles=2))
    assert result['complete'] and result['attempted_tiles']==2 and not result['reason_codes']
    assembled=b''
    for tile in sorted(result['tiles'],key=lambda tile:tile['tile_index']):
        _,value=pixels(store.blobs[tile['artifact']['sha256']])
        assembled+=value[:tile['valid_pixels']]
        assert pixel_offset(tile,0,0)==tile['source_byte_start']
    assert assembled==data and result['sources'][0]['retained_source_bytes']==len(data)


def test_budget_keeps_whole_head_tail_tiles_and_marks_missing_middle():
    data=bytes(range(256))*1280  # Five complete 64KiB chunks.
    result,_=pure(data,limits=replace(ByteImageLimits(),max_tiles=3))
    assert [tile['tile_index'] for tile in result['tiles']]==[0,4,1]
    assert not result['complete'] and 'byte_image_tile_limit' in result['reason_codes']
    assert result['sources'][0]['retained_source_bytes']==3*65536


def test_round_robin_keeps_root_and_object_views_in_separate_coverage_scopes():
    data=bytes(range(256))*600
    profile={'raw_forensic':{'document_sha256':sha(data),'objects':[{
        'id':'object-one','source_space':'original','top_level_confirmed':True,'byte_start':100,
        'byte_end':len(data)-100,'object_number':1,'generation':7}]}}
    result,_=pure(data,limits=replace(ByteImageLimits(),max_tiles=3),profile=profile)
    assert [tile['source_id'] for tile in result['tiles']][:2]==[s['id'] for s in result['sources']]
    root,obj=result['sources']
    assert root['source_byte_start']==0 and obj['source_byte_start']==100
    assert obj['object_number']==1 and obj['generation']==7
    assert sum(s['encoded_source_bytes'] for s in result['sources'])>root['encoded_source_bytes']


@pytest.mark.parametrize('override',[{'max_tiles':0},{'max_png_bytes':True},{'width':512,'rows_per_tile':256},
                                     {'max_cached_bytes':11*1024**2},{'max_metadata_bytes':1}])
def test_resource_limit_configuration_is_fail_closed(override):
    with pytest.raises(ValueError): ByteImageLimits(**override)


def test_empty_bytes_are_an_observed_empty_source_not_a_zero_pixel():
    result,store=pure(b'')
    assert result['complete'] and result['sources'][0]['mapping_complete']
    assert result['sources'][0]['source_size_bytes']==0 and result['tiles']==[] and not store.blobs


def test_pixels_and_blob_limits_are_distinct_and_do_not_turn_missing_data_into_zero():
    for limits,code in ((replace(ByteImageLimits(),max_mapped_pixels=1),'byte_image_pixel_limit'),
                        (replace(ByteImageLimits(),max_png_bytes=1),'byte_image_png_limit')):
        result,_=pure(b'abc',limits=limits)
        assert not result['complete'] and code in result['reason_codes']
        tile=result['tiles'][0]
        assert tile['status']=='resource_limit' and result['sources'][0]['retained_source_bytes']==0
        if code=='byte_image_pixel_limit': assert tile['pixels_sha256'] is None


def test_shared_raw_transport_quota_is_not_reset_for_generated_pngs():
    class Connection:
        def __init__(self): self.messages=[]
        def send_bytes(self,data): self.messages.append(json.loads(data))
    connection=Connection();sink=WorkerRawSink(connection,max_bytes=16)
    state=sink(b'inert raw');worker=ByteImages(sha(b'abc'),CodeInspectionLimits(),retain=sink)
    worker.capture(b'inert raw',state)
    result=worker.finish(b'abc',{})
    parent=ParentRawStore(None,max_bytes=16)
    for message in connection.messages: parent.accept(message)
    assert parent.used==len(b'inert raw')==sink.used
    assert result['tiles'][0]['artifact']['status']=='unavailable'
    assert 'raw_storage_limit' in result['reason_codes']


def test_blob_reuse_preserves_distinct_ranges_and_counts_unique_retained_bytes():
    data=b'\x11'*131072
    result,store=pure(data)
    assert len(result['tiles'])==2 and result['tiles'][1]['blob_reused']
    assert len(store.blobs)==1
    assert result['tiles'][0]['source_byte_start']!=result['tiles'][1]['source_byte_start']
    assert result['unique_retained_png_bytes']==sum(len(blob) for blob in store.blobs.values())


def test_missing_cached_decoded_source_stays_unavailable():
    profile={'stream_analysis':{'document_sha256':sha(b'abc'),'records':[{
        'id':'stream-one','backend':'pypdf','decode':{'complete':True,'decoded_sha256':'b'*64}}]}}
    result,_=pure(b'abc',profile=profile)
    source=next(s for s in result['sources'] if s['source_ref']=='stream-one')
    assert source['source_size_bytes'] is None and not source['mapping_complete']
    assert 'byte_image_source_unavailable' in result['reason_codes']


def test_cache_and_metadata_caps_do_not_resume_after_finish():
    data=b'abc';worker=ByteImages(sha(data),CodeInspectionLimits(),limits=replace(ByteImageLimits(),max_cached_bytes=1),retain=Blobs())
    worker.capture(b'xy',{'sha256':sha(b'xy'),'size_bytes':2,'status':'retained'})
    first=deepcopy(worker.finish(data,{}));assert first['source_capture_failures']==1
    assert worker.finish(data,{})==first
    tiny,_=pure(bytes(range(256))*100,limits=replace(ByteImageLimits(),width=16,rows_per_tile=16,max_metadata_bytes=4096))
    assert not tiny['complete'] and len(json.dumps(tiny,separators=(',',':')).encode())<=4096


def raw_fixture(body=b'<< /Type /Catalog >>'):
    data=b'%PDF-1.7\n1 7 obj\n'+body+b'\nendobj\n';offset=len(data)
    data+=b'xref\n0 2\n0000000000 65535 f \n0000000009 00007 n \ntrailer\n<< /Size 2 /Root 1 7 R >>\nstartxref\n'+str(offset).encode()+b'\n%%EOF\n'
    return data


def test_original_object_maps_exact_declaration_and_nonzero_generation():
    data=raw_fixture();code=CodeInspectionLimits()
    forensic=inspect_raw_forensic(data,code,remaining=1024**2)
    assert forensic['objects']
    result,store=pure(data,profile={'raw_forensic':forensic})
    source=next(s for s in result['sources'] if s['kind']=='object_bytes')
    tile=next(t for t in result['tiles'] if t['source_id']==source['id'])
    _,value=pixels(store.blobs[tile['artifact']['sha256']])
    assert value[:tile['valid_pixels']]==data[source['source_byte_start']:source['source_byte_end']]
    assert source['generation']==7 and tile['original_file_byte_start']==9


def test_unfinished_object_only_maps_verified_value_prefix():
    data=raw_fixture(b'<< /Length 100 >>\nstream\ninert')
    forensic=inspect_raw_forensic(data,CodeInspectionLimits(),remaining=1024**2)
    result,_=pure(data,profile={'raw_forensic':forensic})
    source=next(s for s in result['sources'] if s['kind']=='object_value_prefix')
    assert source['source_span_complete'] is False
    assert data[source['source_byte_start']:source['source_byte_end']].endswith(b'>>')
    assert b'stream' not in data[source['source_byte_start']:source['source_byte_end']]


def pdf_fixture(*,child=None,js=False):
    writer=PdfWriter();writer.add_blank_page(72,72)
    if js:
        writer.root_object[NameObject('/OpenAction')]=DictionaryObject({NameObject('/S'):NameObject('/JavaScript'),
            NameObject('/JS'):TextStringObject('var inert=1;')})
    if child is not None:
        stream=DecodedStreamObject();stream.set_data(child)
        writer.root_object[NameObject('/Private')]=writer._add_object(stream)
    out=BytesIO();writer.write(out);return out.getvalue()


def test_decoded_object_stream_members_use_decoded_coordinates_without_original_offsets():
    source=pdf_fixture()
    with pikepdf.Pdf.open(BytesIO(source)) as doc:
        out=BytesIO();doc.save(out,object_stream_mode=pikepdf.ObjectStreamMode.generate)
    data=out.getvalue();code=CodeInspectionLimits();store=Blobs();worker=ByteImages(sha(data),code,retain=store)
    def retained(body):
        state=store(body);worker.capture(body,state);return state
    forensic=inspect_raw_forensic(data,code,remaining=1024**2,retain=retained)
    raw=dict(store.blobs);before=deepcopy(forensic)
    result=worker.finish(data,{'raw_forensic':forensic})
    members=[s for s in result['sources'] if s['kind']=='decoded_object_bytes']
    assert members and forensic==before
    for member in members:
        tile=next(t for t in result['tiles'] if t['source_id']==member['id'])
        assert tile['original_file_byte_start'] is None and member['generation']==0
        _,value=pixels(store.blobs[tile['artifact']['sha256']])
        expected=raw[member['source_namespace_sha256']][tile['source_byte_start']:tile['source_byte_end']]
        assert value[:tile['valid_pixels']]==expected


def test_pure_mapping_calls_no_pdf_parser_and_preserves_markov_probabilities(monkeypatch):
    import pypdf,pymupdf
    data=bytes(range(256))*20;original=byte_transition_matrix(data)
    def forbidden(*args,**kwargs): pytest.fail('Byte mapping must not parse/render PDF content')
    with monkeypatch.context() as patch:
        patch.setattr(pypdf,'PdfReader',forbidden);patch.setattr(pikepdf.Pdf,'open',forbidden);patch.setattr(pymupdf,'open',forbidden)
        result,_=pure(data)
    assert result['additional_pdf_decodes']==0 and not result['pdf_rendered']
    after=byte_transition_matrix(data)
    assert after.dtype==np.float32 and np.array_equal(original,after)


def test_source_document_mismatch_refuses_without_mapping():
    worker=ByteImages(sha(b'abc'),CodeInspectionLimits(),retain=Blobs())
    with pytest.raises(ValueError,match='document_mismatch'): worker.finish(b'wrong',{})
    worker=ByteImages(sha(b'abc'),CodeInspectionLimits(),retain=Blobs())
    with pytest.raises(ValueError,match='profile_mismatch'): worker.finish(b'abc',{'raw_forensic':{'document_sha256':'a'*64}})


def test_parent_persisted_tiles_are_independently_decodable_and_traceable(tmp_path):
    from malpdf.static.profile_worker import profile_pdf
    data=pdf_fixture(child=b'inert bytes\x00\xff',js=True);path=tmp_path/'benign.pdf';path.write_bytes(data)
    directory=tmp_path/'blobs'
    # Both sides need v9's JS source enrichment. This parity fixture allows
    # bounded startup/scheduling slack; it does not measure the offline job's
    # production deadline (20s). CPU and memory caps stay identical.
    limits=CodeInspectionLimits(wall_seconds=30,cpu_seconds=12)
    baseline=profile_pdf(path,boundary=tmp_path,digest=sha(data),limits=limits,analysis_version='v9')
    assert baseline['analysis_v8']['complete'], baseline.get('errors')
    bundle=extract_pdf(path,boundary=tmp_path,raw_artifact_dir=directory,limits=limits)
    validate_bundle(bundle)
    primary=next(r for r in bundle['evidence_store']['records'] if r['evidence_id']=='primary:'+sha(data))
    assert primary['details']['features']==baseline['static']['features']
    assert primary['details']['source_profile']['code']==baseline['code']
    assert primary['details']['source_profile']['analysis_v8']==baseline['analysis_v8']
    sources={r['evidence_id']:r['details'] for r in bundle['evidence_store']['records'] if r['kind']=='byte_image_source'}
    tiles=[r for r in bundle['evidence_store']['records'] if r['kind']=='byte_image_tile']
    assert tiles
    for record in tiles:
        tile=record['details'];artifact=tile['artifact']
        assert tile['image_availability']=='persisted' and artifact['parent_verification_status']=='verified'
        png=(directory/artifact['blob_name']).read_bytes()
        assert sha(png)==artifact['sha256']
        _,value=pixels(png);assert sha(value)==tile['pixels_sha256']
        if tile['source_space']=='original_bytes':
            assert value[:tile['valid_pixels']]==data[tile['source_byte_start']:tile['source_byte_end']]
        assert record['object_number']==sources[tile['source_id']]['object_number']
    assert bundle['coverage_report']['provenance']['raw_artifact_directory']==str(directory)
    assert all(v is False for v in bundle['safety'].values())
    assert bundle['coverage_report']['worker']['worker_cleanup_complete'] and path.read_bytes()==data
    (tmp_path/'byte_images_bundle.json').write_text(json.dumps(bundle,allow_nan=False))


def test_metadata_only_library_call_does_not_claim_png_files_are_persisted(tmp_path):
    data=pdf_fixture();path=tmp_path/'benign.pdf';path.write_bytes(data)
    result=extract_pdf(path,boundary=tmp_path)
    tiles=[r['details'] for r in result['evidence_store']['records'] if r['kind']=='byte_image_tile']
    assert tiles and all(tile['image_availability']=='verified_not_persisted' for tile in tiles)
    assert next(f for f in result['feature_store']['records'] if f['feature_name']=='byte_image_file_persisted_ratio')['value']==0


def test_private_cli_storage_admission_is_fresh_ignored_and_inside_repository(tmp_path):
    subprocess.run(['git','init','-q',str(tmp_path)],check=True,capture_output=True)
    (tmp_path/'.gitignore').write_text('artifacts/**\ndata/processed/**\n')
    allowed=tmp_path/'data/processed/byte_images/new'
    assert private_artifact_directory(tmp_path,allowed)==allowed
    for path in (tmp_path/'reports/new',tmp_path.parent/'outside'):
        with pytest.raises(ValueError): private_artifact_directory(tmp_path,path)
    allowed.mkdir(parents=True)
    with pytest.raises(ValueError): private_artifact_directory(tmp_path,allowed)


def test_cli_exposes_explicit_blob_retention_option():
    from malpdf.cli import build_parser
    args=build_parser().parse_args(['extract','benign.pdf','--raw-artifact-dir','data/processed/byte_images/new'])
    assert args.raw_artifact_dir==Path('data/processed/byte_images/new')


def test_cli_refuses_incompatible_retention_before_pdf_access(monkeypatch,capsys):
    from malpdf.cli import main
    from malpdf.extraction import orchestrator
    monkeypatch.setattr(orchestrator,'extract_pdf',lambda *a,**k:pytest.fail('No PDF access before option admission'))
    assert main(['extract','unused.pdf','--profile','fast-static','--raw-artifact-dir','data/processed/new'])==2
    assert 'deep-static' in capsys.readouterr().out


def test_recovered_stream_pixels_keep_repaired_provenance_and_unknown_original_offset():
    from malpdf.extraction.byte_image_exports import append_byte_images
    from malpdf.extraction.normalize import _record
    data=b'inert root';decoded=b'inert decoded';store=Blobs();worker=ByteImages(sha(data),CodeInspectionLimits(),retain=store)
    worker.capture(decoded,store(decoded))
    profile={'stream_analysis':{'document_sha256':sha(data),'records':[{
        'id':'stream-one','backend':'MuPDF','object_number':8,'generation':None,
        'decode':{'complete':True,'decoded_sha256':sha(decoded)}}]}}
    analysis=worker.finish(data,profile)
    records=[_record('original:'+sha(data),'document','original'),_record('stream-one','stream','MuPDF',is_synthetic_repaired=True)]
    edges=[];features=[]
    append_byte_images({'byte_images':analysis},sha(data),records,features,edges)
    source=next(r for r in records if r['kind']=='byte_image_source' and r['details']['source_ref']=='stream-one')
    tiles=[r for r in records if r['kind']=='byte_image_tile' and r['details']['source_id']==source['evidence_id']]
    assert tiles and source['is_synthetic_repaired']
    assert all(t['is_synthetic_repaired'] and t['byte_offset_start'] is None and t['generation'] is None for t in tiles)


def _image_checkpoint_then_stall(connection,path,boundary,digest,limits,*args):
    import os,time
    os.setsid();data=pdf_fixture()
    images,_=pure(data)
    assert sha(data)==digest
    connection.send_bytes(json.dumps({'event':'checkpoint','profile':{'status':'complete','errors':[],
        'static':{'input':{'sha256':digest},'features':{'canary':7}},'code':None,
        'raw_layout':inspect_raw_layout(data),'byte_images':images}}).encode())
    time.sleep(30)


def test_worker_timeout_keeps_completed_byte_tiles_and_primary(tmp_path,monkeypatch):
    import multiprocessing
    from malpdf.static import profile_worker
    context=multiprocessing.get_context('fork')
    monkeypatch.setattr(profile_worker.multiprocessing,'get_context',lambda *args:context)
    monkeypatch.setattr(profile_worker,'_profile_child',_image_checkpoint_then_stall)
    monkeypatch.setattr(profile_worker,'_worker_count',lambda *args:1)
    data=pdf_fixture();result=profile_worker.profile_pdf(tmp_path/'unused.pdf',boundary=tmp_path,digest=sha(data),
        analysis_version='v9',extraction_profile='deep-static',limits=CodeInspectionLimits(wall_seconds=2,cpu_seconds=1))
    assert result['byte_images']['tiles'] and result['byte_images']['complete'] is False
    assert result['static']['features']=={'canary':7} and result['worker_cleanup_complete']
    validate_bundle(normalize_profile(result,sha(data),'deep-static'))
