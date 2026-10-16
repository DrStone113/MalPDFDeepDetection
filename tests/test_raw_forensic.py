"""Independent original-byte grammar/history using generated benign fixtures."""

from copy import deepcopy
from dataclasses import replace
import hashlib
import io
import json
import re
import os
import zlib

import pikepdf
import pytest
from pypdf import PdfWriter

from malpdf.extraction.contracts import validate_bundle
from malpdf.extraction.normalize import normalize_profile
from malpdf.extraction.orchestrator import extract_pdf
from malpdf.extraction.parser_views import inspect_parser_views
from malpdf.extraction.raw import inspect_raw_layout
from malpdf.extraction.raw_forensic import ForensicLimits, inspect_raw_forensic
from malpdf.extraction.raw_syntax import Lexer, SyntaxBudget, SyntaxIssue, parse_value
from malpdf.static.code_inspector import CodeInspectionLimits


def sha(data):
    return hashlib.sha256(data).hexdigest()


def syntax(data, **overrides):
    values=dict(max_tokens=1024,max_nodes=1024,max_depth=64,max_string_bytes=1024)
    values.update(overrides)
    lexer=Lexer(data,SyntaxBudget(**values))
    return parse_value(lexer)


def fixture(objects=None, *, overrides=None, trailer=b'', root=b'/Root 1 0 R'):
    objects=objects or [(1,0,b'<< /Type /Catalog /Pages 2 0 R >>'),(2,0,b'<< /Type /Pages /Count 0 /Kids [] >>')]
    data=b'%PDF-1.7\n'
    offsets,entries={},{}
    for number,generation,body in objects:
        offsets[(number,generation)]=len(data)
        entries[number]=(len(data),generation,b'n')
        data+=f'{number} {generation} obj\n'.encode()+body+b'\nendobj\n'
    entries.update(overrides or {})
    size=max(entries)+1
    xref=len(data)
    data+=f'xref\n0 {size}\n'.encode()+b'0000000000 65535 f \n'
    for number in range(1,size):
        offset,generation,kind=entries.get(number,(0,0,b'f'))
        data+=f'{offset:010d} {generation:05d} '.encode()+kind+b' \n'
    data+=b'trailer\n<< /Size '+str(size).encode()+b' '+root+b' '+trailer+b' >>\nstartxref\n'+str(xref).encode()+b'\n%%EOF\n'
    return data,{'xref':xref,'offsets':offsets,'size':size}


def update(data, old, objects=(), *, overrides=None, root=b'', self_prev=False):
    entries={}
    offsets={}
    for number,generation,body in objects:
        offsets[(number,generation)]=len(data)
        entries[number]=(len(data),generation,b'n')
        data+=f'{number} {generation} obj\n'.encode()+body+b'\nendobj\n'
    entries.update(overrides or {})
    xref=len(data)
    data+=b'xref\n'
    if not entries:
        data+=b'0 1\n0000000000 65535 f \n'
    for number,(offset,generation,kind) in sorted(entries.items()):
        data+=f'{number} 1\n{offset:010d} {generation:05d} '.encode()+kind+b' \n'
    size=max(old['size'],max(entries,default=0)+1)
    data+=b'trailer\n<< /Size '+str(size).encode()+b' /Prev '+str(xref if self_prev else old['xref']).encode()+b' '+root+b' >>\nstartxref\n'+str(xref).encode()+b'\n%%EOF\n'
    return data,{'xref':xref,'offsets':offsets,'size':size}


def inspect(data, *, remaining=1024**2, limits=None, native=None, code=None, **kwargs):
    return inspect_raw_forensic(data,code or CodeInspectionLimits(),remaining=remaining,limits=limits,native_analysis=native,**kwargs)


def bundle(data,result,native=None):
    return normalize_profile({'status':'complete','raw_layout':inspect_raw_layout(data),'raw_forensic':result,
                              'parser_analysis':native},sha(data),'deep-static')


@pytest.mark.parametrize(('body','kind','expected'),[
    (b'/J#53','name',b'/JS'),(b'<61 6>','string',b'a`'),(b'<>','string',b''),(b'()','string',b''),
    (b'(a\\(b\\)\\040c\\\r\nd)','string',b'a(b) cd'),
    (b'(a\r\nb\rc\nd)','string',b'a\nb\nc\nd'),(b'(\\777\\101\\9)','string',b'\xffA9'),
    (b'12 7 R','reference',(12,7)),(b'false','boolean',False),(b'null','null',None),
    (b'-123','number',-123),(b'123456789012345678901234567890','number',123456789012345678901234567890),
])
def test_independent_lexical_values(body,kind,expected):
    node=syntax(body)
    assert (node.kind,node.value)==(kind,expected)
    assert node.start==0 and node.end==len(body)


@pytest.mark.parametrize('body',[b'(unfinished',b'<GG>',b'<< /Key >>',b'[1 2',b'12 -1 R',b'1e3'])
def test_invalid_syntax_stays_an_explicit_failure(body):
    with pytest.raises(SyntaxIssue):
        syntax(body)


@pytest.mark.parametrize(('body','options','code'),[
    (b'[[[]]]',{'max_depth':1},'forensic_object_depth_limit'),
    (b'(abc)',{'max_string_bytes':2},'forensic_string_byte_limit'),
    (b'((()))',{'max_depth':2},'forensic_string_depth_limit'),
    (b'[1 2 3]',{'max_tokens':2},'forensic_token_limit'),
    (b'[1 2 3]',{'max_nodes':2},'forensic_node_limit'),
])
def test_grammar_budgets_are_shared(body,options,code):
    with pytest.raises(SyntaxIssue) as caught:
        syntax(body,**options)
    assert caught.value.code==code and caught.value.status=='resource_limit'


def test_no_native_object_parser_is_called_and_names_content_stay_redacted(monkeypatch):
    import pypdf
    import pypdf.generic
    import pymupdf
    def forbidden(*args,**kwargs):
        raise AssertionError('Raw grammar must not call a native PDF parser')
    monkeypatch.setattr(pikepdf.Pdf,'open',forbidden)
    monkeypatch.setattr(pypdf.PdfReader,'__init__',forbidden)
    monkeypatch.setattr(pypdf.generic,'read_object',forbidden)
    monkeypatch.setattr(pymupdf,'open',forbidden)
    data,meta=fixture([(1,0,b'<< /Type /Catalog /PrivateSecret (inert private canary) /J#53 (var harmless = 1;) >>')])
    result=inspect(data)
    assert result['complete'] and result['selection_context_verified']
    exported=bundle(data,result)
    validate_bundle(exported)
    assert 'inert private canary' not in json.dumps(exported) and 'PrivateSecret' not in json.dumps(exported)
    assert any(node['known_name']=='/JS' for node in result['syntax_nodes'] if node['kind']=='name')
    for node in result['syntax_nodes']:
        assert node['raw_sha256']==sha(data[node['start']:node['end']])


def test_stream_payload_markers_never_become_verified_declarations_or_xrefs():
    payload=b'99 0 obj\n<< /JS (inert) >>\nendobj\nxref\n0 0\nstartxref\n0\n%%EOF\n'
    stream=b'<< /Length '+str(len(payload)).encode()+b' >>\nstream\n'+payload+b'\nendstream'
    data,_=fixture([(1,0,b'<< /Type /Catalog /Private 3 0 R >>'),(3,0,stream)])
    result=inspect(data)
    assert result['complete']
    assert {item['object_number'] for item in result['objects']}=={1,3}
    assert len(result['xref_blocks'])==1 and len([marker for marker in result['markers'] if marker['kind']=='eof'])==1
    observed=next(item for item in result['objects'] if item['stream'])
    assert observed['stream']['raw_sha256']==sha(payload)


def test_xref_target_inside_stream_is_a_candidate_with_unverified_context():
    payload=b'99 0 obj\n<< /Flag 123 >>\nendobj\n'
    objects=[(1,0,b'<< /Type /Catalog >>'),(3,0,b'<< /Length '+str(len(payload)).encode()+b' >>\nstream\n'+payload+b'\nendstream')]
    data,meta=fixture(objects)
    fake=data.index(b'99 0 obj')
    data,_=fixture(objects,overrides={99:(fake,0,b'n')})
    result=inspect(data)
    candidate=next(item for item in result['objects'] if item['object_number']==99)
    assert candidate['status']=='partial' and not candidate['top_level_confirmed'] and candidate['inside_stream_id']
    assert 'forensic_xref_target_not_top_level_confirmed' in result['reason_codes']
    exported=bundle(data,result)
    record=next(item for item in exported['evidence_store']['records'] if item['evidence_id']==candidate['id'])
    assert record['kind']=='forensic_object_candidate'


def test_duplicate_keys_are_preserved_without_selecting_a_winner():
    data,_=fixture([(1,0,b'<< /Type /Catalog /J#53 (inert one) /JS (inert two) >>')])
    result=inspect(data)
    assert not result['complete']
    names=[node for node in result['syntax_nodes'] if node['kind']=='name' and node['known_name']=='/JS']
    assert len(names)==2 and names[0]['id']!=names[1]['id']
    record=result['objects'][0]
    assert not record['projection']['projection_complete']
    assert any(node['reason_codes']==['forensic_duplicate_dictionary_key'] for node in result['syntax_nodes'])
    validate_bundle(bundle(data,result))


def test_incremental_replacement_keeps_old_bytes_offsets_and_inherited_root():
    data,old=fixture([(1,0,b'<< /Type /Catalog /Ref 4 7 R >>'),(4,7,b'<< /Flag 1 >>')])
    final,new=update(data,old,[(4,7,b'<< /Flag 2 >>')])
    result=inspect(final)
    assert result['complete'] and len(result['revisions'])==2
    declarations=[item for item in result['objects'] if item['object_number']==4]
    assert {item['byte_start'] for item in declarations}=={old['offsets'][(4,7)],new['offsets'][(4,7)]}
    assert {item['xref_membership'] for item in declarations}=={'selected_by_examined_latest_xref','listed_in_examined_history'}
    current=next(item for item in declarations if item['xref_membership'].startswith('selected'))
    assert current['generation']==7
    assert result['revisions'][0]['root_source_xref_context_distance']==1
    assert result['linked_revision_ordinals_verified'] and [row['revision_ordinal'] for row in result['revisions']]==[1,0]
    resolved=[item for item in result['references'] if item['target_number']==4]
    assert {item['xref_context_distance'] for item in resolved}=={0,1} and all(item['resolved'] for item in resolved)
    assert len({item['target_id'] for item in resolved})==2
    validate_bundle(bundle(final,result))


def test_free_entry_masks_older_object_and_synthetic_null_does_not_replace_literal_null():
    data,old=fixture([(1,0,b'<< /Type /Catalog /Ref 4 0 R /ActualNull null >>'),(4,0,b'123')])
    final,_=update(data,old,overrides={4:(0,1,b'f')})
    result=inspect(final)
    rows=[row for row in result['references'] if row['target_number']==4]
    assert any(row['xref_context_distance']==0 and not row['resolved'] for row in rows)
    assert any(row['xref_context_distance']==1 and row['resolved'] for row in rows)
    assert result['synthetic_nodes'] and all(node['is_synthetic'] for node in result['synthetic_nodes'])
    assert any(node['kind']=='null' and node['is_synthetic'] is False for node in result['syntax_nodes'])
    assert all(item['object_number']!=4 for item in result['objects'] if item['id'] in result['current_view']['selected_ids'])
    validate_bundle(bundle(final,result))


def test_unlisted_declaration_is_scoped_to_examined_xrefs_not_maliciousness():
    data,_=fixture([(1,0,b'<< /Type /Catalog >>'),(9,0,b'<< /Private (inert) >>')],overrides={9:(0,1,b'f')})
    result=inspect(data)
    orphan=next(item for item in result['objects'] if item['object_number']==9)
    assert orphan['xref_membership']=='unlisted_in_examined_xrefs'
    assert result['complete']


def test_indirect_length_is_verified_in_each_examined_revision():
    payload=b'inert'
    objects=[(1,0,b'<< /Type /Catalog /Private 5 0 R >>'),(4,0,str(len(payload)).encode()),
             (5,0,b'<< /Length 4 0 R >>\nstream\n'+payload+b'\nendstream')]
    data,old=fixture(objects)
    result=inspect(data)
    stream=next(item['stream'] for item in result['objects'] if item['stream'])
    assert stream['boundary_verified'] and stream['length_mode']=='resolved_across_examined_revisions'
    final,_=update(data,old,[(4,0,b'1')])
    result=inspect(final)
    stream=next(item['stream'] for item in result['objects'] if item['stream'])
    assert not result['complete'] and not stream['boundary_verified'] and stream['raw_sha256'] is None
    assert stream['length_mode']=='unresolved_reference'
    validate_bundle(bundle(final,result))


@pytest.mark.parametrize('mode',['missing_length','wrong_length','out_of_bounds','bad_eol'])
def test_unknown_stream_boundary_stops_scan_without_decoding_a_guess(mode):
    length=b'' if mode=='missing_length' else b'/Length 1' if mode=='wrong_length' else b'/Length 999999' if mode=='out_of_bounds' else b'/Length 5'
    eol=b' ' if mode=='bad_eol' else b'\n'
    data,_=fixture([(1,0,b'<< /Type /Catalog >>'),(3,0,b'<< '+length+b' >>\nstream'+eol+b'inert\nendstream'),
                    (4,0,b'<< /Flag 1 >>')])
    result=inspect(data)
    assert not result['complete'] and not result['sequential_scan_complete']
    assert result['reason_codes']
    if mode!='bad_eol':
        stream=next(item['stream'] for item in result['objects'] if item['stream'])
        assert not stream['boundary_verified'] and stream['raw_sha256'] is None
        assert result['structural_streams']==[]


def test_xref_stream_and_object_stream_have_independent_syntax_and_derived_locators():
    writer=PdfWriter();writer.add_blank_page(72,72)
    buffer=io.BytesIO();writer.write(buffer)
    output=io.BytesIO()
    with pikepdf.Pdf.open(io.BytesIO(buffer.getvalue())) as document:
        document.save(output,object_stream_mode=pikepdf.ObjectStreamMode.generate)
    data=output.getvalue()
    native=inspect_parser_views(data,CodeInspectionLimits())
    result=inspect(data,native=native)
    assert result['complete']
    assert result['xref_blocks'][0]['kind']=='stream'
    members=[item for item in result['objects'] if item['source_space']=='decoded_stream']
    assert members and all(item['generation']==0 and item['byte_start'] is None and item['container_id'] for item in members)
    assert result['decoded_bytes_used']>0
    assert result['comparisons'] and all(item['result']=='projection_equal' for item in result['comparisons'])
    exported=bundle(data,result,native)
    validate_bundle(exported)
    for item in exported['evidence_store']['records']:
        if item['details'].get('source_space')=='decoded_stream':
            assert item['byte_offset_start'] is None


@pytest.mark.parametrize('mode',['cycle','bad_offset','duplicate_xref'])
def test_xref_ambiguity_never_falls_back_to_a_favorable_revision(mode):
    data,old=fixture()
    if mode=='cycle':
        data,_=update(data,old,self_prev=True)
    elif mode=='bad_offset':
        data=re.sub(rb'startxref\n\d+\n',b'startxref\n0\n',data)
    else:
        position=data.index(b'trailer')
        # Duplicate a subsection entry with a conflicting offset in one block.
        data=data[:position]+b'1 1\n0000000000 00000 n \n'+data[position:]
    result=inspect(data)
    assert not result['complete'] and result['reason_codes']
    assert result['current_view']['complete'] is False
    validate_bundle(bundle(data,result))


@pytest.mark.parametrize(('limits','reason'),[
    (ForensicLimits(max_objects=1),'forensic_object_limit'),
    (ForensicLimits(max_tokens=3),'forensic_token_limit'),
    (ForensicLimits(max_nodes=1),'forensic_node_limit'),
    (ForensicLimits(max_ir_nodes=1),'forensic_ir_node_limit'),
    (ForensicLimits(max_xref_entries=1),'forensic_xref_entry_limit'),
    (ForensicLimits(max_metadata_bytes=2048),'forensic_metadata_limit'),
])
def test_limit_returns_last_bounded_checkpoint_with_unavailable_remainder(limits,reason):
    data,_=fixture()
    checkpoints=[]
    result=inspect(data,limits=limits,checkpoint=lambda value:checkpoints.append(value))
    assert result['complete'] is False and reason in result['reason_codes']
    assert result.get('counters_are_interrupted_lower_bounds')
    assert checkpoints and checkpoints[-1]==result
    validate_bundle(bundle(data,result))


def test_decode_allowance_is_not_reset_for_structural_streams():
    writer=PdfWriter();writer.add_blank_page(72,72)
    original=io.BytesIO();writer.write(original)
    output=io.BytesIO()
    with pikepdf.Pdf.open(io.BytesIO(original.getvalue())) as document:
        document.save(output,object_stream_mode=pikepdf.ObjectStreamMode.generate)
    result=inspect(output.getvalue(),remaining=8)
    assert result['complete'] is False and result['decoded_bytes_used']<=8
    assert not any(item['source_space']=='decoded_stream' for item in result['objects'])
    assert result['structural_streams']


def test_encrypted_fixture_keeps_bytes_without_decoding_object_payloads():
    writer=PdfWriter();writer.add_blank_page(72,72);writer.encrypt('synthetic fixture key')
    output=io.BytesIO();writer.write(output)
    data=output.getvalue()
    result=inspect(data)
    assert result['encrypted'] and not result['complete'] and 'forensic_encrypted_pdf' in result['reason_codes']
    assert 'synthetic fixture key' not in json.dumps(result)
    validate_bundle(bundle(data,result))


def test_source_identity_remaining_budget_and_export_edges_are_checked():
    data,_=fixture()
    with pytest.raises(ValueError,match='forensic_input_invalid'):
        inspect(bytearray(data))
    with pytest.raises(ValueError,match='forensic_remaining_budget_invalid'):
        inspect(data,remaining=8*1024**2)
    with pytest.raises(ValueError,match='forensic_native_document_mismatch'):
        inspect(data,native={'document_sha256':'a'*64})
    result=inspect(data)
    with pytest.raises(ValueError,match='forensic_export_document_mismatch'):
        bundle(data,{**result,'document_sha256':'f'*64})
    broken=deepcopy(result)
    broken['edges'][0]['target']='unverified-missing-evidence'
    with pytest.raises(ValueError,match='forensic_export_reference_missing'):
        bundle(data,broken)


@pytest.mark.parametrize('mode',['unfinished_value','bad_stream_eol','missing_endobj'])
def test_partial_declaration_keeps_header_and_completed_value_prefix(mode):
    body=b'<< /Type /Catalog >>'
    if mode=='unfinished_value':
        body=b'<< /Type /Catalog /Private (unfinished'
    elif mode=='bad_stream_eol':
        body=b'<< /Type /Catalog /Length 5 >>\nstream inert\nendstream'
    data,_=fixture([(1,0,body)])
    if mode=='missing_endobj':
        data=data.replace(b'\nendobj\n',b'\n',1)
    result=inspect(data)
    assert not result['complete']
    exported=bundle(data,result)
    headers=[row for row in exported['evidence_store']['records'] if row['kind'] in {'forensic_partial_declaration','forensic_object_declaration'}]
    assert headers and headers[0]['object_number']==1 and headers[0]['byte_offset_start']==data.index(b'1 0 obj')
    if mode!='unfinished_value':
        assert any(row['kind']=='forensic_syntax_dictionary' for row in exported['evidence_store']['records'])


def test_regular_truncations_keep_a_valid_partial_bundle_with_no_native_fallback():
    data,_=fixture([(1,0,b'<< /Type /Catalog /Private (inert fixture) /Array [1 2 3] >>')])
    for end in range(5,len(data),7):
        truncated=data[:end]
        result=inspect(truncated)
        if result['complete']:
            assert truncated.rstrip()==data.rstrip()  # Only final whitespace was removed.
        validate_bundle(bundle(truncated,result))


def test_unindexed_compressed_member_is_not_labeled_as_historical_membership():
    member=b'9 0 123'
    data,_=fixture([(1,0,b'<< /Type /Catalog /Private 5 0 R >>'),
        (5,0,b'<< /Type /ObjStm /N 1 /First 4 /Length '+str(len(member)).encode()+b' >>\nstream\n'+member+b'\nendstream')])
    result=inspect(data)
    child=next(item for item in result['objects'] if item['source_space']=='decoded_stream')
    assert child['object_number']==9 and child['xref_membership']=='unlisted_in_examined_xrefs'
    assert child['byte_start'] is None and child['decoded_start']==4


def binary_xref_fixture(*, zero_width=False, invalid_width=False, flate=False):
    base=b'%PDF-1.7\n'
    offsets={}
    for number,body in [(1,b'<< /Type /Catalog /Pages 2 0 R >>'),(2,b'<< /Type /Pages /Kids [] /Count 0 >>')]:
        offsets[number]=len(base)
        base+=str(number).encode()+b' 0 obj\n'+body+b'\nendobj\n'
    offsets[6]=len(base)
    widths=[0,4,0] if zero_width else [1,4,2]
    selected=[1,2,6] if zero_width else list(range(7))
    raw=b''
    for number in selected:
        fields=(1 if number in offsets else 0,offsets.get(number,0),65535 if number==0 else 0)
        raw+=b''.join(value.to_bytes(width,'big') for value,width in zip(fields,widths) if width)
    index=b' /Index [1 2 6 1]' if zero_width else b''
    width_text=b'[0 0 0]' if invalid_width else ('['+' '.join(map(str,widths))+']').encode()
    if flate:
        raw=zlib.compress(raw)
    filter_name=b' /Filter /FlateDecode' if flate else b''
    base+=b'6 0 obj\n<< /Type /XRef /Size 7 /Root 1 0 R /W '+width_text+index+filter_name+b' /Length '+str(len(raw)).encode()+b' >>\nstream\n'+raw+b'\nendstream\nendobj\n'
    base+=b'startxref\n'+str(offsets[6]).encode()+b'\n%%EOF\n'
    return base


@pytest.mark.parametrize('zero_width',[False,True])
def test_binary_xref_field_defaults_and_noncontiguous_index(zero_width):
    data=binary_xref_fixture(zero_width=zero_width)
    result=inspect(data)
    assert result['complete'] and result['xref_blocks'][0]['kind']=='stream'
    assert {item['object_number'] for item in result['objects']}=={1,2,6}
    assert all(item['generation']==0 for item in result['objects'])
    assert result['decoded_bytes_used']>0
    validate_bundle(bundle(data,result))


def test_invalid_xref_widths_do_not_decode_an_empty_table_as_success():
    data=binary_xref_fixture(invalid_width=True)
    result=inspect(data)
    assert not result['complete'] and 'forensic_xref_width_invalid' in result['reason_codes']
    validate_bundle(bundle(data,result))


def test_structural_filter_time_is_recorded_and_unknown_prev_does_not_resolve_length():
    from malpdf.static.profiling import StageTimings
    timing=StageTimings()
    result=inspect(binary_xref_fixture(),timings=timing)
    assert result['complete'] and timing.seconds['stream_decode']>0 and timing.seconds['js_ast'] is None
    data,old=fixture([(1,0,b'<< /Type /Catalog /Private 5 0 R >>'),(4,0,b'5'),
        (5,0,b'<< /Length 4 0 R >>\nstream\ninert\nendstream')])
    final,_=update(data,old,self_prev=True)
    result=inspect(final)
    assert not result['complete']
    stream=next(item['stream'] for item in result['objects'] if item['stream'])
    assert stream['length_mode']=='unresolved_reference' and not stream['boundary_verified']


def test_null_name_byte_remains_invalid_without_changing_original_token():
    node=syntax(b'/J#00S')
    assert node.value==b'/J\x00S' and node.issues==('forensic_null_name_byte',)


def test_hybrid_supplement_priority_keeps_both_physical_object_versions():
    data=b'%PDF-1.7\n'
    offsets={}
    versions=[]
    for number,generation,body in [(1,0,b'<< /Type /Catalog /Ref 4 7 R >>'),(4,7,b'<< /Flag 1 >>'),(4,7,b'<< /Flag 2 >>')]:
        offsets[number]=len(data)
        if number==4:
            versions.append(len(data))
        data+=f'{number} {generation} obj\n'.encode()+body+b'\nendobj\n'
    supplement=len(data)
    payload=b'\x01'+versions[-1].to_bytes(4,'big')+(7).to_bytes(2,'big')
    data+=b'6 0 obj\n<< /Type /XRef /Size 7 /Index [4 1] /W [1 4 2] /Length 7 >>\nstream\n'+payload+b'\nendstream\nendobj\n'
    table=len(data)
    data+=b'xref\n0 2\n0000000000 65535 f \n'+f'{offsets[1]:010d} 00000 n \n'.encode()
    data+=b'4 1\n'+f'{versions[0]:010d} 00007 n \n'.encode()+b'6 1\n'+f'{supplement:010d} 00000 n \n'.encode()
    data+=b'trailer\n<< /Size 7 /Root 1 0 R /XRefStm '+str(supplement).encode()+b' >>\nstartxref\n'+str(table).encode()+b'\n%%EOF\n'
    result=inspect(data)
    assert result['complete'] and len(result['xref_blocks'])==2
    assert result['revisions'][0]['supplement_id']
    selected=next(item for item in result['objects'] if item['object_number']==4 and item['id'] in result['current_view']['selected_ids'])
    assert selected['byte_start']==versions[-1] and selected['generation']==7
    assert any(item['byte_start']==versions[0] and item['xref_membership']=='listed_in_examined_history' for item in result['objects'])
    validate_bundle(bundle(data,result))


def test_linearized_sections_are_not_automatically_counted_as_historical_revisions():
    writer=PdfWriter();writer.add_blank_page(72,72)
    original=io.BytesIO();writer.write(original)
    output=io.BytesIO()
    with pikepdf.Pdf.open(io.BytesIO(original.getvalue())) as document:
        document.save(output,linearize=True)
    data=output.getvalue()
    result=inspect(data)
    assert result['complete'] and len(result['revisions'])==2
    assert result['linked_revision_ordinals_verified'] is False
    assert all(context['revision_ordinal'] is None for context in result['revisions'])
    exported=bundle(data,result)
    assert all(item['revision'] is None for item in exported['evidence_store']['records'] if item['kind']=='forensic_revision_context')


def test_startxref_without_its_eof_cannot_prove_a_revision_ordinal():
    data,old=fixture()
    data=data.replace(b'%%EOF',b'% incomplete old footer',1)
    final,_=update(data,old)
    result=inspect(final)
    assert len(result['revisions'])==2 and not result['linked_revision_ordinals_verified']
    assert all(context['revision_ordinal'] is None for context in result['revisions'])


def test_old_xref_pointing_beyond_its_footer_does_not_prove_historical_identity():
    data,old=fixture([(1,0,b'<< /Type /Catalog /Ref 4 0 R >>'),(4,0,b'1')])
    final,new=update(data,old,[(4,0,b'2')])
    old_entry=f'{old["offsets"][(4,0)]:010d} 00000 n'.encode()
    future_entry=f'{new["offsets"][(4,0)]:010d} 00000 n'.encode()
    final=final.replace(old_entry,future_entry,1)
    result=inspect(final)
    assert result['complete'] and not result['linked_revision_ordinals_verified']
    assert all(context['revision_ordinal'] is None for context in result['revisions'])


def test_compressed_members_share_declaration_quota_with_partial_headers():
    payload=b'9 0 123'
    data,_=fixture([(1,0,b'<< /Type /Catalog /Private 5 0 R >>'),
        (5,0,b'<< /Type /ObjStm /N 1 /First 4 /Length 7 >>\nstream\n'+payload+b'\nendstream'),
        (3,0,b'<< /Length 5 >>\nstream inert\nendstream')])
    result=inspect(data,limits=ForensicLimits(max_objects=3))
    assert 'forensic_object_limit' in result['reason_codes'] and not result['complete']
    assert len(result['objects'])+len(result['partial_declarations'])<=3
    assert result['partial_declarations'] and not any(item['source_space']=='decoded_stream' for item in result['objects'])
    validate_bundle(bundle(data,result))


def _checkpoint_then_stall(connection,path,boundary,digest,limits,*args):
    import time
    os.setsid()
    data,_=fixture()
    assert sha(data)==digest
    result=inspect_raw_forensic(data,limits,remaining=1000)
    connection.send_bytes(json.dumps({'event':'checkpoint','profile':{'status':'complete','errors':[],
        'static':{'input':{'sha256':digest},'features':{'JS':1}},'code':None,
        'raw_layout':inspect_raw_layout(data),'raw_forensic':result}}).encode())
    time.sleep(30)


def test_worker_deadline_keeps_raw_syntax_and_primary_checkpoint(tmp_path,monkeypatch):
    import multiprocessing
    from malpdf.static import profile_worker
    context=multiprocessing.get_context('fork')
    monkeypatch.setattr(profile_worker.multiprocessing,'get_context',lambda *args:context)
    monkeypatch.setattr(profile_worker,'_profile_child',_checkpoint_then_stall)
    monkeypatch.setattr(profile_worker,'_worker_count',lambda *args:1)
    data,_=fixture()
    result=profile_worker.profile_pdf(tmp_path/'unused.pdf',boundary=tmp_path,digest=sha(data),analysis_version='v9',
        extraction_profile='deep-static',limits=CodeInspectionLimits(wall_seconds=1,cpu_seconds=1))
    assert result['status']=='timeout' and result['worker_cleanup_complete']
    assert result['raw_forensic']['worker_failure_codes']==['wall_timeout']
    normalized=normalize_profile(result,sha(data),'deep-static')
    assert normalized['status']=='timeout'
    assert any(item['kind']=='forensic_object_declaration' for item in normalized['evidence_store']['records'])


def test_isolated_raw_pass_keeps_primary_native_views_and_parent_verified_bytes(tmp_path):
    from malpdf.static.profile_worker import profile_pdf
    writer=PdfWriter();writer.add_blank_page(72,72)
    output=io.BytesIO();writer.write(output);data=output.getvalue()
    path=tmp_path/'synthetic.pdf';path.write_bytes(data)
    limits=CodeInspectionLimits(wall_seconds=20,cpu_seconds=12)
    baseline=profile_pdf(path,boundary=tmp_path,digest=sha(data),limits=limits,analysis_version='v9')
    extracted=extract_pdf(path,boundary=tmp_path,limits=limits,raw_artifact_dir=tmp_path/'blobs')
    primary=next(item for item in extracted['evidence_store']['records'] if item['evidence_id']=='primary:'+sha(data))
    assert primary['details']['features']==baseline['static']['features']
    assert primary['details']['source_profile']['code']==baseline['code']
    assert primary['details']['source_profile']['analysis_v8']==baseline['analysis_v8']
    assert any(item['kind']=='forensic_xref' for item in extracted['evidence_store']['records'])
    assert {item['backend'] for item in extracted['evidence_store']['records'] if item['kind']=='parser_view'}=={'pypdf','QPDF','MuPDF'}
    assert path.read_bytes()==data and all(value is False for value in extracted['safety'].values())
    assert extracted['coverage_report']['worker']['worker_cleanup_complete']


def test_parent_verifies_and_persists_raw_structural_decode_blobs(tmp_path):
    data=binary_xref_fixture(flate=True)
    path=tmp_path/'synthetic_binary_xref.pdf'
    path.write_bytes(data)
    retained=tmp_path/'blobs'
    result=extract_pdf(path,boundary=tmp_path,raw_artifact_dir=retained,
                       limits=CodeInspectionLimits(wall_seconds=20,cpu_seconds=12))
    decodes=[item for item in result['evidence_store']['records'] if item['kind']=='forensic_structural_decode']
    assert decodes
    for observation in decodes:
        decode=observation['details']['decode']
        assert decode['complete']
        raw=decode['raw_retention']
        assert raw['parent_verification_status']=='verified'
        assert sha((retained/(raw['sha256']+'.bin')).read_bytes())==raw['sha256']
        final=decode['decoded_sha256']
        assert sha((retained/(final+'.bin')).read_bytes())==final
        assert decode['steps'] and all(step['retention']['parent_verification_status']=='verified' for step in decode['steps'])
    assert path.read_bytes()==data and all(value is False for value in result['safety'].values())
