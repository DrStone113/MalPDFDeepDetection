"""Generated inert XFA/JavaScript syntax fixtures; no real PDFs or execution."""

from dataclasses import replace
import io
import json
import zlib

import pytest
from pypdf import PdfWriter
from pypdf.generic import ArrayObject, DecodedStreamObject, DictionaryObject, EncodedStreamObject, IndirectObject, NameObject, TextStringObject

from malpdf.static.code_inspector import CodeInspectionLimits, _inspect_code_bytes, inspect_pdf_code


def xfa_pdf(xml, *, packets=False, compressed=False, action=None):
    writer = PdfWriter(); writer.add_blank_page(72, 72)
    def stream(data):
        value = EncodedStreamObject() if compressed else DecodedStreamObject()
        value._data = zlib.compress(data) if compressed else data
        if compressed:
            value[NameObject('/Filter')] = NameObject('/FlateDecode')
        return writer._add_object(value)
    if packets:
        xml = [xml] if isinstance(xml, bytes) else xml
        payload = ArrayObject([value for i, part in enumerate(xml)
                               for value in (TextStringObject(f'private_packet_{i}'), stream(part))])
    else:
        payload = stream(xml)
    form = writer._add_object(DictionaryObject({NameObject('/XFA'): payload}))
    writer._root_object[NameObject('/AcroForm')] = form
    if action is not None:
        writer._root_object[NameObject('/OpenAction')] = DictionaryObject({NameObject('/JS'): TextStringObject(action)})
    output = io.BytesIO(); writer.write(output)
    return output.getvalue()


def xml_script(source='var inertCount=1;', *, language='application/x-javascript'):
    return ('<template xmlns="http://www.xfa.org/schema/xfa-template/3.3/">'
            f'<script contentType="{language}"><![CDATA[{source}]]></script></template>').encode()


@pytest.mark.parametrize('packets',[False,True])
@pytest.mark.parametrize('compressed',[False,True])
def test_xfa_stream_and_packet_array_add_missing_ast_with_object_provenance(packets,compressed):
    xml=xml_script('var private_fixture_text="inert"; unescape("%41");')
    # Packet fragments exercise namespaced XML split through the script tag.
    parts=[xml[:95],xml[95:]] if packets else xml
    result=_inspect_code_bytes(xfa_pdf(parts,packets=packets,compressed=compressed),CodeInspectionLimits())
    assert result['complete'] and result['scripts_found']==result['scripts_parsed']==1
    assert result['ast']['named_calls']['unescape']==1
    source=result['script_sources'][0]
    assert source['kind']=='xfa_javascript' and source['container_object'] is not None
    assert source['script_object'] is not None and '/AcroForm/XFA/packet[' in source['path']
    assert result['xfa_observed']['containers_parsed']==1
    assert 'private_fixture_text' not in json.dumps(result) and 'private_packet' not in json.dumps(result)
    assert result['active_content_executed'] is False


def test_xfa_xml_utf16_encoding_and_escaped_text_feed_the_same_ast():
    xml='<?xml version="1.0" encoding="UTF-16"?><template><script contentType="application/x-javascript">var count=0; if(count &lt; 2){count++;}</script></template>'
    result=_inspect_code_bytes(xfa_pdf(xml.encode('utf-16'),compressed=True),CodeInspectionLimits())
    assert result['complete'] and result['scripts_parsed']==1
    assert result['ast']['node_types']['IfStatement']==1


def test_xfa_formcalc_and_text_mentions_are_not_javascript():
    xml=b'<template><script>Sum(1,2)</script><text>application/x-javascript eval()</text></template>'
    result=_inspect_code_bytes(xfa_pdf(xml),CodeInspectionLimits())
    assert result['complete'] and result['javascript_state']=='absent'
    assert result['scripts_found']==result['scripts_parsed']==0
    assert result['xfa_observed']['non_javascript_scripts_observed']==1
    assert result['ast']['node_count']==0


@pytest.mark.parametrize('xml,error',[
    (b'<template><script contentType="application/x-javascript">var x=1;', 'xfa_xml_parse_error'),
    (b'<!DOCTYPE template [<!ENTITY local "inert">]><template/>','xfa_xml_dtd_unsupported'),
    (b'<!DOCTYPE template SYSTEM "https://invalid.example/never-fetch"><template/>','xfa_xml_dtd_unsupported'),
    (b'<template><script contentType="unknown-language">inert</script></template>','xfa_script_language_unsupported'),
    (b'<template><script contentType="application/x-javascript" usehref="https://invalid.example/never-fetch"/></template>','xfa_reference_unsupported'),
])
def test_xfa_incomplete_or_unsupported_xml_never_becomes_absent(xml,error):
    result=_inspect_code_bytes(xfa_pdf(xml),CodeInspectionLimits())
    assert error in result['errors'] and result['status']=='partial'
    assert result['scripts_found'] is None and result['ast'] is None
    assert result['javascript_state']=='partial' and not result['script_extraction_complete']
    assert result['referral_recommended'] and not result['active_content_executed']
    assert 'never-fetch' not in json.dumps(result)


def test_xfa_ast_error_retains_present_script_and_other_pdf_ast():
    result=_inspect_code_bytes(xfa_pdf(xml_script('var =;'),action='var inertCount=1;'),CodeInspectionLimits())
    assert result['scripts_found']==2 and result['scripts_parsed']==1
    assert 'javascript_parse_error' in result['errors']
    assert result['ast'] is None and result['observed']['ast']['node_count']>0
    assert all(s['extraction_status']=='complete' for s in result['script_sources'])


@pytest.mark.parametrize('changes,error',[
    ({'max_decoded_bytes':32},'decoded_byte_limit'),
    ({'max_scripts':1},'script_count_limit'),
    ({'max_ast_nodes':1},'ast_node_limit'),
    ({'max_script_bytes':8},'script_byte_limit'),
    ({'max_objects':1},'pdf_structure_limit'),
    ({'max_pdf_depth':1},'pdf_structure_limit'),
])
def test_xfa_and_pdf_actions_share_existing_caps(changes,error):
    result=_inspect_code_bytes(xfa_pdf(xml_script(),action='var anotherInertCount=2;'),replace(CodeInspectionLimits(),**changes))
    assert error in result['errors'] and not result['complete'] and result['referral_recommended']


def test_xfa_xml_node_budget_is_separate_bounded_work_not_pdf_keyword_count():
    xml=b'<template>'+b'<field/>'*30+b'</template>'
    result=_inspect_code_bytes(xfa_pdf(xml),replace(CodeInspectionLimits(),max_objects=20))
    assert 'xfa_xml_node_limit' in result['errors'] and result['scripts_found'] is None
    assert result['xfa_observed']['xml_nodes_observed']==21


def test_xfa_missing_indirect_packet_preserves_unknown_counts():
    writer=PdfWriter();writer.add_blank_page(72,72)
    writer._root_object[NameObject('/XFA')]=ArrayObject([TextStringObject('private_packet'),IndirectObject(999,0,writer)])
    output=io.BytesIO();writer.write(output)
    result=_inspect_code_bytes(output.getvalue(),CodeInspectionLimits())
    assert 'pdf_reference_unavailable' in result['errors'] and result['scripts_found'] is None
    assert result['observed']['scripts_found']==0


def test_xfa_actual_worker_uses_os_limits_and_redacts_fixture_content(tmp_path):
    path=tmp_path/'inert_xfa.pdf';path.write_bytes(xfa_pdf(xml_script(),compressed=True))
    limits=replace(CodeInspectionLimits(),wall_seconds=20,cpu_seconds=12)
    result=inspect_pdf_code(path,boundary=tmp_path,limits=limits)
    assert result['complete'] and result['scripts_parsed']==1
    assert result['resource_limits']['address_space_bytes']==[limits.memory_bytes]*2
    assert result['resource_limits']['cpu_seconds']==[limits.cpu_seconds]*2
    assert 'inertCount' not in json.dumps(result)


def test_xfa_malformed_tail_retains_known_ast_but_unknown_global_totals():
    xml=xml_script()+b'<malformed'
    result=_inspect_code_bytes(xfa_pdf(xml),CodeInspectionLimits())
    assert 'xfa_xml_parse_error' in result['errors']
    assert result['scripts_found'] is None and result['scripts_parsed']==1
    assert result['ast'] is None and result['observed']['ast']['node_count']>0


def test_xfa_nested_xml_has_its_own_depth_cap_without_increasing_pdf_caps():
    xml=b'<template>'+b'<field>'*15+b'</field>'*15+b'</template>'
    result=_inspect_code_bytes(xfa_pdf(xml),replace(CodeInspectionLimits(),max_pdf_depth=10))
    assert 'xfa_xml_depth_limit' in result['errors'] and result['scripts_found'] is None


def test_xfa_unsupported_stream_filter_keeps_unknown_xml_and_js():
    writer=PdfWriter();writer.add_blank_page(72,72)
    stream=EncodedStreamObject();stream._data=b'inert unsupported fixture bytes'
    stream[NameObject('/Filter')]=NameObject('/LZWDecode')
    writer._root_object[NameObject('/XFA')]=writer._add_object(stream)
    output=io.BytesIO();writer.write(output)
    result=_inspect_code_bytes(output.getvalue(),CodeInspectionLimits())
    assert 'unsupported_script_filter' in result['errors']
    assert result['scripts_found'] is None and result['javascript_state']=='partial'


@pytest.mark.parametrize('malformed',[False,True])
def test_xfa_shared_stream_is_deduplicated_and_odd_packet_array_is_unknown(malformed):
    writer=PdfWriter();writer.add_blank_page(72,72)
    stream=DecodedStreamObject();stream._data=xml_script()
    reference=writer._add_object(stream)
    if malformed:
        writer._root_object[NameObject('/XFA')]=ArrayObject([TextStringObject('inert_packet')])
    else:
        for key in ('/AcroForm','/OtherFixture'):
            writer._root_object[NameObject(key)]=writer._add_object(DictionaryObject({NameObject('/XFA'):reference}))
    output=io.BytesIO();writer.write(output)
    result=_inspect_code_bytes(output.getvalue(),CodeInspectionLimits())
    if malformed:
        assert 'xfa_packet_array_invalid_or_limit' in result['errors'] and result['scripts_found'] is None
    else:
        assert result['complete'] and result['scripts_found']==result['scripts_parsed']==1
        assert result['xfa_observed']['containers_parsed']==1
