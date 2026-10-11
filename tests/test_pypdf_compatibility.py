"""Synthetic hybrid xrefs exercise the pinned pypdf compatibility repair."""

import io

import pytest
from pypdf import PdfReader
from pypdf.generic import DictionaryObject, NameObject, NumberObject

from malpdf.static.code_inspector import CodeInspectionLimits, _inspect_code_bytes
from malpdf.static.evidence import inspect_evidence
from malpdf.static.evidence_v9 import inspect_evidence_v9
from malpdf.static.pdf_parser import _apply_pypdf_patches, inspect_pdf_structure
from malpdf.static.safety import StaticInspectionLimits


def xref_pdf(pointer):
    data = bytearray(b'%PDF-1.5\n')
    offsets = [0]
    objects = [b'<< /Type /Catalog /Pages 2 0 R >>',
               b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
               b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 72 72] >>']
    for number, value in enumerate(objects, 1):
        offsets.append(len(data))
        data.extend(str(number).encode()+b' 0 obj\n'+value+b'\nendobj\n')
    offsets.append(len(data))
    stream = b'\x00\x00\x00\x00\x00\xff\xff'+b''.join(b'\x01'+offset.to_bytes(4,'big')+b'\x00\x00' for offset in offsets[1:])
    target = offsets[4] if pointer == 'valid' else offsets[1] if pointer == 'malformed' else pointer
    data.extend(b'4 0 obj\n<< /Type /XRef /Size 5 /W [1 4 2] /Root 1 0 R /Length 35 /XRefStm '+
                str(target).encode()+b' >>\nstream\n'+stream+b'\nendstream\nendobj\nstartxref\n'+
                str(offsets[4]).encode()+b'\n%%EOF\n')
    return bytes(data)


def test_valid_supplemental_xref_initializes_stream_before_parsing_and_patch_is_idempotent():
    _apply_pypdf_patches()
    initializer, processor = PdfReader._initialize_stream, PdfReader._process_xref_stream
    _apply_pypdf_patches()
    assert initializer is PdfReader._initialize_stream and processor is PdfReader._process_xref_stream
    reader = PdfReader(io.BytesIO(xref_pdf('valid')), strict=False)
    assert len(reader.pages)==1 and not getattr(reader, '_malpdf_xrefstm_failures', [])


@pytest.mark.parametrize('pointer', [-1, 999999, 'malformed'])
def test_unverified_supplemental_xref_keeps_usable_objects_and_explicit_partial(pointer):
    import hashlib
    data = xref_pdf(pointer)
    reader = PdfReader(io.BytesIO(data), strict=False)
    assert len(reader.pages)==1 and reader._malpdf_xrefstm_failures
    parsed = inspect_pdf_structure(data, StaticInspectionLimits())
    assert parsed.success and not parsed.structural_complete
    assert 'supplemental_xref_unavailable' in {issue.code for issue in parsed.warnings}
    assert 'xrefstm_partial' in parsed.diagnostics['recovery_notice_codes']
    code = _inspect_code_bytes(data, CodeInspectionLimits())
    assert not code['complete'] and code['parser_recovered']
    assert 'supplemental_xref_unavailable' in code['errors']
    assert code['observed']['scripts_found']==0
    static = {'input':{'sha256':hashlib.sha256(data).hexdigest(),'size_bytes':len(data)},
              'features':{}, 'parser':{'success':True,'structural_complete':False},'errors':[]}
    legacy = inspect_evidence(data, static, code, CodeInspectionLimits(), primary_complete=False)
    assert not legacy['complete']
    result = inspect_evidence_v9(data, static, code, CodeInspectionLimits(), primary_complete=False,
                                 legacy_analysis=legacy)
    assert not result['complete'] and any(item['kind']=='xref_check' for item in result['observations'])


@pytest.mark.parametrize('exception', [MemoryError, RecursionError, OSError])
def test_resource_or_system_failure_propagates_and_cursor_is_restored(monkeypatch, exception):
    reader = object.__new__(PdfReader)
    reader.stream = io.BytesIO(b'benign bounded stream')
    reader.stream.seek(3)
    reader.trailer = DictionaryObject()
    def fail(*args): raise exception('synthetic failure')
    monkeypatch.setattr(reader, '_read_pdf15_xref_stream', fail)
    with pytest.raises(exception):
        reader._process_xref_stream(DictionaryObject({NameObject('/XRefStm'):NumberObject(1)}))
    assert reader.stream.tell()==3 and not getattr(reader, '_malpdf_xrefstm_failures', [])
