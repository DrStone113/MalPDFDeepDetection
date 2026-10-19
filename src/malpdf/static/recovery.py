"""Bounded MuPDF object adapter; no scrub, save, stream decoding or execution.

Production callers must use the disposable PDF worker. Objects remain a
separate backend view; this adapter does not create a repaired PDF or certify
that MuPDF retained every object or historical revision.
"""

import io

from pypdf.generic import DictionaryObject, EncodedStreamObject, IndirectObject, NameObject, read_object

from malpdf.static.js_ast import CodeInspectionError
from malpdf.static.execution import capacity


class MuPDFObjectReader:
    strict = False

    def __init__(self, data, limits, *, raw_stream_allowance=None):
        import pymupdf
        if not isinstance(data, bytes) or not data.startswith(b"%PDF-") or len(data) > limits.max_file_bytes:
            raise CodeInspectionError("recovery_input_invalid")
        self.limits, self.objects = limits, {}
        self.raw_stream_allowance = raw_stream_allowance
        pymupdf.TOOLS.mupdf_warnings(reset=True)
        self.document = pymupdf.open(stream=data, filetype="pdf")
        try:
            self.is_encrypted = bool(self.document.is_encrypted or self.document.needs_pass)
            if self.is_encrypted:
                raise CodeInspectionError("recovery_encrypted_pdf")
            self.repaired = bool(self.document.is_repaired)
            notices = pymupdf.TOOLS.mupdf_warnings(reset=True)
            self.warning_count = len(notices.splitlines())
            root = self.document.pdf_catalog()
            if root <= 0:
                raise CodeInspectionError("recovery_root_unavailable")
            self.trailer = DictionaryObject({NameObject("/Root"): IndirectObject(root, 0, self)})
        except BaseException:
            self.document.close()
            raise

    def get_object(self, reference):
        number, generation = reference.idnum, reference.generation


        if generation != 0:
            raise CodeInspectionError("recovery_generation_unsupported")
        if number in self.objects:
            return self.objects[number]
        if not 0 < number < self.document.xref_length():
            raise CodeInspectionError("recovery_reference_unavailable")
        if len(self.objects) >= self.limits.max_objects:
            raise CodeInspectionError("recovery_object_limit")
        text = self.document.xref_object(number, compressed=False, ascii=True)
        if not text or text.strip() == "null":
            raise CodeInspectionError("recovery_reference_unavailable")
        if len(text) > self.limits.max_file_bytes:
            raise CodeInspectionError("recovery_object_byte_limit")
        encoded = text.encode("ascii")
        value = read_object(io.BytesIO(encoded), self)
        if self.document.xref_is_stream(number):
            if not isinstance(value, DictionaryObject):
                raise CodeInspectionError("recovery_stream_dictionary_invalid")
            cap = self.limits.max_file_bytes
            if self.raw_stream_allowance is not None:
                cap = min(cap,self.raw_stream_allowance())
                declared = value.get('/Length')
                if (cap == 0 and declared != 0) or isinstance(declared,int) and declared > cap:
                    raise CodeInspectionError('recovery_stream_byte_limit')
            raw = self.document.xref_stream_raw(number)
            if not isinstance(raw, bytes) or len(raw) > cap:
                raise CodeInspectionError("recovery_stream_byte_limit")
            stream = EncodedStreamObject()
            stream.update(value)
            stream._data = raw
            value = stream
        self.objects[number] = value
        return value

    def close(self):
        self.document.close()


def projected_object(value, *, include_fields=False, limits=None):
    """A bounded comparison of selected fields, never object content export."""
    import hashlib
    import json
    from decimal import Decimal
    from pypdf.generic import ArrayObject, FloatObject, NumberObject, StreamObject
    visited = 0
    truncations = 0
    complete = True
    fields, fields_complete = [], True
    node_limit, field_limit = capacity(limits, 1024), capacity(limits, 64)
    def project(item, depth=0):
        nonlocal visited, complete, fields_complete, truncations
        visited += 1
        if visited > node_limit or depth > 8:
            complete = False
            truncations += 1
            return ['unverified']
        if isinstance(item, IndirectObject):
            return ['reference', item.idnum, item.generation]
        if isinstance(item, DictionaryObject):
            result = []
            for key, child in sorted(item.items(), key=lambda pair: str(pair[0])):



                if isinstance(item, StreamObject) and key == '/Length':
                    continue
                if visited >= node_limit:
                    complete = False
                    truncations += 1
                    break
                key_hash = hashlib.sha256(str(key).encode()).hexdigest()
                before = truncations
                projected = project(child, depth+1)
                result.append([key_hash, projected])
                if include_fields and depth == 0:
                    if len(fields) < field_limit:
                        fields.append({'key_sha256': key_hash, 'value_type': projected[0],
                            'value_sha256': hashlib.sha256(json.dumps(projected,sort_keys=True).encode()).hexdigest(),
                            'complete': truncations == before})
                    else:
                        fields_complete = False
            return ['dictionary', result]
        if isinstance(item, ArrayObject):
            result = []
            for child in item:
                if visited >= node_limit:
                    complete = False
                    truncations += 1
                    break
                result.append(project(child, depth+1))
            return ['array', result]
        if isinstance(item, bytes):
            return ['bytes', hashlib.sha256(item).hexdigest()]
        if isinstance(item,(NumberObject,FloatObject,Decimal)):


            decimal=Decimal(str(item))
            if not decimal.is_finite():
                raise CodeInspectionError('object_nonfinite_number')
            sign,digits,exponent=decimal.as_tuple()
            digits=list(digits)
            while digits and digits[-1]==0:
                digits.pop();exponent+=1
            return ['number',sign if digits else 0,digits,exponent if digits else 0]
        return [type(item).__name__, hashlib.sha256(str(item).encode()).hexdigest()]
    projection = hashlib.sha256(json.dumps(project(value), sort_keys=True).encode()).hexdigest()
    action = value.get("/S") if isinstance(value, DictionaryObject) else None
    known = {"/JavaScript", "/Launch", "/URI", "/SubmitForm", "/GoToR", "/GoToE", "/ImportData"}
    result = {"type": 'StreamObject' if isinstance(value,StreamObject) else type(value).__name__, "action": str(action) if str(action) in known else None,
            "projected_values_sha256": projection, "projection_complete": complete,
            "stream_sha256": hashlib.sha256(value._data).hexdigest() if isinstance(value, StreamObject) else None,
            "security_keys": sorted(str(k) for k in value if str(k) in known | {"/JS", "/AA", "/OpenAction", "/XFA", "/EF"})
                if isinstance(value, DictionaryObject) else []}
    if include_fields:
        result.update(key_projections=fields, key_enumeration_complete=bool(complete and fields_complete), projection_nodes=visited)
    return result
