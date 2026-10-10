"""Bounded MuPDF object adapter; no scrub, save, stream decoding or execution.

Production callers must use the disposable PDF worker. Objects remain a
separate backend view; this adapter does not create a repaired PDF or certify
that MuPDF retained every object or historical revision.
"""

import io

from pypdf.generic import DictionaryObject, EncodedStreamObject, IndirectObject, NameObject, read_object

from malpdf.static.js_ast import CodeInspectionError


class MuPDFObjectReader:
    strict = False

    def __init__(self, data, limits):
        import pymupdf
        if not isinstance(data, bytes) or not data.startswith(b"%PDF-") or len(data) > limits.max_file_bytes:
            raise CodeInspectionError("recovery_input_invalid")
        self.limits, self.objects = limits, {}
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
        # MuPDF's public xref API addresses current objects by number only.
        # Never silently alias a nonzero generation to a different object.
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
            raw = self.document.xref_stream_raw(number)
            if not isinstance(raw, bytes) or len(raw) > self.limits.max_file_bytes:
                raise CodeInspectionError("recovery_stream_byte_limit")
            stream = EncodedStreamObject()
            stream.update(value)
            stream._data = raw
            value = stream
        self.objects[number] = value
        return value

    def close(self):
        self.document.close()


def projected_object(value):
    """A bounded comparison of selected fields, never object content export."""
    import hashlib
    import json
    from decimal import Decimal
    from pypdf.generic import ArrayObject, FloatObject, NumberObject, StreamObject
    visited = 0
    complete = True
    def project(item, depth=0):
        nonlocal visited, complete
        visited += 1
        if visited > 1024 or depth > 8:
            complete = False
            return ['unverified']
        if isinstance(item, IndirectObject):
            return ['reference', item.idnum, item.generation]
        if isinstance(item, DictionaryObject):
            result = []
            for key, child in sorted(item.items(), key=lambda pair: str(pair[0])):
                # pypdf removes /Length while reading streams; the raw digest
                # separately checks the actual bytes. Avoid representation-only
                # conflicts with MuPDF retaining this derived field.
                if isinstance(item, StreamObject) and key == '/Length':
                    continue
                if visited >= 1024:
                    complete = False
                    break
                result.append([hashlib.sha256(str(key).encode()).hexdigest(), project(child, depth+1)])
            return ['dictionary', result]
        if isinstance(item, ArrayObject):
            result = []
            for child in item:
                if visited >= 1024:
                    complete = False
                    break
                result.append(project(child, depth+1))
            return ['array', result]
        if isinstance(item, bytes):
            return ['bytes', hashlib.sha256(item).hexdigest()]
        if isinstance(item,(NumberObject,FloatObject)):
            # MuPDF canonicalizes 0.0 to 0; preserve exact decimal identity
            # without lossy float conversion of large integer PDF values.
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
    return {"type": 'StreamObject' if isinstance(value,StreamObject) else type(value).__name__, "action": str(action) if str(action) in known else None,
            "projected_values_sha256": projection, "projection_complete": complete,
            "stream_sha256": hashlib.sha256(value._data).hexdigest() if isinstance(value, StreamObject) else None,
            "security_keys": sorted(str(k) for k in value if str(k) in known | {"/JS", "/AA", "/OpenAction", "/XFA", "/EF"})
                if isinstance(value, DictionaryObject) else []}
