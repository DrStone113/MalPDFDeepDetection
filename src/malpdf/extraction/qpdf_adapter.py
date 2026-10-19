"""Read-only QPDF object view of the verified snapshot inside the PDF worker.

QPDF chooses and parses objects. pypdf containers below provide a common inert
projection format only; no QPDF object text is reparsed with pypdf.
"""

import io
import re
from decimal import Decimal

from pypdf.generic import (ArrayObject, BooleanObject, DictionaryObject, EncodedStreamObject,
    IndirectObject, NameObject, NullObject, NumberObject, PdfObject, create_string_object)

from malpdf.static.js_ast import CodeInspectionError
from malpdf.static.execution import capacity


class _ExactReal(Decimal, PdfObject):
    """Common projection container: never convert QPDF decimals to float."""


class QPDFReader:
    def __init__(self, data, limits):
        import pikepdf
        if not isinstance(data,bytes) or not data.startswith(b'%PDF-') or len(data) > limits.max_file_bytes:
            raise CodeInspectionError('inventory_input_invalid')
        self.library, self.data, self.limits = pikepdf, data, limits
        self.document = pikepdf.Pdf.open(io.BytesIO(data), attempt_recovery=False,
            inherit_page_attributes=False, suppress_warnings=True, conversion_mode='explicit')
        if self.document.is_encrypted:
            self.document.close()
            raise CodeInspectionError('inventory_encrypted_pdf')
        self.version = {'pikepdf': pikepdf.__version__, 'qpdf': pikepdf.__libqpdf_version__}
        self.repaired = False

    def candidates(self):
        for (number, generation), entry in self.document.get_xref_table().items():
            if number > 0 and entry.type in (1, 2):
                offset = entry.offset
                verified = False
                if type(offset) is int and 0 <= offset < len(self.data):
                    header = re.match(rb'(\d+)\s+(\d+)\s+obj(?:\s|[<\[/])', self.data[offset:offset + 128])
                    verified = bool(header and (int(header[1]),int(header[2])) == (number,generation))
                yield {'number': number, 'generation': generation,
                    'offset': offset if verified else None,
                    'xref_type': entry.type, 'object_stream_number': entry.obj_stream_number,
                    'object_stream_index': entry.obj_stream_index}

    def object(self, candidate, raw_budget):
        lib, nodes, complete = self.library, 0, True
        node_limit = capacity(self.limits, 1024)
        reasons = set()
        def convert(value, depth=0, root=False):
            nonlocal nodes, complete
            nodes += 1
            if nodes > node_limit or depth > 8:
                complete = False
                return NullObject()
            if isinstance(value, lib.Object) and value.is_indirect and not root:
                return IndirectObject(*value.objgen, None)
            kind = getattr(value, '_type_code', None)
            if value is None or kind == lib.ObjectType.null:
                return NullObject()
            if isinstance(value, bool) or kind == lib.ObjectType.boolean:
                return BooleanObject(bool(value))
            if isinstance(value, int) or kind == lib.ObjectType.integer:
                return NumberObject(int(value))
            if kind == lib.ObjectType.real:
                return _ExactReal(str(value.as_decimal()))
            if kind == lib.ObjectType.name_:
                return NameObject(str(value))
            if kind == lib.ObjectType.string:
                return create_string_object(bytes(value))
            if kind == lib.ObjectType.array:
                output = ArrayObject()
                for item in value:
                    if nodes >= node_limit:
                        complete = False
                        break
                    output.append(convert(item, depth + 1))
                return output
            if kind in (lib.ObjectType.dictionary, lib.ObjectType.stream):
                output = EncodedStreamObject() if kind == lib.ObjectType.stream else DictionaryObject()
                items = value.stream_dict.items() if kind == lib.ObjectType.stream else value.items()
                for key, item in items:
                    if nodes >= node_limit:
                        complete = False
                        break
                    output[NameObject(key)] = convert(item, depth + 1)
                if kind == lib.ObjectType.stream:


                    declared = value.stream_dict.get('/Length')
                    if declared is not None and int(declared) > raw_budget.remaining:
                        body = None
                    elif raw_budget.remaining == 0 and (declared is None or int(declared) != 0):
                        body = None
                    else:
                        body = value.read_raw_bytes()
                    if body is None or len(body) > raw_budget.remaining:
                        if body is not None:
                            raw_budget.remaining = 0
                        complete = False
                        reasons.add('inventory_raw_byte_limit')
                        output._data = b''
                    else:
                        raw_budget.remaining -= len(body)
                        output._data = body
                return output
            complete = False
            return NullObject()
        value = convert(self.document.get_object((candidate['number'],candidate['generation'])), root=True)
        if not complete and not reasons:
            reasons.add('inventory_projection_limit')
        return value, complete, sorted(reasons)

    def warnings(self):

        messages = self.document.get_warnings()
        return {'count': len(messages), 'codes': ['qpdf_parser_warning'] if messages else []}

    def close(self):
        self.document.close()
