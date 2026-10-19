"""Native MuPDF inventory without reparsing object dictionaries with pypdf.

Production callers run inside the disposable LAB worker. Common pypdf objects
are inert projection containers. Only native scalar serialization is decoded;
object selection, containers, references and streams come from MuPDF itself.
"""

from decimal import Decimal

from pypdf.generic import (ArrayObject, BooleanObject, DictionaryObject, EncodedStreamObject,
    IndirectObject, NameObject, NullObject, NumberObject, PdfObject, create_string_object)

from malpdf.extraction.raw_syntax import Lexer, SyntaxBudget, SyntaxIssue, parse_value
from malpdf.static.execution import capacity
from malpdf.static.js_ast import CodeInspectionError


class _NativeReal(Decimal, PdfObject):
    """Preserve MuPDF's canonical selected real without a Python float cast."""


class MuPDFReader:
    def __init__(self, data, limits):
        import pymupdf
        if not isinstance(data, bytes) or not data.startswith(b'%PDF-') or len(data) > limits.max_file_bytes:
            raise CodeInspectionError('inventory_input_invalid')
        self.library, self.limits = pymupdf.mupdf, limits
        pymupdf.TOOLS.mupdf_warnings(reset=True)
        self.document = pymupdf.open(stream=data, filetype='pdf')
        try:
            if self.document.is_encrypted or self.document.needs_pass:
                raise CodeInspectionError('inventory_encrypted_pdf')
            self.native = self.library.PdfDocument(self.document.this)
            self.repaired = bool(self.document.is_repaired)
            self.warning_count = len(pymupdf.TOOLS.mupdf_warnings(reset=True).splitlines())
            self.version = {'PyMuPDF': pymupdf.VersionBind, 'MuPDF': pymupdf.VersionFitz,
                            'adapter': 'mupdf-native-object-v1'}
        except BaseException:
            self.document.close()
            raise

    def candidates(self):
        for number in range(1, self.document.xref_length()):
            yield {'number': number, 'generation': None, 'offset': None}

    def _scalar_text(self, value, maximum):
        text, length = self.library.pdf_sprint_obj(None, 0, value, 1, 1)
        if not isinstance(text, str) or length != len(text) or length > maximum:
            raise CodeInspectionError('inventory_projection_limit')
        return text

    def _name(self, value):
        name = self.library.pdf_to_name(value)
        name.encode('utf-8', errors='strict')
        return NameObject('/' + name)

    def _string(self, value):
        size = self.library.pdf_to_str_len(value)
        if size > self.limits.max_file_bytes:
            raise CodeInspectionError('inventory_projection_limit')
        encoded = self._scalar_text(value, 4 * size + 2).encode('ascii')
        budget = SyntaxBudget(4, 1, self.limits.max_pdf_depth, self.limits.max_file_bytes)
        lexer = Lexer(encoded, budget)
        node = parse_value(lexer)
        if node.kind != 'string' or node.issues or lexer.pop().kind != 'eof' or len(node.value) != size:
            raise CodeInspectionError('inventory_scalar_encoding_unavailable')
        return create_string_object(node.value)

    def object(self, candidate, raw_budget):
        lib = self.library
        number = candidate['number']
        if type(number) is not int or not 0 < number < self.document.xref_length():
            raise CodeInspectionError('inventory_reference_unavailable')
        native = lib.pdf_load_object(self.native, number)
        if lib.pdf_is_null(native):
            raise CodeInspectionError('inventory_reference_unavailable')
        nodes, node_limit, reasons = 0, capacity(self.limits, 1024), set()

        def unknown(reason):
            reasons.add(reason)
            return NullObject()

        def convert(value, depth=0):
            nonlocal nodes
            nodes += 1
            if nodes > node_limit or depth > 8:
                return unknown('inventory_projection_limit')
            if lib.pdf_is_indirect(value):
                return IndirectObject(lib.pdf_to_num(value), lib.pdf_to_gen(value), None)
            if lib.pdf_is_null(value):
                return NullObject()
            if lib.pdf_is_bool(value):
                return BooleanObject(bool(lib.pdf_to_bool(value)))
            if lib.pdf_is_int(value):
                return NumberObject(lib.pdf_to_int64(value))
            try:
                if lib.pdf_is_real(value):
                    number = _NativeReal(self._scalar_text(value, 128))
                    if not number.is_finite():
                        return unknown('inventory_scalar_encoding_unavailable')
                    return number
                if lib.pdf_is_name(value):
                    return self._name(value)
                if lib.pdf_is_string(value):
                    return self._string(value)
            except (UnicodeError, ValueError, SyntaxIssue, CodeInspectionError) as error:
                reason = 'inventory_projection_limit' if isinstance(error, CodeInspectionError) and str(error) == 'inventory_projection_limit' else 'inventory_scalar_encoding_unavailable'
                return unknown(reason)
            if lib.pdf_is_array(value):
                output = ArrayObject()
                for index in range(lib.pdf_array_len(value)):
                    if nodes >= node_limit:
                        reasons.add('inventory_projection_limit')
                        break
                    output.append(convert(lib.pdf_array_get(value, index), depth + 1))
                return output
            if lib.pdf_is_dict(value):
                output = DictionaryObject()
                for index in range(lib.pdf_dict_len(value)):
                    if nodes >= node_limit:
                        reasons.add('inventory_projection_limit')
                        break
                    try:
                        key = self._name(lib.pdf_dict_get_key(value, index))
                    except UnicodeError:
                        reasons.add('inventory_scalar_encoding_unavailable')
                        continue
                    output[key] = convert(lib.pdf_dict_get_val(value, index), depth + 1)
                return output
            return unknown('inventory_scalar_encoding_unavailable')

        value = convert(native)
        if self.document.xref_is_stream(number):
            if not isinstance(value, DictionaryObject):
                raise CodeInspectionError('inventory_stream_dictionary_invalid')
            stream = EncodedStreamObject()
            stream.update(value)
            declared = value.get('/Length')
            cap = min(self.limits.max_file_bytes, raw_budget.remaining)
            if type(declared) is NumberObject and int(declared) > cap or cap == 0 and declared != 0:
                raw = None
            else:
                raw = self.document.xref_stream_raw(number)
            if not isinstance(raw, bytes) or len(raw) > cap:
                if isinstance(raw, bytes):
                    raw_budget.remaining = 0
                reasons.add('inventory_raw_byte_limit')
                stream._data = b''
            else:
                raw_budget.remaining -= len(raw)
                stream._data = raw
            value = stream
        return value, not reasons, sorted(reasons)

    def warnings(self):
        import pymupdf
        count = self.warning_count + len(pymupdf.TOOLS.mupdf_warnings(reset=True).splitlines())
        return {'count': count, 'codes': ['mupdf_parser_warning'] if count else []}

    def close(self):
        self.document.close()
