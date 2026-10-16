"""Incremental, size-capped PDF stream filters with explicit failure evidence.

Never execute scripts or call an external media decoder. Decoded prefixes are
evidence of partial work only; a failed stage never becomes input to the next.
Production callers run this module inside the existing disposable PDF worker.
"""

from dataclasses import asdict, dataclass
from copy import deepcopy
import hashlib
import zlib


ALIASES = {"/Fl": "/FlateDecode", "/LZW": "/LZWDecode", "/AHx": "/ASCIIHexDecode",
           "/A85": "/ASCII85Decode", "/RL": "/RunLengthDecode", "/CCF": "/CCITTFaxDecode",
           "/DCT": "/DCTDecode"}
SUPPORTED = frozenset({"/FlateDecode", "/LZWDecode", "/ASCIIHexDecode", "/ASCII85Decode", "/RunLengthDecode"})
_WHITESPACE = frozenset(b"\x00\t\n\f\r ")


@dataclass(frozen=True)
class FilterLimits:
    max_input_bytes: int = 10 * 1024**2
    max_stage_bytes: int = 1024**2
    max_total_bytes: int = 4 * 1024**2
    max_filters: int = 8
    max_expansion_ratio: int = 100

    def __post_init__(self):
        if any(type(value) is not int or value <= 0 for value in asdict(self).values()):
            raise ValueError("Filter limits must be positive integers")
        if (self.max_input_bytes > 50 * 1024**2 or self.max_stage_bytes > 8 * 1024**2
                or self.max_total_bytes > 8 * 1024**2 or self.max_filters > 16
                or self.max_expansion_ratio > 1000):
            raise ValueError("Filter limits exceed the static resource budget")


@dataclass
class DecodeBudget:
    remaining: int

    def __post_init__(self):
        if type(self.remaining) is not int or not 0 <= self.remaining <= 8 * 1024**2:
            raise ValueError("Invalid shared decoded-byte budget")


@dataclass(frozen=True)
class DecodedStream:
    data: bytes | None
    partial_data: bytes | None
    metadata: dict


class _Stopped(Exception):
    def __init__(self, status, code, prefix=None):
        self.status, self.code = status, code
        self.prefix = None if prefix is None else bytes(prefix)


def _append(output, chunk, cap):
    room = max(0, cap - len(output))
    output.extend(chunk[:room])
    if len(chunk) > room:
        raise _Stopped("resource_limit", "decoded_byte_or_expansion_limit", output)


def _flate(data, cap, *, wbits=zlib.MAX_WBITS):
    decoder, output = zlib.decompressobj(wbits), bytearray()
    # Snapshot at bounded chunk boundaries. If a chunk corrupts the checksum,
    # replay only that chunk bytewise to preserve its observed decoded prefix.
    for start in range(0, len(data), 16 * 1024):
        chunk, before = data[start:start + 16 * 1024], decoder.copy()
        try:
            decoded = decoder.decompress(chunk, max(1, cap - len(output) + 1))
        except zlib.error:
            decoder = before
            for value in chunk:
                try:
                    decoded = decoder.decompress(bytes([value]), max(1, cap - len(output) + 1))
                except zlib.error:
                    raise _Stopped("decode_error", "invalid_flate_stream", output) from None
                _append(output, decoded, cap)
                if decoder.unconsumed_tail:
                    raise _Stopped("resource_limit", "decoded_byte_or_expansion_limit", output)
            raise _Stopped("decode_error", "invalid_flate_stream", output) from None
        _append(output, decoded, cap)
        if decoder.unconsumed_tail:
            raise _Stopped("resource_limit", "decoded_byte_or_expansion_limit", output)
        if decoder.unused_data:
            raise _Stopped("decode_error", "trailing_flate_data", output)
    if not decoder.eof:
        raise _Stopped("decode_error", "truncated_flate_stream", output)
    return bytes(output)


def _asciihex(data, cap):
    output, high, ended = bytearray(), None, False
    for value in data:
        if value in _WHITESPACE:
            continue
        if ended:
            raise _Stopped("decode_error", "trailing_asciihex_data", output)
        if value == ord(">"):
            if high is not None:
                _append(output, bytes([high << 4]), cap)
            ended = True
            continue
        digit = value - 48 if 48 <= value <= 57 else value - 55 if 65 <= value <= 70 else value - 87 if 97 <= value <= 102 else -1
        if digit < 0:
            raise _Stopped("decode_error", "invalid_asciihex_digit", output)
        if high is None:
            high = digit
        else:
            _append(output, bytes([(high << 4) | digit]), cap)
            high = None
    if not ended:
        raise _Stopped("decode_error", "missing_asciihex_end", output)
    return bytes(output)


def _ascii85(data, cap):
    # PDF ASCII85 begins with data and ends with ~>. Accept the optional Adobe
    # <~ wrapper without treating '<' as part of a five-character tuple.
    data = data.lstrip(bytes(_WHITESPACE))
    if data.startswith(b"<~"):
        data = data[2:]
    output, group, index, ended = bytearray(), [], 0, False
    while index < len(data):
        value = data[index]
        index += 1
        if value in _WHITESPACE:
            continue
        if ended:
            raise _Stopped("decode_error", "trailing_ascii85_data", output)
        if value == ord("~"):
            if index == len(data) or data[index] != ord(">"):
                raise _Stopped("decode_error", "invalid_ascii85_end", output)
            index += 1
            if len(group) == 1:
                raise _Stopped("decode_error", "invalid_ascii85_tuple", output)
            if group:
                count, number = len(group), 0
                for digit in group + [84] * (5 - len(group)):
                    number = number * 85 + digit
                if number > 0xFFFFFFFF:
                    raise _Stopped("decode_error", "invalid_ascii85_tuple", output)
                _append(output, number.to_bytes(4, "big")[:count - 1], cap)
            ended = True
        elif value == ord("z"):
            if group:
                raise _Stopped("decode_error", "invalid_ascii85_z", output)
            _append(output, b"\0" * 4, cap)
        elif 33 <= value <= 117:
            group.append(value - 33)
            if len(group) == 5:
                number = 0
                for digit in group:
                    number = number * 85 + digit
                if number > 0xFFFFFFFF:
                    raise _Stopped("decode_error", "invalid_ascii85_tuple", output)
                _append(output, number.to_bytes(4, "big"), cap)
                group.clear()
        else:
            raise _Stopped("decode_error", "invalid_ascii85_digit", output)
    if not ended:
        raise _Stopped("decode_error", "missing_ascii85_end", output)
    return bytes(output)


def _runlength(data, cap):
    output, index, ended = bytearray(), 0, False
    while index < len(data):
        control = data[index]
        index += 1
        if control == 128:
            ended = True
            if index != len(data):
                raise _Stopped("decode_error", "trailing_runlength_data", output)
            break
        count = control + 1 if control < 128 else 257 - control
        if control < 128:
            available = data[index:index + count]
            _append(output, available, cap)
            if len(available) != count:
                raise _Stopped("decode_error", "truncated_runlength_literal", output)
            index += count
        else:
            if index == len(data):
                raise _Stopped("decode_error", "truncated_runlength_repeat", output)
            _append(output, bytes([data[index]]) * count, cap)
            index += 1
    if not ended:
        raise _Stopped("decode_error", "missing_runlength_end", output)
    return bytes(output)


def _lzw(data, cap, early_change):
    output, bit, width = bytearray(), 0, 9
    table, previous = [bytes([value]) for value in range(256)] + [None, None], None
    clear_seen = False
    while bit + width <= len(data) * 8:
        # At most three bytes contain one code. Avoid constructing an integer
        # spanning the entire stream or an unbounded dictionary of sequences.
        start, shift = bit // 8, bit % 8
        count = (shift + width + 7) // 8
        code = (int.from_bytes(data[start:start + count], "big") >> (count * 8 - shift - width)) & ((1 << width) - 1)
        bit += width
        if code == 256:
            table, previous, width = [bytes([value]) for value in range(256)] + [None, None], None, 9
            clear_seen = True
            continue
        if not clear_seen:
            raise _Stopped("decode_error", "missing_lzw_clear", output)
        if code == 257:
            # A byte may contain padding bits; further whole bytes are not part
            # of this encoded stream and must not silently disappear.
            if (bit + 7) // 8 != len(data):
                raise _Stopped("decode_error", "trailing_lzw_data", output)
            return bytes(output)
        if code < len(table) and table[code] is not None:
            chunk = table[code]
        elif code == len(table) and previous is not None:
            chunk = previous + previous[:1]
        else:
            raise _Stopped("decode_error", "invalid_lzw_code", output)
        _append(output, chunk, cap)
        if previous is not None and len(table) < 4096:
            table.append(previous + chunk[:1])
            if width < 12 and len(table) == (1 << width) - early_change:
                width += 1
        previous = chunk
    raise _Stopped("decode_error", "missing_lzw_end", output)


def _parameters(name, value):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise _Stopped("decode_error", "invalid_decode_parameters")
    allowed = {"/Predictor", "/Columns", "/Colors", "/BitsPerComponent"} if name in {"/FlateDecode", "/LZWDecode"} else set()
    if name == "/LZWDecode":
        allowed.add("/EarlyChange")
    if set(value) - allowed:
        raise _Stopped("unsupported", "unsupported_decode_parameter")
    if any(type(item) is not int for item in value.values()):
        raise _Stopped("decode_error", "invalid_decode_parameter_value")
    if value.get("/EarlyChange", 1) not in (0, 1):
        raise _Stopped("decode_error", "invalid_lzw_early_change")
    if value.get("/Predictor", 1) not in (1, 2, 10, 11, 12, 13, 14, 15):
        raise _Stopped("unsupported", "unsupported_predictor")
    if value.get("/BitsPerComponent", 8) not in (1, 2, 4, 8, 16) or value.get("/Colors", 1) < 1 or value.get("/Columns", 1) < 1:
        raise _Stopped("decode_error", "invalid_predictor_geometry")
    return value


def _predict(data, parameters, cap):
    predictor = parameters.get("/Predictor", 1)
    if predictor == 1 or not data:
        return data
    columns, colors, bits = (parameters.get(key, default) for key, default in
                            (("/Columns", 1), ("/Colors", 1), ("/BitsPerComponent", 8)))
    samples = columns * colors
    row_bytes, bpp = (samples * bits + 7) // 8, max(1, (colors * bits + 7) // 8)
    if row_bytes > cap or samples > cap * 8:
        raise _Stopped("resource_limit", "predictor_row_limit")
    encoded_row = row_bytes + (0 if predictor == 2 else 1)
    output, previous = bytearray(), bytes(row_bytes)
    for start in range(0, len(data), encoded_row):
        row = data[start:start + encoded_row]
        if len(row) != encoded_row:
            raise _Stopped("decode_error", "truncated_predictor_row", output)
        if predictor == 2:
            # TIFF horizontal differences operate on samples, including packed
            # 1/2/4-bit and big-endian 16-bit samples, rather than on bytes.
            decoded_row, previous_values = bytearray(row_bytes), [0] * colors
            for index in range(samples):
                position = index * bits
                count = (position % 8 + bits + 7) // 8
                shift = count * 8 - position % 8 - bits
                encoded = (int.from_bytes(row[position // 8:position // 8 + count], "big") >> shift) & ((1 << bits) - 1)
                decoded = (encoded + previous_values[index % colors]) & ((1 << bits) - 1)
                previous_values[index % colors] = decoded
                if bits <= 8:
                    decoded_row[position // 8] |= decoded << (8 - bits - position % 8)
                else:
                    decoded_row[position // 8:position // 8 + 2] = decoded.to_bytes(2, "big")
            padding = row_bytes * 8 - samples * bits
            decoded_row[-1] |= row[-1] & ((1 << padding) - 1)
            _append(output, decoded_row, cap)
            continue
        kind, decoded = row[0], bytearray(row[1:])
        if kind > 4:
            raise _Stopped("decode_error", "invalid_png_predictor", output)
        for index in range(row_bytes):
            left = decoded[index - bpp] if index >= bpp else 0
            above = previous[index]
            upper_left = previous[index - bpp] if index >= bpp else 0
            if kind == 0:
                prediction = 0
            elif kind == 1:
                prediction = left
            elif kind == 2:
                prediction = above
            elif kind == 3:
                prediction = (left + above) // 2
            else:
                estimate = left + above - upper_left
                choices = (left, above, upper_left)
                prediction = min(enumerate(choices), key=lambda pair: (abs(estimate - pair[1]), pair[0]))[1]
            decoded[index] = (decoded[index] + prediction) & 255
        _append(output, decoded, cap)
        previous = decoded
    return bytes(output)


def decode_filters(raw, filters=(), *, decode_parms=None, limits=None, budget=None, retain=None, checkpoint=None, plugins=None):
    """Decode ordered filters, recording every completed/failed/unrun layer.

    Crypt without an approved decryption context is encrypted. Image codecs
    remain unsupported instead of being mistaken for decoded empty streams.
    Retention is optional and returns metadata, never arbitrary output paths.
    """
    limits = limits or FilterLimits()
    if plugins is not None:
        from malpdf.extraction.plugins import PluginRegistry
        if type(plugins) is not PluginRegistry:raise ValueError('plugin_registry_required')
    budget = DecodeBudget(limits.max_total_bytes) if budget is None else budget
    if not isinstance(raw, bytes) or len(raw) > limits.max_input_bytes:
        raise ValueError("Invalid raw stream or input byte cap")
    if not isinstance(filters, (tuple, list)):
        raise ValueError("Invalid filter sequence")
    overflow = len(filters) > limits.max_filters
    declared_count = len(filters)
    filters = filters[:limits.max_filters]
    if any(not isinstance(name, str) or len(name) > 256 for name in filters):
        raise ValueError("Invalid filter sequence")
    names = [ALIASES.get(name, name) for name in filters]
    metadata = {"schema_version": "pdf-filter-matrix-v1", "filters": list(filters),
        "declared_filter_count": declared_count, "filter_sequence_complete": not overflow,
        "raw_sha256": hashlib.sha256(raw).hexdigest(), "raw_bytes": len(raw), "steps": [],
        "status": "observed", "complete": False, "decoded_sha256": None, "decoded_bytes": None,
        "decoded_byte_debit": 0, "limits": asdict(limits), "reason_codes": []}
    initial = budget.remaining
    def emit():
        metadata["decoded_byte_debit"] = initial - budget.remaining
        metadata["decoded_bytes_remaining"] = budget.remaining
        if checkpoint is not None:
            value = deepcopy(metadata)
            if not value["complete"] and value["status"] == "observed":
                value["status"] = "partial"
            checkpoint(value)

    def retained(data):
        identity = {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
        if retain is None:
            return {**identity, "status": "not_retained"}
        result = retain(data)
        if not isinstance(result, dict) or any(result.get(key) != value for key, value in identity.items()):
            raise ValueError("Invalid stream retention identity")
        return result

    raw_retention = retained(raw)
    metadata["raw_retention"] = raw_retention
    emit()
    if overflow:
        metadata.update(status="resource_limit", reason_codes=["stream_filter_count_limit"])
        emit()
        return DecodedStream(None, None, metadata)
    if decode_parms is None:
        parameters = [None] * len(names)
    elif isinstance(decode_parms, dict) and len(names) == 1:
        parameters = [decode_parms]
    elif isinstance(decode_parms, (tuple, list)) and len(decode_parms) == len(names):
        parameters = list(decode_parms)
    else:
        metadata.update(status="decode_error", reason_codes=["filter_parameter_alignment"])
        emit()
        return DecodedStream(None, None, metadata)
    data, partial, failed = raw, None, False
    chain_cap = min(limits.max_stage_bytes, len(raw) * limits.max_expansion_ratio)
    for index, (name, parms) in enumerate(zip(names, parameters)):
        step = {"index": index, "filter": name, "input_sha256": hashlib.sha256(data).hexdigest() if not failed else None,
                "input_bytes": len(data) if not failed else None, "status": "not_run", "complete": False,
                "output_sha256": None, "output_bytes": None, "reason_codes": [], "retention": None}
        metadata["steps"].append(step)
        if failed:
            step["reason_codes"] = ["previous_filter_incomplete"]
            continue
        cap = min(chain_cap, budget.remaining, limits.max_total_bytes - (initial - budget.remaining),
                  len(data) * limits.max_expansion_ratio)
        debit = 0
        try:
            custom=plugins.decoder(name) if plugins is not None else None
            identity_crypt = name == "/Crypt" and isinstance(parms, dict) and parms.get("/Name") == "/Identity"
            if name == "/Crypt" and not identity_crypt:
                raise _Stopped("encrypted", "crypt_context_unavailable")
            if name not in SUPPORTED and not identity_crypt and custom is None:
                raise _Stopped("unsupported", "unsupported_stream_filter")
            if custom is not None:
                from malpdf.extraction.plugins import BoundedOutput,PluginDecodeFailure
                step['plugin']=custom.describe();step['plugin_invoked']=False
                if parms is None:parms={}
                if (type(parms) is not dict or len(parms)>16 or set(parms)-set(custom.parameter_keys)
                        or any(type(v) is not int for v in parms.values())):
                    raise _Stopped('unsupported','plugin_decode_parameters_unsupported')
                output=BoundedOutput(cap)
                try:
                    step['status']='partial';emit()
                    implementation=custom.build();step['plugin_invoked']=True;emit()
                    returned=implementation.decode(data,dict(parms),output)
                    if returned is not None:raise ValueError('plugin_decoder_return_type')
                    decoded=output.finish()
                except PluginDecodeFailure as error:
                    raise _Stopped(error.status,error.code,output.prefix()) from None
                except (MemoryError,RecursionError):
                    debit=budget.remaining
                    raise _Stopped('resource_limit','plugin_decoder_resource_limit',output.prefix()) from None
                except Exception:
                    raise _Stopped('decode_error','plugin_decoder_failed',output.prefix()) from None
            elif identity_crypt:
                if set(parms) - {"/Name", "/Type"}:
                    raise _Stopped("unsupported", "unsupported_decode_parameter")
                if parms.get("/Type", "/CryptFilterDecodeParms") != "/CryptFilterDecodeParms":
                    raise _Stopped("decode_error", "invalid_crypt_parameters")
                identity = bytearray()
                _append(identity, data, cap)
                decoded = bytes(identity)
            else:
                parms = _parameters(name, parms)
            step["decode_parameters"] = parms
            if identity_crypt or custom is not None:
                pass
            elif name == "/FlateDecode":
                decoded = _flate(data, cap)
            elif name == "/ASCIIHexDecode":
                decoded = _asciihex(data, cap)
            elif name == "/ASCII85Decode":
                decoded = _ascii85(data, cap)
            elif name == "/RunLengthDecode":
                decoded = _runlength(data, cap)
            else:
                decoded = _lzw(data, cap, parms.get("/EarlyChange", 1))
            debit = len(decoded)
            if custom is None and parms.get("/Predictor", 1) != 1:
                step.update(predictor_input_sha256=hashlib.sha256(decoded).hexdigest(), predictor_input_bytes=len(decoded),
                    predictor_input_retention=retained(decoded))
            data = decoded if custom is not None else _predict(decoded, parms, cap)
            step.update(status="observed", complete=True, output_sha256=hashlib.sha256(data).hexdigest(),
                        output_bytes=len(data), retention=retained(data))
        except _Stopped as error:
            partial, failed = error.prefix, True
            debit = max(debit, len(partial) if partial is not None else 0)
            step.update(status=error.status, reason_codes=[error.code],
                        output_sha256=hashlib.sha256(partial).hexdigest() if partial is not None else None,
                        output_bytes=len(partial) if partial is not None else None,
                        retention=retained(partial) if partial is not None else None)
            metadata.update(status=error.status, reason_codes=[error.code])
        finally:
            budget.remaining -= debit
        emit()
    if not names:
        if len(raw) > min(limits.max_stage_bytes, budget.remaining, limits.max_total_bytes):
            metadata.update(status="resource_limit", reason_codes=["decoded_byte_or_expansion_limit"])
            emit()
            return DecodedStream(None, None, metadata)
        budget.remaining -= len(raw)
    metadata["decoded_byte_debit"] = initial - budget.remaining
    if not failed:
        metadata.update(complete=True, decoded_sha256=hashlib.sha256(data).hexdigest(), decoded_bytes=len(data))
    emit()
    return DecodedStream(data if not failed else None, partial, metadata)
