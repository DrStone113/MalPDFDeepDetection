"""Decoder evidence/budget tests using synthetic bytes only; no PDF execution."""

import base64
from dataclasses import replace
import hashlib
import json
import zlib

import pytest
from pypdf._codecs._codecs import LzwCodec

from malpdf.extraction.filters import DecodeBudget, FilterLimits, decode_filters


def test_ordered_filters_keep_all_intermediates_and_original_identity():
    payload = b"inert content; no active code\n" * 8
    compressed = zlib.compress(payload)
    raw = base64.a85encode(compressed, adobe=True)
    retained = {}
    def sink(value):
        digest = hashlib.sha256(value).hexdigest()
        retained[digest] = value
        return {"sha256": digest, "size_bytes": len(value), "status": "retained"}
    result = decode_filters(raw, ["/A85", "/Fl"], retain=sink)
    assert result.data == payload and result.partial_data is None
    assert result.metadata["complete"] and result.metadata["filters"] == ["/A85", "/Fl"]
    assert [step["filter"] for step in result.metadata["steps"]] == ["/ASCII85Decode", "/FlateDecode"]
    assert set(retained.values()) == {raw, compressed, payload}
    assert result.metadata["decoded_byte_debit"] == len(compressed) + len(payload)
    assert "inert content" not in json.dumps(result.metadata)


@pytest.mark.parametrize("encoded,filter_name", [
    (zlib.compress(b""), "/FlateDecode"), (b">", "/ASCIIHexDecode"),
    (b"~>", "/ASCII85Decode"), (b"\x80", "/RunLengthDecode"),
    (LzwCodec().encode(b""), "/LZWDecode"), (b"", None),
])
def test_truly_empty_decoded_output_is_verified_even_with_no_remaining_budget(encoded, filter_name):
    result = decode_filters(encoded, [filter_name] if filter_name else [], budget=DecodeBudget(0))
    assert result.metadata["status"] == "observed" and result.metadata["complete"]
    assert result.data == b"" and result.metadata["decoded_bytes"] == 0
    assert result.metadata["decoded_sha256"] == hashlib.sha256(b"").hexdigest()


@pytest.mark.parametrize("name,status", [("/JBIG2Decode", "unsupported"), ("/JPXDecode", "unsupported"),
    ("/CCITTFaxDecode", "unsupported"), ("/DCTDecode", "unsupported"),
    ("/UnknownCodec", "unsupported"), ("/Crypt", "encrypted")])
def test_unavailable_codec_is_never_confused_with_an_empty_stream(name, status):
    result = decode_filters(b"inert bytes", [name, "/FlateDecode"])
    assert result.data is None and result.partial_data is None
    assert not result.metadata["complete"] and result.metadata["status"] == status
    assert result.metadata["decoded_bytes"] is None and result.metadata["decoded_sha256"] is None
    assert result.metadata["steps"][0]["output_bytes"] is None
    assert result.metadata["steps"][1]["status"] == "not_run"


def test_explicit_identity_crypt_passes_bytes_without_a_decryption_context():
    result = decode_filters(b"inert", ["/Crypt"], decode_parms={"/Name": "/Identity"})
    assert result.data == b"inert" and result.metadata["status"] == "observed"
    assert decode_filters(b"inert", ["/Crypt"], decode_parms={"/Name": "/Other"}).metadata["status"] == "encrypted"


@pytest.mark.parametrize("corrupt", [lambda value: value[:-2], lambda value: value[:-1] + bytes([value[-1] ^ 1])])
def test_bad_flate_retains_decoded_prefix_and_stops_the_chain(corrupt):
    payload = b"4142>"
    raw = corrupt(zlib.compress(payload))
    result = decode_filters(raw, ["/FlateDecode", "/ASCIIHexDecode"])
    assert result.data is None and result.partial_data == payload
    assert result.metadata["status"] == "decode_error"
    assert result.metadata["steps"][1]["status"] == "not_run"
    assert result.metadata["decoded_bytes"] is None
    assert result.metadata["decoded_byte_debit"] == len(payload)


def test_decompression_bomb_is_capped_before_allocating_the_full_output():
    raw = zlib.compress(b"A" * 100_000)
    limits = FilterLimits(max_stage_bytes=64, max_total_bytes=64)
    budget = DecodeBudget(64)
    result = decode_filters(raw, ["/FlateDecode"], limits=limits, budget=budget)
    assert result.data is None and result.partial_data == b"A" * 64
    assert result.metadata["status"] == "resource_limit" and budget.remaining == 0
    assert result.metadata["decoded_byte_debit"] == 64
    # A shared budget cannot be reset by moving to the next stream.
    other = decode_filters(zlib.compress(b"B"), ["/FlateDecode"], limits=limits, budget=budget)
    assert other.metadata["status"] == "resource_limit" and other.partial_data == b""


def test_expansion_ratio_and_per_call_budget_apply_even_with_a_larger_shared_budget():
    raw = zlib.compress(b"A" * 2000)
    limits = FilterLimits(max_expansion_ratio=2)
    result = decode_filters(raw, ["/FlateDecode"], limits=limits)
    assert len(result.partial_data) == len(raw) * 2 and result.metadata["status"] == "resource_limit"
    result = decode_filters(b"4142434445>", ["/ASCIIHexDecode"], limits=replace(limits, max_total_bytes=3), budget=DecodeBudget(100))
    assert result.partial_data == b"ABC" and result.metadata["decoded_byte_debit"] == 3


@pytest.mark.parametrize("raw,expected", [(b"F>", b"\xf0"), (b"41 42\t43>\n", b"ABC"), (b"00>\x00", b"\0")])
def test_asciihex_odd_nibbles_whitespace_and_null_bytes(raw, expected):
    assert decode_filters(raw, ["/ASCIIHexDecode"]).data == expected


@pytest.mark.parametrize("raw,prefix", [(b"4142G>", b"AB"), (b"4142", b"AB"), (b"41>X", b"A")])
def test_asciihex_errors_preserve_only_completed_byte_prefixes(raw, prefix):
    result = decode_filters(raw, ["/ASCIIHexDecode"])
    assert result.data is None and result.partial_data == prefix
    assert result.metadata["status"] == "decode_error"


@pytest.mark.parametrize("size", [1, 2, 3, 4, 5, 31, 257])
def test_ascii85_matches_standard_library_encoder_including_partial_tuples(size):
    data = bytes((index * 83) % 256 for index in range(size))
    for adobe in (False, True):
        raw = base64.a85encode(data, adobe=adobe)
        if not adobe:
            raw += b"~>"
        assert decode_filters(raw, ["/ASCII85Decode"]).data == data


@pytest.mark.parametrize("raw", [b"!z~>", b"!~>", b"uuuuu~>", b"zz", b"z~>X", b"y~>"])
def test_ascii85_rejects_invalid_tuples_endings_and_extensions(raw):
    result = decode_filters(raw, ["/ASCII85Decode"])
    assert result.data is None and result.metadata["status"] == "decode_error"


def test_runlength_literals_repeats_and_truncation():
    assert decode_filters(b"\x02ABC\xffZ\x80", ["/RunLengthDecode"]).data == b"ABCZZ"
    assert decode_filters(b"\x81X\x80", ["/RunLengthDecode"]).data == b"X" * 128
    result = decode_filters(b"\x02AB", ["/RunLengthDecode"])
    assert result.partial_data == b"AB" and result.metadata["status"] == "decode_error"


@pytest.mark.parametrize("size", [1, 100, 1024, 16000])
def test_lzw_matches_pinned_upstream_encoder_across_width_changes_and_table_resets(size):
    # Hash-derived bytes are deterministic and exercise dictionary growth without
    # machine state or a random generator shared with the decoder implementation.
    data = b"".join(hashlib.sha256(str(index).encode()).digest() for index in range((size + 31) // 32))[:size]
    encoded = LzwCodec().encode(data)
    result = decode_filters(encoded, ["/LZWDecode"])
    assert result.data == data, result.metadata


def test_lzw_truncated_end_and_invalid_clear_are_not_complete():
    result = decode_filters(LzwCodec().encode(b"ABC")[:-1], ["/LZWDecode"])
    assert result.metadata["status"] == "decode_error" and result.data is None
    assert result.partial_data == b"ABC"
    result = decode_filters(b"\0\0", ["/LZWDecode"])
    assert result.metadata["reason_codes"] == ["missing_lzw_clear"]


@pytest.mark.parametrize("early_change", [0, 1])
def test_lzw_explicit_width_transition_vectors_for_both_early_change_modes(early_change):
    # Valid, deliberately uncompressed literal-code stream. Independent fixed
    # transition positions encode all 9/10/11/12-bit boundaries and an EOD.
    count = 2600
    def width(index):
        return 9 if index < 255 - early_change else 10 if index < 767 - early_change else 11 if index < 1791 - early_change else 12
    bits = format(256, '09b') + ''.join(format(index % 256, f'0{width(index)}b') for index in range(count)) + format(257, f'0{width(count)}b')
    bits += '0' * (-len(bits) % 8)
    encoded = int(bits, 2).to_bytes(len(bits) // 8, 'big')
    expected = bytes(index % 256 for index in range(count))
    result = decode_filters(encoded, ["/LZWDecode"], decode_parms={"/EarlyChange": early_change})
    assert result.data == expected


@pytest.mark.parametrize("encoded,parameters,expected", [
    (b"\x02\x01\x02\x03\x02\x03\x03\x03", {"/Predictor": 12, "/Columns": 3}, b"\x01\x02\x03\x04\x05\x06"),
    (b"\x01\x01\x02\x03\x03\x03\x03", {"/Predictor": 15, "/Columns": 2, "/Colors": 3}, b"\x01\x02\x03\x04\x05\x06"),
    (b"\x01\x80\x80", {"/Predictor": 15, "/Columns": 9, "/BitsPerComponent": 1}, b"\x80\x00"),
    (b"\x12\x30", {"/Predictor": 2, "/Columns": 3, "/BitsPerComponent": 4}, b"\x13\x60"),
    (b"\x54", {"/Predictor": 2, "/Columns": 3, "/BitsPerComponent": 2}, b"\x6c"),
    (b"\x00\x01\x00\x02\x00\x03", {"/Predictor": 2, "/Columns": 3, "/BitsPerComponent": 16}, b"\x00\x01\x00\x03\x00\x06"),
    (b"\x03\x02\x02\x02", {"/Predictor": 15, "/Columns": 3}, b"\x02\x03\x03"),
    (b"\x00\x0a\x14\x1e\x04\x01\x01\x01", {"/Predictor": 15, "/Columns": 3}, b"\x0a\x14\x1e\x0b\x15\x1f"),
])
def test_predictors_respect_color_stride_packed_samples_and_word_endianness(encoded, parameters, expected):
    result = decode_filters(zlib.compress(encoded), ["/FlateDecode"], decode_parms=parameters)
    assert result.data == expected
    assert result.metadata["steps"][0]["predictor_input_sha256"] == hashlib.sha256(encoded).hexdigest()


def test_truncated_predictor_retains_prior_rows_and_pre_predictor_evidence():
    encoded = b"\x00ABC\x00X"
    result = decode_filters(zlib.compress(encoded), ["/FlateDecode"], decode_parms={"/Predictor": 15, "/Columns": 3})
    assert result.data is None and result.partial_data == b"ABC"
    assert result.metadata["decoded_byte_debit"] == len(encoded)
    step = result.metadata["steps"][0]
    assert step["predictor_input_bytes"] == len(encoded)
    assert step["reason_codes"] == ["truncated_predictor_row"]


def test_unsupported_parameters_and_chain_alignment_fail_before_decoding():
    result = decode_filters(zlib.compress(b"ABC"), ["/FlateDecode"], decode_parms={"/Custom": 1})
    assert result.metadata["status"] == "unsupported" and result.partial_data is None
    assert result.metadata["decoded_byte_debit"] == 0
    result = decode_filters(b"41>", ["/ASCIIHexDecode"], decode_parms=[])
    assert result.metadata["reason_codes"] == ["filter_parameter_alignment"]


def test_retention_identity_mismatch_and_excessive_input_are_refused():
    with pytest.raises(ValueError, match="retention identity"):
        decode_filters(b"x", retain=lambda data: {"sha256": "0" * 64, "size_bytes": 1})
    with pytest.raises(ValueError, match="input byte cap"):
        decode_filters(b"AB", limits=FilterLimits(max_input_bytes=1))
    result = decode_filters(b"x", ["/Fl"] * 9)
    assert result.metadata["status"] == "resource_limit" and result.metadata["decoded_bytes"] is None
    assert result.metadata["declared_filter_count"] == 9 and not result.metadata["filter_sequence_complete"]
    assert len(result.metadata["filters"]) == 8


def test_each_completed_filter_emits_an_independent_checkpoint_before_later_failure():
    compressed = zlib.compress(b"inert")[:-2]
    raw = compressed.hex().encode() + b">"
    checkpoints = []
    result = decode_filters(raw, ["/ASCIIHexDecode", "/FlateDecode"], checkpoint=checkpoints.append)
    first = next(item for item in checkpoints if len(item["steps"]) == 1)
    assert first["status"] == "partial" and not first["complete"]
    assert first["steps"][0]["complete"] and first["steps"][0]["output_sha256"] == hashlib.sha256(compressed).hexdigest()
    assert first["decoded_byte_debit"] == len(compressed)
    assert result.metadata["status"] == "decode_error" and result.data is None
    assert len(first["steps"]) == 1  # Later stages cannot mutate an older checkpoint.
