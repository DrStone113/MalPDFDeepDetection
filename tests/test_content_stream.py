import pytest

from malpdf.extraction.content_stream import (
    ContentStreamIssue,
    inspect_content_stream,
    tokenize_stream,
)


def test_normal_visible_text_stream() -> None:
    data = b"BT /F1 12 Tf 72 712 Td (Hello World) Tj ET"
    result = inspect_content_stream(data)
    assert result["complete"]
    assert result["total_characters"] == 11
    assert result["visible_characters"] == 11
    assert result["invisible_characters"] == 0
    assert result["invisible_character_ratio"] == 0.0
    assert result["text_blocks_count"] == 1
    assert "/F1" in result["font_names_present"]
    assert not result["has_text_rendering_mode_3"]
    assert not result["has_zero_font_size"]
    assert not result["has_white_on_white_text"]


def test_invisible_text_rendering_mode_3() -> None:
    data = b"BT /F1 12 Tf 3 Tr (Hidden Keyword) Tj ET"
    result = inspect_content_stream(data)
    assert not result["complete"]
    assert "invisible_text_tr3" in result["reason_codes"]
    assert result["has_text_rendering_mode_3"]
    assert result["invisible_characters"] == 14
    assert result["visible_characters"] == 0
    assert result["invisible_character_ratio"] == 1.0


def test_zero_font_size_detection() -> None:
    data = b"BT /F1 0 Tf (Hidden by Zero Size) Tj ET"
    result = inspect_content_stream(data)
    assert not result["complete"]
    assert "zero_font_size" in result["reason_codes"]
    assert result["has_zero_font_size"]
    assert result["invisible_characters"] == 19
    assert result["invisible_character_ratio"] == 1.0


def test_white_on_white_text_detection() -> None:
    data = b"BT /F1 12 Tf 1 1 1 rg (White on White Text) Tj ET"
    result = inspect_content_stream(data)
    assert not result["complete"]
    assert "white_on_white_text" in result["reason_codes"]
    assert result["has_white_on_white_text"]
    assert result["visible_characters"] == 19


def test_off_page_coordinates_detection() -> None:
    data = b"BT /F1 12 Tf 9999 9999 Td (Off Page Text) Tj ET"
    result = inspect_content_stream(data, boundary_box=(0, 0, 612, 792))
    assert not result["complete"]
    assert "off_page_text" in result["reason_codes"]
    assert result["has_off_page_text"]


def test_array_tj_and_hex_strings() -> None:
    data = b"BT /F1 12 Tf [(Hello) -120 <576f726c64>] TJ ET"
    result = inspect_content_stream(data)
    assert result["complete"]
    assert result["total_characters"] == 10
    assert result["visible_characters"] == 10


def test_graphics_state_stack_q_and_Q() -> None:
    data = (
        b"q\n"
        b"BT /F1 12 Tf 3 Tr (Hidden Inside State) Tj ET\n"
        b"Q\n"
        b"BT /F2 10 Tf 0 Tr (Visible Outside) Tj ET"
    )
    result = inspect_content_stream(data)
    assert not result["complete"]
    assert "invisible_text_tr3" in result["reason_codes"]
    assert result["total_characters"] == 34
    assert result["invisible_characters"] == 19
    assert result["visible_characters"] == 15
    assert result["font_names_present"] == ["/F1", "/F2"]


def test_stream_comments_and_escaped_strings() -> None:
    data = (
        b"% Header comment\n"
        b"BT /F1 12 Tf (String with \\(nested\\) parens) Tj ET % End comment"
    )
    result = inspect_content_stream(data)
    assert result["complete"]
    assert result["visible_characters"] == 27


def test_unterminated_literal_string_raises_issue() -> None:
    data = b"BT /F1 12 Tf (Unterminated string"
    with pytest.raises(ContentStreamIssue, match="unterminated_literal_string"):
        inspect_content_stream(data)


def test_invalid_hex_string_raises_issue() -> None:
    data = b"BT /F1 12 Tf <ZZZZ> Tj ET"
    with pytest.raises(ContentStreamIssue, match="invalid_hex_string"):
        inspect_content_stream(data)


def test_carver_analyzes_content_stream_artifact() -> None:
    import hashlib
    from malpdf.extraction.carving import RecursiveCarver
    from malpdf.static.code_inspector import VMInspectionLimits
    from malpdf.static.execution import UNLIMITED

    data = b"BT /F1 12 Tf 3 Tr (Hidden Payload) Tj ET"
    digest = hashlib.sha256(data).hexdigest()
    carver = RecursiveCarver("a" * 64, VMInspectionLimits())
    identity = carver.add(data, parent_id="source", decoded_sha256=digest, hint="content_stream")
    result = carver.finish(UNLIMITED)
    assert result["records"][0]["kind"] == "content_stream"
    assert result["records"][0]["status"] == "partial"
    assert "invisible_text_tr3" in result["records"][0]["reason_codes"]
    analysis = result["analyses"][identity]
    assert analysis["has_text_rendering_mode_3"] is True
    assert analysis["invisible_characters"] == 14


def test_stream_collector_observes_form_and_untyped_content_stream() -> None:
    from malpdf.extraction.streams import StreamCollector
    from malpdf.static.code_inspector import VMInspectionLimits
    from malpdf.static.execution import UNLIMITED
    from pypdf.generic import ArrayObject, EncodedStreamObject, NameObject, NumberObject

    body = b"q /F1 10 Tf 1 0 0 1 10 10 cm (Visible) Tj Q"
    stream = EncodedStreamObject()
    stream._data = body
    stream.update({NameObject("/Subtype"): NameObject("/Form"),
                   NameObject("/BBox"): ArrayObject([NumberObject(0), NumberObject(0), NumberObject(100), NumberObject(100)])})
    collector = StreamCollector("a" * 64, VMInspectionLimits())
    routed = []
    collector.artifact_sink = lambda d, entry: routed.append((d, entry))
    collector.observe(stream, backend="pypdf", source_id="form_source", object_number=1, generation=0, offset=0)
    assert len(collector.sources) == 1
    assert collector.sources[0][1]["artifact_context"]["hint"] == "content_stream"
    assert collector.sources[0][1]["artifact_context"]["boundary_box"] == [0.0, 0.0, 100.0, 100.0]
    result = collector.finish(UNLIMITED)
    assert len(routed) == 1
    assert routed[0][0] == body
