"""Stream bounded XFA XML into the existing inert JavaScript inspector."""

from bisect import bisect_right
from xml.parsers import expat

from malpdf.static.js_ast import CodeInspectionError


def inspect_xfa_xml(chunks, *, start_script, finish_script, problem, node_observed,
                    max_nodes, max_depth, max_script_bytes):
    """Parse one XML document, including ordered PDF XFA packet fragments.

    Callbacks receive fixed metadata, never arbitrary XML names/attributes.
    DTDs, entities, inherited/external scripts and non-text script markup are
    unsupported. No DOM, external resource fetch or script execution occurs.
    Production access must stay inside the resource-limited PDF worker.
    """
    parser = expat.ParserCreate(namespace_separator="}")
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    starts, origins = [], []
    depth = nodes = offset = non_javascript = 0
    active = None

    def origin():
        index = bisect_right(starts, parser.CurrentByteIndex) - 1
        return origins[max(index, 0)]

    def reject(*args):
        raise CodeInspectionError("xfa_xml_dtd_unsupported")

    def start(name, attributes):
        nonlocal depth, nodes, active, non_javascript
        depth += 1; nodes += 1
        node_observed()
        if nodes > max_nodes:
            raise CodeInspectionError("xfa_xml_node_limit")
        if depth > max_depth:
            raise CodeInspectionError("xfa_xml_depth_limit")
        if active is not None:
            raise CodeInspectionError("xfa_script_markup_unsupported")
        referenced = any(key.rsplit("}", 1)[-1] in {"use", "usehref", "href"} for key in attributes)
        if referenced:
            problem("xfa_reference_unsupported")
        if name.rsplit("}", 1)[-1] != "script":
            return
        language = attributes.get("contentType", "application/x-formcalc")
        if language == "application/x-javascript":
            source = start_script({**origin(), "xml_byte_offset": parser.CurrentByteIndex})
            active = (source, [], 0, referenced)
        elif language == "application/x-formcalc":
            non_javascript += 1
        else:
            problem("xfa_script_language_unsupported")

    def text(value):
        nonlocal active
        if active is None:
            return
        source, parts, size, referenced = active
        size += len(value.encode("utf-8"))
        if size > max_script_bytes:
            raise CodeInspectionError("script_byte_limit")
        parts.append(value)
        active = source, parts, size, referenced

    def end(name):
        nonlocal depth, active
        if active is not None:
            source, parts, _, referenced = active
            source["xfa_end_packet_index"] = origin()["packet_index"]
            if referenced:
                source["error"] = "xfa_reference_unsupported"
            else:
                finish_script(source, "".join(parts))
            active = None
        depth -= 1

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = text
    parser.StartDoctypeDeclHandler = reject
    parser.EntityDeclHandler = reject
    parser.ExternalEntityRefHandler = reject
    try:
        for data, metadata in chunks:
            starts.append(offset); origins.append(metadata)
            offset += len(data)
            for position in range(0, len(data), 8192):
                parser.Parse(data[position:position + 8192], False)
        parser.Parse(b"", True)
    except expat.ExpatError:
        raise CodeInspectionError("xfa_xml_parse_error") from None
    return {"xml_nodes": nodes, "non_javascript_scripts": non_javascript}
