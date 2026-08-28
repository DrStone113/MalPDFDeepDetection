"""Canonical RIT-schema metadata used by the static extractor.

The feature names and paper meanings deliberately originate in the existing
paper-alignment module.  This module adds extractor-specific implementation
status without creating an independent feature-name list.
"""

from __future__ import annotations

from collections.abc import Mapping

from malpdf.data.rit_pdfmal_paper_alignment import PAPER_FEATURE_DICTIONARY
from malpdf.static.result import FeatureStatus

RIT_FEATURES = tuple(item["column"] for item in PAPER_FEATURE_DICTIONARY)
RIT_FEATURE_DETAILS = {item["column"]: item for item in PAPER_FEATURE_DICTIONARY}
PROTOCOL_G_DROPPED_CONSTANT_FEATURES = ("Acroform", "Colors", "BaseEncoding")
PROTOCOL_G_REQUIRED_FEATURES = tuple(
    feature for feature in RIT_FEATURES if feature not in PROTOCOL_G_DROPPED_CONSTANT_FEATURES
)

if len(RIT_FEATURES) != 41 or len(set(RIT_FEATURES)) != 41:
    raise RuntimeError("The committed RIT schema must contain exactly 41 unique predictive features")
if len(PROTOCOL_G_REQUIRED_FEATURES) != 38:
    raise RuntimeError("Protocol G drop3constant must require exactly 38 features")


# Paper Table 2 explicitly defines most of these as occurrences of a named
# string.  Exact lexical counting implements that documented concept; it is
# nevertheless kept distinct from parser-confirmed active-content structure.
_VERIFIED_RAW_FEATURES = frozenset(
    {
        "obj", "endobj", "stream", "endstream", "trailer", "xref", "startxref",
        "page_command", "Encrypt", "JS", "JavaScript", "AA", "OpenAction",
        "Acroform", "JBIG2Decode", "RichMedia", "Launch", "EmbeddedFile", "XFA",
        "Colors", "URI", "BaseEncoding", "Encoding", "ProcSet", "Registry",
        "Resources", "www", "server", "Root", "BitsPerComponent",
    }
)

_PROVISIONAL_FEATURES = frozenset(
    {"pages", "title length", "embedded files", "images", "contains_text", "pdf_ver", "ObjStm"}
)
_AMBIGUOUS_FEATURES = frozenset({"pdfsize", "metadata size", "xref length"})


def implementation_statuses() -> Mapping[str, FeatureStatus]:
    """Return static implementation status for all 41 ordered RIT features."""
    statuses: dict[str, FeatureStatus] = {}
    for feature in RIT_FEATURES:
        if feature in _VERIFIED_RAW_FEATURES or feature == "isEncrypted":
            statuses[feature] = FeatureStatus.IMPLEMENTED_VERIFIED_SEMANTICS
        elif feature in _PROVISIONAL_FEATURES:
            statuses[feature] = FeatureStatus.IMPLEMENTED_PROVISIONAL
        elif feature in _AMBIGUOUS_FEATURES:
            statuses[feature] = FeatureStatus.AMBIGUOUS
        else:  # Defensive guard if the source-of-truth dictionary changes.
            statuses[feature] = FeatureStatus.UNSUPPORTED
    return statuses


def feature_meaning(feature: str) -> str:
    """Return the documented RIT meaning for a canonical feature."""
    return str(RIT_FEATURE_DETAILS[feature]["paper_meaning"])
