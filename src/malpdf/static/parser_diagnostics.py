"""Fixed parser reason codes; never retain exception text or PDF content."""

from contextlib import contextmanager
import logging

_EXCEPTION_TYPES = frozenset({"PdfReadError", "PdfStreamError", "EmptyFileError", "FileNotDecryptedError",
    "DependencyError", "ParseError", "ValueError", "TypeError", "KeyError", "IndexError", "EOFError",
    "OSError", "RuntimeError", "RecursionError", "MemoryError", "UnicodeDecodeError", "CodeInspectionError"})
_REASONS = (("broken xref table", "xref_invalid"), ("startxref not found", "startxref_missing"),
    ("eof marker not found", "eof_missing"), ("cannot rebuild xref", "xref_rebuild_failed"),
    ("xref table read error", "xref_read_failed"), ("could not find xref table", "xref_missing"),
    ("trailer cannot be read", "trailer_unreadable"), ("cannot find root object", "root_missing"),
    ("maximum recursion depth", "recursion_limit"), ("pdf_reference_limit", "reference_limit"))
_RECOVERY = (("incorrect startxref pointer", "xref_offset_recovery"),
    ("malpdf xrefstm incomplete", "xrefstm_partial"),
    ("invalid/truncated xref table", "xref_table_rebuild"), ("xref table not zero-indexed", "xref_index_recovery"),
    ("rebuilding xref", "xref_table_rebuild"), ("parsing for object streams", "object_stream_recovery"),
    ("eof marker seems truncated", "eof_recovery"), ("eof marker not found", "eof_recovery"))


def exception_type(error):
    name = type(error).__name__
    return name if name in _EXCEPTION_TYPES else "OtherError"


class ParserDiagnostics:
    def __init__(self, *, strict):
        self.data = {"strict": strict, "open_success": False, "recovery_notice_codes": [], "failures": [],
            "scope": "fixed exception categories and pypdf open-time recovery notices; no raw messages or complete repair history"}

    def failure(self, error, stage):


        message = str(error)[:512].lower()
        reason = next((code for phrase, code in _REASONS if phrase in message), "unclassified_parser_exception")
        event = {"stage": stage, "exception_type": exception_type(error), "reason": reason}
        if event not in self.data["failures"] and len(self.data["failures"]) < 16:
            self.data["failures"].append(event)

    @contextmanager
    def capture_open_notices(self):
        observed = set()
        class Notices(logging.Handler):
            def emit(self, record):
                message = record.getMessage()[:512].lower()
                observed.update(code for phrase, code in _RECOVERY if phrase in message)
        logger = logging.getLogger("pypdf")
        handler = Notices(level=logging.WARNING)
        level = logger.level
        logger.setLevel(logging.WARNING)
        logger.addHandler(handler)
        try:
            yield
        finally:
            logger.removeHandler(handler)
            logger.setLevel(level)
            self.data["recovery_notice_codes"] = sorted(observed)
