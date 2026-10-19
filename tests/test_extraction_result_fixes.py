"""Synthetic regressions motivated by saved VM JSON, without corpus access."""

from copy import deepcopy
import hashlib
import json
import re

import pytest

from malpdf.extraction.arlington_memo import BindingMemo
from malpdf.extraction.arlington_model import Catalog
from malpdf.extraction.arlington_validate import RuleLimits, Value, _Engine
from malpdf.extraction.contracts import validate_bundle
from malpdf.extraction.normalize import normalize_profile
from malpdf.extraction.raw import inspect_raw_layout
from malpdf.extraction.raw_forensic import ForensicLimits, _Document
from malpdf.extraction.raw_syntax import SyntaxIssue
from malpdf.extraction.vm_jobs import run_vm_job
from malpdf.static.code_inspector import CodeInspectionLimits, VMInspectionLimits
from malpdf.static.execution import UNLIMITED, expand_limits
from test_arlington import catalog, pdf, row
from test_extraction_jobs import root
from test_extraction_performance import resumable


def document(data: bytes, *, bounded: bool = False) -> _Document:
    limits = CodeInspectionLimits() if bounded else VMInspectionLimits()
    forensic = ForensicLimits() if bounded else expand_limits(ForensicLimits(), limits)
    doc = _Document(data, limits, 1024**2 if bounded else UNLIMITED, forensic, None, None, None)
    doc.run(None)
    return doc


def engine(doc: _Document, model: Catalog, *, memo: bool = True, rules: RuleLimits | None = None) -> _Engine:
    value = _Engine(doc, model, rules or expand_limits(RuleLimits(), doc.code), None)
    value.memo.enabled = value.memo.enabled and memo
    return value


def shared_graph(levels: int = 4) -> tuple[bytes, Catalog]:
    tables = {}
    objects = []
    for level in range(levels):
        model = "Catalog" if level == 0 else f"Branch{level}"
        target = level + 2
        tables[model] = tuple(row(key, "dictionary", Link=f"[Branch{level + 1}]") for key in ("A", "B"))
        if level:
            objects.append((level + 1, f"<< /A {target} 0 R /B {target} 0 R >>".encode()))
    tables[f"Branch{levels}"] = (row("N", Required="TRUE"),)
    objects.append((levels + 1, b"<< /N 8 >>"))
    model = catalog(tables.pop("Catalog"), **tables)
    return pdf(b"<< /A 2 0 R /B 2 0 R >>", objects), model


def cyclic_alternatives() -> tuple[bytes, Catalog]:
    alternatives = "[FieldA,FieldB,FieldC]"
    tables = {name: (row("Parent", "dictionary", Link=alternatives), row("Kids", "array", Link="[FieldList]"))
              for name in ("FieldA", "FieldB", "FieldC")}
    model = catalog([row("Fields", "array", Link="[FieldList]")],
                    FieldList=(row("*", "dictionary", Link=alternatives),), **tables)
    data = pdf(b"<< /Fields [2 0 R 2 0 R] >>",
               [(2, b"<< /Kids [3 0 R 3 0 R] >>"), (3, b"<< /Parent 2 0 R >>")])
    return data, model


def check_semantics(value: dict) -> set[str]:
    return {json.dumps({key: item for key, item in check.items() if key not in {"id", "binding_id"}}, sort_keys=True)
            for check in value["checks"]}


def test_shared_dag_keeps_rule_outcomes_and_every_incoming_link() -> None:
    data, model = shared_graph()
    doc = document(data)
    before = deepcopy(doc.value)
    reference = engine(doc, model, memo=False).run()
    result = engine(doc, model).run()
    assert result["root_schema_candidate_outcomes"] == reference["root_schema_candidate_outcomes"]
    assert check_semantics(result) == check_semantics(reference)
    assert len(result["bindings"]) == 6
    assert len(result["binding_reuses"]) == 4
    assert len(reference["bindings"]) == 32
    assert doc.value == before
    assert len(result["checks"]) < len(reference["checks"]) / 3
    profile = {"status": "complete", "raw_layout": inspect_raw_layout(data),
               "raw_forensic": doc.value, "arlington_analysis": result}
    bundle = normalize_profile(profile, hashlib.sha256(data).hexdigest(), "deep-static")
    validate_bundle(bundle)
    edges = bundle["evidence_store"]["edges"]
    assert len([edge for edge in edges if edge["kind"] == "arlington_completed_binding_reuse"]) == 4
    assert next(item for item in bundle["feature_store"]["records"]
                if item["feature_name"] == "arlington_reused_schema_bindings")["value"] == 4


def test_cycle_results_are_not_cached_as_context_independent_results() -> None:
    data = pdf(b"<< /A 2 0 R /B 3 0 R >>", [(2, b"<< /Next 3 0 R >>"), (3, b"<< /Next 2 0 R >>")])
    model = catalog([row(key, "dictionary", Link="[Chain]") for key in ("A", "B")],
                    Chain=(row("Next", "dictionary", Link="[Chain]"),))
    doc = document(data)
    reference = engine(doc, model, memo=False).run()
    value = engine(doc, model)
    result = value.run()
    assert result["root_schema_candidate_outcomes"] == reference["root_schema_candidate_outcomes"]
    assert check_semantics(result) == check_semantics(reference)
    assert not result["binding_reuses"] and not value.memo.completed
    assert any("schema_link_cycle" in check["reason_codes"] for check in result["checks"])


def test_cached_subtrees_cannot_hide_an_active_ancestor_or_bypass_depth() -> None:
    memo = BindingMemo(True)
    memo.begin(("parent",), 0)
    memo.begin(("child",), 1)
    memo.finish(("child-key",), "child-id", False)
    memo.finish(("parent-key",), "parent-id", False)
    assert memo.find(("parent-key",), {("child",)}, 0, 24) is None
    assert memo.find(("parent-key",), set(), 24, 24) is None
    assert memo.find(("parent-key",), set(), 23, 24).result is False


def test_cycle_result_reuse_requires_identical_ancestors_and_depth() -> None:
    data = pdf(b"<< /A 2 0 R /B 2 0 R /C 3 0 R >>", [(2, b"<< /Next 3 0 R >>"), (3, b"<< /Next 2 0 R >>")])
    model = catalog([row(key, "dictionary", Link="[Chain]") for key in ("A", "B", "C")],
                    Chain=(row("Next", "dictionary", Link="[Chain]"),))
    doc = document(data)
    reference = engine(doc, model, memo=False).run()
    result = engine(doc, model).run()
    assert result["root_schema_candidate_outcomes"] == reference["root_schema_candidate_outcomes"]
    assert check_semantics(result) == check_semantics(reference)
    assert len(result["binding_reuses"]) == 1
    assert result["binding_reuses"][0]["cache_scope"] == "identical_active_ancestors_and_depth"
    assert result["binding_reuses"][0]["outcome"] == "indeterminate"


def test_contextual_cache_rejects_other_ancestor_sets_and_propagates_cycle_dependency() -> None:
    memo = BindingMemo(True)
    memo.begin(("parent",), 0)
    memo.begin(("child",), 1)
    memo.note_cycle()
    memo.finish(("child-key",), "child-id", False)
    memo.finish(("parent-key",), "parent-id", False)
    assert memo.find(("child-key",), {("different",)}, 1, 24) is None
    assert memo.find(("child-key",), {("parent",)}, 2, 24) is None
    memo.begin(("parent",), 0)
    assert memo.find(("child-key",), {("parent",)}, 1, 24).result is False
    memo.finish(("parent-copy",), "copy-id", False)
    assert not memo.completed


def test_cyclic_schema_alternatives_retain_unknowns_without_exponential_path_rechecks() -> None:
    data, model = cyclic_alternatives()
    doc = document(data)
    reference = engine(doc, model, memo=False).run()
    result = engine(doc, model).run()
    assert result["root_schema_candidate_outcomes"] == reference["root_schema_candidate_outcomes"]
    assert check_semantics(result) == check_semantics(reference)
    assert len(result["checks"]) < len(reference["checks"]) / 2
    assert any(item["cache_scope"] == "identical_active_ancestors_and_depth" for item in result["binding_reuses"])
    assert any("schema_link_cycle" in item["reason_codes"] for item in result["checks"])


def test_shared_binding_export_rejects_missing_canonical_targets() -> None:
    data, model = shared_graph(1)
    doc = document(data)
    result = engine(doc, model).run()
    result["binding_reuses"][0]["target_binding_id"] = "missing-canonical-binding"
    profile = {"status": "complete", "raw_layout": inspect_raw_layout(data),
               "raw_forensic": doc.value, "arlington_analysis": result}
    with pytest.raises(ValueError, match="arlington_reuse_binding_identity"):
        normalize_profile(profile, hashlib.sha256(data).hexdigest(), "deep-static")


@pytest.mark.parametrize("context", ["version", "revision", "stream"])
def test_binding_memo_separates_semantic_contexts(context: str) -> None:
    data = pdf(b"<< /N 8 >>")
    doc = document(data)
    value = engine(doc, catalog([], Target=(row("N", SinceVersion="2.0"),)))
    item = next(iter(doc.objects.values()))
    ref = Value(item["node"], item["record"]["id"], item)
    value.bind(ref, "Target", 0, (1, 7), None, 0, "one")
    revision, version = (1, (1, 7)) if context == "revision" else (0, (2, 0)) if context == "version" else (0, (1, 7))
    if context == "stream":
        ref = Value(item["node"], item["record"]["id"], {**item, "record": {**item["record"], "stream": {"boundary_verified": True}}})
    value.bind(ref, "Target", revision, version, None, 0, "two")
    assert len(value.value["bindings"]) == 2 and not value.value["binding_reuses"]
    value.bind(ref, "Target", revision, version, None, 0, "three")
    assert len(value.value["bindings"]) == 2 and len(value.value["binding_reuses"]) == 1
    if context == "version":
        assert [record["outcome"] for record in value.value["bindings"]] == ["fail", "pass"]


def test_unknown_rules_stay_unknown_when_a_completed_binding_is_reused() -> None:
    data = pdf(b"<< /A 2 0 R /B 2 0 R >>", [(2, b"<< /N 8 >>")])
    model = catalog([row(key, "dictionary", Link="[Leaf]") for key in ("A", "B")],
                    Leaf=(row("N", SpecialCase="[fn:Not(fn:Unknown())]"),))
    result = engine(document(data), model).run()
    assert result["root_schema_candidate_outcomes"][0]["outcome"] == "indeterminate"
    assert len(result["binding_reuses"]) == 1
    assert result["binding_reuses"][0]["outcome"] == "indeterminate"
    assert any("unsupported_predicate:Unknown" in check["reason_codes"] for check in result["checks"])


def test_incomplete_bindings_are_never_cached_and_bounded_policy_keeps_occurrences() -> None:
    data, model = shared_graph(2)
    value = engine(document(data), model, rules=RuleLimits(max_checks=1))
    with pytest.raises(ValueError, match="arlington_check_limit"):
        value.run()
    assert not value.memo.completed and not value.memo.frames
    bounded = engine(document(data, bounded=True), model).run()
    assert "binding_reuses" not in bounded
    assert len(bounded["bindings"]) == 8


def test_invalid_xref_offset_is_distinct_from_the_number_of_xref_blocks() -> None:
    data = re.sub(rb"startxref\n[0-9]+", b"startxref\n999999999", pdf())
    result = document(data).value
    assert "forensic_xref_offset_invalid" in result["reason_codes"]
    assert "forensic_xref_offset_or_count_limit" not in result["reason_codes"]
    doc = document(pdf(), bounded=True)
    doc.xrefs = {-index: {} for index in range(1, doc.limits.max_revisions * 2 + 1)}
    with pytest.raises(SyntaxIssue) as caught:
        doc.xref_at(doc.data.index(b"xref\n"))
    assert caught.value.status == "resource_limit" and caught.value.code == "forensic_xref_count_limit"


def test_interruption_during_worker_cleanup_still_writes_coverage_and_resume_metadata(resumable, monkeypatch) -> None:
    root, config, calls = resumable
    from malpdf.extraction import vm_jobs
    original = vm_jobs.extract_pdfs

    class InterruptedResults:
        def __init__(self, *args, **kwargs):
            self.values = original(*args, **kwargs)
            self.delivered = False

        def __iter__(self):
            return self

        def __next__(self):
            if self.delivered:
                raise KeyboardInterrupt()
            self.delivered = True
            return next(self.values)

        def close(self):
            self.values.close()
            raise KeyboardInterrupt()

    monkeypatch.setattr(vm_jobs, "extract_pdfs", InterruptedResults)
    with pytest.raises(KeyboardInterrupt):
        run_vm_job(root, config)
    path = next((root / "reports/experiments/pdf_extraction_vm").glob("*/run_summary.json"))
    state = json.loads(path.read_text())
    coverage = json.loads(path.with_name("coverage_summary.json").read_text())
    assert state["status"] == "interrupted" and state["rows"] == 1
    assert state["output_path"] and coverage["completed"] == 1 and coverage["not_completed"] == 2
    monkeypatch.setattr(vm_jobs, "extract_pdfs", original)
    resumed = run_vm_job(root, config, resume_from=state["run_id"])
    assert resumed["reused"] == 1 and resumed["rows"] == 3
