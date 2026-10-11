"""Synthetic evidence graphs and original adapter values; no PDF corpus."""

from copy import deepcopy
import hashlib
import io

import pytest

from malpdf.experiments.cic_v8 import v8_feature_values
from malpdf.inference.evidence_policy_v9 import (
    build_dependency_ledger, evidence_decision_v9, frozen_feature_order, verify_model_inputs,
)
from malpdf.static.schema import RIT_FEATURES

DIGEST = hashlib.sha256(b"synthetic original PDF byte identity").hexdigest()
HASH = hashlib.sha256(b"synthetic inert content").hexdigest()
IDENTITY = {"model_id": "c1-v8-fixed-rf-evidence-v1", "train_rows": 31,
            "feature_count": 173, "threshold": 0.5, "artifact_sha256": HASH}


def node(identifier, kind, **extra):
    return {"id": identifier, "kind": kind, "backend": "pypdf", "document_sha256": DIGEST,
            "status": "verified", "object_number": "unknown", "generation": "unknown",
            "revision": "unknown", "offset": "unknown", "raw_sha256": "unknown",
            "decoded_sha256": "unknown", "locator": identifier, "reason_codes": [], **extra}


def edge(source, target, kind):
    return {"id": f"edge:{source}:{kind}:{target}", "source": source, "target": target,
            "kind": kind, "status": "verified", "reason_codes": []}


def analysis(*, complete=False):
    nodes = [node("doc", "document"), node("catalog", "catalog"),
             node("action", "action", action_kind="/JavaScript"),
             node("script", "script", raw_sha256=HASH, decoded_sha256=HASH, decoded_validated=True,
                  extraction_status="complete", ast_status="complete", ast_summary={"node_count": 4}),
             node("input", "model_inputs"), node("unrelated", "object")]
    return {"schema_version": "pdf-evidence-v9", "document_sha256": DIGEST,
            "original_bytes_changed": False, "active_content_executed": False,
            "status": "complete" if complete else "partial", "primary_profile_complete": complete,
            "observations": nodes, "edges": [edge("doc", "catalog", "document_catalog"),
                edge("catalog", "action", "catalog_action"), edge("action", "script", "action_JS")],
            "capability_checks": [{"id": "check:" + name, "capability": name,
                "status": "complete" if complete else "partial", "scope_ids": ["unrelated"],
                "required_ids": [], "reason_codes": []} for name in ("catalog", "actions", "scripts", "xfa", "embedded")],
            "conflicts": [], "feature_provenance": {}}


def contract(*, complete=False):
    return {"verified": True, "feature_order": list(frozen_feature_order()), "required_ids": ["input"],
            "required_checks": [], "profile_complete": complete, "reason_codes": []}


def decide(view=None, probability=0.9, **kwargs):
    return evidence_decision_v9(probability, view or analysis(), input_available=True,
                               model_identity=IDENTITY, model_contract=kwargs.pop("model_contract", contract()), **kwargs)


def test_all173_ledger_columns_preserve_original_order_and_semantics():
    names = frozen_feature_order()
    assert len(names) == 173
    ledger = build_dependency_ledger(names, missing_supported={"pages", "observed_ast_node_count"})
    assert [row["feature"] for row in ledger] == list(names)
    lookup = {row["feature"]: row for row in ledger}
    assert lookup["obj"]["meaning"] == "original_raw_measurement"
    assert lookup["pdfsize"]["scope"] == "immutable_original_bytes"
    assert lookup["pages"]["completion_required"]
    assert lookup["ast_node_count"]["meaning"] == "complete_total"
    assert not lookup["observed_ast_node_count"]["completion_required"]
    assert lookup["v8_action_JavaScript"]["zero_requires_completed_enumeration"]
    assert lookup["pages"]["supported_missingness"] is True
    assert lookup["obj"]["supported_missingness"] is False
    assert build_dependency_ledger(names)[0]["supported_missingness"] == "not_verified_until_offline_frozen_load"


@pytest.mark.parametrize("names", [["new_score"], ["JS", "JS"]])
def test_unknown_and_duplicate_feature_contracts_rejected(names):
    with pytest.raises(ValueError):
        build_dependency_ledger(names)


def test_partial_valid_linked_javascript_and_fixed_positive_can_classify():
    result = decide()
    assert result["decision"] == "Malicious" and result["predicted_label"] == 1
    assert result["selected_witness"]["family"] == "pdf_javascript"
    assert {"input", "script", "action", "catalog", "doc"} <= set(result["supporting_evidence_ids"])
    assert result["threshold"] == 0.5 and not result["deployment"]


def test_partial_negative_is_inconclusive_even_with_valid_script():
    result = decide(probability=0.49)
    assert result["decision"] == "Inconclusive" and "incomplete_negative" in result["reasons"]
    assert result["operational_action"] == "quarantine"


@pytest.mark.parametrize("mutate", [
    lambda view: view["edges"].pop(),
    lambda view: view["edges"][1].update(kind="contains"),
    lambda view: view["observations"][3].update(ast_status="partial"),
    lambda view: view["observations"][3].update(extraction_status="partial"),
    lambda view: view["observations"][3].update(decoded_validated=False),
    lambda view: view["observations"][3].update(decoded_sha256="unknown"),
    lambda view: view["observations"][2].update(action_kind="/URI"),
])
def test_cooccurrence_incomplete_or_unvalidated_script_never_qualifies(mutate):
    view = analysis()
    mutate(view)
    result = decide(view)
    assert result["decision"] == "Inconclusive" and "linked_evidence_unavailable" in result["reasons"]


def test_shared_script_keeps_two_action_paths_and_next_cycles_are_bounded():
    view = analysis()
    view["observations"].append(node("next", "action", action_kind="/JavaScript"))
    view["edges"] += [edge("action", "next", "action_Next"), edge("next", "action", "action_Next"),
                      edge("next", "script", "action_JS")]
    view["edges"] = [item for item in view["edges"] if not (item["source"] == "action" and item["kind"] == "action_JS")]
    assert decide(view)["selected_witness"]["terminal_id"] == "script"
    assert "next" in decide(view)["supporting_evidence_ids"]


@pytest.mark.parametrize("affected, expected", [(["script"], "Inconclusive"), (["input"], "Inconclusive"), (["unrelated"], "Malicious")])
def test_localized_conflict_checks_model_and_selected_witness_closure(affected, expected):
    view = analysis()
    view["conflicts"] = [{"localized": True, "affected_ids": affected, "fields": [], "reason_code": "synthetic_conflict"}]
    assert decide(view)["decision"] == expected


def test_unlocalized_conflict_and_model_column_conflict_abstain():
    view = analysis()
    view["conflicts"] = [{"localized": False, "affected_ids": ["unrelated"]}]
    assert "unlocalized_backend_conflict" in decide(view)["reasons"]
    view["conflicts"] = [{"localized": True, "affected_ids": [], "fields": ["JS"]}]
    assert "dependency_backend_conflict" in decide(view)["reasons"]


@pytest.mark.parametrize("scope, expected", [(["script"], "Inconclusive"), (["input"], "Inconclusive"), (["unrelated"], "Malicious"), ([], "Inconclusive")])
def test_resource_limit_respects_dependency_scope(scope, expected):
    view = analysis()
    view["capability_checks"].append({"id": "limit", "capability": "diagnostic", "status": "resource_limited",
        "scope_ids": scope, "required_ids": [], "reason_codes": ["synthetic_ast_node_limit"]})
    result = decide(view)
    assert result["decision"] == expected
    assert "synthetic_ast_node_limit" in result["resource_error_codes"]


def launch_view(kind="/Launch"):
    view = analysis()
    view["observations"][2]["action_kind"] = kind
    view["observations"] += [node("spec", "filespec"), node("payload", "payload", magic="pe",
        extraction_status="complete", decoded_validated=True, decoded_sha256=HASH, raw_sha256=HASH)]
    view["edges"] += [edge("action", "spec", "Launch_filespec"), edge("spec", "payload", "filespec_EF")]
    return view


def test_launch_requires_exact_filespec_and_embedded_payload():
    assert decide(launch_view())["selected_witness"]["family"] == "embedded_launch"
    view = launch_view()
    view["edges"] = [item for item in view["edges"] if item["kind"] != "filespec_EF"]
    assert decide(view)["decision"] == "Inconclusive"


@pytest.mark.parametrize("kind", ["/GoToE", "/GoToR", "/URI", "/SubmitForm"])
def test_other_action_plus_pe_is_not_an_executable_launch_witness(kind):
    assert decide(launch_view(kind))["decision"] == "Inconclusive"


def xfa_view():
    view = analysis()
    view["observations"] += [node("form", "form"), node("packet", "xfa_packet"), node("event", "xfa_event")]
    view["edges"] = [edge("doc", "form", "document_acroform"), edge("form", "packet", "acroform_xfa"),
                     edge("packet", "event", "XFA_event"), edge("event", "script", "event_script")]
    return view


def test_xfa_needs_declared_event_ancestor():
    assert decide(xfa_view())["selected_witness"]["family"] == "xfa_javascript"
    view = xfa_view()
    view["edges"][2]["kind"] = "contains"
    assert decide(view)["decision"] == "Inconclusive"


def test_complete_negative_requires_all_mandatory_checks_and_primary_gates():
    view = analysis(complete=True)
    assert decide(view, probability=0.1, model_contract=contract(complete=True))["decision"] == "Benign"
    view["capability_checks"][-1]["status"] = "partial"
    assert "mandatory_checks_incomplete" in decide(view, probability=0.1, model_contract=contract(complete=True))["reasons"]


@pytest.mark.parametrize("mutate", [
    lambda view: view["observations"].append(deepcopy(view["observations"][0])),
    lambda view: view["observations"][3].update(document_sha256=HASH),
    lambda view: view["observations"][3].update(backend="MuPDF"),
    lambda view: view["edges"][2].update(target="unknown"),
])
def test_malformed_or_spoofed_identity_graph_abstains(mutate):
    view = analysis()
    mutate(view)
    assert decide(view)["decision"] == "Inconclusive"


def test_typed_edge_cannot_turn_arbitrary_object_into_a_legal_action_owner():
    view = analysis()
    view["edges"] = [edge("doc", "unrelated", "document_catalog"),
                     edge("unrelated", "action", "catalog_action"), edge("action", "script", "action_JS")]
    assert decide(view)["decision"] == "Inconclusive"
    view["edges"][1]["kind"] = None
    assert decide(view)["decision"] == "Inconclusive"


@pytest.mark.parametrize("field,value", [("original_bytes_changed", True), ("active_content_executed", True),
    ("original_bytes_changed", None), ("active_content_executed", None)])
def test_immutable_nonexecuting_flags_are_mandatory(field, value):
    view = analysis()
    view[field] = value
    assert "immutable_nonexecuting_analysis_unverified" in decide(view)["reasons"]


@pytest.mark.parametrize("mutate", [
    lambda view: view["capability_checks"][0].update(required_ids=None),
    lambda view: view["capability_checks"][0].update(scope_ids=[{}]),
    lambda view: view["edges"][0].update(target={}),
    lambda view: view["observations"][0].update(backend=None),
    lambda view: view.update(conflicts=[{"localized": True, "affected_ids": [{}], "fields": []}]),
])
def test_malformed_collection_fields_abstain_without_raising(mutate):
    view = analysis()
    mutate(view)
    assert decide(view)["decision"] == "Inconclusive"


def test_semantic_edge_intermediate_dependencies_belong_to_witness_closure():
    view = analysis()
    view["observations"].append(node("name_tree", "pdf_object"))
    view["edges"][1]["supporting_ids"] = ["name_tree"]
    result = decide(view)
    assert result["decision"] == "Malicious" and "name_tree" in result["supporting_evidence_ids"]
    view["conflicts"] = [{"localized": True, "affected_ids": ["name_tree"], "fields": []}]
    assert decide(view)["decision"] == "Inconclusive"
    view["conflicts"] = []
    view["edges"][1]["supporting_ids"] = ["unknown"]
    assert "edge_dependency_provenance_unverified" in decide(view)["reasons"]


@pytest.mark.parametrize("score", [None, float("nan"), float("inf"), -0.1, 1.1, True])
def test_invalid_scores_never_become_a_label(score):
    result = decide(probability=score)
    assert result["predicted_label"] is None and result["malicious_probability"] is None


def profile_and_provenance():
    view = analysis()
    profile = {"pdf_sha256": DIGEST, "status": "partial", "static": {"input": {"sha256": DIGEST},
        "features": {name: 0 for name in RIT_FEATURES}, "parser": {}}, "code": None}
    values = v8_feature_values(profile)
    support = {name for name, value in values.items() if value is None}
    for name, value in values.items():
        view["feature_provenance"][name] = {"status": "unknown" if value is None else "verified",
            "source_ids": ["input"], "required_check_ids": [], "completion_status": "complete", "value": value}
    return profile, view, support


def test_input_ledger_verifies_all173_without_redefining_unknowns():
    profile, view, support = profile_and_provenance()
    result = verify_model_inputs(profile, frozen_feature_order(), view, missing_supported=support)
    assert result["verified"] and len(result["dependencies"]) == 173
    assert profile["code"] is None
    assert {"input"} == set(result["required_ids"])


def test_missingness_support_requires_frozen_indicator_and_explicit_provenance():
    profile, view, support = profile_and_provenance()
    unsupported = verify_model_inputs(profile, frozen_feature_order(), view, missing_supported=set())
    assert "model_missingness_unsupported" in unsupported["reason_codes"]
    missing_name = next(iter(support))
    view["feature_provenance"][missing_name]["status"] = "verified"
    assert "model_unknown_input_unverified" in verify_model_inputs(profile, frozen_feature_order(), view,
        missing_supported=support)["reason_codes"]


def test_false_values_in_missingness_mapping_do_not_authorize_missing_inputs():
    profile, view, support = profile_and_provenance()
    support_map = {name: name in support for name in frozen_feature_order()}
    assert verify_model_inputs(profile, frozen_feature_order(), view, missing_supported=support_map)["verified"]
    target = next(iter(support))
    support_map[target] = False
    assert "model_missingness_unsupported" in verify_model_inputs(profile, frozen_feature_order(), view,
        missing_supported=support_map)["reason_codes"]
    with pytest.raises(ValueError):
        build_dependency_ledger(frozen_feature_order(), missing_supported={target: "false"})


def test_complete_total_never_reinterpreted_as_observed_lower_bound():
    profile, view, support = profile_and_provenance()
    view["feature_provenance"]["pages"]["completion_status"] = "partial"
    result = verify_model_inputs(profile, frozen_feature_order(), view, missing_supported=support)
    assert "model_input_completion_unverified" in result["reason_codes"]
    view["feature_provenance"]["pages"]["completion_status"] = "complete"
    view["feature_provenance"]["pages"]["value"] = 123
    assert "model_input_value_conflict" in verify_model_inputs(profile, frozen_feature_order(), view,
        missing_supported=support)["reason_codes"]


def test_feature_order_or_missing_source_provenance_blocks_frozen_model_contract():
    profile, view, support = profile_and_provenance()
    order = list(frozen_feature_order())
    order[0], order[1] = order[1], order[0]
    assert "model_feature_order_unverified" in verify_model_inputs(profile, order, view,
        missing_supported=support)["reason_codes"]
    del view["feature_provenance"]["obj"]
    assert "model_input_provenance_unverified" in verify_model_inputs(profile, frozen_feature_order(), view,
        missing_supported=support)["reason_codes"]


def test_model_identity_requires_original_training_size_hash_and_threshold():
    for field, bad_value in [("train_rows", 32), ("threshold", 0.49), ("feature_count", 174), ("artifact_sha256", "unknown")]:
        identity = {**IDENTITY, field: bad_value}
        result = evidence_decision_v9(0.9, analysis(), input_available=True, model_identity=identity, model_contract=contract())
        assert "frozen_model_identity_unverified" in result["reasons"]


def benign_pdf(kind):
    from pypdf import PdfWriter
    from pypdf.generic import ArrayObject, DictionaryObject, NameObject, DecodedStreamObject, TextStringObject
    writer = PdfWriter()
    page = writer.add_blank_page(72, 72)
    action = DictionaryObject({NameObject("/S"): NameObject("/JavaScript"),
                               NameObject("/JS"): TextStringObject("var inert = 1;")})
    if kind == "catalog":
        writer._root_object[NameObject("/OpenAction")] = writer._add_object(action)
    elif kind == "page":
        page[NameObject("/AA")] = DictionaryObject({NameObject("/O"): writer._add_object(action)})
    elif kind == "annotation":
        annotation = DictionaryObject({NameObject("/Type"): NameObject("/Annot"), NameObject("/Subtype"): NameObject("/Link"),
                                       NameObject("/A"): writer._add_object(action)})
        page[NameObject("/Annots")] = ArrayObject([writer._add_object(annotation)])
    elif kind == "field":
        field = DictionaryObject({NameObject("/FT"): NameObject("/Tx"), NameObject("/AA"):
                                  DictionaryObject({NameObject("/K"): writer._add_object(action)})})
        writer._root_object[NameObject("/AcroForm")] = DictionaryObject({NameObject("/Fields"): ArrayObject([writer._add_object(field)])})
    elif kind == "named":
        writer._root_object[NameObject("/Names")] = DictionaryObject({NameObject("/JavaScript"):
            DictionaryObject({NameObject("/Names"): ArrayObject([TextStringObject("inert"), writer._add_object(action)])})})
    elif kind == "xfa":
        stream = DecodedStreamObject()
        stream.set_data(b'<template xmlns="http://www.xfa.org/schema/xfa-template/2.5/"><subform><event activity="initialize"><script contentType="application/x-javascript">var inert=1;</script></event></subform></template>')
        writer._root_object[NameObject("/AcroForm")] = DictionaryObject({NameObject("/XFA"):
            ArrayObject([TextStringObject("template"), writer._add_object(stream)])})
    elif kind == "two_scripts":
        writer._root_object[NameObject("/OpenAction")] = writer._add_object(action)
        writer._root_object[NameObject("/Private")] = DictionaryObject({NameObject("/S"): NameObject("/JavaScript"),
            NameObject("/JS"): TextStringObject("var unrelated = 2;")})
    elif kind == "fake_annotation":
        writer._root_object[NameObject("/Private")] = DictionaryObject({NameObject("/Type"): NameObject("/Annot"),
                                                                       NameObject("/A"): writer._add_object(action)})
    else:
        raise AssertionError(kind)
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


def measured_benign_profile(tmp_path, kind, *, metadata=True):
    from malpdf.static.analyzer import StaticPDFAnalyzer
    from malpdf.static.code_inspector import CodeInspectionLimits, _inspect_code_bytes
    from malpdf.static.evidence import inspect_evidence
    from malpdf.static.evidence_v9 import inspect_evidence_v9
    from malpdf.inference.evidence_policy_v9 import derive_feature_provenance
    data = benign_pdf(kind)
    path = tmp_path / "benign.pdf"
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    measured = StaticPDFAnalyzer().inspect(path, snapshot=data, snapshot_sha256=digest)
    static = {"input": {key: measured.input[key] for key in ("size_bytes", "sha256")},
              "features": measured.features, "parser": measured.parser,
              "reference_parser_repaired": measured.diagnostics.get("rit_reference_diagnostics", {}).get("parser_repaired"),
              "errors": [{"code": item.code, "fatal": item.fatal} for item in measured.errors],
              "warnings": [item.code for item in measured.warnings]}
    limits = CodeInspectionLimits()
    code = _inspect_code_bytes(data, limits, evidence_metadata=metadata)
    legacy = inspect_evidence(data, static, code, limits, primary_complete=False, checkpoint=lambda *_: None)
    view = inspect_evidence_v9(data, static, code, limits, legacy_analysis=legacy)
    profile = {"static": static, "code": code, "analysis_v8": legacy, "pdf_sha256": digest, "status": "partial"}
    values = v8_feature_values(profile)
    view["feature_provenance"].update(derive_feature_provenance(profile, view))
    support = {name for name, value in values.items() if value is None}
    return profile, view, support


@pytest.mark.parametrize("kind", ["catalog", "page", "annotation", "field", "named", "xfa"])
def test_actual_benign_extractor_graph_connects_to_policy_and_frozen_inputs(tmp_path, kind):
    profile, view, support = measured_benign_profile(tmp_path, kind)
    verified = verify_model_inputs(profile, frozen_feature_order(), view, missing_supported=support)
    assert verified["verified"], verified["reason_codes"]
    # Synthetic model probability tests eligibility only, with no malware claim.
    result = evidence_decision_v9(0.9, view, input_available=True, model_identity=IDENTITY, model_contract=verified)
    assert result["decision"] == "Malicious", result["reasons"]
    assert result["selected_witness"]["family"] == ("xfa_javascript" if kind == "xfa" else "pdf_javascript")


def test_legacy_ast_numeric_values_without_source_hashes_are_unverified(tmp_path):
    profile, view, support = measured_benign_profile(tmp_path, "catalog", metadata=False)
    verified = verify_model_inputs(profile, frozen_feature_order(), view, missing_supported=support)
    assert not verified["verified"]
    assert "model_script_ast_provenance_unverified" in verified["reason_codes"]


def test_cap_on_model_contributing_script_blocks_otherwise_valid_witness(tmp_path):
    profile, view, support = measured_benign_profile(tmp_path, "two_scripts")
    verified = verify_model_inputs(profile, frozen_feature_order(), view, missing_supported=support)
    assert verified["verified"], verified["reason_codes"]
    qualified = evidence_decision_v9(0.9, view, input_available=True, model_identity=IDENTITY, model_contract=verified)
    assert qualified["decision"] == "Malicious"
    witness_script = qualified["selected_witness"]["terminal_id"]
    other = next(item for item in view["observations"] if item.get("kind") == "script" and item["id"] != witness_script)
    assert other["id"] in verified["required_ids"]
    view["capability_checks"].append({"id": "related:model:limit", "capability": "diagnostic",
        "status": "resource_limited", "scope_ids": [other["id"]], "required_ids": [], "reason_codes": ["ast_node_limit"]})
    result = evidence_decision_v9(0.9, view, input_available=True, model_identity=IDENTITY, model_contract=verified)
    assert result["decision"] == "Inconclusive" and "dependency_resource_limit" in result["reasons"]


def test_source_hash_mismatch_is_not_repaired_by_numeric_ast_agreement(tmp_path):
    from malpdf.inference.evidence_policy_v9 import derive_feature_provenance
    import json
    profile, view, support = measured_benign_profile(tmp_path, "catalog")
    profile["code"]["script_sources"][0]["decoded_sha256"] = HASH
    digest = hashlib.sha256(json.dumps({"static": profile["static"], "code": profile["code"],
        "analysis_v8": profile["analysis_v8"]}, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    for item in view["observations"]:
        if item.get("kind") == "primary_model_inputs":
            item["measurement_sha256"] = digest
    view["feature_provenance"].update(derive_feature_provenance(profile, view))
    result = verify_model_inputs(profile, frozen_feature_order(), view, missing_supported=support)
    assert not result["verified"] and "model_script_ast_provenance_unverified" in result["reason_codes"]


def test_actual_arbitrary_annotation_dictionary_does_not_create_legal_context():
    from malpdf.static.code_inspector import CodeInspectionLimits, _inspect_code_bytes
    from malpdf.static.evidence_v9 import inspect_evidence_v9
    data = benign_pdf("fake_annotation")
    digest = hashlib.sha256(data).hexdigest()
    static = {"input": {"sha256": digest}, "parser": {}, "features": {}, "errors": []}
    view = inspect_evidence_v9(data, static, _inspect_code_bytes(data, CodeInspectionLimits()), CodeInspectionLimits())
    verified = contract()
    verified["required_ids"] = [next(item["id"] for item in view["observations"] if item.get("kind") == "primary_model_inputs")]
    result = evidence_decision_v9(0.9, view, input_available=True, model_identity=IDENTITY, model_contract=verified)
    assert result["decision"] == "Inconclusive"
    assert "linked_evidence_unavailable" in result["reasons"]
