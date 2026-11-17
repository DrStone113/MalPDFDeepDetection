"""Lightweight static/v8 feature extraction shared without pulling ML runtimes into PDF workers."""

from __future__ import annotations

import math

from malpdf.static.code_inspector import SECURITY_NAMES
from malpdf.static.js_ast import CALL_NAMES
from malpdf.static.schema import RIT_FEATURES

PROFILE_VARIANTS = ("P0_rit41_fallback", "P1_observed_static", "P2_observed_plus_status")
AST_NODE_TYPES = (
    "ArrayExpression", "AssignmentExpression", "BinaryExpression", "BlockStatement",
    "CallExpression", "ConditionalExpression", "ExpressionStatement", "FunctionDeclaration",
    "FunctionExpression", "Identifier", "IfStatement", "Literal", "MemberExpression", "NewExpression",
    "ObjectExpression", "ReturnStatement", "SequenceExpression", "UnaryExpression", "UpdateExpression",
    "VariableDeclaration", "VariableDeclarator", "WhileStatement", "ForStatement", "ForInStatement",
    "DoWhileStatement", "SwitchStatement", "TryStatement", "CatchClause", "ThrowStatement",
)


def advanced_features(profile: dict) -> dict:
    """Extract structural indicator and JS AST summary columns from a static profile."""
    code = profile.get("code")
    structural = None if code is None else code.get("structural_indicators")
    ast = None if code is None else code.get("ast")
    values = {"structure_" + name[1:]: None if structural is None else structural.get(name[1:]) for name in sorted(SECURITY_NAMES)}
    values.update({"ast_" + name: None if ast is None else ast[name] for name in ("node_count", "max_depth", "loops", "computed_members")})
    values.update({"call_" + name: None if ast is None else ast["named_calls"][name] for name in sorted(CALL_NAMES)})
    values["scripts_found"] = None if code is None else code["scripts_found"]
    values["ast_complete"] = None if code is None else int(code["ast_complete"])
    return values


def profile_feature_values(row: dict, variant: str) -> dict:
    """Extract fixed static/observed profile feature dictionary for a schema variant."""
    if variant not in PROFILE_VARIANTS:
        raise ValueError("Unknown fixed profile feature variant")
    static, code = row.get("static") or {}, row.get("code") or {}
    values = {name: static.get("features", {}).get(name) for name in RIT_FEATURES}
    if variant != PROFILE_VARIANTS[0]:
        values.update(advanced_features(row))
        observed = code.get("observed") or {}
        ast = observed.get("ast")
        structure = observed.get("structural_indicators")
        values.update({"observed_structure_" + name[1:]: None if structure is None else structure.get(name[1:])
                       for name in sorted(SECURITY_NAMES)})
        values.update({"observed_ast_" + name: None if ast is None else ast.get(name)
                       for name in ("node_count", "max_depth", "loops", "computed_members")})
        values.update({"observed_call_" + name: None if ast is None else ast.get("named_calls", {}).get(name, 0)
                       for name in sorted(CALL_NAMES)})
        values.update({"observed_ast_type_" + name: None if ast is None else ast.get("node_types", {}).get(name, 0)
                       for name in AST_NODE_TYPES})
        values["observed_scripts_found"] = observed.get("scripts_found")
        values["observed_scripts_parsed"] = code.get("scripts_parsed")
        for name in ("traversal_complete", "script_extraction_complete"):
            value = code.get(name)
            if value is not None and type(value) is not bool:
                raise ValueError("Non-boolean profile coverage flag")
            values[name] = None if value is None else int(value)
    if variant == PROFILE_VARIANTS[2]:
        parser = static.get("parser") or {}
        for prefix, source, names in (("parser_", parser, ("success", "structural_complete", "resource_limit_reached", "encrypted")),
                                      ("code_", code, ("complete", "parser_recovered"))):
            for name in names:
                value = source.get(name)
                if value is not None and type(value) is not bool:
                    raise ValueError("Non-boolean profile coverage flag")
                values[prefix + name] = None if value is None else int(value)
        values["reference_parser_repaired"] = static.get("reference_parser_repaired")
    for value in values.values():
        if value is not None and (type(value) not in (int, float, bool) or not math.isfinite(value)):
            raise ValueError("Non-finite or nonnumeric saved profile measurement")
    return values


def v8_feature_values(row: dict) -> dict:
    """Extract v8 action, embedded, and backend AST feature dictionary."""
    values = profile_feature_values(row, PROFILE_VARIANTS[2])
    values = {name: None if value == -1 else value for name, value in values.items()}
    evidence = row.get("analysis_v8") or {}
    names = ["action_" + s for s in ["JavaScript", "Launch", "URI", "SubmitForm", "GoToR", "GoToE", "ImportData"]]
    names += ["embedded_" + s for s in ["pdf", "pe", "elf", "zip", "png", "jpeg", "other"]]
    for name in names:
        facts = [f for f in evidence.get("features", []) if f["name"] == name and f["status"] in {"observed", "absent_after_complete_check"}]
        selected = next((f for f in facts if f["source"] == "pypdf"), facts[0] if facts else None)
        values["v8_" + name] = None if selected is None else selected["value"]

    for backend in ("pypdf", "MuPDF"):
        view = next((b.get("code") for b in evidence.get("backends", []) if b["backend"] == backend), None) or {}
        observed = view.get("observed") or {}
        ast = observed.get("ast") or {}
        for name in ("node_count", "max_depth", "loops", "computed_members"):
            values[f"v8_{backend}_ast_{name}"] = ast.get(name)
        for name in sorted(CALL_NAMES):
            values[f"v8_{backend}_call_{name}"] = None if not ast else ast.get("named_calls", {}).get(name, 0)
        values[f"v8_{backend}_scripts_parsed"] = view.get("scripts_parsed")
        values[f"v8_{backend}_scripts_found"] = observed.get("scripts_found")
    return values
