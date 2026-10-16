"""Bounded JavaScript syntax evidence, without evaluation or source export."""

from collections import Counter
from contextvars import ContextVar

_TREE_OBSERVER=ContextVar('malpdf_js_tree_observer',default=None)


def set_tree_observer(observer):
    """Private worker hook; default syntax callers retain their old contract."""
    return _TREE_OBSERVER.set(observer)


def reset_tree_observer(token):
    _TREE_OBSERVER.reset(token)

CALL_NAMES = frozenset({"eval", "unescape", "atob", "Function", "String.fromCharCode",
                       "util.printf", "Collab.collectEmailInfo", "app.launchURL"})


class CodeInspectionError(ValueError):
    """A redacted, fixed-code inspection failure."""


def _literal_string(node, depth=0):
    # Only literal concatenation is recognized; no interpreter or user function.
    if not isinstance(node, dict) or depth > 16:
        return None
    if node.get("type") == "Literal" and isinstance(node.get("value"), str):
        value = node["value"]
        return value if len(value) <= 2048 else None
    if node.get("type") == "BinaryExpression" and node.get("operator") == "+":
        left, right = (_literal_string(node.get(k), depth + 1) for k in ("left", "right"))
        if left is not None and right is not None and len(left) + len(right) <= 2048:
            return left + right
    return None


def _callee_name(node, depth=0):
    if not isinstance(node, dict) or depth > 16:
        return None
    if node.get("type") == "Identifier":
        return node.get("name")
    if node.get("type") == "MemberExpression":
        owner = _callee_name(node.get("object"), depth + 1)
        prop = (_literal_string(node.get("property")) if node.get("computed")
                else node.get("property", {}).get("name"))
        if owner and prop and len(owner) + len(prop) < 2048:
            return owner + "." + prop
    return None


def inspect_js_syntax(source, *, max_bytes=256 * 1024, max_nodes=20_000, max_depth=100):
    """Parse ECMAScript 2017 syntax. Production callers use a capped child process.

    Named calls are syntactic evidence only: identifiers can be shadowed or
    aliased. Absence of these names does not establish that code is benign.
    """
    import esprima

    if not isinstance(source, str) or len(source.encode("utf-8")) > max_bytes:
        raise CodeInspectionError("script_byte_limit")
    try:
        observer=_TREE_OBSERVER.get()
        tree = esprima.parseScript(source, options={"tolerant": False,**({'range':True} if observer is not None else {})}).toDict()
    except Exception:
        raise CodeInspectionError("javascript_parse_error") from None
    histogram, calls = Counter(), Counter({name: 0 for name in sorted(CALL_NAMES)})
    pending, count, deepest, computed = [(tree, 0)], 0, 0, 0
    while pending:
        node, depth = pending.pop()
        if depth > max_depth:
            raise CodeInspectionError("ast_depth_limit")
        if not isinstance(node, dict):
            continue
        kind = node.get("type")
        if kind:
            count += 1
            if count > max_nodes:
                raise CodeInspectionError("ast_node_limit")
            histogram[kind] += 1
            deepest = max(deepest, depth)
        if kind in {"CallExpression", "NewExpression"}:
            name = _callee_name(node.get("callee"))
            if name in CALL_NAMES:
                calls[name] += 1
        if kind == "MemberExpression" and node.get("computed"):
            computed += 1
        for value in node.values():
            if isinstance(value, dict):
                pending.append((value, depth + 1))
            elif isinstance(value, list):
                pending.extend((item, depth + 1) for item in value if isinstance(item, dict))
    summary={"node_count": count, "max_depth": deepest,
            "node_types": dict(sorted(histogram.items())), "named_calls": dict(calls),
            "computed_members": computed,
            "loops": sum(histogram[name] for name in ("ForStatement", "WhileStatement", "DoWhileStatement", "ForInStatement", "ForOfStatement"))}
    if observer is not None:
        observer.capture(source,tree,summary)
    return summary
