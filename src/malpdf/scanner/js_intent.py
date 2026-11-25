from __future__ import annotations

from collections import Counter
import math
import re
from typing import Any

import esprima

from malpdf.static.js_semantics import children

_EMPTY = "empty_noop"
_FORM = "form_formatting_and_validation"
_CALC = "form_calculation"
_PRINT = "print_helper"
_NAV = "document_navigation_ui"
_NOTICE = "user_dialog_notice"
_HELPER = "benign_helper_library"
_INTENT_LABELS = {
    _EMPTY: "Khóa JavaScript rỗng hoặc chỉ chứa ghi chú (không có lệnh thực thi).",
    _FORM: "Định dạng và kiểm tra dữ liệu biểu mẫu",
    _CALC: "Tính toán và cập nhật trường biểu mẫu",
    _PRINT: "Thiết lập và in tài liệu",
    _NAV: "Điều hướng và tùy chỉnh hiển thị tài liệu",
    _NOTICE: "Hiển thị thông báo cho người dùng",
    _HELPER: "Hàm hỗ trợ JavaScript",
}
_DIRECT_CALLS = {
    **dict.fromkeys(
        """AFNumber_Format AFNumber_Keystroke AFPercent_Format AFPercent_Keystroke
        AFDate_FormatEx AFDate_Format AFDate_KeystrokeEx AFDate_Keystroke
        AFTime_FormatEx AFTime_Format AFTime_Keystroke AFSpecial_Format AFSpecial_Keystroke AFSpecial_KeystrokeEx
        AFRange_Validate AFMergeChange AFMakeNumber AFExactMatch AFParseDateEx AFExtractNums""".split(),
        _FORM,
    ),
    **dict.fromkeys(("AFSimple_Calculate", "AFSimple", "getField", "resetForm"), _CALC),
    **dict.fromkeys(("print", "getPrintParams"), _PRINT),
    **dict.fromkeys(
        ("Number", "String", "Boolean", "parseInt", "parseFloat", "isNaN", "isFinite", "Date", "Array"), _HELPER
    ),
}
_HOST_CALLS = {
    "this": {
        **dict.fromkeys(("getField", "resetForm", "calculateNow", "getNthFieldName"), _CALC),
        **dict.fromkeys(("print", "getPrintParams"), _PRINT),
        **dict.fromkeys(("gotoNamedDest", "getOCGs"), _NAV),
    },
    "util": dict.fromkeys(("printd", "scand", "printx"), _FORM),
    "app": {"alert": _NOTICE, "beep": _NOTICE, "goBack": _NAV, "goForward": _NAV, "execMenuItem": _NAV},
    "console": dict.fromkeys(("println", "show", "clear"), _NOTICE),
}
_MENU_ITEMS = frozenset(
    """Print NextPage PrevPage FirstPage LastPage FitPage FitWidth FitHeight FitVisible ActualSize
    SinglePage OneColumn TwoColumns Find ShowHideBookmarks ShowHideThumbnails""".split()
)
_FIELD_PROPERTIES = frozenset(
    """value display readonly required hidden textColor fillColor strokeColor borderStyle comb charLimit
    defaultValue userName""".split()
)
_EVENT_PROPERTIES = frozenset({"value", "rc", "change", "selStart", "selEnd", "willCommit"})
_UI_PROPERTIES = frozenset({"pageNum", "zoom", "zoomType", "dirty", "layout", "viewState"})
_WRITABLE_PROPERTIES = {
    "event": _EVENT_PROPERTIES,
    "field": _FIELD_PROPERTIES,
    "print_params": frozenset(
        {"interactive", "firstPage", "lastPage", "pageHandling", "bUI", "printerName", "NumCopies"}
    ),
    "ocg": frozenset({"state"}),
    "this": _UI_PROPERTIES,
}
_CONST_GLOBALS = frozenset({"color", "display", "border", "font", "zoomtype"})
_HOST_GLOBALS = _CONST_GLOBALS | {"app", "util", "console", "event", "Math", "Date", "Array", "RegExp"}
_UNSAFE_NAMES = frozenset(
    """eval Function arguments __proto__ constructor prototype caller callee window global globalThis
    Collab media spell doc document with setTimeout setInterval unescape atob charCodeAt fromCharCode""".split()
)
_RESERVED = _HOST_GLOBALS | _UNSAFE_NAMES | _DIRECT_CALLS.keys() | {"undefined", "NaN", "Infinity"}
_FIELD_CALLS = frozenset({"setFocus", "checkThisBox", "isBoxChecked", "getItemAt", "setItems", "clearItems"})
_MATH_CALLS = frozenset(
    """abs acos acosh asin asinh atan atanh atan2 cbrt ceil clz32 cos cosh exp expm1 floor fround hypot imul
    log log1p log2 log10 max min pow random round sign sin sinh sqrt tan tanh trunc""".split()
)
_DATE_CALLS = frozenset(
    """getDate getDay getFullYear getHours getMilliseconds getMinutes getMonth getSeconds getTime
    getTimezoneOffset getUTCDate getUTCDay getUTCFullYear getUTCHours getUTCMilliseconds getUTCMinutes
    getUTCMonth getUTCSeconds getYear toDateString toISOString toJSON toLocaleDateString toLocaleString
    toLocaleTimeString toString toTimeString toUTCString valueOf""".split()
)
_CALLBACKS = frozenset({"forEach", "map", "filter", "every", "some", "reduce"})
_ARRAYS = frozenset({"array", "ocg_list", "match"})
_NUMBERS = frozenset({"number", "small_integer", "length", "document_count", "last_index"})
_SCALARS = _NUMBERS | {"string", "boolean", "null", "scalar"}
_DECODERS = {
    "fromCharCode": "fromCharCode_decode",
    "atob": "base64_atob_decode",
    "unescape": "unescape_percent_decode",
    "reverse": "string_reverse_fold",
}
_STRING_CALLS = {
    **dict.fromkeys(
        """charAt concat replace slice substr substring trim trimStart trimEnd toLowerCase
        toUpperCase toLocaleLowerCase toLocaleUpperCase toFixed toPrecision toExponential toString""".split(),
        "string",
    ),
    **dict.fromkeys(("indexOf", "lastIndexOf", "localeCompare", "search"), "number"),
    **dict.fromkeys(("endsWith", "includes", "startsWith"), "boolean"),
    "split": "array",
    "match": "match",
}
_LOOPS = frozenset({"ForStatement", "WhileStatement", "DoWhileStatement", "ForInStatement"})
_FUNCTIONS = frozenset({"FunctionExpression", "ArrowFunctionExpression"})
_OPERATORS = {
    "UnaryExpression": {"+", "-", "!", "typeof", "void"},
    "UpdateExpression": {"++", "--"},
    "BinaryExpression": {"+", "-", "*", "/", "%", "==", "!=", "===", "!==", "<", "<=", ">", ">=", "in", "instanceof"},
    "LogicalExpression": {"&&", "||"},
    "AssignmentExpression": {"=", "+=", "-=", "*=", "/="},
}
_SIMPLE_STATEMENTS = frozenset(
    {
        "Program",
        "BlockStatement",
        "EmptyStatement",
        "ExpressionStatement",
        "ReturnStatement",
        "BreakStatement",
        "ContinueStatement",
    }
)
_ASCII_ESCAPE = re.compile(r"\\u00[0-7][0-9a-fA-F]|\\u\{0*[0-7]?[0-9a-fA-F]\}")
_HEX_ESCAPE = re.compile(r"\\x[0-9a-fA-F]{2}")
_OCTAL_ESCAPE = re.compile(r"\\[0-7]")
_SHORT_FRAGMENT = r"""(?:"[^"\\\r\n]{0,3}"|'[^'\\\r\n]{0,3}')"""
_FRAGMENT_CHAIN = re.compile(rf"{_SHORT_FRAGMENT}(?:\s*\+\s*{_SHORT_FRAGMENT}){{3}}")


def classify_obfuscation_techniques(raw_code: str, techniques: list[str]) -> tuple[list[str], list[str]]:
    evasive, benign = [], []
    for technique in techniques:
        if (
            technique == "unicode_escape_decode"
            and not (_ASCII_ESCAPE.search(raw_code) or _HEX_ESCAPE.search(raw_code) or _OCTAL_ESCAPE.search(raw_code))
            or technique == "string_concat_fold"
            and not _FRAGMENT_CHAIN.search(raw_code)
        ):
            benign.append(technique)
        else:
            evasive.append(technique)
    return evasive, benign


class _Unverified(ValueError):
    pass


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise _Unverified(reason)


def _name(node: dict) -> str:
    return node["name"] if node["type"] == "Identifier" else ""


def _integer(node: dict | None) -> int | None:
    value = (node or {}).get("value")
    return value if type(value) is int else None


def _valid_array_args(args: list[dict]) -> bool:
    if not args:
        return True
    if len(args) == 1:
        size = _integer(args[0])
        return 0 <= size <= 256 if size is not None else isinstance(args[0].get("value"), (str, bool))
    return 2 <= len(args) <= 128


def _property(node: dict) -> str | None:
    if node["type"] == "Identifier":
        return node["name"]
    if node["type"] == "Literal" and isinstance(node.get("value"), (str, int)):
        return str(node["value"])
    return None


def _label_intents(intents: list[str]) -> str:
    if intents == [_EMPTY] or not intents:
        return _INTENT_LABELS[_EMPTY] if intents else ""
    labels = [_INTENT_LABELS[intent].lower() for intent in intents if intent != _EMPTY]
    return "JavaScript đã kiểm chứng: " + ", ".join(labels) + "."


def _bounds(tree: dict, max_nodes: int, max_depth: int) -> tuple[int, set[str]]:
    pending = [(tree, 1, False)]
    indicators = set()
    count = 0
    loops = 0
    while pending:
        node, depth, in_loop = pending.pop()
        count += 1
        _require(count <= max_nodes and depth <= max_depth, "ast_limit")
        kind = node["type"]
        if kind in _LOOPS:
            loops += 1
            in_loop = True
        if kind in {"NewExpression", "CallExpression"} and _name(node["callee"]) == "Array":
            args = node["arguments"]
            if len(args) == 1 and (_integer(args[0]) or 0) >= 1024:
                indicators.add("heap_spray_loop")
        if in_loop and kind == "AssignmentExpression" and _self_doubling(node):
            indicators.add("heap_spray_loop")
        pending.extend((child, depth + 1, in_loop) for _, child in children(node))
    return loops, indicators


class _IntentVerifier:
    def __init__(self, functions: set[str], root: str) -> None:
        self.functions = functions
        self.scopes: list[dict[str, str]] = [{}]
        self.function_scope = 0
        self.target = root
        self.intents: set[str] = set()
        self.api_calls: set[str] = set()
        self.calls: dict[str, set[str]] = {}
        self.loop_calls: set[str] = set()
        self.loop_unsafe: set[str] = set()
        self.loop_depth = 0
        self.guarded_writes: set[str] = set()
        self.indicators: set[str] = set()
        self.evasive: set[str] = set()

    def _binding(self, name: str) -> dict[str, str] | None:
        return next((scope for scope in reversed(self.scopes) if name in scope), None)

    def _declare(self, name: str, value: str, *, var: bool = False, initialized: bool = True) -> None:
        _require(bool(name) and name not in _RESERVED and name not in self.functions, "unsupported_binding")
        scope = self.scopes[self.function_scope] if var else self.scopes[-1]
        if name in scope and scope[name].startswith("local:"):
            raise _Unverified("function_reassignment")
        if name in scope and not initialized:
            return
        if self.loop_depth and name in scope and scope[name] not in {"unknown", value}:
            _require(scope[name] in _NUMBERS and value in _NUMBERS, "loop_binding_change")
        scope[name] = value

    def _read_many(self, nodes: list[dict | None]) -> list[str]:
        return [self.read(node) for node in nodes]

    def _fork(self, node: dict | None) -> tuple[str, list[dict[str, str]]]:
        scopes = self.scopes
        self.scopes = [scope.copy() for scope in scopes]
        try:
            return self.read(node), self.scopes
        finally:
            self.scopes = scopes

    def _merge(self, *paths: list[dict[str, str]]) -> None:
        for scope, *branches in zip(self.scopes, *paths):
            for name in scope.keys() | set().union(*(branch.keys() for branch in branches)):
                values = {branch.get(name, "unknown") for branch in branches}
                scope[name] = values.pop() if len(values) == 1 else "number" if values <= _NUMBERS else "unknown"

    def _unsafe_in_loop(self, reason: str) -> None:
        self.loop_unsafe.add(self.target)
        _require(not self.loop_depth, reason)

    def _literal(self, node: dict) -> str:
        if regex := node.get("regex"):
            _require(len(regex["pattern"]) <= 128, "regexp_limit")
            return "regexp"
        value = node.get("value")
        if isinstance(value, str):
            _require(len(value) <= 1024, "string_literal_limit")
            if len(value) >= 64:
                entropy = -sum((n / len(value)) * math.log2(n / len(value)) for n in Counter(value).values())
                _require(entropy <= 5.0, "high_entropy_literal")
            return "string"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, int):
            _require(abs(value) < 0x10000000, "numeric_literal_limit")
            return "small_integer" if 0 <= value <= 512 else "number"
        if isinstance(value, float):
            _require(
                math.isfinite(value) and (not value.is_integer() or abs(value) < 0x10000000), "numeric_literal_limit"
            )
            return "number"
        return "null"

    def _owner(self, node: dict) -> str:
        if node["type"] == "ThisExpression":
            return "this"
        if _name(node) in _HOST_GLOBALS:
            return node["name"]
        return self.read(node)

    def _member(self, node: dict) -> str:
        owner = self._owner(node["object"])
        prop = node["property"]
        if node["computed"]:
            index_type = self.read(prop)
            _require(
                owner in _ARRAYS | {"object"}
                and (
                    _integer(prop) is not None
                    and prop["value"] >= 0
                    or bool(_name(prop))
                    and (
                        index_type in _NUMBERS
                        or index_type == "index_key"
                        or owner == "object"
                        and index_type == "string"
                    )
                ),
                "computed_member",
            )
            return "ocg" if owner == "ocg_list" else "string" if owner == "match" else "unknown"
        name = _name(prop)
        _require(name not in _UNSAFE_NAMES, "unsafe_member")
        if name == "length" and owner in _ARRAYS | {"string", "scalar"}:
            return "length" if owner in _ARRAYS else "number"
        if owner == "this" and name in {"numFields", "numPages"}:
            self.intents.add(_NAV if name == "numPages" else _CALC)
            return "document_count"
        if owner == "print_params" and name == "constants":
            return "print_constants"
        if owner == "print_constants":
            return "print_constant_group"
        if owner in {"print_constant_group", "Math"} and (
            owner != "Math" or name in {"E", "LN2", "LN10", "LOG2E", "LOG10E", "PI", "SQRT1_2", "SQRT2"}
        ):
            return "number"
        if owner in _CONST_GLOBALS or owner == "object":
            return "scalar" if owner in _CONST_GLOBALS else "unknown"
        if owner == "field" and name in {"valueAsString", "name", "type"} or owner == "ocg" and name == "name":
            return "string"
        if owner == "event" and name in {"name", "type", "modifier", "shift", "keyDown", "commitKey", "targetName"}:
            return "scalar"
        if owner == "event" and name in {"target", "source"}:
            return "field"
        _require(name in _WRITABLE_PROPERTIES.get(owner, ()), "unverified_member")
        return "scalar"

    def _write(self, node: dict, value: str) -> None:
        if name := _name(node):
            scope = self._binding(name)
            _require(scope is not None and name not in self.guarded_writes, "unverified_assignment")
            previous = scope[name]
            _require(not previous.startswith("local:") and not value.startswith("local:"), "function_reassignment")
            numeric_update = previous in _NUMBERS and value in _NUMBERS
            if self.loop_depth and previous != "unknown":
                _require(
                    previous == value or numeric_update or previous in _SCALARS - _NUMBERS and value in _SCALARS,
                    "loop_binding_change",
                )
                if previous != value and not numeric_update:
                    value = "scalar"
            _require(
                all(scope is not outer for outer in self.scopes[: self.function_scope])
                or previous == value
                or numeric_update,
                "captured_binding_change",
            )
            scope[name] = value
            return
        _require(node["type"] == "MemberExpression" and not node["computed"], "unverified_assignment")
        owner = self._owner(node["object"])
        prop = _name(node["property"])
        _require(prop in _WRITABLE_PROPERTIES.get(owner, ()), "unverified_assignment")
        self.intents.add({"this": _NAV, "ocg": _NAV, "print_params": _PRINT}.get(owner, _CALC))
        if owner in {"this", "print_params"}:
            self._unsafe_in_loop("loop_display_assignment")
        if owner == "field" and prop in {"value", "defaultValue", "userName"}:
            self._unsafe_in_loop("loop_field_value_assignment")

    def _function(self, node: dict, target: str, *, callback_item: str | None = None) -> None:
        _require(not node.get("generator") and not node.get("async"), "unsupported_function")
        callback = callback_item is not None
        enclosing, scope, caller, loop_depth, guards = (
            self.scopes,
            self.function_scope,
            self.target,
            self.loop_depth,
            self.guarded_writes,
        )
        self.scopes = (
            [env.copy() for env in enclosing] + [{}]
            if callback
            else [
                {
                    name: value if value.startswith("local:") and node["type"] in _FUNCTIONS else "unknown"
                    for env in enclosing
                    for name, value in env.items()
                },
                {},
            ]
        )
        self.function_scope = len(self.scopes) - 1
        self.target = caller if callback else target
        self.loop_depth = loop_depth + 1 if callback else 0
        self.guarded_writes = guards if callback else set()
        try:
            for index, param in enumerate(node["params"]):
                self._declare(_name(param), callback_item if callback and index == 0 else "unknown")
            self.read(node["body"])
            if callback:
                after = self.scopes[:-1]
        finally:
            self.scopes, self.function_scope, self.target, self.loop_depth, self.guarded_writes = (
                enclosing,
                scope,
                caller,
                loop_depth,
                guards,
            )
        if callback:
            self._merge(enclosing, after)
        self.intents.add(_HELPER)

    def _new(self, node: dict) -> str:
        name = _name(node["callee"])
        args = node["arguments"]
        if name == "Array":
            _require(_valid_array_args(args), "array_constructor_limit")
            self._unsafe_in_loop("loop_array_constructor")
        elif name == "RegExp":
            _require(
                len(args) <= 2 and all(isinstance(a.get("value"), str) and len(a["value"]) <= 128 for a in args),
                "dynamic_regexp",
            )
        else:
            _require(name == "Date", "unverified_constructor")
        self._read_many(args)
        self.intents.add(_HELPER)
        self.api_calls.add(f"new {name}")
        return {"Date": "date", "RegExp": "regexp", "Array": "array"}[name]

    def _call(self, node: dict) -> str:
        callee, args = node["callee"], node["arguments"]
        name = _name(callee)
        owner = ""
        if callee["type"] == "MemberExpression":
            _require(not callee["computed"], "computed_call")
            name = _name(callee["property"])
        if name in _DECODERS:
            self.evasive.add(_DECODERS[name])
            raise _Unverified("evasive_string_method")
        if callee["type"] == "MemberExpression":
            receiver = callee["object"]
            owner = self._owner(receiver)
            if name == "join" and receiver["type"] == "ArrayExpression" and len(args) == 1:
                if isinstance(args[0].get("value"), str) and all(
                    item and isinstance(item.get("value"), str) for item in receiver["elements"]
                ):
                    self.evasive.add("array_join_fold")
                    raise _Unverified("evasive_string_method")
        _require(bool(name) and name not in _UNSAFE_NAMES, "dynamic_or_unsafe_call")
        qualified = f"{owner}.{name}" if owner else name
        if name in {"concat", "repeat", "join", "substr", "substring", "slice"}:
            self._unsafe_in_loop("loop_string_method")

        binding = self._binding(name) if not owner else None
        helper = name if not owner and name in self.functions else binding.get(name, "") if binding is not None else ""
        if helper and (helper in self.functions or helper.startswith("local:")):
            self.calls.setdefault(self.target, set()).add(helper)
            if self.loop_depth:
                self.loop_calls.add(helper)
            intent, result = _HELPER, "unknown"
        else:
            _require(binding is None, "dynamic_local_call")
            intent, result = self._call_capability(owner, name, args)
        alert = qualified == "app.alert"
        for index, arg in enumerate(args):
            if arg["type"] in _FUNCTIONS:
                _require(owner in _ARRAYS and name in _CALLBACKS and index == 0, "unverified_callback")
                item_type = {"ocg_list": "ocg", "match": "string"}.get(owner, "unknown")
                self._function(arg, self.target, callback_item=item_type if name != "reduce" else "unknown")
            elif alert and len(args) == 1 and arg["type"] == "ObjectExpression":
                self._object(arg, alert_options=True)
            else:
                value = self.read(arg)
                if alert:
                    _require(value in _SCALARS, "unverified_alert_argument")
        self.intents.add(intent)
        self.api_calls.add(qualified)
        return result

    def _call_capability(self, owner: str, name: str, args: list[dict]) -> tuple[str, str]:
        intent = _HOST_CALLS.get(owner, {}).get(name) if owner else _DIRECT_CALLS.get(name)
        if intent:
            if name == "execMenuItem":
                menu_item = args[0].get("value") if len(args) == 1 else None
                _require(isinstance(menu_item, str) and menu_item in _MENU_ITEMS, "unverified_menu_item")
                if menu_item == "Print":
                    intent = _PRINT
            if owner == "app" and name == "alert":
                _require(bool(args) and len(args) <= 4, "unverified_alert_arguments")
            if not owner and name == "Array":
                _require(_valid_array_args(args), "array_constructor_limit")
            if (
                intent in {_NOTICE, _PRINT, _NAV}
                and name != "getOCGs"
                or name in {"resetForm", "calculateNow", "Array"}
            ):
                self._unsafe_in_loop("loop_pdf_side_effect")
            return intent, {
                "getField": "field",
                "getPrintParams": "print_params",
                "getOCGs": "ocg_list",
                "getNthFieldName": "string",
                "Number": "number",
                "parseInt": "number",
                "parseFloat": "number",
                "String": "string",
                "Boolean": "boolean",
                "isNaN": "boolean",
                "isFinite": "boolean",
                "printd": "string",
                "printx": "string",
                "scand": "date",
                "AFMakeNumber": "number",
                "AFExtractNums": "array",
                "AFParseDateEx": "date",
                "Array": "array",
            }.get(name, "scalar")
        if owner == "field" and name in _FIELD_CALLS:
            if name in {"setFocus", "setItems", "clearItems", "checkThisBox"}:
                self._unsafe_in_loop("loop_field_method")
            return _CALC, "scalar"
        if owner == "Math" and name in _MATH_CALLS or owner == "Date" and name in {"now", "parse", "UTC"}:
            return _HELPER, "number"
        if owner == "date" and name in _DATE_CALLS:
            return _HELPER, "string" if name.startswith("to") else "number"
        if owner == "regexp" and name in {"test", "exec"}:
            return _FORM, "boolean" if name == "test" else "match"
        if owner in _SCALARS | {"unknown"} and name in _STRING_CALLS:
            return _HELPER, _STRING_CALLS[name]
        if owner in _ARRAYS:
            if name in _CALLBACKS:
                _require(bool(args) and args[0]["type"] in _FUNCTIONS, "unverified_callback")
                return _HELPER, {"map": "array", "filter": owner, "some": "boolean", "every": "boolean"}.get(
                    name, "unknown"
                )
            if name in {"indexOf", "lastIndexOf", "includes", "slice", "concat", "join"}:
                return _HELPER, {"slice": owner, "concat": owner, "join": "string", "includes": "boolean"}.get(
                    name, "number"
                )
        raise _Unverified("unverified_api")

    def _assignment(self, node: dict) -> str:
        left, right, op = node["left"], node["right"], node["operator"]
        name = _name(left)
        reads_target = bool(name) and _references_name(right, name)
        if self.loop_depth and _self_doubling(node):
            self.indicators.add("heap_spray_loop")
            raise _Unverified("heap_spray_loop")
        old = self.read(left) if op != "=" else "unknown"
        right_value = self.read(right)
        value = right_value
        if op == "+=":
            numeric_rhs = right["type"] == "Literal" and right_value in _NUMBERS
            numeric_rhs |= right["type"] == "CallExpression" and _name(right["callee"]) in {
                "Number",
                "parseFloat",
                "parseInt",
            }
            if old not in _NUMBERS or not numeric_rhs or reads_target:
                self._unsafe_in_loop("loop_string_accumulation")
            value = _add_type(old, right_value)
        elif op != "=":
            value = "number"
        elif reads_target and value not in _NUMBERS:
            self._unsafe_in_loop("loop_string_accumulation")
        _require(not _self_doubling(node) or value in _NUMBERS, "unbounded_string_growth")
        self._write(left, value)
        return value

    def _loop(self, node: dict) -> None:
        kind = node["type"]
        self.scopes.append({})
        before: list[dict[str, str]]
        guards = self.guarded_writes
        self.loop_depth += 1
        try:
            body = node["body"]
            if kind == "ForInStatement":
                _require(self.read(node["right"]) in _ARRAYS | {"object"}, "unverified_loop_iterable")
                left = node["left"]
                if left["type"] == "VariableDeclaration":
                    self.read(left)
                    index = _name(left["declarations"][0]["id"])
                else:
                    index = _name(left)
                _require(bool(index), "unverified_loop_index")
                self._write({"type": "Identifier", "name": index}, "index_key")
                loop_guard = {index}
            else:
                self.read(node.get("init"))
                test = node.get("test") or {}
                _require(
                    test.get("type") == "BinaryExpression" and test["operator"] in {"<", "<=", ">", ">="},
                    "unverified_loop_bound",
                )
                index, bound = _name(test["left"]), test["right"]
                ascending = test["operator"] in {"<", "<="}
                start_type = self.read(test["left"])
                _require(
                    bool(index) and (start_type == "small_integer" or not ascending and start_type == "last_index"),
                    "unverified_loop_index",
                )
                bound_type = self.read(bound)
                _require(
                    bound_type == "small_integer" or ascending and bound_type in {"length", "document_count"},
                    "unverified_loop_bound",
                )
                update = node.get("update")
                if kind != "ForStatement":
                    statements = body["body"] if body["type"] == "BlockStatement" else [body]
                    _require(bool(statements), "unverified_loop_progress")
                    first, last = statements[0], statements[-1]
                    progress = first if _progresses(first.get("expression"), index, test["operator"]) else last
                    update = progress.get("expression")
                    if progress is last and progress is not first:
                        _require(not _contains_kind(body, "ContinueStatement"), "unverified_loop_progress")
                    body = {"type": "BlockStatement", "body": [stmt for stmt in statements if stmt is not progress]}
                _require(_progresses(update, index, test["operator"]), "unverified_loop_progress")
                self.read(update)
                loop_guard = {index}
                if bound["type"] == "MemberExpression":
                    loop_guard.add(_name(bound["object"]))
                else:
                    loop_guard.add(_name(bound))
            self.guarded_writes = guards | loop_guard
            before = [scope.copy() for scope in self.scopes]
            self.read(body)
            self._merge(before, self.scopes)
        finally:
            self.guarded_writes = guards
            self.loop_depth -= 1
            self.scopes.pop()

    def read(self, node: dict | None) -> str:
        if node is None:
            return "unknown"
        kind = node["type"]
        _require(kind not in _OPERATORS or node.get("operator") in _OPERATORS[kind], "unsupported_operator")
        if kind in _SIMPLE_STATEMENTS:
            if kind == "BlockStatement":
                self.scopes.append({})
            try:
                self._read_many([child for _, child in children(node) if child["type"] != "FunctionDeclaration"])
            finally:
                if kind == "BlockStatement":
                    self.scopes.pop()
            _require(
                kind == "Program" or not any(child["type"] == "FunctionDeclaration" for _, child in children(node)),
                "non_top_level_function",
            )
        elif kind == "VariableDeclaration":
            for decl in node["declarations"]:
                name, init = _name(decl["id"]), decl.get("init")
                _require(name not in self.guarded_writes, "unverified_loop_index_rebinding")
                if init and init["type"] in _FUNCTIONS:
                    target = f"local:{id(init)}"
                    self._function(init, target)
                    value = target
                else:
                    value = self.read(init)
                    if init and value not in _NUMBERS and _references_name(init, name):
                        self._unsafe_in_loop("loop_string_accumulation")
                self._declare(name, value, var=node["kind"] == "var", initialized=init is not None)
        elif kind in {"IfStatement", "ConditionalExpression", "LogicalExpression"}:
            test_value = self.read(node["left"] if kind == "LogicalExpression" else node["test"])
            left, left_scopes = self._fork(node["right"] if kind == "LogicalExpression" else node["consequent"])
            right, right_scopes = self._fork(node.get("alternate"))
            self._merge(left_scopes, right_scopes)
            result_types = {left, test_value if kind == "LogicalExpression" else right}
            if len(result_types) == 1:
                return left
            if result_types <= _NUMBERS:
                return "number"
            return "scalar" if result_types <= _SCALARS else "unknown"
        elif kind == "SwitchStatement":
            self.read(node["discriminant"])
            entry = [scope.copy() for scope in self.scopes]
            for case in node["cases"]:
                _, path = self._fork(case)
                self._merge(entry, self.scopes, path)
        elif kind == "SwitchCase":
            self.read(node.get("test"))
            self._read_many(node["consequent"])
        elif kind == "TryStatement":
            _, attempted = self._fork(node["block"])
            handler, finalizer = node.get("handler"), node.get("finalizer")
            if handler or finalizer:
                for name in _assigned_names(node["block"]):
                    scope = self._binding(name)
                    if scope is not None:
                        scope[name] = "unknown"
                _, caught = self._fork(handler)
                self._merge(attempted, caught)
                self.read(finalizer)
        elif kind == "CatchClause":
            self.scopes.append({})
            try:
                self._declare(_name(node["param"]), "unknown")
                self.read(node["body"])
            finally:
                self.scopes.pop()
        elif kind in _LOOPS:
            self._loop(node)
        elif kind == "Literal":
            return self._literal(node)
        elif kind == "Identifier":
            name = node["name"]
            if name in {"undefined", "NaN", "Infinity"}:
                return "number" if name != "undefined" else "scalar"
            scope = self._binding(name)
            _require(scope is not None and not scope[name].startswith("local:"), "unverified_identifier")
            return scope[name]
        elif kind == "SequenceExpression":
            return self._read_many(node["expressions"])[-1]
        elif kind == "UnaryExpression":
            self.read(node["argument"])
            return {"typeof": "string", "!": "boolean", "void": "scalar"}.get(node["operator"], "number")
        elif kind == "UpdateExpression":
            _require(bool(_name(node["argument"])), "unverified_update")
            self.read(node["argument"])
            self._write(node["argument"], "number")
            return "number"
        elif kind == "BinaryExpression":
            left = self.read(node["left"])
            right = (
                "constructor"
                if node["operator"] == "instanceof" and _name(node["right"]) in {"Date", "RegExp", "Array"}
                else self.read(node["right"])
            )
            if node["operator"] == "-" and left in {"length", "document_count"} and _integer(node["right"]) == 1:
                return "last_index"
            return (
                _add_type(left, right)
                if node["operator"] == "+"
                else ("number" if node["operator"] in {"-", "*", "/", "%"} else "boolean")
            )
        elif kind == "AssignmentExpression":
            return self._assignment(node)
        elif kind == "ArrayExpression":
            _require(len(node["elements"]) <= 128, "array_literal_limit")
            self._read_many(node["elements"])
            return "array"
        elif kind == "ObjectExpression":
            return self._object(node)
        elif kind == "MemberExpression":
            return self._member(node)
        elif kind == "CallExpression":
            return self._call(node)
        elif kind == "NewExpression":
            return self._new(node)
        else:
            raise _Unverified(f"unsupported_ast:{kind}")
        return "unknown"

    def _object(self, node: dict, *, alert_options: bool = False) -> str:
        for prop in node["properties"]:
            _require(prop["type"] == "Property", "unsafe_object_property")
            name = _property(prop["key"])
            _require(
                name is not None
                and name not in _UNSAFE_NAMES
                and not prop["computed"]
                and not prop["method"]
                and prop["kind"] == "init",
                "unsafe_object_property",
            )
            if prop["key"]["type"] == "Literal":
                self._literal(prop["key"])
            value = self.read(prop["value"])
            if alert_options:
                _require(name in {"cMsg", "cTitle", "nIcon", "nType"} and value in _SCALARS, "unverified_alert_options")
        return "object"


def _add_type(left: str, right: str) -> str:
    if left == "string" or right == "string":
        return "string"
    return "number" if left in _NUMBERS and right in _NUMBERS else "unknown"


def _references_name(node: dict, name: str) -> bool:
    return _name(node) == name or any(_references_name(child, name) for _, child in children(node))


def _contains_kind(node: dict, kind: str) -> bool:
    return node["type"] == kind or any(_contains_kind(child, kind) for _, child in children(node))


def _assigned_names(node: dict) -> set[str]:
    names = set()
    target = {"VariableDeclarator": "id", "AssignmentExpression": "left", "UpdateExpression": "argument"}
    pending = [node]
    while pending:
        child = pending.pop()
        if key := target.get(child["type"]):
            names.add(_name(child[key]))
        pending.extend(descendant for _, descendant in children(child))
    return names - {""}


def _self_doubling(node: dict) -> bool:
    name = _name(node["left"])
    right = node["right"]
    return bool(name) and (
        node["operator"] == "+="
        and _name(right) == name
        or node["operator"] == "="
        and right["type"] == "BinaryExpression"
        and right["operator"] == "+"
        and _name(right["left"]) == _name(right["right"]) == name
    )


def _progresses(node: dict | None, index: str, comparison: str) -> bool:
    direction = comparison in {"<", "<="}
    if not node:
        return False
    if node["type"] == "UpdateExpression":
        return _name(node["argument"]) == index and node["operator"] == ("++" if direction else "--")
    if node["type"] == "AssignmentExpression":
        if _name(node["left"]) != index:
            return False
        if node["operator"] == ("+=" if direction else "-="):
            return (_integer(node["right"]) or 0) > 0
        right = node["right"]
        return (
            node["operator"] == "="
            and right["type"] == "BinaryExpression"
            and right["operator"] == ("+" if direction else "-")
            and _name(right["left"]) == index
            and (_integer(right["right"]) or 0) > 0
        )
    return False


def _script_report(
    intents: set[str], reasons: set[str], evasive: set[str], calls: set[str], indicators: set[str]
) -> dict[str, Any]:
    codes = sorted(intents)
    return {
        "is_verified_benign": not (reasons or evasive or indicators),
        "intent_codes": codes,
        "intent_label_vi": _label_intents(codes) if not (reasons or evasive or indicators) else "",
        "unverified_reasons": sorted(reasons),
        "evasive_obfuscation_techniques": sorted(evasive),
        "benign_api_calls": sorted(calls),
        "dangerous_indicators": sorted(indicators),
    }


def analyze_pdf_javascript_intent(
    codes: list[str],
    *,
    max_js_bytes: int = 262_144,
    max_verified_total_bytes: int = 32_768,
    max_verified_nodes_per_script: int = 2_500,
    max_verified_depth: int = 32,
) -> dict[str, Any]:
    unique = Counter(codes)
    reasons: dict[str, set[str]] = {code: set() for code in unique}
    trees = {}
    declarations: dict[str, str] = {}
    remaining = max_verified_total_bytes
    total_loops = 0
    hazards = {}
    for code in unique:
        size = (
            len(code) if len(code) > min(max_js_bytes, remaining) else len(code.encode("utf-8", errors="surrogatepass"))
        )
        if size > max_js_bytes or size * unique[code] > remaining:
            reasons[code].add("script_byte_limit" if size > max_js_bytes else "total_byte_limit")
            continue
        remaining -= size * unique[code]
        try:
            tree = esprima.parseScript(code, tolerant=False).toDict()
            loops, indicators = _bounds(tree, max_verified_nodes_per_script, max_verified_depth)
        except _Unverified as error:
            reasons[code].add(str(error))
            continue
        except (esprima.Error, RecursionError, ValueError, OverflowError):
            reasons[code].add("javascript_syntax_error")
            continue
        trees[code] = tree
        total_loops += loops * unique[code]
        hazards[code] = indicators
        for node in tree["body"]:
            if node["type"] == "FunctionDeclaration":
                name = _name(node["id"])
                if name in declarations:
                    reasons[code].add("ambiguous_helper_binding")
                    reasons[declarations[name]].add("ambiguous_helper_binding")
                declarations[name] = code

    functions = set(declarations)
    verifiers = {code: _IntentVerifier(functions, f"script:{index}") for index, code in enumerate(trees)}
    owners = dict(declarations)
    calls: dict[str, set[str]] = {}
    loop_unsafe: set[str] = set()
    for code, verifier in verifiers.items():
        tree = trees[code]
        verifier.indicators.update(hazards[code])
        owners[verifier.target] = code
        if all(node["type"] == "EmptyStatement" for node in tree["body"]):
            verifier.intents.add(_EMPTY)
            continue
        techniques = []
        if _HEX_ESCAPE.search(code):
            techniques.append("hex_escape_decode")
        if _ASCII_ESCAPE.search(code) or _OCTAL_ESCAPE.search(code):
            techniques.append("unicode_escape_decode")
        if _FRAGMENT_CHAIN.search(code):
            techniques.append("string_concat_fold")
        verifier.evasive.update(techniques)
        try:
            verifier.read(tree)
            for node in tree["body"]:
                if node["type"] == "FunctionDeclaration":
                    name = _name(node["id"])
                    _require(bool(name) and name not in _RESERVED, "unsupported_helper_binding")
                    verifier._function(node, name)
        except _Unverified as error:
            reasons[code].add(str(error))
        if not verifier.intents:
            verifier.intents.add(_HELPER)
        calls.update(verifier.calls)
        for target in verifier.calls.keys() | verifier.loop_unsafe | set().union(*verifier.calls.values()):
            if target.startswith("local:"):
                owners[target] = code
        loop_unsafe.update(verifier.loop_unsafe)
        if verifier.evasive:
            reasons[code].add("evasive_obfuscation")

    if total_loops > 8:
        for code in unique:
            reasons[code].add("loop_count_limit")

    dependencies = {target: set(callees) for target, callees in calls.items()}
    while ready := {target for target, callees in dependencies.items() if not callees.intersection(dependencies)}:
        for target in ready:
            if calls[target].intersection(loop_unsafe):
                loop_unsafe.add(target)
            del dependencies[target]
    for target in dependencies:
        reasons[owners[target]].add("recursive_or_dependent_helper")
    for code, verifier in verifiers.items():
        if verifier.loop_calls.intersection(loop_unsafe):
            reasons[code].add("unverified_loop_helper")
    while True:
        unverified = {code for code in unique if reasons[code]}
        affected = {
            owners[target]
            for target, callees in calls.items()
            if any(owners[callee] in unverified for callee in callees)
        }
        if affected <= unverified:
            break
        for code in affected - unverified:
            reasons[code].add("unverified_helper_dependency")

    reports = {}
    for code in unique:
        verifier = verifiers.get(code)
        reports[code] = _script_report(
            verifier.intents if verifier else set(),
            reasons[code],
            verifier.evasive if verifier else set(),
            verifier.api_calls if verifier else set(),
            verifier.indicators if verifier else set(),
        )
    per_script = [reports[code].copy() for code in codes]
    verified = bool(codes) and all(report["is_verified_benign"] for report in reports.values())
    intents = sorted(
        {intent for report in reports.values() if report["is_verified_benign"] for intent in report["intent_codes"]}
    )
    return {
        "is_verified_benign_js": verified,
        "script_intents": intents,
        "intent_summary_vi": _label_intents(intents) if verified else "",
        "per_script_intents": per_script,
        "unverified_reasons": sorted(
            {reason for report in reports.values() for reason in report["unverified_reasons"]}
        ),
        "benign_api_calls": sorted(
            {call for report in reports.values() if report["is_verified_benign"] for call in report["benign_api_calls"]}
        ),
        "evasive_obfuscation_techniques": sorted(
            {tech for report in reports.values() for tech in report["evasive_obfuscation_techniques"]}
        ),
        "dangerous_indicators": sorted(
            {indicator for report in reports.values() for indicator in report["dangerous_indicators"]}
        ),
    }
