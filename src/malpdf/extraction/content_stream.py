from collections import Counter
import re
import struct


class ContentStreamIssue(Exception):
    def __init__(self, code: str, details: dict | None = None, status: str = "partial") -> None:
        self.code, self.details, self.status = code, details or {}, status


def extract_literal_string(data: bytes, start: int) -> tuple[bytes, int]:
    result = bytearray()
    depth = 1
    offset = start + 1
    escaped = False
    while offset < len(data):
        char = data[offset]
        if escaped:
            if char in b"()\\":
                result.append(char)
            elif char == ord(b"n"):
                result.append(ord(b"\n"))
            elif char == ord(b"r"):
                result.append(ord(b"\r"))
            elif char == ord(b"t"):
                result.append(ord(b"\t"))
            elif char == ord(b"b"):
                result.append(ord(b"\b"))
            elif char == ord(b"f"):
                result.append(ord(b"\f"))
            elif 48 <= char <= 55:
                octal = bytes([char])
                for _ in range(2):
                    if offset + 1 < len(data) and 48 <= data[offset + 1] <= 55:
                        offset += 1
                        octal += bytes([data[offset]])
                    else:
                        break
                result.append(int(octal, 8) & 0xFF)
            else:
                result.append(char)
            escaped = False
            offset += 1
            continue
        if char == ord(b"\\"):
            escaped = True
            offset += 1
            continue
        if char == ord(b"("):
            depth += 1
        elif char == ord(b")"):
            depth -= 1
            if depth == 0:
                return bytes(result), offset + 1
        result.append(char)
        offset += 1
    raise ContentStreamIssue("unterminated_literal_string")


def extract_hex_string(data: bytes, start: int) -> tuple[bytes, int]:
    end = data.find(b">", start)
    if end < 0:
        raise ContentStreamIssue("unterminated_hex_string")
    cleaned = re.sub(rb"\s+", b"", data[start + 1:end])
    if len(cleaned) % 2 == 1:
        cleaned += b"0"
    try:
        parsed = bytes.fromhex(cleaned.decode("ascii"))
    except ValueError:
        raise ContentStreamIssue("invalid_hex_string") from None
    return parsed, end + 1


def tokenize_stream(data: bytes) -> list:
    tokens = []
    offset = 0
    length = len(data)
    while offset < length:
        while offset < length and data[offset] in b"\x00\t\n\f\r ":
            offset += 1
        if offset >= length:
            break
        char = data[offset]
        if char == ord(b"%"):
            newline = data.find(b"\n", offset)
            offset = length if newline < 0 else newline + 1
            continue
        if char == ord(b"("):
            val, offset = extract_literal_string(data, offset)
            tokens.append(("string", val))
            continue
        if char == ord(b"<"):
            if offset + 1 < length and data[offset + 1] == ord(b"<"):
                tokens.append(("dict_begin", b"<<"))
                offset += 2
                continue
            val, offset = extract_hex_string(data, offset)
            tokens.append(("string", val))
            continue
        if char == ord(b">") and offset + 1 < length and data[offset + 1] == ord(b">"):
            tokens.append(("dict_end", b">>"))
            offset += 2
            continue
        if char == ord(b"/"):
            start = offset
            offset += 1
            while offset < length and data[offset] not in b"\x00\t\n\f\r /()<>[]{}/%":
                offset += 1
            tokens.append(("name", data[start:offset].decode("latin-1", "replace")))
            continue
        if char == ord(b"["):
            tokens.append(("array_begin", b"["))
            offset += 1
            continue
        if char == ord(b"]"):
            tokens.append(("array_end", b"]"))
            offset += 1
            continue
        start = offset
        while offset < length and data[offset] not in b"\x00\t\n\f\r /()<>[]{}/%":
            offset += 1
        word = data[start:offset]
        try:
            val = int(word)
            tokens.append(("int", val))
        except ValueError:
            try:
                val = float(word)
                tokens.append(("float", val))
            except ValueError:
                tokens.append(("op", word.decode("latin-1", "replace")))
    return tokens


def inspect_content_stream(data: bytes, boundary_box: tuple[float, float, float, float] | None = None) -> dict:
    result = {
        "format": "content_stream",
        "complete": False,
        "reason_codes": [],
        "operator_counts": {},
        "total_characters": 0,
        "visible_characters": 0,
        "invisible_characters": 0,
        "invisible_character_ratio": 0.0,
        "has_text_rendering_mode_3": False,
        "has_zero_font_size": False,
        "has_white_on_white_text": False,
        "has_off_page_text": False,
        "font_names_present": [],
        "text_blocks_count": 0,
        "scope": "static page content stream token inspection and visibility modeling without pixel rendering",
        "rendering_performed": False,
    }
    try:
        tokens = tokenize_stream(data)
    except ContentStreamIssue as error:
        result["reason_codes"] = [error.code]
        raise ContentStreamIssue(error.code, details=result) from None

    operator_counts = Counter()
    font_names = set()
    reasons = set()

    state = {
        "font": None,
        "font_size": 12.0,
        "render_mode": 0,
        "fill_color": (0.0, 0.0, 0.0),
        "text_matrix": [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
        "line_matrix": [1.0, 0.0, 0.0, 1.0, 0.0, 0.0],
    }
    state_stack = []
    in_text = False
    stack = []

    def record_text(text_bytes: bytes, current_state: dict) -> None:
        chars = len(text_bytes)
        result["total_characters"] += chars
        invisible = False
        if current_state["render_mode"] == 3:
            result["has_text_rendering_mode_3"] = True
            reasons.add("invisible_text_tr3")
            invisible = True
        if current_state["font_size"] == 0.0:
            result["has_zero_font_size"] = True
            reasons.add("zero_font_size")
            invisible = True
        if current_state["fill_color"] == (1.0, 1.0, 1.0) and not invisible:
            result["has_white_on_white_text"] = True
            reasons.add("white_on_white_text")
        if boundary_box is not None:
            tx = current_state["text_matrix"][4]
            ty = current_state["text_matrix"][5]
            bx0, by0, bx1, by1 = boundary_box
            if not (bx0 <= tx <= bx1 and by0 <= ty <= by1):
                result["has_off_page_text"] = True
                reasons.add("off_page_text")
        if invisible:
            result["invisible_characters"] += chars
        else:
            result["visible_characters"] += chars

    token_index = 0
    while token_index < len(tokens):
        kind, value = tokens[token_index]
        token_index += 1
        if kind in ("int", "float", "name", "string"):
            stack.append(value)
            continue
        if kind == "array_begin":
            sub_array = []
            while token_index < len(tokens) and tokens[token_index][0] != "array_end":
                sub_array.append(tokens[token_index][1])
                token_index += 1
            if token_index < len(tokens):
                token_index += 1
            stack.append(sub_array)
            continue
        if kind != "op":
            continue

        op = value
        operator_counts[op] += 1

        if op == "q":
            if len(state_stack) < 32:
                state_stack.append({
                    "font": state["font"],
                    "font_size": state["font_size"],
                    "render_mode": state["render_mode"],
                    "fill_color": state["fill_color"],
                    "text_matrix": list(state["text_matrix"]),
                    "line_matrix": list(state["line_matrix"]),
                })
            else:
                reasons.add("graphics_state_overflow")
            stack.clear()
        elif op == "Q":
            if state_stack:
                state = state_stack.pop()
            else:
                reasons.add("graphics_state_underflow")
            stack.clear()
        elif op == "BT":
            in_text = True
            result["text_blocks_count"] += 1
            state["text_matrix"] = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0]
            state["line_matrix"] = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0]
            stack.clear()
        elif op == "ET":
            in_text = False
            stack.clear()
        elif op == "Tf":
            if len(stack) >= 2:
                size_val = stack.pop()
                name_val = stack.pop()
                if isinstance(size_val, (int, float)):
                    state["font_size"] = float(size_val)
                if isinstance(name_val, str):
                    state["font"] = name_val
                    font_names.add(name_val)
            stack.clear()
        elif op == "Tr":
            if stack and isinstance(stack[-1], (int, float)):
                state["render_mode"] = int(stack.pop())
            stack.clear()
        elif op in ("Td", "TD"):
            if len(stack) >= 2:
                ty = float(stack.pop())
                tx = float(stack.pop())
                state["line_matrix"][4] += tx
                state["line_matrix"][5] += ty
                state["text_matrix"] = list(state["line_matrix"])
            stack.clear()
        elif op == "Tm":
            if len(stack) >= 6:
                vals = [float(stack.pop()) for _ in range(6)][::-1]
                state["text_matrix"] = vals
                state["line_matrix"] = list(vals)
            stack.clear()
        elif op == "T*":
            stack.clear()
        elif op in ("Tj", "'", "\""):
            if stack and isinstance(stack[-1], bytes):
                record_text(stack.pop(), state)
            stack.clear()
        elif op == "TJ":
            if stack and isinstance(stack[-1], list):
                arr = stack.pop()
                for item in arr:
                    if isinstance(item, bytes):
                        record_text(item, state)
            stack.clear()
        elif op == "g":
            if stack and isinstance(stack[-1], (int, float)):
                val = float(stack.pop())
                state["fill_color"] = (val, val, val)
            stack.clear()
        elif op == "rg":
            if len(stack) >= 3:
                b = float(stack.pop())
                g = float(stack.pop())
                r = float(stack.pop())
                state["fill_color"] = (r, g, b)
            stack.clear()
        elif op == "k":
            if len(stack) >= 4:
                k = float(stack.pop())
                y = float(stack.pop())
                m = float(stack.pop())
                c = float(stack.pop())
                r = (1.0 - c) * (1.0 - k)
                g = (1.0 - m) * (1.0 - k)
                b = (1.0 - y) * (1.0 - k)
                state["fill_color"] = (round(r, 4), round(g, 4), round(b, 4))
            stack.clear()
        else:
            stack.clear()

    total = result["total_characters"]
    result["operator_counts"] = dict(operator_counts)
    result["font_names_present"] = sorted(font_names)
    result["invisible_character_ratio"] = (result["invisible_characters"] / total) if total > 0 else 0.0
    result["complete"] = not bool(reasons)
    result["reason_codes"] = sorted(reasons)
    return result
