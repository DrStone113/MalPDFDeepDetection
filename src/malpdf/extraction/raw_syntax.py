"""Bounded PDF byte lexer and object grammar, independent of native parsers.

No PDF reader/object parser is called here. The existing text codec is reused
only to compare decoded string identities; all original lexical bytes survive
as ranges/digests. Nodes stay internal; exports redact arbitrary names/content.
"""

from dataclasses import dataclass
from decimal import Decimal
import hashlib
import json
import re

WS = frozenset(b'\x00\t\n\f\r ')
DELIMITERS = WS | frozenset(b'()<>[]{}/%')
NUMBER = re.compile(rb'[+-]?(?:\d+(?:\.\d*)?|\.\d+)\Z')
INTEGER = re.compile(rb'[+-]?\d+\Z')


def digest(data):
    return hashlib.sha256(data).hexdigest()


class SyntaxIssue(Exception):
    def __init__(self, code, offset, status='partial'):
        self.code,self.offset,self.status = code,offset,status


@dataclass
class SyntaxBudget:
    max_tokens: int
    max_nodes: int
    max_depth: int
    max_string_bytes: int
    tokens: int = 0
    nodes: int = 0

    def token(self, offset):
        if self.tokens >= self.max_tokens:
            raise SyntaxIssue('forensic_token_limit',offset,'resource_limit')
        self.tokens += 1

    def node(self, offset):
        if self.nodes >= self.max_nodes:
            raise SyntaxIssue('forensic_node_limit',offset,'resource_limit')
        self.nodes += 1


@dataclass
class Node:
    kind: str
    value: object
    start: int
    end: int
    issues: tuple = ()


@dataclass
class Token:
    kind: str
    value: object
    start: int
    end: int
    issues: tuple = ()


class Lexer:
    def __init__(self, data, budget, start=0, end=None):
        self.data,self.budget,self.pos = data,budget,start
        self.end = len(data) if end is None else end
        self.queue = []

    def seek(self, position):
        if not 0 <= position <= self.end:
            raise SyntaxIssue('forensic_position_invalid',self.pos)
        self.pos,self.queue = position,[]

    def skip(self, *, eof_callback=None):
        while self.pos < self.end:
            if self.data[self.pos] in WS:
                self.pos += 1
            elif self.data[self.pos] == 37:
                begin = self.pos
                while self.pos < self.end and self.data[self.pos] not in (10,13):
                    self.pos += 1
                if eof_callback and self.data[begin:self.pos].rstrip(b'\x00\t\f ') == b'%%EOF':
                    eof_callback(begin,self.pos)
            else:
                break

    def _string(self, start):
        output,depth = bytearray(),1
        self.pos += 1
        escapes = {110:10,114:13,116:9,98:8,102:12}
        while self.pos < self.end:
            byte = self.data[self.pos]
            self.pos += 1
            if byte == 92:
                if self.pos == self.end:
                    break
                byte = self.data[self.pos]
                self.pos += 1
                if byte in (10,13):
                    if byte == 13 and self.pos < self.end and self.data[self.pos] == 10:
                        self.pos += 1
                    continue
                if 48 <= byte <= 55:
                    octal = byte - 48
                    for _ in range(2):
                        if self.pos < self.end and 48 <= self.data[self.pos] <= 55:
                            octal = octal*8 + self.data[self.pos] - 48
                            self.pos += 1
                        else:
                            break
                    output.append(octal & 255)
                else:
                    output.append(escapes.get(byte,byte))
            elif byte == 40:
                depth += 1
                if depth > self.budget.max_depth:
                    raise SyntaxIssue('forensic_string_depth_limit',start,'resource_limit')
                output.append(byte)
            elif byte == 41:
                depth -= 1
                if depth == 0:
                    return Token('string',bytes(output),start,self.pos)
                output.append(byte)
            elif byte == 13:
                output.append(10)
                if self.pos < self.end and self.data[self.pos] == 10:
                    self.pos += 1
            else:
                output.append(byte)
            if len(output) > self.budget.max_string_bytes:
                raise SyntaxIssue('forensic_string_byte_limit',start,'resource_limit')
        raise SyntaxIssue('forensic_unterminated_string',start)

    def _hex(self, start):
        self.pos += 1
        output,high = bytearray(),None
        while self.pos < self.end:
            byte = self.data[self.pos]
            self.pos += 1
            if byte in WS:
                continue
            if byte == 62:
                if high is not None:
                    output.append(high << 4)
                return Token('string',bytes(output),start,self.pos)
            if 48 <= byte <= 57:
                value = byte-48
            elif 65 <= byte <= 70:
                value = byte-55
            elif 97 <= byte <= 102:
                value = byte-87
            else:
                raise SyntaxIssue('forensic_invalid_hex_string',self.pos-1)
            if high is None:
                high = value
            else:
                output.append((high<<4)|value)
                high = None
            if len(output) > self.budget.max_string_bytes:
                raise SyntaxIssue('forensic_string_byte_limit',start,'resource_limit')
        raise SyntaxIssue('forensic_unterminated_hex_string',start)

    def _read(self):
        self.skip()
        start = self.pos
        if start >= self.end:
            return Token('eof',None,start,start)
        self.budget.token(start)
        byte = self.data[self.pos]
        if byte == 40:
            return self._string(start)
        pair = self.data[self.pos:self.pos+2]
        if pair in (b'<<',b'>>'):
            self.pos += 2
            return Token(pair.decode(),None,start,self.pos)
        if byte == 60:
            return self._hex(start)
        if byte in b'[]()>{}':
            self.pos += 1
            return Token(chr(byte),None,start,self.pos)
        if byte == 47:
            self.pos += 1
            while self.pos < self.end and self.data[self.pos] not in DELIMITERS:
                self.pos += 1
                if self.pos-start > 4096:
                    raise SyntaxIssue('forensic_name_byte_limit',start,'resource_limit')
            raw = self.data[start+1:self.pos]
            output,issues,index = bytearray(b'/'),[],0
            while index < len(raw):
                if raw[index] == 35:
                    code = raw[index+1:index+3]
                    if len(code)==2 and all(value in b'0123456789abcdefABCDEF' for value in code):
                        value=int(code,16)
                        if value==0:
                            issues.append('forensic_null_name_byte')
                        output.append(value);index += 3
                        continue
                    issues.append('forensic_invalid_name_escape')
                output.append(raw[index]);index += 1
            return Token('name',bytes(output),start,self.pos,tuple(sorted(set(issues))))
        while self.pos < self.end and self.data[self.pos] not in DELIMITERS:
            self.pos += 1
            if self.pos-start > 256:
                raise SyntaxIssue('forensic_token_byte_limit',start,'resource_limit')
        if self.pos == start:
            raise SyntaxIssue('forensic_unexpected_delimiter',start)
        value = self.data[start:self.pos]
        if NUMBER.fullmatch(value):
            return Token('number',int(value) if INTEGER.fullmatch(value) else Decimal(value.decode('ascii')),start,self.pos)
        return Token('keyword',value,start,self.pos)

    def peek(self, index=0):
        while len(self.queue) <= index:
            self.queue.append(self._read())
        return self.queue[index]

    def pop(self):
        return self.queue.pop(0) if self.queue else self._read()

    def expect(self, kind, value=None):
        token = self.pop()
        if token.kind != kind or value is not None and token.value != value:
            raise SyntaxIssue('forensic_expected_'+kind.replace('<','l').replace('>','r'),token.start)
        return token


def parse_value(lexer, depth=0):
    token = lexer.pop()
    lexer.budget.node(token.start)
    if depth > lexer.budget.max_depth:
        raise SyntaxIssue('forensic_object_depth_limit',token.start,'resource_limit')
    kind,value,end,issues = token.kind,token.value,token.end,token.issues
    if kind == 'number' and type(value) is int:
        following = lexer.peek()
        if following.kind == 'number' and type(following.value) is int:
            marker = lexer.peek(1)
            if marker.kind == 'keyword' and marker.value == b'R':
                lexer.pop();lexer.pop()
                if value < 0 or not 0 <= following.value <= 65535:
                    raise SyntaxIssue('forensic_invalid_reference',token.start)
                return Node('reference',(value,following.value),token.start,marker.end)
    if kind == '[':
        value = []
        while lexer.peek().kind != ']':
            if lexer.peek().kind == 'eof':
                raise SyntaxIssue('forensic_unterminated_array',token.start)
            value.append(parse_value(lexer,depth+1))
        end,kind = lexer.pop().end,'array'
    elif kind == '<<':
        value,seen,duplicates = [],set(),False
        while lexer.peek().kind != '>>':
            key = lexer.expect('name')
            lexer.budget.node(key.start)
            if key.value in seen:
                duplicates = True
            seen.add(key.value)
            value.append((Node('name',key.value,key.start,key.end,key.issues),parse_value(lexer,depth+1)))
        end,kind = lexer.pop().end,'dictionary'
        if duplicates:
            issues += ('forensic_duplicate_dictionary_key',)
    elif kind == 'keyword' and value in (b'true',b'false',b'null'):
        kind = 'null' if value == b'null' else 'boolean'
        value = None if kind == 'null' else value == b'true'
    elif kind not in {'number','name','string'}:
        raise SyntaxIssue('forensic_invalid_object_value',token.start)
    return Node(kind,value,token.start,end,issues)


def dictionary_get(node, name):
    if node is None or node.kind != 'dictionary':
        return None
    matches = [value for key,value in node.value if key.value == name and not key.issues]
    return matches[0] if len(matches)==1 else None


def integer(node):
    return node.value if node is not None and node.kind == 'number' and type(node.value) is int else None


def children(node):
    if node.kind == 'dictionary':
        return [child for pair in node.value for child in pair]
    return node.value if node.kind == 'array' else []


def projection(node, *, stream_sha256=None, is_stream=False, code_limits=None, encrypted=False):
    """Common projection convention; original syntax never uses a native reader."""
    if code_limits is None:
        from malpdf.static.code_inspector import CodeInspectionLimits
        code_limits = CodeInspectionLimits()
    visited,complete,keys,fields_complete = 0,True,[],True
    def project(item, depth=0):
        nonlocal visited,complete,fields_complete
        visited += 1
        if visited > 1024 or depth > 8 or item.issues:
            complete = False
            return ['unverified']
        if item.kind == 'reference':
            return ['reference',*item.value]
        if item.kind == 'dictionary':
            output = []
            for key,value in sorted(item.value,key=lambda pair:pair[0].value):
                if is_stream and depth==0 and key.value == b'/Length':
                    continue
                if visited >= 1024:
                    complete = fields_complete = False
                    break
                try:
                    text = key.value.decode('utf-8') if not key.issues else None
                except UnicodeDecodeError:
                    text = None
                if text is None:
                    complete = False
                key_hash = digest(text.encode()) if text is not None else digest(key.value)
                tree = project(value,depth+1)
                output.append([key_hash,tree])
                if depth == 0:
                    if len(keys)<64:
                        def verified(value):
                            return not (isinstance(value,list) and (value==['unverified'] or any(not verified(x) for x in value)))
                        keys.append({'key_sha256':key_hash,'value_type':tree[0],
                            'value_sha256':digest(json.dumps(tree,sort_keys=True).encode()),'complete':text is not None and verified(tree)})
                    else:
                        fields_complete = False
            return ['dictionary',output]
        if item.kind == 'array':
            output = []
            for child in item.value:
                if visited >= 1024:
                    complete = False
                    break
                output.append(project(child,depth+1))
            return ['array',output]
        if item.kind == 'number':
            value = Decimal(item.value)
            sign,digits,exponent = value.as_tuple()
            digits = list(digits)
            while digits and digits[-1] == 0:
                digits.pop();exponent += 1
            return ['number',sign if digits else 0,digits,exponent if digits else 0]
        if item.kind == 'name':
            try:
                return ['NameObject',digest(item.value.decode('utf-8').encode())]
            except UnicodeDecodeError:
                complete = False
                return ['unverified']
        if item.kind == 'string':
            if encrypted:
                complete = False
                return ['unverified']
            from malpdf.static.code_inspector import _decode_script_bytes
            try:
                text = _decode_script_bytes(item.value,code_limits)
                return ['TextStringObject',digest(text.encode())]
            except UnicodeError:
                return ['bytes',digest(item.value)]
            except ValueError:
                complete = False
                return ['unverified']
        return ['BooleanObject' if item.kind == 'boolean' else 'NullObject',
                digest((str(item.value) if item.kind == 'boolean' else 'NullObject').encode())]
    tree = project(node)
    if is_stream and stream_sha256 is None:
        complete = False
    security = {b'/JavaScript',b'/Launch',b'/URI',b'/SubmitForm',b'/GoToR',b'/GoToE',b'/ImportData',
                b'/JS',b'/AA',b'/OpenAction',b'/XFA',b'/EF'}
    action = dictionary_get(node,b'/S')
    return {'type':'StreamObject' if is_stream else {'dictionary':'DictionaryObject','array':'ArrayObject',
            'number':'NumberObject' if type(node.value) is int else 'Decimal','name':'NameObject',
            'string':'StringObject','reference':'IndirectObject','null':'NullObject','boolean':'BooleanObject'}[node.kind],
        'projected_values_sha256':digest(json.dumps(tree,sort_keys=True).encode()),'projection_complete':complete,
        'stream_sha256':stream_sha256,'security_keys':sorted(key.value.decode() for key,value in node.value if key.value in security) if node.kind=='dictionary' else [],
        'action':action.value.decode() if action is not None and action.kind=='name' and action.value in {b'/JavaScript',b'/Launch',b'/URI',b'/SubmitForm',b'/GoToR',b'/GoToE',b'/ImportData'} else None,
        'key_projections':keys,'key_enumeration_complete':bool(complete and fields_complete),'projection_nodes':visited}
