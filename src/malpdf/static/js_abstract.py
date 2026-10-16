"""Small finite abstract values for static AST facts; no JavaScript runtime."""

from dataclasses import dataclass
import hashlib
import json


def digest(value):
    return hashlib.sha256(value.encode('utf-8',errors='surrogatepass')).hexdigest()


@dataclass(frozen=True)
class Atom:
    kind: str
    value: object = None


@dataclass(frozen=True)
class Value:
    atoms: frozenset = frozenset()
    reasons: tuple = ()

    @property
    def unknown(self):
        return not self.atoms

    def __bool__(self):
        raise TypeError('Abstract JavaScript values cannot be used as Python booleans')


def top(reason):
    return Value(reasons=(reason,))


def one(kind,value=None):
    if kind=='string': value=canonical_string(value)
    return Value(frozenset({Atom(kind,value)}))


def canonical_string(text):
    """Equal UTF16 code-unit sequences have one scalar representation."""
    return text.encode('utf-16-le',errors='surrogatepass').decode('utf-16-le',errors='surrogatepass')


def join(values,cap=4):
    values=list(values)
    if any(value.unknown for value in values):
        return Value(reasons=tuple(sorted({r for v in values for r in v.reasons})))
    atoms=frozenset(atom for value in values for atom in value.atoms)
    return Value(atoms) if 0<len(atoms)<=cap else top('finite_set_widened')


def units(text):
    return len(text.encode('utf-16-le',errors='surrogatepass'))//2


def literal(node,max_units=2048):
    if 'regex' in node: return top('regexp_semantics_unsupported')
    value=node.get('value')
    if value is None: return one('null')
    if type(value) is bool: return one('boolean',value)
    if type(value) in (int,float):
        if isinstance(value,float) and (not value.is_integer() or value==0 and str(value).startswith('-')):
            return top('non_integer_number_unsupported')
        return one('number',int(value)) if abs(value)<=2**53-1 else top('unsafe_integer_or_nonfinite')
    if isinstance(value,str):
        return one('string',value) if units(value)<=max_units else top('abstract_string_limit')
    return top('literal_semantics_unsupported')


def boolean(value):
    if value.unknown: return None
    results=set()
    for atom in value.atoms:
        if atom.kind in {'null','undefined'}: results.add(False)
        elif atom.kind in {'string','number','boolean'}: results.add(bool(atom.value))
        elif atom.kind=='function': results.add(True)
        else: return None
    return next(iter(results)) if len(results)==1 else None


def unary(operator,value):
    if value.unknown: return value
    results=[]
    for atom in value.atoms:
        if operator=='!':
            truth=boolean(Value(frozenset({atom})))
            results.append(one('boolean',not truth) if truth is not None else top('truthiness_unavailable'))
        elif operator=='typeof' and atom.kind in {'null','undefined','boolean','number','string','function'}:
            results.append(one('string','object' if atom.kind=='null' else atom.kind))
        elif operator in {'+','-'} and atom.kind=='number':
            results.append(top('negative_zero_unsupported') if operator=='-' and atom.value==0 else one('number',atom.value if operator=='+' else -atom.value))
        else: results.append(top('unary_operator_or_coercion_unsupported'))
    return join(results)


def binary(operator,left,right,max_units=2048):
    if left.unknown or right.unknown: return join((left,right))
    results=[]
    for a in left.atoms:
        for b in right.atoms:
            result=top('binary_operator_or_coercion_unsupported')
            if operator in {'===','!=='}:
                if a.kind in {'string','number','boolean','null','undefined'} and b.kind in {'string','number','boolean','null','undefined'}:
                    equal=a.kind==b.kind and a.value==b.value
                    result=one('boolean',equal if operator=='===' else not equal)
            elif operator=='+' and a.kind==b.kind=='string':
                result=one('string',a.value+b.value) if units(a.value)+units(b.value)<=max_units else top('abstract_string_limit')
            elif a.kind==b.kind=='number':
                x,y=a.value,b.value
                if operator in {'<','<=','>','>='}:
                    result=one('boolean',{'<':x<y,'<=':x<=y,'>':x>y,'>=':x>=y}[operator])
                elif operator in {'+','-','*','/','%'}:
                    if operator in {'/','%'} and y==0: result=top('division_by_zero_unmodeled')
                    elif operator=='/' and (x%y or x==0 and y<0): result=top('non_integer_division_unsupported')
                    else:
                        number=x+y if operator=='+' else x-y if operator=='-' else x*y if operator=='*' else x//y if operator=='/' else (abs(x)%abs(y))*(-1 if x<0 else 1)
                        result=top('negative_zero_unsupported') if number==0 and (operator=='*' and (x<0 or y<0) or operator=='%' and x<0) else one('number',number) if abs(number)<=2**53-1 else top('unsafe_integer_result')
            results.append(result)
    return join(results)


def describe(value):
    """Export types/digests/lengths only; never strings, variable names or URLs."""
    alternatives=[]
    for atom in sorted(value.atoms,key=lambda item:(item.kind,repr(item.value))):
        data=json.dumps([atom.kind,atom.value],ensure_ascii=True,separators=(',',':'))
        record={'kind':atom.kind,'value_sha256':digest(data)}
        if atom.kind=='string': record['utf16_units']=units(atom.value)
        alternatives.append(record)
    return {'status':'unknown' if value.unknown else 'finite',
            'alternatives':alternatives,'reason_codes':list(value.reasons)}
