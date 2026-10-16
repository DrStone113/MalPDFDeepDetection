"""Bounded Arlington expression syntax and three-valued static evaluation.

No Python/JavaScript eval, no execution of PDF content. Unsupported predicates
and missing context are explicit unknowns, including under negation.
"""

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, localcontext
from fractions import Fraction
from functools import lru_cache
import re


@dataclass(frozen=True)
class Unknown:
    reasons: tuple = ('unsupported_expression',)

    def __bool__(self):
        raise TypeError('An unknown Arlington result has no truth value')


@dataclass(frozen=True)
class Symbol:
    value: str


SKIP=Symbol('__inapplicable__')
TOKEN=re.compile(r"\s*(fn:[A-Za-z][A-Za-z0-9_]*|(?:[0-9]+\.[0-9]+|[0-9]+)|'(?:\\.|[^'\\])*'|&&|\|\||==|!=|>=|<=|[A-Za-z_@][A-Za-z0-9_:@.\-]*(?:::\*)?|[(),\[\]+*/%<>!\-]|[^\s(),\[\]+*/%<>!=&|\-]+)")


class ExpressionError(ValueError):
    pass


def split_top(text, separator):
    """Split model branches/lists without breaking function args or arrays."""
    parts=[]; start=0; stack=[]; quoted=False; escaped=False
    for i,char in enumerate(text):
        if quoted:
            if escaped: escaped=False
            elif char=='\\': escaped=True
            elif char=="'": quoted=False
            continue
        if char=="'": quoted=True
        elif char in '([': stack.append(char)
        elif char in ')]':
            if not stack or stack.pop()!=('(' if char==')' else '['):
                raise ExpressionError('unbalanced_model_expression')
        elif char==separator and not stack:
            parts.append(text[start:i].strip()); start=i+1
        if len(stack)>32:
            raise ExpressionError('expression_depth_limit')
    if quoted or stack:
        raise ExpressionError('unbalanced_model_expression')
    return parts+[text[start:].strip()]


@lru_cache(maxsize=8192)
def parse(text):
    if not isinstance(text,str) or not 0<len(text)<=16384:
        raise ExpressionError('expression_byte_limit')
    tokens=[]; pos=0
    while pos<len(text):
        if not text[pos:].strip(): break
        match=TOKEN.match(text,pos)
        if not match: raise ExpressionError('unsupported_expression_syntax')
        tokens.append(match[1]); pos=match.end()
        if len(tokens)>2048: raise ExpressionError('expression_token_limit')
    cursor=0; count=0
    precedences={'||':1,'&&':2,'==':3,'!=':3,'>':3,'<':3,'>=':3,'<=':3,
                 '+':4,'-':4,'*':5,'/':5,'%':5,'mod':5}
    def expression(minimum=0,depth=0):
        nonlocal cursor,count
        count+=1
        if depth>32 or count>1024 or cursor>=len(tokens):
            raise ExpressionError('expression_structure_limit')
        token=tokens[cursor]; cursor+=1
        if token in ('!','-','+'):
            left=('unary',token,expression(6,depth+1))
        elif token=='(':
            left=expression(0,depth+1)
            if cursor>=len(tokens) or tokens[cursor]!=')': raise ExpressionError('expected_parenthesis')
            cursor+=1
        elif token=='[':
            items=[]
            while cursor<len(tokens) and tokens[cursor]!=']':
                items.append(expression(0,depth+1))
                if cursor<len(tokens) and tokens[cursor]==',': cursor+=1
            if cursor>=len(tokens): raise ExpressionError('expected_array_end')
            cursor+=1; left=('array',tuple(items))
        elif token.startswith('fn:'):
            if cursor>=len(tokens) or tokens[cursor]!='(': raise ExpressionError('expected_call')
            cursor+=1; args=[]
            while cursor<len(tokens) and tokens[cursor]!=')':
                args.append(expression(0,depth+1))
                if cursor<len(tokens) and tokens[cursor]==',': cursor+=1
                elif cursor<len(tokens) and tokens[cursor]!=')': raise ExpressionError('expected_argument_separator')
            if cursor>=len(tokens): raise ExpressionError('expected_call_end')
            cursor+=1; left=('call',token[3:],tuple(args))
        elif token in (')',']',','):
            raise ExpressionError('unexpected_expression_delimiter')
        else: left=('atom',token)
        while cursor<len(tokens) and precedences.get(tokens[cursor],-1)>=minimum:
            op=tokens[cursor]; cursor+=1
            left=('binary',op,left,expression(precedences[op]+1,depth+1))
        return left
    result=expression()
    if cursor!=len(tokens): raise ExpressionError('expression_trailing_syntax')
    return result


def truth(value):
    if isinstance(value,Unknown): return value
    if value==SKIP: return False
    return value if type(value) is bool else Unknown(('non_boolean_predicate',))


def negate(value):
    if value==SKIP: return Unknown(('conditional_boolean_context_unsupported',))
    value=truth(value)
    return value if isinstance(value,Unknown) else not value


def combine(a,b,operator):
    # List/type/link callers exclude inapplicable conditional literals. Their
    # reduction inside nested Boolean formulae needs additional context; never
    # invent FALSE and report a spurious SpecialCase violation.
    if a==SKIP: a=Unknown(('conditional_boolean_context_unsupported',))
    if b==SKIP: b=Unknown(('conditional_boolean_context_unsupported',))
    a,b=truth(a),truth(b)
    if operator=='&&':
        if a is False or b is False: return False
        if a is True and b is True: return True
    else:
        if a is True or b is True: return True
        if a is False and b is False: return False
    return Unknown(tuple(sorted(set((a.reasons if isinstance(a,Unknown) else ())+
                                    (b.reasons if isinstance(b,Unknown) else ())))))


def version(text):
    if not isinstance(text,str) or len(text)>16 or not re.fullmatch(r'[12]\.[0-9]+',text):
        return Unknown(('version_context_unavailable',))
    return tuple(map(int,text.split('.')))


def atom_text(ast):
    return ast[1] if ast[0]=='atom' else None


class EvaluationBudget:
    def __init__(self, maximum=50000):
        self.maximum=maximum; self.used=0; self.exhausted=False

    def take(self):
        if self.used>=self.maximum:
            self.exhausted=True
            raise ExpressionError('expression_step_limit')
        self.used+=1


def evaluate(text, context, *, budget=None, since=False):
    budget=budget or EvaluationBudget()
    try:
        return _evaluate(parse(text),context,budget,since)
    except (ExpressionError,InvalidOperation,ZeroDivisionError,OverflowError,UnicodeError):
        return Unknown(('unsupported_or_limited_expression',))


def _evaluate(ast,ctx,budget,since=False):
    budget.take()
    kind=ast[0]
    ev=lambda node: _evaluate(node,ctx,budget,since)
    if kind=='atom':
        token=ast[1]
        if token in ('TRUE','true','FALSE','false'): return token in ('TRUE','true')
        if token=='null': return None
        if token.startswith("'"): return token[1:-1].replace("\\'","'").replace('\\\\','\\').encode('utf-8')
        if '@' in token: return ctx.value(token)
        if re.fullmatch(r'[0-9]+(?:\.[0-9]+)?',token):
            if len(token)>128: return Unknown(('numeric_literal_limit',))
            if since:
                current=getattr(ctx,'version',Unknown(('version_context_unavailable',)))
                candidate=version(token)
                return current if isinstance(current,Unknown) else candidate if isinstance(candidate,Unknown) else current>=candidate
            return Decimal(token)
        return Symbol(token)
    if kind=='array':
        return tuple(ev(item) for item in ast[1])
    if kind=='unary':
        value=ev(ast[2])
        if ast[1]=='!': return negate(value)
        if isinstance(value,Unknown): return value
        return (-value if ast[1]=='-' else value) if isinstance(value,Decimal) else Unknown(('non_numeric_operand',))
    if kind=='binary':
        op=ast[1]; a,b=ev(ast[2]),ev(ast[3])
        if op in ('&&','||'): return combine(a,b,op)
        if isinstance(a,Unknown) or isinstance(b,Unknown):
            return Unknown(tuple(sorted(set((a.reasons if isinstance(a,Unknown) else ())+(b.reasons if isinstance(b,Unknown) else ())))))
        if a==SKIP or b==SKIP: return Unknown(('conditional_operand_unavailable',))
        if op in ('==','!='):
            # Keep model names, byte strings, booleans and numbers distinct.
            equal=type(a)==type(b) and a==b
            return equal if op=='==' else not equal
        if not isinstance(a,Decimal) or not isinstance(b,Decimal): return Unknown(('non_numeric_operand',))
        if op in ('>','<','>=','<='): return {'>':a>b,'<':a<b,'>=':a>=b,'<=':a<=b}[op]
        if max(len(a.as_tuple().digits),len(b.as_tuple().digits))>128 or max(abs(a.as_tuple().exponent),abs(b.as_tuple().exponent))>256:
            return Unknown(('numeric_operand_limit',))
        # Avoid Decimal's process-global precision silently rounding a rule.
        x,y=Fraction(a),Fraction(b)
        result=x+y if op=='+' else x-y if op=='-' else x*y if op=='*' else x/y if op=='/' else x%y
        denominator=result.denominator
        for factor in (2,5):
            while denominator%factor==0: denominator//=factor
        if denominator!=1 or max(len(str(abs(result.numerator))),len(str(result.denominator)))>512:
            return Unknown(('non_finite_or_large_numeric_result',))
        with localcontext() as decimal_context:
            decimal_context.prec=2048
            return Decimal(result.numerator)/Decimal(result.denominator)
    name,args=ast[1:]
    if name in ('SinceVersion','BeforeVersion','IsPDFVersion','Deprecated') and 1<=len(args)<=2:
        target=version(atom_text(args[0])); current=getattr(ctx,'version',Unknown(('version_context_unavailable',)))
        if isinstance(target,Unknown) or isinstance(current,Unknown): return Unknown(('version_context_unavailable',))
        condition=current>=target if name in ('SinceVersion','Deprecated') else current<target if name=='BeforeVersion' else current==target
        if name=='Deprecated': return ev(args[1]) if len(args)==2 else condition
        if len(args)==1: return condition
        return ev(args[1]) if condition else SKIP
    if name=='Extension': return Unknown(('extension_context_unsupported',))
    if name in ('Eval','IsRequired') and len(args)==1: return ev(args[0])
    if name=='Not' and len(args)==1: return negate(ev(args[0]))
    if name=='IsPresent' and 1<=len(args)<=2:
        path=atom_text(args[0])
        present=ctx.present(path) if path is not None and '@' not in path else truth(ev(args[0]))
        return present if len(args)==1 else combine(negate(present),ev(args[1]),'||')
    if name in ('ArrayLength','StringLength','RectWidth','RectHeight') and len(args)==1:
        path=atom_text(args[0])
        value=ctx.value(path) if path is not None else ev(args[0])
        if isinstance(value,Unknown): return value
        if name=='ArrayLength' and isinstance(value,tuple): return Decimal(len(value))
        if name=='StringLength' and isinstance(value,bytes): return Decimal(len(value))
        if name.startswith('Rect') and isinstance(value,tuple) and len(value)==4 and all(isinstance(x,Decimal) for x in value):
            return abs(value[2]-value[0]) if name=='RectWidth' else abs(value[3]-value[1])
        return Unknown(('predicate_operand_type_unavailable',))
    if name=='Contains' and len(args)==2:
        a,b=ev(args[0]),ev(args[1])
        if isinstance(a,tuple):
            result=False
            for item in a:
                result=combine(result,Unknown() if isinstance(item,Unknown) or isinstance(b,Unknown) else type(item)==type(b) and item==b,'||')
            return result
        return Unknown(('contains_operand_unsupported',))
    # Directness is evaluated by the rule engine with the original reference.
    return Unknown(('unsupported_predicate:'+name,))
