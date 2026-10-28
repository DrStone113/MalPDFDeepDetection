"""Synthetic tables/bytes only; no network, external model or real samples."""

from copy import deepcopy
from dataclasses import replace
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from malpdf.extraction.arlington_expression import (Unknown,Symbol,SKIP,EvaluationBudget,
    ExpressionError,evaluate,parse,split_top,truth,version)
from malpdf.extraction.arlington_model import Catalog,HEADER,ModelUnavailable,load_model,seal_model
from malpdf.extraction.arlington_validate import RuleLimits,validate_document,Context,Value,_Engine
from malpdf.extraction.contracts import validate_bundle
from malpdf.extraction.normalize import normalize_profile
from malpdf.extraction.raw import inspect_raw_layout
from malpdf.extraction.raw_forensic import _Document,ForensicLimits,inspect_raw_forensic
from malpdf.extraction.raw_syntax import Node
from malpdf.static.code_inspector import CodeInspectionLimits


def row(key,type='integer',**fields):
    value=dict.fromkeys(HEADER,'')
    value.update(Key=key,Type=type,SinceVersion='1.0',Required='FALSE',IndirectReference='FALSE',Inheritable='FALSE')
    value.update(fields,line=2,source_sha256='a'*64)
    return value


def catalog(rows=(),**tables):
    return Catalog({'FileTrailer':(row('Size',Required='TRUE'),row('Root','dictionary',Required='TRUE',Link='[Catalog]')),
                    'Catalog':tuple(rows),**tables},
                   {'source':'synthetic-fixture','commit':'a'*40,'status':'available','tsv_count':len(tables)+2})


def pdf(body=b'<< /Type /Catalog >>',others=()):
    data=b'%PDF-1.7\n'; entries={}
    for number,value in [(1,body),*others]:
        entries[number]=len(data);data+=f'{number} 0 obj\n'.encode()+value+b'\nendobj\n'
    size=max(entries)+1; xref=len(data)
    data+=f'xref\n0 {size}\n'.encode()+b'0000000000 65535 f \n'
    for number in range(1,size):
        data+=(f'{entries[number]:010d} 00000 n \n' if number in entries else '0000000000 00000 f \n').encode()
    data+=f'trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode()
    return data


def inspect(data,model,**kwargs):
    captured=[]
    raw=inspect_raw_forensic(data,CodeInspectionLimits(),remaining=1024**2,arlington_catalog=model,
        arlington_checkpoint=lambda value:captured.append(deepcopy(value)),**kwargs)
    return raw,captured[-1]


def checks(result,category,key=None,model='Catalog'):
    return [check for check in result['checks'] if check['model_table']==model and check['category']==category and (key is None or check.get('key')==key)]


class ExprContext:
    version=(1,7)
    def value(self,path):
        return {'@N':Decimal(8),'N':Decimal(8),'@Name':Symbol('Catalog'),
                'Items':(Decimal(1),Decimal(2))}.get(path,Unknown(('value_absent',)))
    def present(self,path): return path=='N'


class BitContext(ExprContext):
    def __init__(self,value): self.bits=value
    def current_bitmask(self): return self.bits


@pytest.mark.parametrize('expression,value,expected',[
    ('fn:BitClear(1)',0,True),('fn:BitClear(1)',1,False),
    ('fn:BitSet(1)',1,True),('fn:BitSet(1)',2,False),
    ('fn:BitSet(32)',-(1<<31),True),('fn:BitSet(32)',1<<31,True),
    ('fn:BitSet(32)',0,False),('fn:BitsClear(1,2)',-4,True),
    ('fn:BitsClear(1,2)',-1,False),('fn:BitsSet(3,5)',28,True),
    ('fn:BitsSet(3,5)',20,False),('fn:BitsClear(31,32)',(1<<30)-1,True),
    ('fn:BitsClear(31,32)',1<<31,False),('fn:BitsSet(1,32)',-1,True),
    ('fn:BitsSet(1,32)',(1<<32)-1,True),('fn:BitsSet(1,32)',1<<32,False),
    ('fn:BitsClear(1,32)',0,True),('fn:BitsClear(1,32)',-(1<<31)-1,False),
    ('fn:BitSet(1)',True,False),('fn:BitSet(1)',Decimal(1),False),
])
def test_bitmask_predicates_use_current_integer_and_exact_32_bit_width(expression,value,expected):
    assert evaluate(expression,BitContext(value)) is expected


@pytest.mark.parametrize('expression',[
    'fn:BitSet(0)','fn:BitSet(33)','fn:BitSet(-1)','fn:BitSet(1.5)',
    'fn:BitSet(TRUE)','fn:BitSet()','fn:BitSet(1,2)',
    'fn:BitsClear(2,2)','fn:BitsSet(32,1)','fn:BitsSet(1,33)',
    'fn:BitsSet(1)','fn:BitSet(fn:Unknown())',
])
def test_invalid_bit_arguments_stay_unknown_including_under_not(expression):
    for formula in (expression,'fn:Not('+expression+')'):
        result=evaluate(formula,BitContext(0));assert isinstance(result,Unknown)
        with pytest.raises(TypeError):bool(result)


def test_bitmask_reference_bits_and_budget_unknowns_are_preserved():
    for value in (-(1<<31),-4,-1,0,1,2,3,(1<<31)-1,1<<31,(1<<32)-1):
        bits=format(value%(1<<32),'032b')[::-1]
        for position in range(1,33):
            assert evaluate(f'fn:BitSet({position})',BitContext(value)) is (bits[position-1]=='1')
            assert evaluate(f'fn:BitClear({position})',BitContext(value)) is (bits[position-1]=='0')
        for low,high in ((1,2),(1,32),(7,8),(31,32)):
            selected=bits[low-1:high]
            assert evaluate(f'fn:BitsSet({low},{high})',BitContext(value)) is all(b=='1' for b in selected)
            assert evaluate(f'fn:BitsClear({low},{high})',BitContext(value)) is all(b=='0' for b in selected)
    assert isinstance(evaluate('fn:Not(fn:BitSet(1))',ExprContext()),Unknown)
    unknown=Unknown(('xref_selection_unverified',))
    assert evaluate('fn:BitSet(1)',BitContext(unknown))==unknown
    budget=EvaluationBudget(2)
    assert isinstance(evaluate('fn:BitsSet(1,32)',BitContext(0),budget=budget),Unknown)
    assert budget.exhausted and budget.used==2


@pytest.mark.parametrize('value,expected',[
    (Symbol('FlateDecode'),True),(Symbol('DCTDecode'),False),
    ((Symbol('FlateDecode'),Symbol('DCTDecode')),True),
    ((Symbol('DCTDecode'),),False),
    ((Unknown(('missing_target',)),Symbol('FlateDecode')),True),
    ((Unknown(('missing_target',)),Symbol('DCTDecode')),None),
])
def test_contains_name_or_array_preserves_unknown_elements(value,expected):
    ctx=SimpleNamespace(value=lambda path:value)
    result=evaluate('fn:Contains(@Filter,FlateDecode)',ctx)
    assert isinstance(result,Unknown) if expected is None else result is expected


@pytest.mark.parametrize('expression,expected',[
    ("fn:Contains('abc','abc')",True),("fn:Contains('abc',abc)",False),
    ('fn:Contains(1,1)',True),('fn:Contains(1,TRUE)',False),
    ('fn:Contains([TRUE,1],FALSE)',False),('fn:Contains([1],TRUE)',False),
])
def test_contains_never_coerces_names_strings_booleans_or_numbers(expression,expected):
    assert evaluate(expression,ExprContext()) is expected


def test_contains_charges_each_array_element_and_keeps_unknown_operand_unknown():
    ctx=SimpleNamespace(value=lambda path:(Symbol('DCTDecode'),)*10)
    budget=EvaluationBudget(4)
    assert isinstance(evaluate('fn:Contains(@Filter,FlateDecode)',ctx,budget=budget),Unknown)
    assert budget.exhausted and budget.used==4
    assert isinstance(evaluate('fn:Not(fn:Contains([],fn:Unknown()))',ctx),Unknown)


@pytest.mark.parametrize('value,formula,expected',[
    (b'1','fn:BitSet(1)','pass'),(b'0','fn:BitSet(1)','fail'),
    (b'-4','fn:BitsClear(1,2)','pass'),(b'-1','fn:BitsClear(1,2)','fail'),
    (b'-2147483648','fn:BitSet(32)','pass'),
    (b'4294967296','fn:BitSet(1)','fail'),
])
def test_current_field_bitmask_rules_keep_raw_values_and_source_ids(value,formula,expected):
    data=pdf(b'<< /Flags '+value+b' >>')
    raw,result=inspect(data,catalog([row('Flags','bitmask',SpecialCase='['+formula+']')]))
    assert checks(result,'special_case','Flags')[0]['outcome']==expected
    assert raw==inspect_raw_forensic(data,CodeInspectionLimits(),remaining=1024**2)
    bundle=normalize_profile({'status':'complete','raw_layout':inspect_raw_layout(data),
        'raw_forensic':raw,'arlington_analysis':result},hashlib.sha256(data).hexdigest(),'deep-static')
    validate_bundle(bundle)


def test_current_bitmask_context_does_not_leak_between_keys_or_type_branches():
    model=catalog([row('A','bitmask',SpecialCase='[fn:BitSet(1)]'),
                   row('B','bitmask',SpecialCase='[fn:BitClear(1)]')])
    _,result=inspect(pdf(b'<< /A 1 /B 2 >>'),model)
    assert checks(result,'special_case','A')[0]['outcome']=='pass'
    assert checks(result,'special_case','B')[0]['outcome']=='pass'
    _,changed=inspect(pdf(b'<< /A 1 /B 1 >>'),model)
    assert checks(changed,'special_case','A')[0]['outcome']=='pass'
    assert checks(changed,'special_case','B')[0]['outcome']=='fail'
    _,named=inspect(pdf(b'<< /A /Known >>'),catalog([row('A','bitmask;name',
        PossibleValues='[];[Known]',SpecialCase='[fn:BitSet(1)];[]')]))
    assert checks(named,'row','A')[0]['outcome']=='pass'
    _,integer=inspect(pdf(b'<< /A 1 >>'),catalog([row('A','integer',SpecialCase='[fn:Not(fn:BitSet(1))]')]))
    assert checks(integer,'special_case','A')[0]['outcome']=='indeterminate'


def test_current_bitmask_reference_inheritance_and_unknowns_stay_scoped():
    model=catalog([row('Flags','bitmask',SpecialCase='[fn:BitSet(1)]')])
    _,result=inspect(pdf(b'<< /Flags 2 0 R >>',[(2,b'1')]),model)
    assert checks(result,'special_case','Flags')[0]['outcome']=='pass'
    _,missing=inspect(pdf(b'<< /Flags 99 0 R >>'),model)
    assert checks(missing,'special_case','Flags')[0]['outcome']=='indeterminate'
    assert 'reference_target_unavailable' in checks(missing,'special_case','Flags')[0]['reason_codes']
    _,duplicate=inspect(pdf(b'<< /Flags 1 /Flags 2 >>'),model)
    assert checks(duplicate,'presence')[0]['outcome']=='indeterminate'
    _,inherited=inspect(pdf(b'<< /Parent 2 0 R >>',[(2,b'<< /Flags 1 >>')]),
        catalog([row('Flags','bitmask',Inheritable='TRUE',SpecialCase='[fn:BitSet(1)]')]))
    assert checks(inherited,'special_case','Flags')[0]['outcome']=='pass'


@pytest.mark.parametrize(('expression','expected'),[
    ('fn:Eval((@N>=0) && (@N<9))',True),('fn:IsRequired(fn:IsPresent(N))',True),
    ('fn:Not(fn:IsPresent(Missing))',True),('fn:ArrayLength(Items)',Decimal(2)),
    ('(@N mod 3)==2',True),('fn:SinceVersion(2.0)',False),
    ('fn:SinceVersion(2.0,Catalog)',SKIP),('fn:Deprecated(1.4,Catalog)',Symbol('Catalog')),
    ('@Name==Catalog',True),('true==1',False),('fn:Not(FALSE)',True),
    ('fn:Eval(FALSE && fn:Unknown())',False),('fn:Eval(TRUE || fn:Unknown())',True),
    ('fn:IsPresent(Missing,fn:Unknown())',True),('string-text',Symbol('string-text')),
])
def test_expression_truth_and_typed_values(expression,expected):
    assert evaluate(expression,ExprContext())==expected


def test_dictionary_lookup_indexes_once_and_preserves_duplicates_and_node_identity():
    class CountPairs(list):
        iterations=0
        def __iter__(self):
            self.iterations+=1
            return super().__iter__()
    pairs=CountPairs((Node('name',b'/Key'+str(i).encode(),i,i+1),Node('number',i,i+1,i+2)) for i in range(128))
    duplicate=Node('number',999,200,201)
    pairs.append((Node('name',b'/Key7',201,202),duplicate))
    node=Node('dictionary',pairs,0,300)
    doc=SimpleNamespace(sha='a'*64)
    engine=_Engine(doc,catalog(),RuleLimits(),None)
    context=Context(engine,Value(node,'original-owner'),0,(1,7))
    for _ in range(4):
        for i in range(128):
            value=context.entry('Key'+str(i))
            if i==7:assert isinstance(value,Unknown) and value.reasons==('duplicate_dictionary_key',)
            else:assert value.node is pairs[i][1] and value.owner=='original-owner'
        assert context.entry('Missing') is None
    assert pairs.iterations==1
    assert engine.dictionary_entries(node)[b'/Key7']==[pairs[7][1],duplicate]
    # Same spans in a different node/context must not share an index or owner.
    other=Node('dictionary',[(Node('name',b'/Key7',0,1),Node('number',42,1,2))],0,300)
    ctx=Context(engine,Value(other,'older-owner'),1,(1,4))
    assert ctx.entry('Key7').node.value==42 and ctx.entry('Key7').owner=='older-owner'
    assert len(engine._dictionary_indexes)==2


def test_indexed_trailer_lookup_keeps_missing_and_duplicate_inheritance_rules():
    first=Node('dictionary',[],0,10)
    parent=Node('dictionary',[(Node('name',b'/Info',11,12),Node('number',7,12,13))],10,20)
    doc=SimpleNamespace(sha='a'*64,chain=[{'offset':0},{'offset':10,'id':'older','source_object_id':None}],xref_nodes={10:parent})
    engine=_Engine(doc,catalog(),RuleLimits(),None)
    ctx=Context(engine,Value(first,'newest'),0,(1,7),trailer=True)
    assert ctx.entry('Info').node.value==7 and ctx.entry('Info').owner=='older'
    assert ctx.entry('Private') is None
    assert ctx.entry('Root') is None
    ambiguous=Node('dictionary',[],0,10,issues=('forensic_unclosed_dictionary',))
    assert isinstance(Context(engine,Value(ambiguous,'bad'),0,(1,7)).entry('Info'),Unknown)


@pytest.mark.parametrize('body,rows',[
    (b'<< /N 8 >>',[row('N',PossibleValues='[fn:Eval(@N>0)]')]),
    (b'<< /N 1 /N 2 >>',[row('N',Required='TRUE')]),
    (b'<< /#4e 1 /N 2 >>',[row('*')]),
    (b'<< /PrivateCanary 8 /#ff 9 >>',[row('*')]),
    (b'<< /N null /A [1 2] >>',[row('N',Required='TRUE'),row('A','array')]),
    (b'<< /N 99 0 R >>',[row('N',Required='TRUE')]),
])
def test_indexed_rules_match_uncached_reference_without_modifying_ir(monkeypatch,body,rows):
    data=pdf(body);doc=_Document(data,CodeInspectionLimits(),1024**2,ForensicLimits(),None,None,None)
    raw=deepcopy(doc.run(None));model=catalog(rows)
    result=validate_document(doc,model)
    def uncached(self,node):
        entries={}
        for name,child in node.value:entries.setdefault(name.value,[]).append(child)
        return entries
    monkeypatch.setattr(_Engine,'dictionary_entries',uncached)
    assert validate_document(doc,model)==result
    assert doc.value==raw


@pytest.mark.parametrize('expression',[
    'fn:Unknown()','fn:Not(fn:Unknown())','fn:Eval(TRUE && fn:Unknown())',
    'fn:Extension(UnknownVendor,1.7)','fn:IsPresent(parent::Type)',
    'fn:Eval(@Absent>0)','fn:Eval(1/0)','fn:Eval(__import__(os))',
    '(' * 40 + 'TRUE' + ')' * 40,'fn:Eval(1+)',
])
def test_unsupported_or_missing_context_never_passes(expression):
    context=ExprContext()
    if expression=='fn:IsPresent(parent::Type)':
        context.present=lambda path:Unknown(('path_unsupported',))
    result=evaluate(expression,context)
    assert isinstance(result,Unknown)
    with pytest.raises(TypeError): bool(result)


def test_expression_budget_and_version_components_are_bounded():
    assert isinstance(evaluate('1+2+3',ExprContext(),budget=EvaluationBudget(2)),Unknown)
    assert version('1.10')>version('1.7')
    assert evaluate('fn:Eval(fn:Extension(Vendor,1.7) || 2.0)',ExprContext(),since=True).__class__ is Unknown
    context=ExprContext();context.version=(2,0)
    assert evaluate('fn:Eval(fn:Extension(Vendor,1.7) || 2.0)',context,since=True) is True
    assert split_top('[one,fn:SinceVersion(1.7,two)];[three]',';')==['[one,fn:SinceVersion(1.7,two)]','[three]']
    with pytest.raises(ExpressionError): parse('['*40+'1'+']'*40)


def test_inactive_conditional_inside_boolean_formula_is_not_a_false_violation():
    result=evaluate('fn:Eval(fn:IsPDFVersion(1.3,TRUE) && fn:SinceVersion(1.7,TRUE))',ExprContext())
    assert isinstance(result,Unknown)
    assert 'conditional_boolean_context_unsupported' in result.reasons


@pytest.mark.parametrize(('indirect','body','other','expected'),[
    ('FALSE',b'7',(), 'pass'),('FALSE',b'2 0 R',((2,b'7'),),'pass'),
    ('TRUE',b'7',(),'fail'),('TRUE',b'2 0 R',((2,b'7'),),'pass'),
    ('fn:MustBeDirect()',b'2 0 R',((2,b'7'),),'fail'),
    ('fn:MustBeDirect(fn:BeforeVersion(1.3))',b'2 0 R',((2,b'7'),),'pass'),
    ('fn:MustBeIndirect(fn:SinceVersion(1.3))',b'7',(),'fail'),
    ('fn:MustBeDirect(fn:Unknown())',b'2 0 R',((2,b'7'),),'indeterminate'),
])
def test_reference_policy_uses_original_reference(indirect,body,other,expected):
    _,result=inspect(pdf(b'<< /N '+body+b' >>',other),catalog([row('N',IndirectReference=indirect)]))
    assert checks(result,'indirect','N')[0]['outcome']==expected


@pytest.mark.parametrize(('type','value','expected'),[
    ('integer',b'4','pass'),('integer',b'4.0','fail'),('number',b'4.0','pass'),
    ('rectangle',b'[0 0 10 20]','pass'),('rectangle',b'[0 0 10]','fail'),
    ('string-ascii',b'(abc)','pass'),('string-ascii',b'<ff>','fail'),
    ('string-text',b'(abc)','indeterminate'),('name-tree',b'<<>>','indeterminate'),
    ('fn:SinceVersion(2.0,integer);name',b'/Catalog','pass'),
])
def test_type_candidates_preserve_specialized_unknowns(type,value,expected):
    _,result=inspect(pdf(b'<< /N '+value+b' >>'),catalog([row('N',type)]))
    assert checks(result,'row','N')[0]['outcome']==expected


@pytest.mark.parametrize(('value','possible','expected'),[
    (b'8','[fn:Eval((@N>0) && (@N<10))]','pass'),(b'-1','[fn:Eval(@N>0)]','fail'),
    (b'/Catalog','[Catalog,Pages]','pass'),(b'/Wrong','[Catalog,Pages]','fail'),
    (b'/1.7','[1.0,1.7,2.0]','pass'),(b'/1.7','[1.0,2.0]','fail'),
    (b'3','[fn:Unknown()]','indeterminate'),
])
def test_possible_values_and_evaluated_numeric_constraints(value,possible,expected):
    type='name' if value.startswith(b'/') else 'integer'
    _,result=inspect(pdf(b'<< /N '+value+b' >>'),catalog([row('N',type,PossibleValues=possible)]))
    assert checks(result,'possible_values','N')[0]['outcome']==expected


def test_dictionary_null_is_absent_but_array_null_is_an_original_value():
    data=pdf(b'<< /N null /A [null] >>')
    model=catalog([row('N',Required='TRUE'),row('A','array',Link='[Items]')],Items=(row('0',Required='TRUE'),))
    raw,result=inspect(data,model)
    assert checks(result,'required','N')[0]['outcome']=='fail'
    assert checks(result,'type_candidate','0',model='Items')[0]['outcome']=='fail'
    assert len([node for node in raw['syntax_nodes'] if node['kind']=='null'])==2
    _,nullable=inspect(data,catalog([row('N','integer;null',Required='TRUE')]))
    assert checks(nullable,'row','N')[0]['outcome']=='pass'


def test_link_alternatives_are_disjunctive_and_candidate_failures_stay_scoped():
    model=catalog([row('N','dictionary',Link='[Wrong,Right]')],
        Wrong=(row('Type','name',Required='TRUE',PossibleValues='[Wrong]'),),
        Right=(row('Type','name',Required='TRUE',PossibleValues='[Right]'),))
    _,result=inspect(pdf(b'<< /N << /Type /Right >> >>'),model)
    assert checks(result,'link','N')[0]['outcome']=='pass'
    assert checks(result,'possible_values','Type',model='Wrong')[0]['outcome']=='fail'
    assert result['root_schema_candidate_outcomes'][0]['outcome']=='pass'


def test_type_branches_do_not_apply_other_branch_constraints():
    model=catalog([row('N','array;name',IndirectReference='[TRUE];[FALSE]',
                       PossibleValues='[];[Catalog]',Link='[Items];[]')],Items=(row('*'),))
    _,result=inspect(pdf(b'<< /N /Catalog >>'),model)
    assert checks(result,'row','N')[0]['outcome']=='pass'


def test_unknown_predicate_under_not_stays_indeterminate():
    _,result=inspect(pdf(b'<< /N 1 >>'),catalog([row('N',SpecialCase='[fn:Not(fn:Unknown())]')]))
    assert checks(result,'special_case','N')[0]['outcome']=='indeterminate'
    assert 'unsupported_predicate:Unknown' in checks(result,'special_case','N')[0]['reason_codes']


def test_inheritance_and_default_keep_ir_unchanged_and_link_original_sources():
    data=pdf(b'<< /Parent 2 0 R >>',[(2,b'<< /N 8 >>')])
    raw,result=inspect(data,catalog([row('N',Required='TRUE',Inheritable='TRUE'),row('Default',DefaultValue='9')]))
    baseline=inspect_raw_forensic(data,CodeInspectionLimits(),remaining=1024**2)
    assert raw==baseline
    assert checks(result,'inherited_value','N')[0]['outcome']=='pass'
    assert checks(result,'virtual_default','Default')[0]['outcome']=='pass'
    assert all(node['known_name']!='/Default' for node in raw['syntax_nodes'] if node['kind']=='name')


def test_duplicate_keys_missing_refs_and_inheritance_cycles_stay_unknown():
    for body,extra,reason in (
        (b'<< /N 1 /N 2 >>',(),'duplicate_dictionary_key'),
        (b'<< /N 99 0 R >>',(),'reference_target_unavailable'),
        (b'<< /Parent 1 0 R >>',(),'inheritance_cycle')):
        _,result=inspect(pdf(body,extra),catalog([row('N',Required='TRUE',Inheritable='TRUE')]))
        assert any(reason in check['reason_codes'] for check in result['checks'])


def test_array_repeating_groups_are_bounded_and_every_value_checked():
    model=catalog([row('A','array',Link='[Pairs]')],Pairs=(row('0','name',Required='TRUE'),row('1*','integer'),row('2*','boolean')))
    _,result=inspect(pdf(b'<< /A [/Header 1 true 2 false] >>'),model)
    assert checks(result,'row','A')[0]['outcome']=='pass'
    _,bad=inspect(pdf(b'<< /A [/Header 1 true 2 /Wrong] >>'),model)
    assert any(c['outcome']=='fail' and c.get('actual_index')==4 for c in checks(bad,'row',model='Pairs'))


def test_unknown_key_redaction_and_export_source_integrity():
    data=pdf(b'<< /PrivateCanary (inert secret) /N 8 >>')
    raw,result=inspect(data,catalog([row('N',PossibleValues='[fn:Eval(@N>0)]')]))
    profile={'status':'complete','raw_layout':inspect_raw_layout(data),'raw_forensic':raw,'arlington_analysis':result}
    bundle=normalize_profile(profile,hashlib.sha256(data).hexdigest(),'deep-static')
    validate_bundle(bundle)
    text=json.dumps(bundle)
    assert 'PrivateCanary' not in text and 'inert secret' not in text
    assert checks(result,'unknown_key')
    assert bundle['coverage_report']['backends']['arlington']['model']['status']=='available'
    assert bundle['coverage_report']['whole_document_complete'] is False


def test_rules_use_cached_ir_only_and_limits_preserve_raw_checkpoint(monkeypatch):
    data=pdf(b'<< /N 8 >>')
    doc=_Document(data,CodeInspectionLimits(),1024**2,ForensicLimits(),None,None,None)
    raw=deepcopy(doc.run(None))
    def forbidden(*args,**kwargs): pytest.fail('Rule evaluation must not parse more PDF bytes')
    monkeypatch.setattr(doc,'object_at',forbidden);monkeypatch.setattr(doc,'selected_object',forbidden)
    result=validate_document(doc,catalog([row('N')]),limits=replace(RuleLimits(),max_checks=1))
    assert result['complete'] is False and 'arlington_check_limit' in result['reason_codes']
    assert doc.value==raw
    exhausted=validate_document(doc,catalog([row('N')]),limits=replace(RuleLimits(),max_steps=1))
    assert exhausted['complete'] is False
    assert exhausted['expression_steps_used']<=1
    assert 'arlington_expression_step_limit' in exhausted['reason_codes']


def test_interrupted_raw_ir_cannot_supply_unpublished_rule_sources():
    data=pdf(b'<< /N 8 >>')
    raw,result=inspect(data,catalog([row('N')]),limits=replace(ForensicLimits(),max_ir_nodes=1))
    assert raw['complete'] is False
    assert result['status']=='not_run' and result['reason_codes']==['raw_ir_interrupted_before_arlington']


def test_dictionary_wildcard_keys_stay_redacted_even_for_non_utf8_names():
    data=pdf(b'<< /PrivateCanary 8 /#ff 9 >>')
    raw,result=inspect(data,catalog([row('*')]))
    bundle=normalize_profile({'status':'complete','raw_layout':inspect_raw_layout(data),
        'raw_forensic':raw,'arlington_analysis':result},hashlib.sha256(data).hexdigest(),'deep-static')
    assert 'PrivateCanary' not in json.dumps(bundle)
    assert len([c for c in checks(result,'row') if c.get('key')=='*'])==2
    assert all(c['outcome']=='pass' for c in checks(result,'row'))


def test_repeat_required_elements_cannot_be_silently_truncated():
    model=catalog([row('A','array',Link='[Pairs]')],Pairs=(row('0*',Required='TRUE'),row('1*','boolean',Required='TRUE')))
    _,result=inspect(pdf(b'<< /A [1 true 2] >>'),model)
    missing=[c for c in checks(result,'required',model='Pairs') if c.get('actual_index')==3]
    assert missing and missing[0]['outcome']=='fail'


def test_name_enum_wildcard_and_deprecation_are_not_false_rejections():
    _,result=inspect(pdf(b'<< /N /Other >>'),catalog([row('N','name',PossibleValues='[Known,*]',DeprecatedIn='1.4')]))
    assert checks(result,'row','N')[0]['outcome']=='pass'
    notice=checks(result,'deprecation_notice','N')[0]
    assert notice['outcome']=='pass' and notice['deprecated'] is True


def test_numeric_rules_never_use_global_decimal_rounding():
    context=ExprContext()
    assert evaluate('(999999999999999999999999999999+1)==1000000000000000000000000000000',context) is True
    assert isinstance(evaluate('1/3',context),Unknown)
    assert isinstance(evaluate('0.'+'0'*8000+'1+1',context),Unknown)
    assert isinstance(version('1.'+'7'*8000),Unknown)


def _arlington_checkpoint_then_stall(connection,path,boundary,digest,limits,*args):
    import os,time
    os.setsid()
    data=pdf();raw,analysis=inspect(data,catalog([row('Type','name')]))
    connection.send_bytes(json.dumps({'event':'checkpoint','profile':{'status':'complete','errors':[],
        'static':{'input':{'sha256':digest},'features':{'canary':7}},'code':None,
        'raw_layout':inspect_raw_layout(data),'raw_forensic':raw,'arlington_analysis':analysis}}).encode())
    time.sleep(30)


def test_worker_timeout_keeps_rule_sources_and_primary(tmp_path,monkeypatch):
    import multiprocessing
    from malpdf.static import profile_worker
    context=multiprocessing.get_context('fork')
    monkeypatch.setattr(profile_worker.multiprocessing,'get_context',lambda *args:context)
    monkeypatch.setattr(profile_worker,'_profile_child',_arlington_checkpoint_then_stall)
    monkeypatch.setattr(profile_worker,'_worker_count',lambda *args:1)
    digest=hashlib.sha256(pdf()).hexdigest()
    profile=profile_worker.profile_pdf(tmp_path/'unused.pdf',boundary=tmp_path,digest=digest,
        analysis_version='v9',extraction_profile='deep-static',arlington_catalog=catalog(),
        limits=CodeInspectionLimits(wall_seconds=1,cpu_seconds=1))
    assert profile['static']['features']=={'canary':7}
    assert profile['arlington_analysis']['checks'] and profile['arlington_analysis']['complete'] is False
    assert profile['worker_cleanup_complete'] is True
    validate_bundle(normalize_profile(profile,digest,'deep-static'))


@pytest.fixture
def reference(tmp_path):
    snapshot=tmp_path/'third_party/arlington-pdf-model';tsv=snapshot/'tsv/latest'
    tsv.mkdir(parents=True);(tmp_path/'configs').mkdir()
    (snapshot/'LICENSE').write_bytes(b'Synthetic license fixture\n')
    (snapshot/'NOTICE.txt').write_bytes(b'Synthetic notice fixture\n')
    values=[row('Size',Required='TRUE')]
    (tsv/'FileTrailer.tsv').write_bytes(('\t'.join(HEADER)+'\n'+'\n'.join('\t'.join(r[c] for c in HEADER) for r in values)+'\n').encode())
    for args in (['init','-q'],['-c','core.autocrlf=false','add','.'],['-c','core.autocrlf=false','-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','Benign synthetic model']):
        subprocess.run(['git','-C',str(snapshot),*args],check=True,capture_output=True)
    commit=subprocess.check_output(['git','-C',str(snapshot),'rev-parse','HEAD'],text=True).strip()
    return tmp_path,snapshot,tsv,commit


def test_lock_seals_every_tsv_license_and_notice_and_refuses_collisions(reference):
    root,snapshot,tsv,commit=reference
    sealed=seal_model(root,commit=commit)
    loaded=load_model(root)
    assert loaded.provenance==sealed.provenance
    assert loaded.provenance['tsv_count']==1
    assert len(loaded.provenance['files'])==3
    with pytest.raises(FileExistsError): seal_model(root,commit=commit)
    with pytest.raises(ModelUnavailable,match='full_commit'): seal_model(root,commit=commit[:7])


@pytest.mark.parametrize('change',['content','extra','missing','head','symlink','resealed_content','license'])
def test_model_drift_is_unavailable_without_head_or_fixture_fallback(reference,change):
    root,snapshot,tsv,commit=reference
    seal_model(root,commit=commit)
    file=tsv/'FileTrailer.tsv'
    if change in {'content','resealed_content'}: file.write_bytes(file.read_bytes()+b'\n')
    elif change=='extra': (tsv/'Extra.tsv').write_bytes(file.read_bytes())
    elif change=='missing': file.unlink()
    elif change=='license': (snapshot/'LICENSE').write_bytes(b'changed')
    elif change=='symlink':
        target=root/'redirect.tsv';target.write_bytes(file.read_bytes());file.unlink()
        try:
            file.symlink_to(target)
        except OSError:
            pytest.skip('symlink creation not permitted on this platform')
    else:
        subprocess.run(['git','-C',str(snapshot),'-c','core.autocrlf=false','-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','--allow-empty','-qm','Changed HEAD'],check=True,capture_output=True)
    if change=='resealed_content':
        lock=root/'configs/arlington.lock.json';value=json.loads(lock.read_bytes())
        spec=value['files'][str(file.relative_to(root)).replace('\\', '/')];data=file.read_bytes()
        spec.update(size_bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),git_blob_sha1=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest())
        lock.write_bytes(json.dumps(value).encode())
    with pytest.raises(ModelUnavailable): load_model(root)


def test_missing_model_api_reports_unavailable_and_preserves_primary(tmp_path,monkeypatch):
    from malpdf.extraction import orchestrator
    file=tmp_path/'benign.pdf';file.write_bytes(pdf())
    monkeypatch.setattr(orchestrator,'profile_pdf',lambda *args,**kwargs:{'status':'complete','static':{'features':{'canary':4}}})
    result=orchestrator.extract_pdf(file,arlington_lock='configs/missing.json',repository_root=tmp_path)
    backend=result['coverage_report']['backends']['arlington']
    assert backend['model']['status']=='unavailable' and 'arlington_model_unavailable' in backend['limitations']
    assert result['status']!='observed'
    assert next(r for r in result['evidence_store']['records'] if r['kind']=='primary_checkpoint')['details']['features']=={'canary':4}


def test_reference_cli_is_explicit_and_deep_static_only(tmp_path):
    from malpdf.cli import build_parser
    from malpdf.extraction.orchestrator import extract_pdf
    args=build_parser().parse_args(['extract','benign.pdf','--arlington-lock','configs/arlington.lock.json'])
    assert args.arlington_lock=='configs/arlington.lock.json'
    with pytest.raises(ValueError,match='deep-static'):
        extract_pdf(tmp_path/'unused.pdf',profile='fast-static',arlington_lock=args.arlington_lock,repository_root=tmp_path)


@pytest.mark.parametrize('values',[{'max_checks':0},{'max_metadata_bytes':1},{'max_steps':100001},{'max_depth':True}])
def test_invalid_rule_limits_refused(values):
    with pytest.raises(ValueError): RuleLimits(**values)


def test_extended_predicates_evaluation():
    context = ExprContext()
    assert evaluate('fn:IsNumber(42)', context) is True
    assert evaluate('fn:IsNumber(@Name)', context) is False
    assert isinstance(evaluate('fn:IsNumber(@Missing)', context), Unknown)

    assert evaluate('fn:DefaultValue(10, @N)', context) == Decimal(8)
    assert evaluate('fn:DefaultValue(10, null)', context) == Decimal(10)

    assert evaluate('fn:RequiredValue(42, 42)', context) is True
    assert evaluate('fn:RequiredValue(42, 99)', context) is False
    assert isinstance(evaluate('fn:RequiredValue(@Missing, 42)', context), Unknown)

    assert isinstance(evaluate('fn:PageCount()', context), Unknown)
    context.page_count = lambda: 5
    assert evaluate('fn:PageCount()', context) == Decimal(5)

    assert isinstance(evaluate('fn:PageNumber()', context), Unknown)
    context.page_number = lambda: 1
    assert evaluate('fn:PageNumber()', context) == Decimal(1)

    assert evaluate('fn:InKeyList(42, [1, 42, 99])', context) is True
    assert evaluate('fn:InKeyList(7, [1, 42, 99])', context) is False
    assert isinstance(evaluate('fn:InKeyList(@Missing, [1, 2])', context), Unknown)

    assert evaluate('fn:MustBeDirect(42)', context) is True
    context.is_direct = lambda path: path == 'DirectObj'
    assert evaluate('fn:MustBeDirect(DirectObj)', context) is True
    assert evaluate('fn:MustBeDirect(IndirectObj)', context) is False

    assert evaluate('fn:HasValue(42)', context) is True
    assert evaluate('fn:HasValue(null)', context) is False
    assert isinstance(evaluate('fn:HasValue(@Missing)', context), Unknown)

