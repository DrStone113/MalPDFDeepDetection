"""Arlington rules over worker-private raw IR, without reparsing or execution."""

from dataclasses import dataclass, asdict
from decimal import Decimal
import hashlib
import json
import re
from malpdf.static.execution import capacity, expand_limits, valid_capacity
from malpdf.static.execution import UNLIMITED, is_vm
from malpdf.extraction.checkpointing import CheckpointScheduler
from malpdf.extraction.arlington_memo import BindingMemo, CompletedBinding

from malpdf.extraction.arlington_expression import (Unknown,Symbol,SKIP,EvaluationBudget,
    ExpressionError,evaluate,parse,atom_text,split_top,truth,combine,version)


@dataclass(frozen=True)
class RuleLimits:
    max_bindings: int = 256
    max_checks: int = 2048
    max_depth: int = 24
    max_steps: int = 50000
    max_metadata_bytes: int = 512*1024

    def __post_init__(self):
        for value,ceiling in zip(asdict(self).values(),(1024,8192,32,100000,1024**2)):
            if not valid_capacity(value, ceiling):
                raise ValueError('arlington_invalid_rule_limit')
        if self.max_metadata_bytes<4096:
            raise ValueError('arlington_metadata_requires_terminal_reserve')


@dataclass(frozen=True)
class Value:
    node: object
    owner: str
    item: object = None


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def outcome(value):
    return 'indeterminate' if isinstance(value,Unknown) else 'not_applicable' if value==SKIP else 'pass' if value is True else 'fail'


def conjunction(values):
    result=True
    for value in values: result=combine(result,value,'&&')
    return result


def disjunction(values):
    result=False
    for value in values: result=combine(result,value,'||')
    return result


class Context:
    def __init__(self,engine,value,revision,pdf_version,parent=None,trailer=False,*,field=None,type_name=None,binding_id=None):
        self.engine,self.ref,self.revision,self.version,self.parent,self.trailer=engine,value,revision,pdf_version,parent,trailer
        self.field,self.type_name=field,type_name
        self.binding_id=binding_id

    def for_field(self,ref,type_name):
        return Context(self.engine,self.ref,self.revision,self.version,self.parent,self.trailer,
                       field=ref,type_name=type_name,binding_id=self.binding_id)

    def current_bitmask(self):
        if self.field is None or self.type_name!='bitmask':
            return Unknown(('bitmask_context_unsupported',))
        resolved=self.engine.resolve(self.field,self.revision)
        if isinstance(resolved,Unknown): return resolved
        if resolved.node.issues: return Unknown(('raw_syntax_ambiguous',))
        node=resolved.node
        return node.value if node.kind=='number' and type(node.value) is int else None

    def current_is_hex_string(self):
        if self.field is None: return Unknown(('current_field_context_unsupported',))
        resolved=self.engine.resolve(self.field,self.revision)
        if isinstance(resolved,Unknown): return resolved
        node=resolved.node
        if node.issues: return Unknown(('raw_syntax_ambiguous',))
        if node.kind!='string': return False
        form=getattr(node,'string_form',None)
        if form not in {'hex','literal'}: return Unknown(('string_syntax_unavailable',))
        return form=='hex'

    def entry(self,key):
        if not isinstance(key,str): return Unknown(('key_path_unsupported',))
        resolved=self.engine.resolve(self.ref,self.revision)
        if isinstance(resolved,Unknown): return resolved
        node=resolved.node
        if set(node.issues)-{'forensic_duplicate_dictionary_key'}: return Unknown(('raw_syntax_ambiguous',))
        if node.kind=='dictionary':
            matches=self.engine.dictionary_entries(node).get(b'/'+key.encode(),())
            if len(matches)>1: return Unknown(('duplicate_dictionary_key',))
            if matches: return Value(matches[0],resolved.owner,resolved.item)
            if self.trailer and key in {'Root','Info','Encrypt','ID'}:
                for block in self.engine.doc.chain[self.revision+1:]:
                    older=self.engine.doc.xref_nodes.get(block['offset'])
                    if older is None: return Unknown(('older_trailer_unavailable',))
                    matches=self.engine.dictionary_entries(older).get(b'/'+key.encode(),())
                    if len(matches)>1: return Unknown(('duplicate_dictionary_key',))
                    if matches:
                        return Value(matches[0],block['source_object_id'] or block['id'])
            return None
        if node.kind=='array' and key.isdecimal():
            index=int(key)
            return Value(node.value[index],resolved.owner,resolved.item) if index<len(node.value) else None
        return Unknown(('key_context_unsupported',))

    def path(self,path):
        if not isinstance(path,str) or '*' in path or path.startswith(('trailer::','parent::')):
            return Unknown(('key_path_context_unsupported',))
        parts=path.replace('@','').split('::')
        current=self
        for index,part in enumerate(parts):
            value=current.entry(part)
            if value is None or isinstance(value,Unknown): return value
            if index==len(parts)-1: return value
            current=Context(self.engine,value,self.revision,self.version,parent=current)
        return Unknown(('key_path_unsupported',))

    def present(self,path):
        value=self.path(path)
        if isinstance(value,Unknown): return value
        if value is None: return False
        resolved=self.engine.resolve(value,self.revision)
        if isinstance(resolved,Unknown): return resolved
        return not (self.ref.node.kind=='dictionary' and resolved.node.kind=='null')

    def value(self,path):
        value=self.path(path)
        if value is None: return Unknown(('value_absent',))
        return value if isinstance(value,Unknown) else self.engine.scalar(value,self.revision)


class _Engine:
    def __init__(self,doc,catalog,limits,checkpoint):
        self.doc,self.catalog,self.limits,self.checkpoint=doc,catalog,limits,checkpoint
        self.checkpoints=CheckpointScheduler(getattr(doc,'code',None))
        self.budget=EvaluationBudget(limits.max_steps)
        self.active=set(); self.bindings=0; self.metadata=0
        self.memo=BindingMemo(is_vm(getattr(doc,'code',None)))
        self._dictionary_indexes={}
        self.last_emit=-32
        self.value={'schema_version':'arlington-analysis-v1','document_sha256':doc.sha,
            'model':{key:value for key,value in catalog.provenance.items() if key!='files'},
            'status':'partial','complete':False,'checks':[],'bindings':[],
            'reason_codes':[],'limits':asdict(limits),'root_schema_candidate_outcomes':[],
            'scope':'bounded candidate schemas over cached raw IR and checked xref contexts; never whole-PDF conformance',
            'original_ir_modified':False,'pdf_content_executed':False}
        if self.memo.enabled:
            self.value.update(binding_reuses=[],evaluation_strategy='completed bindings shared within document/version/xref context; cyclic results require identical active ancestors and depth')

    def reuse(self,cached: CompletedBinding,ref: Value,target: Value,parent: Context | None,path: str) -> object:
        if self.bindings+len(self.value['binding_reuses'])>=self.limits.max_bindings:
            raise ExpressionError('arlington_binding_limit')
        refs={self.source(ref),self.source(target)}
        if parent is not None and parent.binding_id is not None:
            refs.add(parent.binding_id)
        record={'id':'arlington-reuse:'+self.doc.sha+':'+str(len(self.value['binding_reuses'])),
                'target_binding_id':cached.binding_id,'source_refs':sorted(refs),
                'outcome':outcome(cached.result),'link_path_sha256':sha(path),
                'cache_scope':'identical_active_ancestors_and_depth' if cached.context_specific else 'acyclic_subtree'}
        self.metadata+=len(json.dumps(record,separators=(',',':')).encode())
        if self.metadata>self.limits.max_metadata_bytes-8192:
            raise ExpressionError('arlington_metadata_limit')
        self.value['binding_reuses'].append(record)
        return cached.result

    def dictionary_entries(self,node):
        """Index immutable cached IR once, retaining every duplicate value.

        This engine is document-local and only runs after raw-IR collection.
        Keep the node alive with its index so Python identity cannot be reused;
        source owners, revisions and schema contexts remain on each Value.
        The existing raw node/check/binding and process limits still apply.
        """
        identity=id(node)
        cached=self._dictionary_indexes.get(identity)
        if cached is None:
            entries={}
            for name,child in node.value:
                entries.setdefault(name.value,[]).append(child)
            cached=(node,entries)
            self._dictionary_indexes[identity]=cached
        return cached[1]

    def source(self,ref):
        node=ref.node
        identity=self.doc.identity('value',ref.owner+'|'+str(node.start)+':'+str(node.end)+':'+node.kind)
        return identity if identity in self.doc.ir_seen else ref.owner

    def resolve(self,ref,revision):
        seen=set()
        while ref.node.kind=='reference':
            if not self.doc.value['selection_context_verified']:
                return Unknown(('xref_selection_unverified',))
            number,generation=ref.node.value
            if (number,generation) in seen or len(seen)>=16:
                return Unknown(('reference_cycle_or_depth_limit',))
            seen.add((number,generation))
            entry=self.doc.effective(number,revision)
            if not entry or entry['type']==0 or entry.get('generation')!=generation:
                return Unknown(('reference_target_unavailable',))
            if entry['type']==1: item=self.doc.objects.get(entry['offset'])
            else:
                container=self.doc.effective(entry['object_stream_number'],revision)
                members=self.doc.members.get(container['offset'],[]) if container and container['type']==1 else []
                index=entry['object_stream_index']
                item=members[index] if 0<=index<len(members) else None
            if not item or (item['number'],item['generation'])!=(number,generation):
                return Unknown(('reference_target_not_in_verified_cache',))
            record=item['record']
            if (record['source_space']=='original' and (not record['top_level_confirmed'] or record['byte_end'] is None)
                    or record.get('stream') and not record['stream']['boundary_verified']):
                return Unknown(('reference_target_not_in_verified_cache',))
            ref=Value(item['node'],item['record']['id'],item)
        return ref

    def scalar(self,ref,revision,depth=0):
        resolved=self.resolve(ref,revision)
        if isinstance(resolved,Unknown): return resolved
        node=resolved.node
        if node.issues or depth>8: return Unknown(('value_projection_unavailable',))
        if node.kind=='number':
            return Decimal(node.value) if len(str(node.value))<=128 else Unknown(('numeric_operand_limit',))
        if node.kind=='name':
            try: return Symbol(node.value[1:].decode('utf-8'))
            except UnicodeError: return Unknown(('name_encoding_unsupported',))
        if node.kind=='string':
            return Unknown(('encrypted_string_unavailable',)) if self.doc.value['encrypted'] else node.value
        if node.kind in {'boolean','null'}: return node.value
        if node.kind=='array' and len(node.value)<=capacity(getattr(self.doc,'code',None),1024):
            return tuple(self.scalar(Value(child,resolved.owner,resolved.item),revision,depth+1) for child in node.value)
        return Unknown(('scalar_projection_unsupported',))

    def emit(self,force=False):
        self.value['expression_steps_used']=self.budget.used
        if force or len(self.value['checks'])-self.last_emit>=32:
            if self.limits.max_metadata_bytes != UNLIMITED and len(json.dumps(self.value,separators=(',',':')).encode())>self.limits.max_metadata_bytes:
                raise ExpressionError('arlington_metadata_limit')
            if not self.checkpoints.due(force=force):
                return
            if self.checkpoint: self.checkpoint(self.value)
            self.last_emit=len(self.value['checks'])
            self.checkpoints.completed()

    def check(self,binding,row,category,result,refs,expression='',**details):
        if len(self.value['checks'])>=self.limits.max_checks:
            raise ExpressionError('arlington_check_limit')
        if 'key' in details and '*' in row.get('Key',''):
            actual=details['key']
            details.update(key=row['Key'],actual_key_sha256=sha(actual))
            if row['Key']!='*' and actual.isdecimal(): details['actual_index']=int(actual)
        item={'id':binding+':check:'+str(len(self.value['checks'])),'binding_id':binding,
            'model_table':details.pop('model_table'), 'model_line':row.get('line'),
            'model_file_sha256':row.get('source_sha256'),'category':category,
            'outcome':outcome(result),'reason_codes':list(result.reasons) if isinstance(result,Unknown) else [],
            'source_refs':sorted(set(refs)),'expression_sha256':sha(expression) if expression else None,
            **details}
        encoded=len(json.dumps(item,separators=(',',':')).encode())
        self.metadata+=encoded
        if self.metadata>self.limits.max_metadata_bytes-8192:
            raise ExpressionError('arlington_metadata_limit')
        self.value['checks'].append(item)
        return result

    def ev(self,text,ctx,**kwargs):
        result=evaluate(text,ctx,budget=self.budget,**kwargs)
        if self.budget.exhausted: raise ExpressionError('arlington_expression_step_limit')
        return result

    def inherited(self,ctx,key):
        seen=set(); current=ctx
        for _ in range(16):
            parent=current.entry('Parent')
            if parent is None: return None
            if isinstance(parent,Unknown): return parent
            resolved=self.resolve(parent,ctx.revision)
            if isinstance(resolved,Unknown): return resolved
            identity=(resolved.owner,resolved.node.start)
            if identity in seen: return Unknown(('inheritance_cycle',))
            seen.add(identity)
            current=Context(self,resolved,ctx.revision,ctx.version)
            value=current.entry(key)
            if isinstance(value,Unknown): return value
            if value is not None:
                target=self.resolve(value,ctx.revision)
                if isinstance(target,Unknown): return target
                if target.node.kind!='null': return value
        return Unknown(('inheritance_depth_limit',))

    def field(self,row,column,index,count):
        values=split_top(row[column],';')
        if len(values)==1: return values[0]
        if len(values)!=count: raise ExpressionError('type_branch_alignment_unsupported')
        result=values[index]
        if column not in {'PossibleValues','SpecialCase','Link'} and result.startswith('[') and result.endswith(']'):
            result=result[1:-1]
        return result

    def type_check(self,ref,type_name,ctx):
        target=self.resolve(ref,ctx.revision)
        if isinstance(target,Unknown): return target
        node=target.node
        if node.issues: return Unknown(('raw_syntax_ambiguous',))
        stream=bool(target.item and target.item['node'] is node and target.item['record'].get('stream'))
        if type_name=='stream': return stream
        if type_name=='dictionary': return node.kind=='dictionary' and not stream
        if type_name=='integer' or type_name=='bitmask': return node.kind=='number' and type(node.value) is int
        if type_name=='number': return node.kind=='number'
        if type_name in {'null','boolean','name','array'}: return node.kind==type_name
        if type_name in {'matrix','rectangle'}:
            if node.kind!='array' or len(node.value)!=(6 if type_name=='matrix' else 4): return False
            return conjunction(self.type_check(Value(child,target.owner,target.item),'number',ctx) for child in node.value)
        if type_name.startswith('string') or type_name=='date':
            if node.kind!='string': return False
            if self.doc.value['encrypted']: return Unknown(('encrypted_string_unavailable',))
            if type_name in {'string','string-byte'}: return True
            if type_name=='string-ascii': return all(byte<128 for byte in node.value)
            return Unknown(('specialized_string_semantics_unsupported',))
        if type_name in {'name-tree','number-tree'}:
            return False if node.kind!='dictionary' else Unknown(('tree_semantics_unsupported',))
        return Unknown(('unsupported_type',))

    def directness(self,text,ref,ctx):
        indirect=ref.node.kind=='reference'
        if text=='TRUE': return indirect
        if text=='FALSE': return True
        try: ast=parse(text)
        except ExpressionError: return Unknown(('unsupported_indirect_rule',))
        if ast[0]=='call' and ast[1] in {'MustBeDirect','MustBeIndirect'} and len(ast[2])<=1:
            required=True if not ast[2] else truth(self.ev(text[text.index('(')+1:-1],ctx))
            satisfied=not indirect if ast[1]=='MustBeDirect' else indirect
            return combine(negation(required),satisfied,'||')
        return Unknown(('unsupported_indirect_rule',))

    def list_rule(self,text,ref,ctx,*,possible=False):
        if not text or text=='[]': return True
        content=text[1:-1] if text.startswith('[') and text.endswith(']') else text
        values=[]
        for entry in split_top(content,','):
            if possible and entry=='*':
                actual=self.scalar(ref,ctx.revision)
                values.append(True if isinstance(actual,Symbol) else actual if isinstance(actual,Unknown) else False)
                continue
            result=self.ev(entry,ctx)
            if result==SKIP: continue
            ast=parse(entry)
            predicate=ast[0]=='call' and ast[1] not in {'SinceVersion','BeforeVersion','IsPDFVersion','Deprecated','Extension'}

            while ast[0]=='call' and ast[1] in {'SinceVersion','BeforeVersion','IsPDFVersion','Deprecated','Extension'} and len(ast[2])==2:
                ast=ast[2][1]
                predicate=ast[0]=='call'
            if not possible or predicate:
                values.append(truth(result)); continue
            actual=self.scalar(ref,ctx.revision)
            if isinstance(result,Unknown) or isinstance(actual,Unknown): values.append(Unknown(('possible_value_unavailable',))); continue
            if isinstance(actual,Symbol) and ast[0]=='atom' and re.fullmatch(r'[0-9]+(?:\.[0-9]+)?',ast[1]): result=Symbol(ast[1])
            values.append(type(actual)==type(result) and actual==result)
        return disjunction(values) if possible else conjunction(values)

    def links(self,text,ref,ctx,depth,path):
        if not text or text=='[]': return True
        text=text[1:-1] if text.startswith('[') and text.endswith(']') else text
        candidates=[]
        for entry in split_top(text,','):
            model=self.ev(entry,ctx)
            if model==SKIP: continue
            if isinstance(model,Unknown): candidates.append(model)
            elif isinstance(model,Symbol): candidates.append(self.bind(ref,model.value,ctx.revision,ctx.version,ctx,depth+1,path))
            else: candidates.append(Unknown(('link_target_unsupported',)))
        return disjunction(candidates) if candidates else Unknown(('no_applicable_link',))

    def row(self,binding,model,row,key,ref,ctx,depth,path):
        refs=[self.source(ctx.ref)]
        if isinstance(ref,Unknown):
            return self.check(binding,row,'presence',ref,refs,model_table=model)
        inherited=False
        if ref is not None:
            resolved=self.resolve(ref,ctx.revision)
            if not isinstance(resolved,Unknown) and ctx.ref.node.kind=='dictionary' and resolved.node.kind=='null' and 'null' not in split_top(row['Type'],';'):
                ref=None
        if ref is None and row['Inheritable']=='TRUE':
            ref=self.inherited(ctx,key); inherited=ref is not None and not isinstance(ref,Unknown)
        if isinstance(ref,Unknown): return self.check(binding,row,'inheritance',ref,refs,model_table=model)
        available=self.ev(row['SinceVersion'],ctx,since=True)
        if ref is None:
            required=truth(self.ev(row['Required'],ctx))
            result=True if required is False or available is False or available==SKIP else Unknown(('required_or_version_context_unavailable',)) if isinstance(required,Unknown) or isinstance(available,Unknown) else False
            self.check(binding,row,'required',result,refs,row['Required'],model_table=model,key=key)
            if row['DefaultValue']:
                default=self.ev(row['DefaultValue'],ctx)
                known=not isinstance(default,Unknown) and default!=SKIP
                self.check(binding,row,'virtual_default',True if known else default if isinstance(default,Unknown) else Unknown(('default_not_applicable',)),
                    refs,row['DefaultValue'],model_table=model,key=key,original_ir_modified=False,
                    virtual_value_sha256=sha(repr(default)) if known else None,
                    usage='recorded semantic default only; no IR, feature or required-value imputation')
            return result
        refs.append(self.source(ref))
        version_result=truth(available)
        self.check(binding,row,'version',version_result,refs,row['SinceVersion'],model_table=model,key=key)
        if row['DeprecatedIn']:
            deprecated=version(row['DeprecatedIn'])
            unknown=isinstance(deprecated,Unknown) or isinstance(ctx.version,Unknown)
            self.check(binding,row,'deprecation_notice',Unknown(('version_context_unavailable',)) if unknown else True,
                refs,row['DeprecatedIn'],model_table=model,key=key,
                deprecated=None if unknown else ctx.version>=deprecated,
                interpretation='deprecation notice does not invalidate an otherwise supported value')
        if inherited:
            self.check(binding,row,'inherited_value',True,refs,model_table=model,key=key,original_ir_modified=False)
        alternatives=split_top(row['Type'],';'); results=[]
        for index,type_expression in enumerate(alternatives):
            kind=Symbol(type_expression) if re.fullmatch('[a-z][a-z-]*',type_expression) else self.ev(type_expression,ctx)
            if kind==SKIP: continue
            matched=kind if isinstance(kind,Unknown) else self.type_check(ref,kind.value,ctx) if isinstance(kind,Symbol) else Unknown(('type_expression_unsupported',))
            self.check(binding,row,'type_candidate',matched,refs,type_expression,model_table=model,key=key,type_branch=index)
            if matched is False: results.append(False); continue
            rule_ctx=ctx.for_field(ref,kind.value if isinstance(kind,Symbol) else None)
            checks=[matched]
            for column,category,fn in (
                ('IndirectReference','indirect',self.directness),
                ('PossibleValues','possible_values',lambda text,value,context:self.list_rule(text,value,context,possible=True)),
                ('SpecialCase','special_case',self.list_rule),
                ('Link','link',lambda text,value,context:self.links(text,value,context,depth,path+'/'+model+':'+key))):
                expression=self.field(row,column,index,len(alternatives))
                result=fn(expression,ref,rule_ctx)
                checks.append(result)
                self.check(binding,row,category,result,refs,expression,model_table=model,key=key,type_branch=index)
            results.append(conjunction(checks))
        result=combine(version_result,disjunction(results),'&&')
        return self.check(binding,row,'row',result,refs,model_table=model,key=key)

    def bind(self,ref,model,revision,pdf_version,parent,depth,path):
        if model not in self.catalog.tables: return Unknown(('model_table_unavailable',))
        target=self.resolve(ref,revision)
        if isinstance(target,Unknown): return target
        identity=(target.owner,target.node.start,target.node.end,model,revision)
        if identity in self.active:
            self.memo.note_cycle()
            return Unknown(('schema_link_cycle',))
        stream=bool(target.item and target.item['node'] is target.node and target.item['record'].get('stream'))
        memo_key=(identity,pdf_version,stream)
        cached=self.memo.find(memo_key,self.active,depth,self.limits.max_depth)
        if cached is not None:
            return self.reuse(cached,ref,target,parent,path)
        if depth>self.limits.max_depth or self.bindings+len(self.value.get('binding_reuses',()))>=self.limits.max_bindings:
            raise ExpressionError('arlington_binding_limit')
        self.bindings+=1
        binding='arlington-binding:'+sha(self.doc.sha+'|'+str(identity)+'|'+path)
        record={'id':binding,'model_table':model,'xref_context_distance':revision,
                'source_refs':[self.source(target)],'outcome':'indeterminate','candidate_only':True}
        self.value['bindings'].append(record); self.metadata+=len(json.dumps(record).encode())
        self.active.add(identity)
        self.memo.begin(identity,depth)
        ctx=Context(self,target,revision,pdf_version,parent,trailer=model in {'FileTrailer','XRefStream'},binding_id=binding)
        rows=self.catalog.tables[model]; node=target.node
        results=[]; covered=set(); completed_result=None
        try:
            if node.kind not in {'dictionary','array'}:
                record['outcome']='fail'; completed_result=False; return False
            explicit={row['Key'] for row in rows if row['Key']!='*' and not row['Key'].endswith('*')}
            repeat=[int(row['Key'][:-1]) for row in rows if row['Key'].endswith('*') and row['Key'][:-1].isdecimal()]
            for row in rows:
                key=row['Key']
                if key=='*':
                    if node.kind=='dictionary':
                        keys=[]
                        for name,child in node.value:
                            try: actual=name.value[1:].decode('utf-8')
                            except UnicodeError: actual='opaque:'+hashlib.sha256(name.value).hexdigest()
                            if actual not in explicit:
                                duplicate=len(self.dictionary_entries(node)[name.value])>1
                                keys.append((actual,Unknown(('duplicate_dictionary_key',)) if duplicate else Value(child,target.owner,target.item)))
                    else: keys=[(str(index),ctx.entry(str(index))) for index in range(len(node.value)) if str(index) not in explicit and not repeat]
                elif key.endswith('*'):
                    if node.kind!='array' or not repeat or sorted(repeat)!=list(range(min(repeat),max(repeat)+1)):
                        results.append(Unknown(('array_repeat_pattern_unsupported',))); continue
                    end=min(repeat)+max(0,(len(node.value)-min(repeat)+len(repeat)-1)//len(repeat))*len(repeat)
                    keys=[(str(index),ctx.entry(str(index))) for index in range(int(key[:-1]),end,len(repeat))]
                else: keys=[(key,ctx.entry(key))]
                for actual,value in keys:
                    covered.add(actual)
                    try: results.append(self.row(binding,model,row,actual,value,ctx,depth,path))
                    except ExpressionError as error:
                        if str(error).startswith('arlington_'): raise
                        results.append(self.check(binding,row,'unsupported_rule',Unknown(('unsupported_rule_syntax',)),[self.source(target)],model_table=model))
                self.emit()
            if node.kind=='dictionary':
                for name,child in node.value:
                    decoded=name.value[1:].decode('utf-8',errors='replace')
                    if decoded not in covered:
                        self.check(binding,{},'unknown_key',Unknown(('unknown_key_preserved',)),[self.source(Value(name,target.owner,target.item)),self.source(Value(child,target.owner,target.item))],model_table=model,key_sha256=sha(decoded))
            else:
                for index,child in enumerate(node.value):
                    if str(index) not in covered:
                        results.append(self.check(binding,{},'unmodeled_array_element',Unknown(('array_element_unmodeled',)),[self.source(Value(child,target.owner,target.item))],model_table=model,index=index))
            result=conjunction(results); record['outcome']=outcome(result)
            completed_result=result
            return result
        finally:
            self.active.remove(identity)
            self.memo.finish(memo_key,binding,completed_result)

    def run(self):
        self.emit()
        if not self.doc.value['selection_context_verified']:
            self.value['reason_codes'].append('xref_selection_unverified'); return self.value
        header=re.match(rb'%PDF-([12]\.[0-9]+)(?:\s|$)',self.doc.data)
        header_version=version(header[1].decode()) if header else Unknown(('version_context_unavailable',))
        for revision,block in enumerate(self.doc.chain):
            node=self.doc.xref_nodes.get(block['offset'])
            if node is None: continue
            owner=block['source_object_id'] or block['id']; ref=Value(node,owner)
            ctx=Context(self,ref,revision,header_version,trailer=True)
            root=ctx.entry('Root'); effective_version=header_version
            if root is not None and not isinstance(root,Unknown):
                catalog=Context(self,root,revision,header_version)
                declared=catalog.entry('Version')
                if isinstance(declared,Unknown): effective_version=declared
                elif declared is not None:
                    value=self.scalar(declared,revision)
                    selected=version(value.value) if isinstance(value,Symbol) else Unknown(('catalog_version_unavailable',))
                    effective_version=selected if isinstance(selected,Unknown) or isinstance(header_version,Unknown) else max(selected,header_version)
            model='FileTrailer' if block['kind']=='table' else 'XRefStream'
            result=self.bind(ref,model,revision,effective_version,None,0,'root:'+str(revision))
            self.value['root_schema_candidate_outcomes'].append({'xref_context_distance':revision,'outcome':outcome(result)})
        if not self.value['bindings']: self.value['reason_codes'].append('no_usable_xref_context')
        self.value['complete']=True

        self.value['reason_codes'].append('whole_document_conformance_unverified')
        self.emit(force=True)
        return self.value


def negation(value):
    value=truth(value)
    return value if isinstance(value,Unknown) else not value


def validate_document(document,catalog,*,limits=None,checkpoint=None):
    engine=_Engine(document,catalog,limits or expand_limits(RuleLimits(), getattr(document,'code',None)),checkpoint)
    try:
        result=engine.run()
    except (ExpressionError,MemoryError,RecursionError) as error:
        result=engine.value
        code=str(error) if isinstance(error,ExpressionError) else 'arlington_memory_or_recursion_limit'
        result.update(complete=False,reason_codes=sorted(set(result['reason_codes'])|{code}),
                      counters_are_interrupted_lower_bounds=True)
    result['expression_steps_used']=engine.budget.used
    if checkpoint: checkpoint(result)
    return result
