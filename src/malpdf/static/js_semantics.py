"""Bounded lexical/data-flow facts from inert Esprima ASTs.

No JavaScript function, builtin, getter, eval body or host operation is invoked.
Abstract transfers cover a small scalar subset; opaque effects widen state.
"""

from dataclasses import dataclass,field,asdict
import json
import re
from malpdf.static.execution import valid_capacity

from malpdf.static.js_abstract import (Value,top,one,join,literal,boolean,unary,
    binary,describe,digest,units,canonical_string)
from malpdf.static.js_ast import CALL_NAMES,_callee_name,_literal_string

API_NAMES=CALL_NAMES|frozenset({'doc.submitForm','this.submitForm','doc.getField',
    'this.getField','doc.getAnnots','this.getAnnots','util.printd'})
ROOTS=frozenset({'app','doc','util','Collab','event','eval','unescape','atob','Function','String'})
FUNCTIONS=frozenset({'FunctionDeclaration','FunctionExpression','ArrowFunctionExpression'})


@dataclass(frozen=True)
class SemanticLimits:
    max_nodes: int = 20000
    max_depth: int = 100
    max_scopes: int = 128
    max_bindings: int = 512
    max_facts: int = 1024
    max_steps: int = 40000
    max_string_units: int = 2048
    max_metadata_bytes: int = 512*1024

    def __post_init__(self):
        ceilings=(100000,200,512,2048,4096,200000,8192,1024**2)
        if any(not valid_capacity(v,c) for v,c in zip(asdict(self).values(),ceilings)) or self.max_metadata_bytes<4096:
            raise ValueError('invalid_js_semantic_limit')


class SemanticLimit(ValueError):
    pass


class SemanticBudget:
    """Shared across scripts; limits never restart for a second source/backend."""
    def __init__(self,limits=None):
        self.limits=limits or SemanticLimits()
        self.used={name:0 for name in ('nodes','scopes','bindings','facts','steps','metadata_bytes')}

    def take(self,name,count=1):
        if self.used[name]+count>getattr(self.limits,'max_'+name):
            raise SemanticLimit('js_semantic_'+name+'_limit')
        self.used[name]+=count


def children(node):
    for key,value in node.items():
        if key in {'range','loc','raw','tokens','comments'}: continue
        if isinstance(value,dict) and 'type' in value: yield key,value
        elif isinstance(value,list):
            for index,item in enumerate(value):
                if isinstance(item,dict) and 'type' in item: yield key+':'+str(index),item


@dataclass
class Scope:
    identity: str
    parent: object
    kind: str
    function: str
    names: dict = field(default_factory=dict)

    def lookup(self,name):
        current=self
        while current:
            if name in current.names: return current.names[name]
            current=current.parent
        return None


@dataclass
class Binding:
    identity: str
    scope: Scope
    kind: str
    declarations: list = field(default_factory=list)
    function: object = None
    ambiguous: bool = False


@dataclass
class State:
    values: dict = field(default_factory=dict)
    ambient_invalidated: bool = False
    flow: str = 'normal'
    initialized: set = field(default_factory=set)

    def copy(self): return State(dict(self.values),self.ambient_invalidated,self.flow,set(self.initialized))


class _Analysis:
    def __init__(self,tree,source_sha256,*,budget=None,checkpoint=None):
        self.tree,self.sha=tree,source_sha256
        self.budget=budget or SemanticBudget();self.limits=self.budget.limits
        self.checkpoint=checkpoint
        self.scopes=[];self.bindings=[];self.functions=[];self.paths={};self.node_scopes={}
        self.binders={};self.function_for={};self.scope_for={};self.call_for={};self.parents={}
        self.value={'schema_version':'js-static-semantics-v1','decoded_script_sha256':self.sha,
            'status':'partial','complete':False,'normalized_ast_sha256':None,
            'scopes':[],'bindings':[],'functions':[],'facts':[],'calls':[],
            'reason_codes':[],'javascript_executed':False,'functions_invoked':False,
            'scope':'finite scalar/static call candidates; no runtime, interprocedural or whole-program proof',
            'normalization_scope':'lexical alpha fingerprint only; reflective names, global properties and dynamic scopes unverified',
            'source_range_unit':'Unicode code points in the decoded script, not PDF byte offsets'}

    def reason(self,code):
        self.value['reason_codes']=sorted(set(self.value['reason_codes'])|{code})

    def new_scope(self,parent,kind,node,function=None):
        self.budget.take('scopes')
        identity='scope_'+str(len(self.scopes))
        scope=Scope(identity,parent,kind,function or (parent.function if parent else 'program'))
        self.scopes.append(scope)
        record={'id':identity,'parent_id':parent.identity if parent else None,'kind':kind,
                'function_id':scope.function,'source_range':node.get('range')}
        self.store('scopes',record)
        return scope

    def store(self,collection,record):

        size=len(json.dumps(record,ensure_ascii=True,separators=(',',':')).encode())
        if self.budget.used['metadata_bytes']+size>self.limits.max_metadata_bytes-2048:
            raise SemanticLimit('js_semantic_metadata_bytes_limit')
        self.budget.take('metadata_bytes',size)
        self.value[collection].append(record)
        return record

    def update(self,record,**details):
        candidate={**record,**details}
        size=lambda value:len(json.dumps(value,ensure_ascii=True,separators=(',',':')).encode())
        growth=max(0,size(candidate)-size(record))
        if self.budget.used['metadata_bytes']+growth>self.limits.max_metadata_bytes-2048:
            raise SemanticLimit('js_semantic_metadata_bytes_limit')
        self.budget.take('metadata_bytes',growth)
        record.update(details)

    def bind(self,node,scope,kind,function=None,ambiguous=False):
        if node.get('type')!='Identifier':
            self.reason('destructuring_or_parameter_pattern_unsupported')
            for _,child in children(node): self.bind(child,scope,kind,ambiguous=True)
            return
        name=node['name'];binding=scope.names.get(name)
        if binding is None:
            self.budget.take('bindings')
            binding=Binding('binding_'+str(len(self.bindings)),scope,kind)
            scope.names[name]=binding;self.bindings.append(binding)
            self.store('bindings',{'id':binding.identity,'scope_id':scope.identity,'kind':kind,
                'declaration_ranges':[],'ambiguous':False})
        elif kind not in {'var','function'} or binding.kind not in {'var','function','parameter'}:
            binding.ambiguous=True
        binding.declarations.append(node.get('range'));binding.ambiguous|=ambiguous
        if function is not None: binding.function=function
        self.binders[id(node)]=binding
        record=self.value['bindings'][int(binding.identity.split('_')[-1])]
        self.update(record,declaration_ranges=list(binding.declarations),ambiguous=binding.ambiguous)

    def prepare(self,node,scope=None,path='root',depth=0,parent=None,role=None,body_scope=False):
        self.budget.take('steps');self.budget.take('nodes')
        if depth>self.limits.max_depth: raise SemanticLimit('js_semantic_depth_limit')
        kind=node.get('type')
        if kind=='Program': scope=self.new_scope(None,'program',node)
        elif kind=='BlockStatement' and not body_scope:
            scope=self.new_scope(scope,'block',node)
        elif kind in {'ForStatement','ForInStatement','ForOfStatement','CatchClause','SwitchStatement'}:
            scope=self.new_scope(scope,'lexical_control',node)
        elif kind=='ClassExpression':
            scope=self.new_scope(scope,'class_expression',node)
        self.paths[id(node)]=path;self.node_scopes[id(node)]=scope
        self.parents[id(node)]=(parent,role)
        if kind in FUNCTIONS:
            fid='function_'+str(len(self.functions))
            if kind=='FunctionDeclaration' and node.get('id'):
                self.bind(node['id'],scope,'function',fid,ambiguous=scope.kind not in {'function','program'})
                if scope.kind not in {'function','program'}:
                    block_binding=self.binders[id(node['id'])]
                    owner=scope.parent
                    while owner.kind not in {'function','program'}: owner=owner.parent
                    self.bind(node['id'],owner,'var',ambiguous=True)
                    self.binders[id(node['id'])]=block_binding
                    self.reason('annex_b_block_function_hoisting_unsupported')
            inner=self.new_scope(scope,'function',node,fid)
            self.functions.append((node,inner,fid));self.function_for[id(node)]=fid
            if kind=='FunctionExpression' and node.get('id'):
                self.bind(node['id'],inner,'function_name',fid)
            for param in node.get('params',[]): self.bind(param,inner,'parameter')
            for key,child in children(node):
                self.prepare(child,inner,path+'/'+key,depth+1,node,key,body_scope=key=='body')
            self.store('functions',{'id':fid,'scope_id':inner.identity,'kind':kind,
                'source_range':node.get('range'),'invocation_status':'not_invoked'})
            return
        self.scope_for[id(node)]=scope
        if kind=='VariableDeclaration':
            owner=scope
            if node['kind']=='var':
                while owner.kind not in {'program','function'}: owner=owner.parent
            for declaration in node['declarations']: self.bind(declaration['id'],owner,node['kind'])
        if kind in {'ClassDeclaration','ClassExpression'} and node.get('id'):
            self.bind(node['id'],scope,'class',ambiguous=True)
        if kind=='CatchClause' and node.get('param'): self.bind(node['param'],scope,'parameter')
        if kind in {'CallExpression','NewExpression'}:
            self.budget.take('facts')
            record={'id':'call_'+str(len(self.value['calls'])),'ast_path':path,'source_range':node.get('range'),
                'source_function':scope.function,'kind':kind,'flow_status':'not_visited',
                'possible_local_functions':[],'known_api_candidates':[],'arguments':[],
                'resolution_status':'unknown','reason_codes':['not_reached_by_modeled_flow'],
                'execution_status':'not_executed'}
            syntactic=_callee_name(node.get('callee'))
            callee=node.get('callee',{})
            if syntactic is None and callee.get('type')=='MemberExpression' and callee.get('object',{}).get('type')=='ThisExpression':
                prop=_literal_string(callee.get('property')) if callee.get('computed') else callee.get('property',{}).get('name')
                syntactic='this.'+prop if isinstance(prop,str) else None
            record['syntactic_api_name']=syntactic if syntactic in API_NAMES else None
            self.call_for[id(node)]=self.store('calls',record)
        for key,child in children(node): self.prepare(child,scope,path+'/'+key,depth+1,node,key)

    def canonical(self,node,depth=0):
        self.budget.take('steps')
        if depth>self.limits.max_depth: raise SemanticLimit('js_semantic_depth_limit')
        kind=node.get('type')
        if kind=='Identifier':
            parent,role=self.parents[id(node)]
            public=(parent and ((parent.get('type')=='MemberExpression' and role=='property' and not parent.get('computed')) or
                (parent.get('type') in {'Property','MethodDefinition'} and role=='key' and not parent.get('computed')) or role=='label'))
            binding=self.binders.get(id(node)) or (None if public else self.node_scopes[id(node)].lookup(node['name']))
            return [kind,'binding',binding.identity] if binding else [kind,'property' if public else 'free',digest(node['name'])]
        if kind=='Literal':
            if 'regex' in node: return [kind,'regex',digest(json.dumps(node['regex'],sort_keys=True))]
            value=node.get('value')
            if isinstance(value,str): value=canonical_string(value)
            label='number' if type(value) in (int,float) else type(value).__name__
            return [kind,label,digest(repr(value))]
        result={}
        for key,value in sorted(node.items()):
            if key in {'range','loc','raw','tokens','comments'}: continue
            if isinstance(value,dict): result[key]=self.canonical(value,depth+1)
            elif isinstance(value,list): result[key]=[self.canonical(item,depth+1) if isinstance(item,dict) else item for item in value]
            else: result[key]=value
        return result

    def enter(self,scope,state):
        for binding in self.bindings:
            if binding.scope is not scope: continue
            state.values[binding.identity]=top('ambiguous_binding') if binding.ambiguous else one('function',binding.function) if binding.function else one('undefined') if binding.kind=='var' and scope.kind=='function' else top('program_entry_or_lexical_uninitialized')
            if binding.kind in {'var','function','parameter','function_name'}:
                state.initialized.add(binding.identity)
            else: state.initialized.discard(binding.identity)

    def havoc(self,state,reason):
        for binding in self.bindings:
            previous=state.values.get(binding.identity,top('uninitialized'))
            immutable=(binding.kind=='const' and not previous.unknown and all(atom.kind in {'string','number','boolean','null','undefined'} for atom in previous.atoms))
            if not immutable: state.values[binding.identity]=top(reason)
        state.ambient_invalidated=True
        self.reason(reason)

    def merge(self,target,states):
        continuing=[state for state in states if state.flow=='normal']
        selected=continuing or states
        keys={key for state in selected for key in state.values}
        target.values={key:join(state.values.get(key,top('branch_value_unavailable')) for state in selected) for key in keys}
        target.ambient_invalidated=any(state.ambient_invalidated for state in selected)
        target.initialized=set.intersection(*(state.initialized for state in selected))
        target.flow='normal' if continuing else selected[0].flow if len({s.flow for s in selected})==1 else 'abrupt_unknown'

    def fact(self,node,kind,value=None,**details):
        self.budget.take('facts')
        record={'id':'fact_'+str(len(self.value['facts'])),'kind':kind,'ast_path':self.paths[id(node)],
                'source_range':node.get('range'),**details}
        if value is not None: record['value']=describe(value)
        return self.store('facts',record)

    def excluded(self,node,reason):
        if not isinstance(node,dict): return
        self.budget.take('steps')
        record=self.call_for.get(id(node))
        if record and record['flow_status']=='not_visited':
            self.update(record,flow_status='excluded_within_modeled_scope',resolution_status='not_applicable',reason_codes=[reason])
        for _,child in children(node): self.excluded(child,reason)

    def read(self,node,state):
        scope=self.node_scopes[id(node)];binding=scope.lookup(node['name'])
        if binding:
            if binding.identity not in state.initialized:
                self.reason('lexical_tdz_or_entry_context_unverified')
                return top('lexical_before_initialization')
            return state.values.get(binding.identity,top('binding_not_initialized'))
        if node['name'] in ROOTS and not state.ambient_invalidated:
            value=one('ambient',(node['name'],))
            self.havoc(state,'ambient_root_read_effects_unmodeled')
            return value
        self.havoc(state,'free_identifier_read_effects_unmodeled')
        return top('free_identifier_or_ambient_state_unknown')

    def write(self,node,value,state,*,initial=False):
        if node.get('type')!='Identifier':
            self.havoc(state,'assignment_target_or_heap_unsupported');return top('assignment_target_unsupported')
        binding=self.binders.get(id(node)) or self.node_scopes[id(node)].lookup(node['name'])
        if binding is None:
            self.havoc(state,'free_assignment_unsupported');return top('free_assignment_unsupported')
        if not initial and binding.identity not in state.initialized:
            self.reason('lexical_tdz_or_entry_context_unverified')
            return top('lexical_before_initialization')
        if binding.ambiguous or binding.kind=='const' and not initial:
            state.values[binding.identity]=top('ambiguous_or_immutable_assignment')
        else: state.values[binding.identity]=value
        if initial: state.initialized.add(binding.identity)
        return state.values[binding.identity]

    def expression(self,node,state,flow,depth=0):
        if not isinstance(node,dict): return top('missing_expression')
        self.budget.take('steps')
        if depth>self.limits.max_depth: raise SemanticLimit('js_semantic_depth_limit')
        kind=node.get('type');ev=lambda child:self.expression(child,state,flow,depth+1)
        if kind=='Literal': return literal(node,self.limits.max_string_units)
        if kind=='Identifier': return self.read(node,state)
        if kind=='ThisExpression': return top('dynamic_this_context_unmodeled')
        if kind in FUNCTIONS: return one('function',self.function_for[id(node)])
        if kind=='BinaryExpression':
            left=ev(node['left']);right=ev(node['right'])
            value=binary(node['operator'],left,right,self.limits.max_string_units)
            self.fact(node,'binary_transfer',value,operator=node['operator'])
            if value.unknown and node['operator'] not in {'===','!=='}: self.havoc(state,'object_coercion_unsupported')
            return value
        if kind=='UnaryExpression' and node['operator'] in {'!','+','-','typeof','void'}:
            argument=ev(node['argument'])
            value=one('undefined') if node['operator']=='void' else unary(node['operator'],argument)
            if value.unknown and node['operator'] in {'+','-'}: self.havoc(state,'object_coercion_unsupported')
            self.fact(node,'unary_transfer',value,operator=node['operator']);return value
        if kind in {'LogicalExpression','ConditionalExpression'}:
            left=ev(node.get('left',node.get('test')));condition=boolean(left)
            if kind=='ConditionalExpression':
                a,b=node['consequent'],node['alternate']
            elif node['operator']=='&&': a,b=node['right'],None
            elif node['operator']=='||': a,b=None,node['right']
            else:
                self.havoc(state,'logical_operator_unsupported');return top('logical_operator_unsupported')
            if condition is not None:
                selected,ignored=(a,b) if condition else (b,a)
                self.excluded(ignored,'constant_short_circuit')
                return ev(selected) if selected else left
            states=[state.copy(),state.copy()]
            values=[self.expression(part,branch,flow,depth+1) if part else left for part,branch in zip((a,b),states)]
            self.merge(state,states);return join(values)
        if kind=='SequenceExpression':
            value=top('empty_sequence')
            for child in node['expressions']: value=ev(child)
            return value
        if kind=='MemberExpression':
            owner=ev(node['object'])
            prop=ev(node['property']) if node.get('computed') else one('string',node['property']['name'])
            values=[]
            if owner.unknown or prop.unknown: value=join((owner,prop))
            else:
                for a in owner.atoms:
                    for b in prop.atoms:
                        if a.kind=='string' and b.kind=='string' and b.value=='length': values.append(one('number',units(a.value)))
                        elif a.kind=='ambient' and b.kind=='string' and len(a.value)<8: values.append(one('ambient',a.value+(b.value,)))
                        else: values.append(top('heap_property_unsupported'))
                value=join(values)
            if value.unknown or any(a.kind=='ambient' for a in value.atoms):
                self.havoc(state,'property_getter_effects_unmodeled')
            return value
        if kind in {'CallExpression','NewExpression'}:
            callee=ev(node['callee']);arguments=[ev(arg) for arg in node.get('arguments',[])]
            record=self.call_for[id(node)]
            local=sorted({a.value for a in callee.atoms if a.kind=='function'})
            names=sorted({'.'.join(a.value) for a in callee.atoms if a.kind=='ambient' and '.'.join(a.value) in API_NAMES})
            self.update(record,flow_status=flow,possible_local_functions=local,known_api_candidates=names,
                arguments=[describe(arg) for arg in arguments],
                resolution_status='candidate' if local or names else 'unknown',
                reason_codes=list(callee.reasons) if callee.unknown else ['static_candidate_only'])
            self.havoc(state,'opaque_call_effects_unmodeled')
            return top('call_return_value_unmodeled')
        if kind in {'AssignmentExpression','UpdateExpression'}:
            target=node.get('left',node.get('argument'))
            if target.get('type')!='Identifier':
                ev(target)
                if kind=='AssignmentExpression': ev(node['right'])
                self.havoc(state,'assignment_target_or_heap_unsupported');return top('assignment_target_unsupported')
            previous=self.read(target,state)
            if kind=='UpdateExpression': value=binary('+' if node['operator']=='++' else '-',previous,one('number',1))
            elif node['operator']=='=': value=ev(node['right'])
            else: value=binary(node['operator'][:-1],previous,ev(node['right']),self.limits.max_string_units)
            if value.unknown and node.get('operator')!='=':
                self.havoc(state,'object_coercion_unsupported')
            stored=self.write(target,value,state)
            self.fact(node,'assignment_transfer',stored)
            return previous if kind=='UpdateExpression' and not node.get('prefix') else stored
        if kind in {'ArrayExpression','ObjectExpression','TemplateLiteral'}:
            for key,child in children(node):
                if kind=='ObjectExpression' and child.get('type')=='Property':
                    if child.get('computed'): ev(child['key'])
                    ev(child['value'])
                elif child.get('type')!='TemplateElement': ev(child)
            return top('aggregate_or_template_value_unmodeled')


        self.havoc(state,'unsupported_expression:'+str(kind))
        return top('unsupported_expression:'+str(kind))

    def statement(self,node,state,flow,depth=0):
        if not isinstance(node,dict): return
        self.budget.take('steps')
        if depth>self.limits.max_depth: raise SemanticLimit('js_semantic_depth_limit')
        kind=node.get('type')
        if state.flow!='normal':
            self.excluded(node,'prior_abrupt_completion_in_modeled_scope');return
        if kind in {'Program','BlockStatement'}:
            scope=self.node_scopes[id(node)]
            self.enter(scope,state)
            for child in node.get('body',[]): self.statement(child,state,flow,depth+1)
        elif kind=='VariableDeclaration':
            for declaration in node['declarations']:
                target=declaration['id'];initial=declaration.get('init')
                if initial is not None: value=self.expression(initial,state,flow)
                elif node['kind']=='var': continue
                else: value=one('undefined')
                stored=self.write(target,value,state,initial=True)
                self.fact(declaration,'binding_transfer',stored)
        elif kind=='ExpressionStatement': self.expression(node['expression'],state,flow)
        elif kind=='IfStatement':
            condition=boolean(self.expression(node['test'],state,flow))
            self.fact(node,'branch',condition_known=condition is not None,
                selected_branch=('consequent' if condition else 'alternate') if condition is not None else None)
            if condition is not None:
                selected,ignored=(node['consequent'],node.get('alternate')) if condition else (node.get('alternate'),node['consequent'])
                self.excluded(ignored,'constant_branch_in_modeled_scope')
                self.statement(selected,state,flow,depth+1)
            else:
                states=[state.copy(),state.copy()]
                for child,branch in zip((node['consequent'],node.get('alternate')),states): self.statement(child,branch,flow,depth+1)
                self.merge(state,states)
        elif kind in {'ForStatement','WhileStatement','DoWhileStatement','ForInStatement','ForOfStatement'}:
            if kind.startswith('For'): self.enter(self.node_scopes[id(node)],state)
            initial=node.get('init')
            if initial:
                if initial.get('type')=='VariableDeclaration': self.statement(initial,state,flow,depth+1)
                else: self.expression(initial,state,flow)
            test=node.get('test')
            condition=boolean(self.expression(test,state,flow)) if test and kind!='DoWhileStatement' else None
            if kind in {'ForInStatement','ForOfStatement'}:
                self.expression(node['right'],state,flow)
                self.reason('enumeration_protocol_unmodeled')
            if condition is False and kind!='DoWhileStatement':
                self.excluded(node['body'],'constant_false_loop_test');self.excluded(node.get('update'),'constant_false_loop_test')
            else:

                self.havoc(state,'loop_state_widened')
                branch=state.copy();self.statement(node['body'],branch,flow,depth+1)
                if node.get('update'):
                    if branch.flow in {'normal','continue'}: self.expression(node['update'],branch,flow)
                    else: self.excluded(node['update'],'abrupt_loop_body_in_modeled_scope')
                if kind=='DoWhileStatement':
                    if branch.flow in {'normal','continue'}: self.expression(test,branch,flow)
                    else: self.excluded(test,'abrupt_loop_body_in_modeled_scope')
                self.havoc(state,'loop_state_widened')
            self.fact(node,'loop_widening',test_known_false=condition is False,
                      concrete_iterations_performed=0)
        elif kind in {'ReturnStatement','ThrowStatement'}:
            if node.get('argument'): self.expression(node['argument'],state,flow)
            state.flow='return' if kind=='ReturnStatement' else 'throw'
        elif kind in {'FunctionDeclaration','EmptyStatement'}: pass
        elif kind in {'BreakStatement','ContinueStatement'}:
            state.flow='break' if kind=='BreakStatement' else 'continue'
        else:
            self.havoc(state,'unsupported_statement:'+str(kind))
            self.fact(node,'unsupported_statement',top('unsupported_statement:'+str(kind)))

    def run(self):
        try:
            self.prepare(self.tree)
            canonical=self.canonical(self.tree)
            self.value['normalized_ast_sha256']=digest(json.dumps(canonical,sort_keys=True,ensure_ascii=True,separators=(',',':')))
            self.statement(self.tree,State(),'program_path_candidate')
            for node,scope,fid in self.functions:
                state=State({binding.identity:top('outer_binding_entry_unknown') for binding in self.bindings},
                    initialized={binding.identity for binding in self.bindings})
                self.enter(scope,state)
                if any(param.get('type')!='Identifier' for param in node.get('params',[])):
                    self.havoc(state,'parameter_default_or_pattern_unsupported')
                if node['body'].get('type')=='BlockStatement': self.statement(node['body'],state,'uninvoked_function_body_candidate')
                else: self.expression(node['body'],state,'uninvoked_function_body_candidate')
            self.value['complete']=True
        except (SemanticLimit,RecursionError,MemoryError) as error:
            self.reason(str(error) if isinstance(error,SemanticLimit) else 'js_semantic_memory_or_recursion_limit')
            self.value['counters_are_interrupted_lower_bounds']=True
        self.reason('whole_program_runtime_behavior_unverified')
        self.value['budget_usage']=dict(self.budget.used)
        if self.checkpoint: self.checkpoint(self.value)
        return self.value


def analyze_js_tree(tree,source_sha256,*,budget=None,checkpoint=None):
    if not isinstance(tree,dict) or tree.get('type')!='Program' or not isinstance(source_sha256,str) or not re.fullmatch('[a-f0-9]{64}',source_sha256):
        raise ValueError('invalid_js_semantic_input')
    return _Analysis(tree,source_sha256,budget=budget,checkpoint=checkpoint).run()
