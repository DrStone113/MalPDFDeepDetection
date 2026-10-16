"""Bounded inert event candidates from existing evidence, without PDF access."""

from collections import Counter,defaultdict,deque
from dataclasses import asdict,dataclass,replace
import hashlib
import json

from malpdf.extraction.contracts import validate_bundle

VERSION='static-events-v2'


@dataclass(frozen=True)
class TriggerLimits:
    max_events:int=128
    max_chain:int=128
    max_nodes:int=32768
    max_edges:int=65536
    max_steps:int=150000
    max_path_ids:int=512
    max_metadata_bytes:int=512*1024

    def __post_init__(self):
        for value,cap in zip(asdict(self).values(),(256,256,65536,131072,200000,1024,1024**2)):
            if type(value) is not int or not 0<value<=cap:raise ValueError('trigger_invalid_limit')
        if self.max_metadata_bytes<4096:raise ValueError('trigger_metadata_requires_reserve')


class _Limit(Exception):pass


_OWNERS={
    'document_catalog':({'document'},{'catalog'}),
    'catalog_pages':({'catalog'},{'pages'}),
    'pages_child':({'pages'},{'page','pages'}),
    'page_annotation':({'page'},{'annotation','field'}),
    'document_acroform':({'catalog'},{'form','pdf_object'}),
    'form_field':({'form','field','pdf_object','annotation'},{'field','pdf_object','annotation'}),
    'acroform_xfa':({'form','pdf_object'},{'stream','array','pdf_object'}),
}
_ACTION_OWNERS={'catalog_action':{'catalog'},'page_action':{'page'},'annotation_action':{'annotation'},
    'field_action':{'field'},'form_action':{'form'}}
_CATALOG_EVENTS={'/WC':'close_document','/DC':'close_document','/WS':'will_save_document',
                 '/DS':'did_save_document','/WP':'will_print_document','/DP':'did_print_document'}
_PAGE_EVENTS={'/O':'open_page','/C':'close_page'}
_ANNOTATION_EVENTS={'/E':'pointer_enter','/X':'pointer_exit','/D':'pointer_down','/U':'pointer_up',
    '/Fo':'focus_annotation','/Bl':'blur_annotation','/PO':'open_annotation_page',
    '/PC':'close_annotation_page','/PV':'show_annotation_page','/PI':'hide_annotation_page'}
_FIELD_EVENTS={'/K':'field_keystroke','/F':'format_field','/V':'validate_field','/C':'calculate_field'}
_XFA_EVENTS=frozenset('initialize calculate validate ready enter exit change click mouseEnter mouseExit mouseDown mouseUp preOpen postOpen prePrint postPrint preSave postSave preSubmit postSubmit docReady docClose indexChange full'.split())


def _event(kind,route):
    if kind=='catalog_action':
        if route=='/OpenAction' or isinstance(route,str) and route.startswith('/Names/JavaScript/Names['):return 'open_document'
        return _CATALOG_EVENTS.get((route or '').removeprefix('/AA'),'pdf_additional_action')
    if kind=='page_action':return _PAGE_EVENTS.get((route or '').removeprefix('/AA'),'page_interaction')
    if kind=='annotation_action':return _ANNOTATION_EVENTS.get((route or '').removeprefix('/AA'),'activate_annotation')
    if kind=='field_action':return _FIELD_EVENTS.get((route or '').removeprefix('/AA'),'field_interaction')
    return 'pdf_additional_action'


class _Planner:
    def __init__(self,bundle,limits):
        self.bundle,self.limits=bundle,limits
        self.nodes={};self.edge_ids=set();self.graph=defaultdict(list);self.steps=0
        self.events=[];self.identities=set();self.reasons=set();self.unresolved=[]
        self.event_limited=False;self.index_complete=False

    def tick(self):
        self.steps+=1
        if self.steps>self.limits.max_steps:raise _Limit('trigger_step_limit')

    def note(self,code,refs=()):
        self.reasons.add(code)
        if refs and len(self.unresolved)<32:
            self.unresolved.append({'reason_code':code,'supporting_ids':list(dict.fromkeys(refs))[:16]})

    def path(self,path,*extra):
        if len(path)+len(extra)>self.limits.max_path_ids:
            self.note('trigger_path_limit');return None
        return path+list(extra)

    def index(self):
        store=self.bundle['evidence_store']
        for node in store['records']:
            self.tick()
            if len(self.nodes)>=self.limits.max_nodes:raise _Limit('trigger_node_index_limit')
            self.nodes[node['evidence_id']]=node
        for edge in store['edges']:
            self.tick()
            if len(self.edge_ids)>=self.limits.max_edges:raise _Limit('trigger_edge_index_limit')
            self.edge_ids.add(edge['id'])
            if edge.get('status')=='verified':
                if not isinstance(edge.get('kind'),str):
                    self.note('trigger_edge_kind_unverified',[edge['id']]);continue
                self.graph[edge['source']].append(edge)
        self.index_complete=True

    def add(self,event,owner,action,route,path,*,chain=(),cycle=False,chain_limited=False,**details):
        self.tick()
        if path is None:return
        support=list(dict.fromkeys(path+[n['evidence_id'] for n in chain]))
        if len(support)>self.limits.max_path_ids:
            self.note('trigger_path_limit');return
        if any(ref not in self.nodes and ref not in self.edge_ids for ref in support):
            raise ValueError('trigger_source_reference_missing')
        signature=[event,owner,action,route,details.get('source_view'),details.get('xfa_event_id'),
            details.get('script_id'),details.get('destination_id')]
        identity='trigger:'+hashlib.sha256(json.dumps(signature,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        if identity in self.identities:return
        if len(self.events)>=self.limits.max_events:
            self.event_limited=True;raise _Limit('trigger_event_limit')
        item={'id':identity,'event':event,'owner_id':owner,'action_id':action,'pdf_route':route,
            'supporting_ids':support,'action_chain':list(chain),'cycle_observed':cycle,'chain_limited':chain_limited,
            'execution_status':'not_run','runtime_feasibility':'unverified',
            'is_synthetic_repaired':any(self.nodes[r]['is_synthetic_repaired'] for r in support if r in self.nodes),**details}
        if len(json.dumps(self.events+[item],allow_nan=False,separators=(',',':')).encode())>self.limits.max_metadata_bytes-4096:
            raise _Limit('trigger_metadata_limit')
        self.events.append(item);self.identities.add(identity)

    def chain(self,first,describe,following):
        result=[];support=[];colors={};cycle=False;limited=False
        def enter(current):
            self.tick()
            item=describe(current)
            if item is None:
                self.note('trigger_action_target_unverified',[current]);return None
            result.append(item);colors[current]=1
            return iter(following(current))
        iterator=enter(first)
        if iterator is None:return result,support,False,False
        stack=[(first,iterator)]
        while stack:
            self.tick();current,iterator=stack[-1]
            try:target,refs=next(iterator)
            except StopIteration:
                colors[current]=2;stack.pop();continue
            support.extend(r for r in refs if r not in support)
            if len(support)>self.limits.max_path_ids:
                self.note('trigger_path_limit');limited=True;break
            if colors.get(target)==1:cycle=True;continue
            if colors.get(target)==2:continue
            if len(result)>=self.limits.max_chain:
                limited=True;self.note('trigger_action_chain_limit');break
            child=enter(target)
            if child is not None:stack.append((target,child))
        return result,support,cycle,limited

    def legacy(self):
        roots=[identifier for identifier,node in self.nodes.items() if node['kind']=='document' and node['backend']=='original'
            and node['details'].get('immutable') is True and self.bundle['sample_sha256'] in
            (node['details'].get('sha256'),node['details'].get('raw_sha256'))]
        pending=deque((r,[r],None) for r in roots);reachable={};xfa_containers=set()
        while pending:
            self.tick();identifier,path,page=pending.popleft()
            if reachable.get(identifier) is not None:continue
            node=self.nodes[identifier]
            if node['kind']=='page':page=identifier
            reachable[identifier]=(path,page)
            for edge in self.graph[identifier]:
                self.tick();types=_OWNERS.get(edge['kind']);target=self.nodes[edge['target']]
                if types and node['kind'] in types[0] and target['kind'] in types[1]:
                    if node['backend']!='original' and target['backend']!=node['backend']:continue
                    child_path=self.path(path,edge['id'],edge['target'])
                    if child_path is not None and edge['target'] not in reachable:
                        if edge['kind']=='acroform_xfa':xfa_containers.add(edge['target'])
                        reachable[edge['target']]=None;pending.append((edge['target'],child_path,page))
        self._legacy_events(reachable,xfa_containers)

    def _legacy_events(self,reachable,xfa_containers):
        pages=set()
        def describe(identifier):
            node=self.nodes[identifier]
            return {'evidence_id':identifier,'action_kind':node['details'].get('action_kind')} if node['kind']=='action' else None
        def following(identifier):
            for edge in self.graph[identifier]:
                self.tick()
                if edge['kind']=='action_Next' and self.nodes[edge['target']]['backend']==self.nodes[identifier]['backend']:
                    yield edge['target'],[edge['id'],edge['target']]
        for owner,entry in reachable.items():
            if entry is None:continue
            path,page=entry;node=self.nodes[owner]
            for edge in self.graph[owner]:
                self.tick();target=self.nodes[edge['target']]
                if node['kind'] in _ACTION_OWNERS.get(edge['kind'],set()) and target['kind']=='action' and target['backend']==node['backend']:
                    route=edge.get('route')
                    if route is not None and (not isinstance(route,str) or len(route)>1024):
                        self.note('trigger_route_unverified',[edge['id']]);continue
                    proof=self.path(path,edge['id'],edge['target'])
                    chain,support,cycle,limited=self.chain(edge['target'],describe,following)
                    if proof is not None:proof=self.path(proof,*support)
                    self.add(_event(edge['kind'],route),owner,edge['target'],route,proof,chain=chain,cycle=cycle,chain_limited=limited,
                        source_view=node['backend'],activation='document_javascript' if isinstance(route,str) and route.startswith('/Names/JavaScript/') else 'pdf_action',page_id=page)
                elif owner in xfa_containers and edge['kind']=='XFA_event' and target['kind']=='xfa_event' and target['backend']==node['backend']:
                    activity=target['details'].get('event_activity')
                    if activity not in _XFA_EVENTS:continue
                    for script_edge in self.graph[edge['target']]:
                        self.tick();script=self.nodes[script_edge['target']]
                        if script_edge['kind']!='event_script' or script['kind']!='script' or script['backend']!=node['backend']:continue
                        proof=self.path(path,edge['id'],edge['target'],script_edge['id'],script_edge['target'])
                        self.add('xfa_event',owner,None,'/AcroForm/XFA/'+activity,proof,source_view=node['backend'],
                            xfa_activity=activity,xfa_event_id=edge['target'],script_id=script_edge['target'],
                            input_proposal={'kind':'synthetic_text','value':'malpdf-fixture','selector_status':'unavailable'},
                            limitations=['xfa_dom_field_selector_unverified','xml_and_runtime_feasibility_unverified'])
                if page is not None and edge['kind'] in {'page_action','page_annotation','annotation_action'} and page not in pages:
                    self.add('visit_page',page,None,'/Pages',path,source_view=node['backend'],page_id=page);pages.add(page)

    def finish(self):
        value={'schema_version':'pdf-trigger-plan-v1','planner_version':VERSION,'sample_sha256':self.bundle['sample_sha256'],
            'events':self.events,'event_limit_reached':self.event_limited,'traversal_complete':not self.reasons and self.index_complete,
            'observation_status':'resource_limit' if any('limit' in c for c in self.reasons) else 'partial',
            'reason_codes':sorted(self.reasons),'unresolved_candidates':self.unresolved,
            'limits':asdict(self.limits),'steps_used':min(self.steps,self.limits.max_steps),
            'family_counts':dict(Counter(e['event'] for e in self.events)),
            'dynamic_execution_status':'not_run','forced_execution':False,
            'limitations':['static_plan_only','runtime_feasibility_unverified','xfa_dom_field_selectors_unverified',
                'named_destinations_and_visibility_unverified','coverage_of_unobserved_or_historical_actions_unknown']}
        while len(json.dumps(value,allow_nan=False,separators=(',',':')).encode())>self.limits.max_metadata_bytes:
            self.reasons.add('trigger_metadata_limit')
            if self.unresolved:self.unresolved.pop()
            elif self.events:self.events.pop()
            else:raise ValueError('trigger_terminal_metadata_limit')
            value.update(reason_codes=sorted(self.reasons),traversal_complete=False,observation_status='resource_limit',
                family_counts=dict(Counter(e['event'] for e in self.events)))
        return value


def plan_triggers(bundle,*,max_events=None,max_chain=None,limits=None):
    """Plan root-document candidates from exported v9 graph and raw IR only."""
    validate_bundle(bundle)
    limits=TriggerLimits() if limits is None else limits
    if type(limits) is not TriggerLimits:raise ValueError('trigger_invalid_limit')
    if max_events is not None:limits=replace(limits,max_events=max_events)
    if max_chain is not None:limits=replace(limits,max_chain=max_chain)
    planner=_Planner(bundle,limits)
    try:
        planner.index();planner.legacy()
        from malpdf.extraction.trigger_ir import plan_raw_candidates
        plan_raw_candidates(planner)
    except _Limit as error:planner.note(str(error))
    return planner.finish()
