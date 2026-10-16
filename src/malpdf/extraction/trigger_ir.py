"""Plan additional placements from exported raw IR; never reparse/decode bytes."""

from dataclasses import dataclass
import hashlib


def _hash(name):return hashlib.sha256(name.encode()).hexdigest()


@dataclass(frozen=True)
class _Ref:
    identity:str
    path:list


_KINDS=('/GoTo','/GoToR','/GoToE','/GoToDp','/Launch','/Thread','/URI','/Sound','/Movie',
    '/Hide','/Named','/SubmitForm','/ResetForm','/ImportData','/SetOCGState','/Rendition',
    '/Trans','/GoTo3DView','/JavaScript','/RichMediaExecute','/NOP','/SetState')


class _Raw:
    def __init__(self,planner):
        self.p=planner;self.references={};self.reference_ids={};self.ambiguous=set();self.keys={};self.arrays={}
        for identity,node in planner.nodes.items():
            planner.tick()
            if node['backend']!='raw_forensic':continue
            details=node['details']
            if node['kind']=='forensic_reference_resolution' and details.get('xref_context_distance')==0:
                source=details['source_id']
                old=self.references.get(source)
                if old and any(old['details'].get(k)!=details.get(k) for k in ('target_id','resolved','target_number','target_generation')):
                    self.ambiguous.add(source)
                self.references.setdefault(source,node)
                self.reference_ids.setdefault(source,[]).append(identity)
        for identity,node in planner.nodes.items():
            planner.tick()
            if node['backend']!='raw_forensic':continue
            if node['kind']=='forensic_syntax_dictionary':
                mapping={}
                for edge in planner.graph[identity]:
                    planner.tick()
                    if edge['kind']!='forensic_dictionary_key':continue
                    key=planner.nodes[edge['target']]
                    digest=key['details'].get('decoded_bytes_sha256')
                    pairs=[]
                    for child in planner.graph[edge['target']]:
                        planner.tick()
                        if child['kind']=='forensic_dictionary_value':pairs.append(child)
                    if digest in mapping or len(pairs)!=1:mapping[digest]=None
                    else:mapping[digest]=(edge,key,pairs[0])
                self.keys[identity]=mapping
            elif node['kind']=='forensic_syntax_array':
                items=[];indices=set();bad=False
                for edge in planner.graph[identity]:
                    planner.tick()
                    if edge['kind']!='forensic_array_item':continue
                    index=edge.get('index')
                    if type(index) is not int or index<0 or index in indices:bad=True
                    else:indices.add(index);items.append(edge)
                if bad:
                    planner.note('trigger_raw_array_index_unverified',[identity]);items=[]
                self.arrays[identity]=sorted(items,key=lambda e:e['index'])

    def ref(self,identity,path):
        seen=set()
        while True:
            self.p.tick();node=self.p.nodes.get(identity)
            if not node or node['backend']!='raw_forensic' or node['observation_status']!='observed':
                self.p.note('trigger_raw_value_unverified',[identity] if node else []);return None
            if node['kind']!='forensic_syntax_reference':return _Ref(identity,path)
            if identity in seen or len(seen)>=16:
                self.p.note('trigger_raw_reference_cycle_or_depth',[identity]);return None
            seen.add(identity);resolution=self.references.get(identity)
            if identity in self.ambiguous or not resolution or resolution['details'].get('resolved') is not True:
                self.p.note('trigger_raw_reference_unresolved',[identity]);return None
            details=resolution['details'];obj=self.p.nodes.get(details['target_id'])
            if (not obj or obj['backend']!='raw_forensic' or obj['kind']!='forensic_object_declaration'
                    or obj['details'].get('xref_membership')!='selected_by_examined_latest_xref'
                    or (obj['object_number'],obj['generation'])!=(node['details'].get('target_number'),node['details'].get('target_generation'))
                    or obj['observation_status']!='observed'):
                self.p.note('trigger_raw_selected_target_unverified',[identity]);return None
            target=obj['details'];root=target['root_node_id']
            roots=[e for e in self.p.graph[obj['evidence_id']] if e['kind']=='forensic_object_value' and e['target']==root]
            if len(roots)!=1:
                self.p.note('trigger_raw_object_root_unverified',[obj['evidence_id']]);return None
            if target['source_space']=='original' and (not target['top_level_confirmed'] or target['byte_end'] is None):
                self.p.note('trigger_raw_object_boundary_unverified',[obj['evidence_id']]);return None
            extra=self.reference_ids[identity]+[obj['evidence_id'],roots[0]['id'],root]
            if target.get('container_id'):extra.insert(1,target['container_id'])
            path=self.p.path(path,*extra)
            if path is None:return None
            identity=root

    def entry(self,ref,key):
        self.p.tick()
        if ref is None:return None
        node=self.p.nodes[ref.identity]
        if node['kind']!='forensic_syntax_dictionary':
            self.p.note('trigger_raw_dictionary_unverified',[ref.identity]);return None
        mapping=self.keys.get(ref.identity,{})
        if _hash(key) not in mapping:return None
        pair=mapping[_hash(key)]
        if pair is None:
            self.p.note('trigger_raw_key_ambiguous',[ref.identity]);return None
        edge,name,value=pair
        if name['observation_status']!='observed':return None
        path=self.p.path(ref.path,edge['id'],name['evidence_id'],value['id'],value['target'])
        return self.ref(value['target'],path) if path is not None else None

    def has(self,ref,key):return _hash(key) in self.keys.get(ref.identity,{})

    def is_name(self,ref,name):
        return ref is not None and self.p.nodes[ref.identity]['kind']=='forensic_syntax_name' and self.p.nodes[ref.identity]['details'].get('decoded_bytes_sha256')==_hash(name)

    def array(self,ref):
        if ref is None:return
        if self.p.nodes[ref.identity]['kind']!='forensic_syntax_array':
            self.p.note('trigger_raw_array_unverified',[ref.identity]);return
        for edge in self.arrays.get(ref.identity,[]):
            self.p.tick();path=self.p.path(ref.path,edge['id'],edge['target'])
            value=self.ref(edge['target'],path) if path is not None else None
            if value is not None:yield value

    def describe(self,identity):
        ref=_Ref(identity,[identity]);kind=self.entry(ref,'/S')
        name=next((name for name in _KINDS if self.is_name(kind,name)),None)
        if name is None:
            self.p.note('trigger_raw_action_kind_unverified',[identity]);return None
        return {'evidence_id':identity,'action_kind':name}

    def following(self,identity):
        value=self.entry(_Ref(identity,[identity]),'/Next')
        if value is None:return
        if self.p.nodes[value.identity]['kind']=='forensic_syntax_array':
            for child in self.array(value):yield child.identity,child.path
        else:yield value.identity,value.path

    def action(self,event,owner,value,route,**details):
        chain,support,cycle,limited=self.p.chain(value.identity,self.describe,self.following)
        if not chain:return
        path=self.p.path(value.path,*support)
        self.p.add(event,owner.identity,value.identity,route,path,chain=chain,cycle=cycle,chain_limited=limited,
            source_view='raw_forensic',placement_scope='latest verified raw xref interpretation; no runtime edge',**details)

    def destination(self,event,owner,value,route,**details):
        kind=self.p.nodes[value.identity]['kind']
        if kind not in {'forensic_syntax_array','forensic_syntax_name','forensic_syntax_string'}:
            self.p.note('trigger_destination_type_unverified',[value.identity]);return
        self.p.add(event,owner.identity,None,route,value.path,source_view='raw_forensic',destination_id=value.identity,
            destination_resolution='unverified',**details)

    def outlines(self,root):
        outline=self.entry(root,'/Outlines')
        if outline is None:return
        first=self.entry(outline,'/First');pending=[(first,outline,'/Outlines/First')] if first else [];seen=set()
        while pending:
            self.p.tick();item,parent,route=pending.pop()
            if item.identity in seen:
                self.p.note('trigger_outline_cycle_or_reuse',[item.identity]);continue
            seen.add(item.identity)
            back=self.entry(item,'/Parent')
            if back is None or back.identity!=parent.identity:
                self.p.note('trigger_outline_parent_unverified',[item.identity]);continue
            proof=list(dict.fromkeys(item.path+back.path))
            if len(proof)>self.p.limits.max_path_ids:
                self.p.note('trigger_path_limit');continue
            item=_Ref(item.identity,proof)
            action=self.entry(item,'/A');dest=self.entry(item,'/Dest')
            if self.has(item,'/A') and self.has(item,'/Dest'):self.p.note('trigger_outline_action_destination_conflict',[item.identity])
            elif action:self.action('activate_bookmark',item,action,route+'/A')
            elif dest:self.destination('activate_bookmark',item,dest,route+'/Dest')
            sibling=self.entry(item,'/Next');child=self.entry(item,'/First')
            if sibling:pending.append((sibling,parent,route+'/Next'))
            if child:pending.append((child,item,route+'/First'))

    def fields(self,root):
        form=self.entry(root,'/AcroForm')
        if form is None:return
        values=self.entry(form,'/Fields');pending=[(item,None) for item in self.array(values)];seen=set()
        while pending:
            self.p.tick();item,inherited=pending.pop()
            if item.identity in seen:
                self.p.note('trigger_field_cycle_or_reuse',[item.identity]);continue
            seen.add(item.identity)
            declared=self.entry(item,'/FT');fieldtype=declared if self.has(item,'/FT') else inherited
            kind=next((name for name in ('/Tx','/Ch','/Btn','/Sig') if self.is_name(fieldtype,name)),None)
            if self.has(item,'/FT') and kind is None:self.p.note('trigger_field_type_unverified',[item.identity])
            kids=self.entry(item,'/Kids')
            if kind in {'/Tx','/Ch','/Btn'} and (self.has(item,'/T') or self.has(item,'/FT')):
                path=self.p.path(item.path,*(fieldtype.path if fieldtype is not None else []))
                proposal={'kind':{'/Tx':'synthetic_text','/Ch':'choose_available_option','/Btn':'button_interaction'}[kind],
                    'value':'malpdf-fixture' if kind=='/Tx' else None,'selector_status':'evidence_id_only',
                    'option_or_widget_state':'unverified'}
                self.p.add('fill_form_field',item.identity,None,'/AcroForm/Fields',path,source_view='raw_forensic',
                    field_type=kind,field_type_status='declared' if declared else 'ancestor_candidate_unverified',
                    input_proposal=proposal,limitations=['field_flags_inheritance_and_runtime_editability_unverified'])
            pending.extend((child,fieldtype) for child in self.array(kids))

    def pages(self,root):
        pages=self.entry(root,'/Pages');pending=[pages] if pages else [];seen=set()
        while pending:
            self.p.tick();page=pending.pop()
            if page.identity in seen:
                self.p.note('trigger_page_cycle_or_reuse',[page.identity]);continue
            seen.add(page.identity);kind=self.entry(page,'/Type')
            if self.is_name(kind,'/Pages'):
                pending.extend(self.array(self.entry(page,'/Kids')));continue
            if not self.is_name(kind,'/Page'):continue
            for annot in self.array(self.entry(page,'/Annots')):
                subtype=self.entry(annot,'/Subtype')
                if not self.is_name(subtype,'/Link'):continue
                dest=self.entry(annot,'/Dest')
                if dest is None:continue
                if self.has(annot,'/A'):
                    self.p.note('trigger_link_action_destination_conflict',[annot.identity]);continue
                self.destination('activate_link',annot,dest,'/Annots/Dest',page_id=page.identity)

    def run(self):
        digest=self.p.bundle['sample_sha256'];summary=self.p.nodes.get('forensic-analysis:'+str(digest))
        if not summary:return
        state=summary['details']
        if summary['backend']!='raw_forensic' or state.get('document_sha256')!=digest or state.get('selection_context_verified') is not True or state.get('xref_chain_complete') is not True:
            self.p.note('trigger_raw_xref_context_unverified',[summary['evidence_id']]);return
        contexts=[n for n in self.p.nodes.values() if n['kind']=='forensic_revision_context' and n['details'].get('xref_chain_distance')==0]
        if len(contexts)!=1:
            self.p.note('trigger_raw_root_context_unverified',[summary['evidence_id']]);return
        context=contexts[0];resolution=self.p.nodes.get(context['evidence_id']+':root-reference')
        if not resolution:
            self.p.note('trigger_raw_root_reference_unverified',[context['evidence_id']]);return
        source=resolution['details']['source_id']
        root=self.ref(source,['original:'+digest,summary['evidence_id'],context['evidence_id'],source])
        if root is None or not self.is_name(self.entry(root,'/Type'),'/Catalog'):return
        value=self.entry(root,'/OpenAction')
        if value and self.p.nodes[value.identity]['kind']=='forensic_syntax_array':self.destination('open_document',root,value,'/OpenAction')
        aa=self.entry(root,'/AA')
        if aa:
            from malpdf.extraction.triggers import _CATALOG_EVENTS
            for key,event in _CATALOG_EVENTS.items():
                value=self.entry(aa,key)
                if value and not any(e['pdf_route']=='/AA'+key for e in self.p.events):self.action(event,root,value,'/AA'+key)
        self.outlines(root);self.fields(root);self.pages(root)


def plan_raw_candidates(planner):
    _Raw(planner).run()
