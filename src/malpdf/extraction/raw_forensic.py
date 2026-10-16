"""Original-byte PDF declarations, xref chains and static reference evidence.

Production access stays in the disposable PDF worker. This parser never calls
a native PDF parser, opens a path, renders, follows a URI or executes content.
Uncertain stream boundaries stop sequential scanning rather than admitting
payload text as verified object declarations.
"""

from copy import deepcopy
from dataclasses import asdict, dataclass
import json
import re

from malpdf.extraction.filters import DecodeBudget, FilterLimits, decode_filters
from malpdf.extraction.raw_syntax import (Lexer, Node, SyntaxBudget, SyntaxIssue, WS,
    children, dictionary_get, digest, integer, parse_value, projection)
from malpdf.static.profiling import stage


@dataclass(frozen=True)
class ForensicLimits:
    max_objects: int = 2000
    max_tokens: int = 128000
    max_nodes: int = 128000
    max_ir_nodes: int = 8192
    max_xref_entries: int = 16000
    max_revisions: int = 32
    max_structural_streams: int = 64
    max_metadata_bytes: int = 1536 * 1024

    def __post_init__(self):
        ceilings = (10000,200000,200000,16384,65536,64,128,2*1024**2)
        for value,ceiling in zip(asdict(self).values(),ceilings):
            if type(value) is not int or not 0 < value <= ceiling:
                raise ValueError('Invalid forensic resource limit')
        if self.max_metadata_bytes < 2048:
            raise ValueError('Forensic metadata requires terminal reserve')


_VOCABULARY = frozenset(b'/Root /Size /Prev /XRefStm /Type /XRef /ObjStm /W /Index /N /First /Length /Filter /DecodeParms /JS /JavaScript /OpenAction /AA /Launch /URI /EmbeddedFile /EF /XFA /AcroForm /Pages /Kids /Parent /S /A /Next /Names /Encrypt /Extends'.split())


class _Document:
    def __init__(self, data, code_limits, remaining, limits, retain, checkpoint, timings,plugins=None):
        self.data,self.code,self.limits,self.retain,self.checkpoint = data,code_limits,limits,retain,checkpoint
        self.sha = digest(data)
        self.timings=timings
        self.plugins=plugins
        self.syntax = SyntaxBudget(limits.max_tokens,limits.max_nodes,code_limits.max_pdf_depth,code_limits.max_script_bytes)
        self.decode_budget = DecodeBudget(remaining)
        self.filter_limits = FilterLimits(max_input_bytes=code_limits.max_file_bytes,
            max_stage_bytes=min(1024**2,code_limits.max_decoded_bytes),max_total_bytes=code_limits.max_decoded_bytes)
        self.objects,self.xrefs,self.decoded,self.members,self.xref_nodes = {},{},{},{},{}
        self.chain,self.local_entries,self.ir_seen = [],{},set()
        self.failed_offsets=set()
        self.value = {'schema_version':'pdf-raw-forensic-v1','document_sha256':self.sha,'status':'partial','complete':False,
            'objects':[],'syntax_nodes':[],'edges':[],'xref_blocks':[],'revisions':[],'markers':[],
            'partial_declarations':[],'active_declaration':None,
            'structural_streams':[],'active_decode':None,'references':[],'synthetic_nodes':[],
            'current_view':None,'comparisons':[],'comparisons_complete':False,'reason_codes':[],
            'encrypted':False,
            'sequential_scan_complete':False,'xref_chain_complete':False,'selection_context_verified':False,
            'linked_revision_ordinals_verified':False,
            'limits':asdict(limits),'decoded_bytes_available':remaining,'decoded_bytes_remaining':remaining,
            'decoded_bytes_used':0,'syntax_tokens_used':0,'syntax_nodes_used':0,
            'scope':'byte declarations and explicitly checked xref/Prev views; graph is static, never execution flow'}
        self.saved = deepcopy(self.value)

    def identity(self, kind, locator):
        return 'forensic-'+kind+':'+digest((self.sha+'|'+str(locator)).encode())

    def emit(self):
        self.value.update(decoded_bytes_remaining=self.decode_budget.remaining,
            decoded_bytes_used=self.value['decoded_bytes_available']-self.decode_budget.remaining,
            syntax_tokens_used=self.syntax.tokens,syntax_nodes_used=self.syntax.nodes)
        if len(json.dumps(self.value,allow_nan=False,separators=(',',':')).encode()) > self.limits.max_metadata_bytes-1024:
            raise SyntaxIssue('forensic_metadata_limit',0,'resource_limit')
        if self.checkpoint:
            self.checkpoint(deepcopy(self.value))
        self.saved = deepcopy(self.value)

    def problem(self, code):
        self.value['reason_codes'] = sorted(set(self.value['reason_codes'])|{code})

    def retained(self, data):
        state = {'sha256':digest(data),'size_bytes':len(data),'status':'not_retained'} if self.retain is None else self.retain(data)
        if not isinstance(state,dict) or state.get('sha256')!=digest(data) or state.get('size_bytes')!=len(data):
            raise SyntaxIssue('forensic_retention_identity_mismatch',0)
        return state

    def ir(self, node, data, owner, *, space='original', container_id=None):
        identity = self.identity('value',owner+'|'+str(node.start)+':'+str(node.end)+':'+node.kind)
        if identity in self.ir_seen:
            return identity
        if len(self.ir_seen) >= self.limits.max_ir_nodes:
            raise SyntaxIssue('forensic_ir_node_limit',node.start,'resource_limit')
        self.ir_seen.add(identity)
        item = {'id':identity,'kind':node.kind,'source_space':space,'container_id':container_id,
            'start':node.start,'end':node.end,'raw_sha256':digest(data[node.start:node.end]),
            'status':'partial' if node.issues else 'observed','reason_codes':list(node.issues),'is_synthetic':False}
        if node.kind in {'name','string'}:
            item.update(decoded_bytes_sha256=digest(node.value),decoded_size_bytes=len(node.value))
        if node.kind == 'name':
            item['known_name'] = node.value.decode() if node.value in _VOCABULARY else None
        if node.kind == 'reference':
            item.update(target_number=node.value[0],target_generation=node.value[1])
        self.value['syntax_nodes'].append(item)
        if node.kind == 'dictionary':
            for index,(key,child) in enumerate(node.value):
                key_id = self.ir(key,data,owner,space=space,container_id=container_id)
                value_id = self.ir(child,data,owner,space=space,container_id=container_id)
                self.value['edges'].extend([
                    {'id':identity+':key:'+str(index),'source':identity,'target':key_id,'kind':'forensic_dictionary_key','index':index},
                    {'id':key_id+':value','source':key_id,'target':value_id,'kind':'forensic_dictionary_value','index':index}])
        elif node.kind == 'array':
            for index,child in enumerate(node.value):
                child_id = self.ir(child,data,owner,space=space,container_id=container_id)
                self.value['edges'].append({'id':identity+':item:'+str(index),'source':identity,'target':child_id,'kind':'forensic_array_item','index':index})
        return identity

    def effective(self, number, revision=0):
        for block in self.chain[revision:]:
            entry = self.local_entries.get(block['offset'],{}).get(number)
            if entry is not None:
                return None if entry.get('ambiguous') else entry
        return None

    def scalar_length(self, reference, object_offset, number, generation):
        if not self.value['xref_chain_complete']:
            return None,[]
        lengths,sources = set(),[]
        for revision in range(len(self.chain)):
            selected = self.effective(number,revision)
            if not selected or selected['type']!=1 or selected['offset']!=object_offset or selected['generation']!=generation:
                continue
            entry = self.effective(reference[0],revision)
            if not entry or entry['type']!=1 or entry['generation']!=reference[1]:
                return None,[]
            lex = Lexer(self.data,self.syntax,entry['offset'])
            try:
                a,b,c = lex.pop(),lex.pop(),lex.pop()
                if (a.kind,a.value,b.kind,b.value,c.kind,c.value)!=('number',reference[0],'number',reference[1],'keyword',b'obj'):
                    return None,[]
                value = parse_value(lex)
                lex.expect('keyword',b'endobj')
                length = integer(value)
                if length is None or length<0:
                    return None,[]
                lengths.add(length)
                sources.append({'xref_context_distance':revision,'object_offset':entry['offset']})
            except SyntaxIssue as error:
                if error.status=='resource_limit':
                    raise
                return None,[]
        return (next(iter(lengths)),sources) if len(lengths)==1 else (None,[])

    def preserve_active(self, error):
        active=self.value.get('active_declaration')
        if active is None:
            return
        active.update(status='partial',reason_codes=[error.code])
        self.value['partial_declarations'].append(active)
        if active['source_space']=='original':
            self.failed_offsets.add(active['byte_start'])
        self.value['active_declaration']=None
        self.emit()

    def object_at(self, offset, *, top_level=False, allow_indirect_length=True):
        if offset in self.objects:
            item = self.objects[offset]
            if top_level:
                item['record']['top_level_confirmed'] = True
            return item
        if offset in self.failed_offsets:
            raise SyntaxIssue('forensic_previous_parse_unavailable',offset)
        if len(self.value['objects'])+len(self.value['partial_declarations']) >= self.limits.max_objects:
            raise SyntaxIssue('forensic_object_limit',offset,'resource_limit')
        lex = Lexer(self.data,self.syntax,offset)
        a,b,c = lex.pop(),lex.pop(),lex.pop()
        if a.start!=offset or a.kind!='number' or type(a.value) is not int or a.value<=0 or b.kind!='number' or type(b.value) is not int or not 0<=b.value<=65535 or c.kind!='keyword' or c.value!=b'obj':
            raise SyntaxIssue('forensic_object_header_invalid',offset)
        identity = self.identity('object',offset)
        active={'id':identity,'object_number':a.value,'generation':b.value,'byte_start':offset,'byte_end':None,
            'header_end':c.end,'root_node_id':None,'source_space':'original','container_id':None,
            'top_level_confirmed':top_level,'status':'partial','reason_codes':['forensic_value_not_finished']}
        self.value['active_declaration']=active
        self.emit()
        root = parse_value(lex)
        active['root_node_id']=self.ir(root,self.data,identity)
        active['value_end']=root.end
        self.emit()
        raw,stream,issues = None,None,[]
        if lex.peek().kind=='keyword' and lex.peek().value==b'stream':
            keyword = lex.pop()
            if root.kind!='dictionary':
                raise SyntaxIssue('forensic_stream_without_dictionary',keyword.start)
            begin = keyword.end
            if self.data[begin:begin+2]==b'\r\n':
                begin += 2
            elif self.data[begin:begin+1]==b'\n':
                begin += 1
            else:
                raise SyntaxIssue('forensic_stream_eol_invalid',begin)
            declared = dictionary_get(root,b'/Length')
            length = integer(declared)
            sources = []
            mode = 'direct' if length is not None else 'unavailable'
            if declared is not None and declared.kind=='reference' and allow_indirect_length:
                length,sources = self.scalar_length(declared.value,offset,a.value,b.value)
                mode = 'resolved_across_examined_revisions' if length is not None else 'unresolved_reference'
            stream = {'data_start':begin,'data_end':None,'length_mode':mode,'declared_length':length,
                'length_sources':sources,'declared_endpoint_matches':None,'boundary_verified':False,
                'raw_sha256':None,'raw_retention':None}
            if length is None or length<0:
                issues.append('forensic_stream_length_unavailable')
            elif length > self.code.max_file_bytes or begin+length>len(self.data):
                issues.append('forensic_stream_length_out_of_bounds')
            else:
                end = begin+length
                marker = end
                if self.data[marker:marker+2]==b'\r\n':
                    marker += 2
                elif self.data[marker:marker+1] in (b'\n',b'\r'):
                    marker += 1
                check = Lexer(self.data,self.syntax,marker)
                token = check.pop()
                stream['declared_endpoint_matches'] = token.kind=='keyword' and token.value==b'endstream' and token.start==marker
                if stream['declared_endpoint_matches']:
                    raw = self.data[begin:end]
                    stream.update(data_end=end,boundary_verified=True,raw_sha256=digest(raw),raw_retention=self.retained(raw))
                    lex.seek(token.end)
                else:
                    issues.append('forensic_stream_endpoint_mismatch')
        end_token = None
        terminal_error = None
        if not stream or stream['boundary_verified']:
            try:
                end_token = lex.expect('keyword',b'endobj')
            except SyntaxIssue as error:
                terminal_error=error if error.status=='resource_limit' else None
                issues.append(error.code if terminal_error else 'forensic_endobj_unavailable')
        record = {'id':identity,'object_number':a.value,'generation':b.value,'byte_start':offset,
            'byte_end':end_token.end if end_token else None,'top_level_confirmed':top_level,'root_node_id':None,
            'source_space':'original','container_id':None,'stream':stream,'status':'partial' if issues else 'observed',
            'reason_codes':issues,'projection':projection(root,stream_sha256=stream['raw_sha256'] if stream else None,
                is_stream=bool(stream),code_limits=self.code,encrypted=self.value['encrypted']),'xref_membership':'unknown'}
        def issues_in(node):
            return set(node.issues)|set().union(*(issues_in(child) for child in children(node)))
        issues[:]=sorted(set(issues)|issues_in(root)|({'forensic_projection_incomplete'} if not record['projection']['projection_complete'] else set()))
        record['status']='partial' if issues else 'observed'
        internal = {'record':record,'node':root,'raw':raw,'number':a.value,'generation':b.value,'offset':offset}
        self.objects[offset] = internal
        self.value['objects'].append(record)
        record['root_node_id'] = active['root_node_id']
        self.value['active_declaration']=None
        self.value['edges'].append({'id':identity+':root','source':identity,'target':record['root_node_id'],'kind':'forensic_object_value'})
        for issue in issues:
            self.problem(issue)
        self.emit()
        if terminal_error:
            raise terminal_error
        return internal

    def structural_decode(self, item):
        offset = item['offset']
        if offset in self.decoded:
            return self.decoded[offset]
        if len(self.value['structural_streams']) >= self.limits.max_structural_streams:
            raise SyntaxIssue('forensic_structural_stream_limit',offset,'resource_limit')
        if item['raw'] is None:
            return None
        root = item['node']
        kind = dictionary_get(root,b'/Type')
        if self.value['encrypted'] and (kind is None or kind.kind!='name' or kind.value!=b'/XRef'):
            self.problem('forensic_encrypted_object_stream')
            self.decoded[offset]=None
            self.value['structural_streams'].append({'id':item['record']['id']+':structural-decode',
                'source_id':item['record']['id'],'status':'encrypted','decode':None,'reason_codes':['forensic_encrypted_object_stream']})
            self.emit()
            return None
        filters = dictionary_get(root,b'/Filter')
        if filters is None:
            names = []
        else:
            values = filters.value if filters.kind=='array' else [filters]
            if any(value.kind!='name' or value.issues for value in values):
                raise SyntaxIssue('forensic_filter_metadata_unavailable',offset)
            try:
                names = [value.value.decode('ascii') for value in values]
            except UnicodeError:
                raise SyntaxIssue('forensic_filter_metadata_unavailable',offset) from None
        parms = dictionary_get(root,b'/DecodeParms')
        def parameters(value):
            if value.kind=='null':
                return None
            if value.kind!='dictionary' or value.issues:
                raise SyntaxIssue('forensic_filter_parameters_unavailable',offset)
            output = {}
            extra={key.encode() for spec in self.plugins.select('decoder') for key in spec.parameter_keys} if self.plugins is not None else set()
            for key,child in value.value:
                if key.issues or key.value not in {b'/Predictor',b'/Columns',b'/Colors',b'/BitsPerComponent',b'/EarlyChange',b'/Name',b'/Type'}|extra:
                    raise SyntaxIssue('forensic_filter_parameters_unsupported',offset,'unsupported')
                if integer(child) is not None:
                    output[key.value.decode()] = child.value
                elif child.kind=='name' and not child.issues:
                    output[key.value.decode()] = child.value.decode('ascii')
                else:
                    raise SyntaxIssue('forensic_filter_parameters_unavailable',offset)
            return output
        params = None if parms is None or parms.kind=='null' else [parameters(value) for value in parms.value] if parms.kind=='array' else parameters(parms)
        def decoded_checkpoint(metadata):
            self.value['active_decode'] = {'source_id':item['record']['id'],'decode':metadata}
            self.emit()
        with stage(self.timings,'stream_decode'):
            result = decode_filters(item['raw'],names,decode_parms=params,limits=self.filter_limits,budget=self.decode_budget,
                retain=self.retain,checkpoint=decoded_checkpoint,plugins=self.plugins)
        self.value['structural_streams'].append({'id':item['record']['id']+':structural-decode','source_id':item['record']['id'],
            'status':result.metadata['status'],'decode':result.metadata})
        self.value['active_decode'] = None
        self.decoded[offset] = result.data
        if not result.metadata['complete']:
            for reason in result.metadata['reason_codes']:
                self.problem(reason)
        self.emit()
        return result.data

    def _xref_entry(self, block, number, kind, first, second):
        if sum(len(value['entries']) for value in self.value['xref_blocks']) >= self.limits.max_xref_entries:
            raise SyntaxIssue('forensic_xref_entry_limit',block['offset'],'resource_limit')
        item = {'id':block['id']+':entry:'+str(len(block['entries'])),'object_number':number,'type':kind,
                'generation':second if kind in (0,1) else 0,'offset':first if kind==1 else None,
                'free_next':first if kind==0 else None,'object_stream_number':first if kind==2 else None,
                'object_stream_index':second if kind==2 else None,'reason_codes':[]}
        if number<0 or kind not in (0,1,2) or kind in (0,1) and not 0<=second<=65535 or kind==0 and first<0 or kind==1 and not 0<=first<len(self.data) or kind==2 and (first<=0 or second<0):
            item['reason_codes'].append('forensic_xref_entry_invalid')
            block['reason_codes'].append('forensic_xref_entry_invalid')
        mapping = self.local_entries.setdefault(block['offset'],{})
        if number in mapping:
            mapping[number] = {'ambiguous':True}
            block['reason_codes'].append('forensic_xref_duplicate_number')
        else:
            mapping[number] = item if not item['reason_codes'] else {'ambiguous':True}
        block['entries'].append(item)

    def xref_at(self, offset):
        if offset in self.xrefs:
            return self.xrefs[offset]
        if not 0<=offset<len(self.data) or len(self.xrefs)>=self.limits.max_revisions*2:
            raise SyntaxIssue('forensic_xref_offset_or_count_limit',max(0,offset),'resource_limit')
        block = {'id':self.identity('xref',offset),'offset':offset,'end':None,'kind':None,'source_object_id':None,
            'entries':[],'trailer_node_id':None,'prev':None,'supplement':None,'top_level_confirmed':False,
            'status':'partial','reason_codes':[]}
        self.xrefs[offset] = block
        self.value['xref_blocks'].append(block)
        lex = Lexer(self.data,self.syntax,offset)
        if lex.peek().kind=='keyword' and lex.peek().value==b'xref' and lex.peek().start==offset:
            lex.pop();block['kind']='table'
            while not (lex.peek().kind=='keyword' and lex.peek().value==b'trailer'):
                first,count = lex.expect('number'),lex.expect('number')
                if type(first.value) is not int or type(count.value) is not int or first.value<0 or count.value<0:
                    raise SyntaxIssue('forensic_xref_subsection_invalid',first.start)
                if count.value > self.limits.max_xref_entries:
                    raise SyntaxIssue('forensic_xref_entry_limit',first.start,'resource_limit')
                for index in range(count.value):
                    a,b,c = lex.expect('number'),lex.expect('number'),lex.expect('keyword')
                    if type(a.value) is not int or type(b.value) is not int or c.value not in (b'n',b'f'):
                        raise SyntaxIssue('forensic_xref_entry_syntax_invalid',a.start)
                    self._xref_entry(block,first.value+index,1 if c.value==b'n' else 0,a.value,b.value)
            lex.pop()
            root = parse_value(lex)
            if root.kind!='dictionary':
                raise SyntaxIssue('forensic_trailer_not_dictionary',root.start)
            block['end']=root.end
            block['trailer_node_id']=self.ir(root,self.data,block['id'])
        else:
            item = self.object_at(offset,allow_indirect_length=False)
            root = item['node']
            kind = dictionary_get(root,b'/Type')
            if kind is None or kind.kind!='name' or kind.value!=b'/XRef':
                raise SyntaxIssue('forensic_xref_target_not_xref',offset)
            block.update(kind='stream',source_object_id=item['record']['id'],end=item['record']['byte_end'],trailer_node_id=item['record']['root_node_id'])
            data = self.structural_decode(item)
            if data is None:
                raise SyntaxIssue('forensic_xref_stream_unavailable',offset)
            width,index,size = dictionary_get(root,b'/W'),dictionary_get(root,b'/Index'),integer(dictionary_get(root,b'/Size'))
            if width is None or width.kind!='array' or len(width.value)!=3 or any(integer(value) is None or not 0<=value.value<=8 for value in width.value):
                raise SyntaxIssue('forensic_xref_width_invalid',offset)
            widths=[value.value for value in width.value]
            if not sum(widths):
                raise SyntaxIssue('forensic_xref_width_invalid',offset)
            if size is None or size<1:
                raise SyntaxIssue('forensic_xref_size_invalid',offset)
            indexes = [0,size] if index is None else [integer(value) for value in index.value] if index.kind=='array' else []
            if not indexes or len(indexes)%2 or any(value is None or value<0 for value in indexes):
                raise SyntaxIssue('forensic_xref_index_invalid',offset)
            count=sum(indexes[1::2])
            if count>self.limits.max_xref_entries or count*sum(widths)!=len(data):
                raise SyntaxIssue('forensic_xref_stream_size_mismatch',offset)
            cursor=0
            for first,count in zip(indexes[::2],indexes[1::2]):
                for number in range(first,first+count):
                    fields=[]
                    for column,length in enumerate(widths):
                        fields.append(int.from_bytes(data[cursor:cursor+length],'big') if length else 1 if column==0 else 0)
                        cursor+=length
                    self._xref_entry(block,number,*fields)
        self.xref_nodes[offset] = root
        if dictionary_get(root,b'/Encrypt') is not None:
            self.value['encrypted']=True
            self.problem('forensic_encrypted_pdf')
        for key,field in ((b'/Prev','prev'),(b'/XRefStm','supplement')):
            value=dictionary_get(root,key)
            if value is not None:
                amount=integer(value)
                if amount is None or not 0<=amount<len(self.data):
                    block['reason_codes'].append('forensic_xref_link_invalid')
                else:
                    block[field]=amount
        size=integer(dictionary_get(root,b'/Size'))
        if size is None or size<1 or any(entry['object_number']>=size for entry in block['entries']):
            block['reason_codes'].append('forensic_xref_size_invalid')
        if root.issues:
            block['reason_codes'].extend(root.issues)
        block['reason_codes']=sorted(set(block['reason_codes']))
        block['status']='observed' if not block['reason_codes'] else 'partial'
        self.emit()
        return block

    def discover_chain(self):
        # This tail anchor is a candidate until the sequential lexer confirms
        # both markers outside strings/comments/opaque stream data.
        tail_start=max(0,len(self.data)-65536)
        matches=list(re.finditer(rb'startxref[\x00\t\n\f\r ]+(\d{1,12})[\x00\t\n\f\r ]+%%EOF[\x00\t\n\f\r ]*\Z',self.data[tail_start:]))
        if not matches:
            self.problem('forensic_terminal_startxref_unavailable')
            return
        marker=matches[-1]
        self.terminal_marker=(tail_start+marker.start(),int(marker[1]))
        offset=self.terminal_marker[1]
        seen=set()
        while offset is not None:
            if offset in seen:
                self.problem('forensic_prev_cycle');return
            if len(self.chain)>=self.limits.max_revisions:
                self.problem('forensic_revision_limit');return
            seen.add(offset)
            block=self.xref_at(offset)
            self.chain.append(block)
            self.value['revisions'].append({'id':self.identity('revision',offset),'xref_chain_distance':len(self.chain)-1,
                'revision_ordinal':None,'xref_id':block['id'],'xref_offset':offset,'supplement_id':None,'root_reference':None})
            root=dictionary_get(self.xref_nodes.get(block['offset']),b'/Root')
            if root is not None and root.kind=='reference':
                self.value['revisions'][-1]['root_reference']=list(root.value)
            if block['supplement'] is not None:
                supplement=self.xref_at(block['supplement'])
                if supplement['kind']!='stream' or supplement['offset'] in seen:
                    self.problem('forensic_hybrid_supplement_invalid');return
                seen.add(supplement['offset'])
                self.value['revisions'][-1]['supplement_id']=supplement['id']
                original=self.local_entries.get(block['offset'],{})
                original.update(self.local_entries.get(supplement['offset'],{}))
                if supplement['prev'] is not None:
                    self.problem('forensic_hybrid_supplement_prev_ignored')
            self.emit()
            offset=block['prev']
        self.value['xref_chain_complete']=all(self.xrefs[value]['status']=='observed' for value in seen)

    def sequential(self):
        lex=Lexer(self.data,self.syntax)
        while lex.pos<len(self.data):
            lex.skip(eof_callback=lambda start,end:self.value['markers'].append({'kind':'eof','offset':start,'end':end}))
            if lex.pos==len(self.data):
                break
            first=lex.peek()
            if first.kind=='number' and type(first.value) is int:
                item=self.object_at(first.start,top_level=True)
                if item['record']['byte_end'] is None:
                    self.problem('forensic_scan_stopped_at_uncertain_stream' if item['record']['stream'] else 'forensic_scan_stopped_at_unclosed_declaration');return
                lex.seek(item['record']['byte_end'])
                if first.start in self.xrefs:
                    self.xrefs[first.start]['top_level_confirmed']=True
            elif first.kind=='keyword' and first.value==b'xref':
                block=self.xref_at(first.start)
                block['top_level_confirmed']=True
                lex.seek(block['end'])
            elif first.kind=='keyword' and first.value==b'startxref':
                lex.pop();value=lex.expect('number')
                if type(value.value) is not int or value.value<0:
                    raise SyntaxIssue('forensic_startxref_invalid',first.start)
                self.value['markers'].append({'kind':'startxref','offset':first.start,'end':value.end,'xref_offset':value.value})
                lex.seek(value.end)
            else:
                raise SyntaxIssue('forensic_unrecognized_top_level_syntax',first.start)
            self.emit()
        self.value['sequential_scan_complete']=True
        terminal=getattr(self,'terminal_marker',None)
        used={revision['xref_id'] for revision in self.value['revisions']}|{revision['supplement_id'] for revision in self.value['revisions'] if revision['supplement_id']}
        self.value['selection_context_verified']=bool(terminal and self.value['xref_chain_complete'] and all(block['top_level_confirmed'] for block in self.value['xref_blocks'] if block['id'] in used)
            and any(marker['kind']=='startxref' and marker['offset']==terminal[0] and marker['xref_offset']==terminal[1] for marker in self.value['markers']))

    def prove_chronology(self):
        footers=[]
        for context in self.value['revisions']:
            matching=[(marker['offset'],eof['end']) for marker in self.value['markers'] if marker['kind']=='startxref' and marker['xref_offset']==context['xref_offset']
                for eof in self.value['markers'] if eof['kind']=='eof' and eof['offset']>=marker['end'] and all(value in WS for value in self.data[marker['end']:eof['offset']])]
            footers.append(matching[0] if len(matching)==1 else None)
        chronology=bool(self.value['selection_context_verified'] and footers and all(value is not None for value in footers)
            and all(footers[index][0]>footers[index+1][0] for index in range(len(footers)-1)))
        numbers=set().union(*(mapping.keys() for mapping in self.local_entries.values())) if self.local_entries else set()
        if chronology:
            for revision,footer in enumerate(footers):
                if any(block['end'] is None or block['end']>footer[1] for block in self.chain[revision:]):
                    chronology=False;break
                supplements={context['supplement_id'] for context in self.value['revisions'][revision:] if context['supplement_id']}
                if any(block['id'] in supplements and (block['end'] is None or block['end']>footer[1]) for block in self.value['xref_blocks']):
                    chronology=False;break
                for number in numbers:
                    entry=self.effective(number,revision)
                    if entry is None or entry['type']==0:
                        continue
                    item=self.selected_object(number,entry['generation'],revision)
                    if item is None:
                        chronology=False;break
                    record=item['record']
                    physical=self.objects[record['container_offset']]['record'] if record['source_space']=='decoded_stream' else record
                    if not physical['top_level_confirmed'] or physical['byte_end'] is None or physical['byte_end']>footer[1]:
                        chronology=False;break
                if not chronology:
                    break
        self.value['linked_revision_ordinals_verified']=chronology
        if chronology:
            for index,context in enumerate(self.value['revisions']):
                context.update(revision_ordinal=len(footers)-1-index,footer_startxref_offset=footers[index][0],prefix_eof_end=footers[index][1])

    def object_stream(self, item):
        if item['offset'] in self.members:
            return
        decoded=self.structural_decode(item)
        if decoded is None:
            return
        first,count=integer(dictionary_get(item['node'],b'/First')),integer(dictionary_get(item['node'],b'/N'))
        if first is None or count is None or not 0<=first<=len(decoded) or count<0:
            raise SyntaxIssue('forensic_object_stream_parameters_invalid',item['offset'])
        if count>self.limits.max_objects-len(self.value['objects'])-len(self.value['partial_declarations']):
            raise SyntaxIssue('forensic_object_limit',item['offset'],'resource_limit')
        header=Lexer(decoded,self.syntax,0,first)
        pairs=[]
        for _ in range(count):
            number,offset=header.expect('number'),header.expect('number')
            if type(number.value) is not int or number.value<=0 or type(offset.value) is not int or offset.value<0:
                raise SyntaxIssue('forensic_object_stream_header_invalid',item['offset'])
            pairs.append((number.value,offset.value))
        if header.pop().kind!='eof' or count==0 and first!=len(decoded) or any(first+offset>=len(decoded) for number,offset in pairs) or any(pairs[i][1]>=pairs[i+1][1] for i in range(len(pairs)-1)):
            raise SyntaxIssue('forensic_object_stream_offsets_invalid',item['offset'])
        self.members[item['offset']]=[]
        if len({number for number,offset in pairs})!=len(pairs):
            self.problem('forensic_object_stream_duplicate_number')
        for index,(number,offset) in enumerate(pairs):
            start=first+offset
            end=first+pairs[index+1][1] if index+1<len(pairs) else len(decoded)
            lex=Lexer(decoded,self.syntax,start,end)
            identity=self.identity('compressed-object',str(item['offset'])+':'+str(index))
            self.value['active_declaration']={'id':identity,'object_number':number,'generation':0,'byte_start':None,'byte_end':None,
                'decoded_start':start,'decoded_end':end,'source_space':'decoded_stream','container_id':item['record']['id'],
                'root_node_id':None,'status':'partial','reason_codes':['forensic_compressed_value_not_finished']}
            self.emit()
            root=parse_value(lex)
            if lex.pop().kind!='eof':
                raise SyntaxIssue('forensic_compressed_object_trailing_data',item['offset'])
            root_id=self.ir(root,decoded,identity,space='decoded_stream',container_id=item['record']['id'])
            record={'id':identity,'object_number':number,'generation':0,'byte_start':None,'byte_end':None,
                'decoded_start':start,'decoded_end':end,'decoded_stream_sha256':digest(decoded),
                'top_level_confirmed':False,'root_node_id':root_id,'source_space':'decoded_stream','container_id':item['record']['id'],
                'container_offset':item['offset'],'member_index':index,'stream':None,'status':'partial' if root.issues else 'observed',
                'container_number':item['number'],
                'reason_codes':list(root.issues),'projection':projection(root,code_limits=self.code,encrypted=self.value['encrypted']),'xref_membership':'unknown'}
            member={'record':record,'node':root,'number':number,'generation':0,'offset':None}
            self.members[item['offset']].append(member)
            self.value['objects'].append(record)
            self.value['active_declaration']=None
            self.value['edges'].extend([{'id':identity+':root','source':identity,'target':root_id,'kind':'forensic_object_value'},
                {'id':identity+':container','source':item['record']['id'],'target':identity,'kind':'forensic_compressed_member'}])
            self.emit()

    def selected_object(self, number, generation, revision=0):
        entry=self.effective(number,revision)
        if entry is None or entry.get('generation')!=generation:
            return None
        if entry['type']==1:
            try:
                item=self.object_at(entry['offset'])
            except SyntaxIssue as error:
                self.preserve_active(error)
                if error.status=='resource_limit':
                    raise
                return None
            return item if (item['number'],item['generation'])==(number,generation) else None
        if entry['type']==2 and generation==0:
            container_entry=self.effective(entry['object_stream_number'],revision)
            if container_entry is None or container_entry['type']!=1:
                return None
            try:
                container=self.object_at(container_entry['offset'])
                if container['number']!=entry['object_stream_number'] or container['generation']!=container_entry['generation']:
                    return None
                kind=dictionary_get(container['node'],b'/Type')
                if kind is None or kind.kind!='name' or kind.value!=b'/ObjStm':
                    return None
                self.object_stream(container)
                members=self.members.get(container_entry['offset'],[])
                index=entry['object_stream_index']
                return members[index] if 0<=index<len(members) and members[index]['number']==number else None
            except SyntaxIssue as error:
                self.preserve_active(error)
                if error.status=='resource_limit':
                    raise
                return None
        return None

    def finish_views(self, native):
        from malpdf.extraction.parser_views import merge_views
        selected,selected_ids=[],set()
        numbers=set().union(*(mapping.keys() for mapping in self.local_entries.values())) if self.local_entries else set()
        for number in sorted(numbers):
            entry=self.effective(number)
            if not entry or entry['type']==0:
                continue
            item=self.selected_object(number,entry['generation'])
            if item is None:
                self.problem('forensic_selected_object_unavailable');continue
            record=item['record'];selected_ids.add(record['id'])
            if record['source_space']=='original' and not record['top_level_confirmed']:
                record['status']='partial'
                record['reason_codes']=sorted(set(record['reason_codes'])|{'forensic_xref_target_not_top_level_confirmed'})
                self.problem('forensic_xref_target_not_top_level_confirmed')
                for container in self.objects.values():
                    stream=container['record'].get('stream')
                    if stream and stream['boundary_verified'] and stream['data_start']<=record['byte_start']<stream['data_end']:
                        record['inside_stream_id']=container['record']['id']
                        break
            selected.append({'id':record['id'],'object_number':record['object_number'],'generation':record['generation'],
                'projection':record['projection'],'status':record['status']})
        for record in self.value['objects']:
            if record['id'] in selected_ids:
                record['xref_membership']='selected_by_examined_latest_xref'
            elif self.value['xref_chain_complete'] and self.value['sequential_scan_complete']:
                if record['source_space']=='original':
                    listed=any(entry['type']==1 and entry['offset']==record['byte_start'] and entry['generation']==record['generation'] and entry['object_number']==record['object_number'] for block in self.value['xref_blocks'] for entry in block['entries'])
                    record['xref_membership']='listed_in_examined_history' if listed else 'unlisted_in_examined_xrefs'
                else:
                    listed=any(entry['type']==2 and entry['object_number']==record['object_number'] and entry['object_stream_number']==record['container_number'] and entry['object_stream_index']==record['member_index'] for block in self.value['xref_blocks'] for entry in block['entries'])
                    known=any((item:=self.selected_object(record['object_number'],0,revision)) is not None and item['record']['id']==record['id'] for revision in range(len(self.chain)))
                    record['xref_membership']='listed_in_examined_history' if known else 'unknown' if listed else 'unlisted_in_examined_xrefs'
        complete=bool(self.value['selection_context_verified'] and not self.value['reason_codes'] and all(record['status']=='observed' and record['projection']['projection_complete'] for record in self.value['objects']))
        view={'backend':'raw_forensic','records':selected,'complete':complete,'status':'observed' if complete else 'partial',
              'scope':'checked latest xref/Prev interpretation; byte occurrences stay separate'}
        self.value['current_view']={key:value for key,value in view.items() if key!='records'}
        self.value['current_view']['selected_ids']=[record['id'] for record in selected]
        comparisons,comparison_complete=merge_views([view]+(native or {}).get('views',[]))
        for comparison in comparisons:
            if comparison['left_backend']!='raw_forensic':
                continue
            comparison['id']+=':'+self.sha
            self.value['comparisons'].append(comparison)
            self.emit()
        self.value['comparisons_complete']=comparison_complete
        if not comparison_complete:
            self.problem('forensic_comparison_limit')

    def reference_graph(self):
        # Resolve each occurrence against every examined revision that actually
        # selects it. Missing targets get separate synthetic evidence nodes.
        all_items=list(self.objects.values())+[member for group in self.members.values() for member in group]
        for item in all_items:
            record=item['record']
            refs=[]
            def walk(node):
                if node.kind=='reference':
                    refs.append(node)
                for child in children(node):
                    walk(child)
            walk(item['node'])
            for revision in range(len(self.chain)):
                selected=self.selected_object(item['number'],item['generation'],revision)
                if selected is None or selected['record']['id']!=record['id']:
                    continue
                for ref in refs:
                    if len(self.value['references'])>=self.limits.max_xref_entries:
                        raise SyntaxIssue('forensic_reference_limit',0,'resource_limit')
                    source_id=self.identity('value',record['id']+'|'+str(ref.start)+':'+str(ref.end)+':reference')
                    target=self.selected_object(*ref.value,revision)
                    target_id=target['record']['id'] if target else self.identity('synthetic-reference',source_id+'|'+str(revision))
                    identity=self.identity('reference',source_id+'|'+str(revision))
                    if target is None:
                        self.value['synthetic_nodes'].append({'id':target_id,'is_synthetic':True,'kind':'unresolved_reference',
                            'target_number':ref.value[0],'target_generation':ref.value[1],'xref_context_distance':revision,
                            'status':'partial','reason_codes':['not_resolved_in_examined_revision'],'original_reference_preserved':True})
                    self.value['references'].append({'id':identity,'source_id':source_id,'target_id':target_id,
                        'xref_context_distance':revision,'target_number':ref.value[0],'target_generation':ref.value[1],
                        'resolved':target is not None,'scope':'static reference under examined xref interpretation; no execution edge'})
                self.emit()
        for revision,context in enumerate(self.value['revisions']):
            # Trailer keys may be inherited in an incremental update. Preserve
            # which older dictionary supplied Root; do not rewrite the trailer.
            for source_revision in range(revision,len(self.chain)):
                block=self.chain[source_revision]
                root=dictionary_get(self.xref_nodes.get(block['offset']),b'/Root')
                if root is None:
                    continue
                context['root_source_xref_context_distance']=source_revision
                if root.kind=='reference':
                    context['root_reference']=list(root.value)
                    owner=block['source_object_id'] or block['id']
                    source_id=self.identity('value',owner+'|'+str(root.start)+':'+str(root.end)+':reference')
                    target=self.selected_object(*root.value,revision)
                    target_id=target['record']['id'] if target else self.identity('synthetic-root',context['id'])
                    if target is None:
                        self.value['synthetic_nodes'].append({'id':target_id,'is_synthetic':True,'kind':'unresolved_reference',
                            'target_number':root.value[0],'target_generation':root.value[1],'xref_context_distance':revision,
                            'status':'partial','reason_codes':['root_not_resolved_in_examined_revision'],'original_reference_preserved':True})
                    if len(self.value['references'])>=self.limits.max_xref_entries:
                        raise SyntaxIssue('forensic_reference_limit',0,'resource_limit')
                    self.value['references'].append({'id':context['id']+':root-reference','source_id':source_id,'target_id':target_id,
                        'xref_context_distance':revision,'target_number':root.value[0],'target_generation':root.value[1],
                        'resolved':target is not None,'scope':'static inherited trailer Root; no execution edge'})
                break
            self.emit()

    def run(self, native):
        self.emit()
        try:
            self.discover_chain()
        except SyntaxIssue as error:
            self.preserve_active(error)
            if 'limit' in error.code:
                raise
            self.problem(error.code)
        try:
            self.sequential()
        except SyntaxIssue as error:
            self.preserve_active(error)
            if 'limit' in error.code:
                raise
            self.problem(error.code)
        for item in list(self.objects.values()):
            kind=dictionary_get(item['node'],b'/Type')
            if kind is not None and kind.kind=='name' and kind.value==b'/ObjStm':
                try:
                    self.object_stream(item)
                except SyntaxIssue as error:
                    self.preserve_active(error)
                    if 'limit' in error.code:
                        raise
                    self.problem(error.code)
        self.finish_views(native)
        self.reference_graph()
        self.prove_chronology()
        # Private parse trees are worker-only and never serialized/exported.
        for block in self.value['xref_blocks']:
            block.pop('_node',None)
        for record in self.value['objects']:
            if not record['projection']['projection_complete']:
                self.problem('forensic_projection_incomplete')
        for block in self.value['xref_blocks']:
            for reason in block['reason_codes']:
                self.problem(reason)
        complete=bool(self.value['sequential_scan_complete'] and self.value['xref_chain_complete'] and self.value['selection_context_verified']
            and self.value['comparisons_complete'] and not self.value['reason_codes'])
        self.value.update(status='observed' if complete else 'partial',complete=complete)
        self.emit()
        return self.value


def inspect_raw_forensic(data, code_limits, *, remaining, native_analysis=None, limits=None, retain=None, checkpoint=None, timings=None,
                         arlington_catalog=None, arlington_checkpoint=None,plugins=None):
    """Inspect a verified snapshot, retaining partial state under explicit caps."""
    if not isinstance(data,bytes) or not data.startswith(b'%PDF-') or len(data)>code_limits.max_file_bytes:
        raise ValueError('forensic_input_invalid')
    if type(remaining) is not int or not 0<=remaining<=code_limits.max_decoded_bytes:
        raise ValueError('forensic_remaining_budget_invalid')
    if native_analysis and native_analysis.get('document_sha256')!=digest(data):
        raise ValueError('forensic_native_document_mismatch')
    limits=limits or ForensicLimits(max_objects=code_limits.max_objects,
        max_tokens=min(200000,max(1024,code_limits.max_objects*64)),max_nodes=min(200000,max(1024,code_limits.max_objects*64)),
        max_xref_entries=min(65536,code_limits.max_objects*8))
    if limits.max_objects>code_limits.max_objects:
        raise ValueError('forensic_object_allowance_exceeds_worker_limit')
    document=_Document(data,code_limits,remaining,limits,retain,checkpoint,timings,plugins=plugins)
    try:
        result=document.run(native_analysis)
    except (SyntaxIssue,MemoryError,RecursionError,ValueError,UnicodeError) as error:
        result=deepcopy(document.saved)
        reason=error.code if isinstance(error,SyntaxIssue) else 'forensic_memory_limit' if isinstance(error,MemoryError) else 'forensic_recursion_limit' if isinstance(error,RecursionError) else 'forensic_internal_validation_failed'
        result.update(status='partial',complete=False,reason_codes=sorted(set(result['reason_codes'])|{reason}),
            counters_are_interrupted_lower_bounds=True)
        for block in result['xref_blocks']:
            block.pop('_node',None)
        if checkpoint:
            checkpoint(deepcopy(result))
        if arlington_catalog is not None and arlington_checkpoint is not None:
            arlington_checkpoint({'schema_version':'arlington-analysis-v1','document_sha256':document.sha,
                'model':{key:value for key,value in arlington_catalog.provenance.items() if key!='files'},
                'status':'not_run','complete':False,'reason_codes':['raw_ir_interrupted_before_arlington']})
        return result
    # Keep the final raw checkpoint intact even if the optional rule pass fails.
    # The rule engine reads only cached trees; it cannot parse/decode more bytes.
    if arlington_catalog is not None:
        from malpdf.extraction.arlington_validate import validate_document
        validate_document(document,arlington_catalog,checkpoint=arlington_checkpoint)
    return result
