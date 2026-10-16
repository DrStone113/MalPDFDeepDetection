"""Lossless byte-to-pixel tiles. No PDF rendering or image/payload decoding."""

from copy import deepcopy
from dataclasses import dataclass,asdict
import hashlib
import json
import struct
import zlib

from malpdf.extraction.raw import _entropy

ALGORITHM='raw-byte-gray8-png-v1'


def sha(data): return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class ByteImageLimits:
    width: int = 256
    rows_per_tile: int = 256
    max_sources: int = 128
    max_tiles: int = 256
    max_mapped_pixels: int = 4*1024**2
    max_png_bytes: int = 4*1024**2
    max_cached_bytes: int = 10*1024**2
    max_cached_blobs: int = 256
    max_metadata_bytes: int = 512*1024

    def __post_init__(self):
        ceilings=(1024,1024,512,1024,16*1024**2,10*1024**2,10*1024**2,1024,1024**2)
        if (any(type(v) is not int or not 0<v<=c for v,c in zip(asdict(self).values(),ceilings))
                or self.width*self.rows_per_tile>65536 or self.max_metadata_bytes<4096):
            raise ValueError('invalid_byte_image_limit')


class ImageLimit(ValueError):
    pass


def encode_tile(data,*,width=256,rows=256):
    """Return a generated 8-bit grayscale PNG and an exact valid-pixel mask."""
    if (not isinstance(data,bytes) or type(width) is not int or type(rows) is not int
            or not 1<=width<=1024 or not 1<=rows<=1024 or width*rows>65536
            or not 0<len(data)<=width*rows):
        raise ValueError('invalid_byte_tile')
    height=(len(data)+width-1)//width
    padding=height*width-len(data);pixels=data+b'\0'*padding
    filtered=b''.join(b'\0'+pixels[start:start+width] for start in range(0,len(pixels),width))
    def chunk(kind,body):
        return struct.pack('>I',len(body))+kind+body+struct.pack('>I',zlib.crc32(kind+body)&0xffffffff)
    header=struct.pack('>IIBBBBB',width,height,8,0,0,0,0)
    png=b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',header)+chunk(b'IDAT',zlib.compress(filtered,level=1))+chunk(b'IEND',b'')
    return png,{'width':width,'height':height,'bit_depth':8,'color_type':'grayscale',
        'valid_pixels':len(data),'padding_pixels':padding,'padding_value':0,
        'valid_mask':'row-major prefix [0, valid_pixels); padding is not source data',
        'pixels_sha256':sha(pixels),'valid_bytes_sha256':sha(data)}


def pixel_offset(tile,x,y):
    """Map a valid pixel to its declared source namespace; padding maps to None."""
    width,height,valid,start=(tile.get(key) for key in ('width','height','valid_pixels','source_byte_start'))
    if (any(type(v) is not int for v in (width,height,valid,start,x,y)) or width<=0 or height<=0
            or not 0<valid<=width*height or start<0 or not 0<=x<width or not 0<=y<height):
        raise ValueError('invalid_byte_pixel_locator')
    index=y*width+x
    return start+index if index<valid else None


def _tile_order(count):
    first,last=0,count-1
    while first<=last:
        yield first
        if last!=first: yield last
        first+=1;last-=1


class ByteImages:
    def __init__(self,digest,code_limits,*,retain=None,limits=None,checkpoint=None):
        self.digest,self.code,self.retain=digest,code_limits,retain
        self.limits=limits or ByteImageLimits();self.checkpoint=checkpoint
        self.cache={};self.cache_bytes=0;self.capture_failures=0
        self.sources=[];self.source_ids=set();self.buffers={};self.positions={}
        self.png_cache={};self.finished=False;self.saved=None
        self.value={'schema_version':'pdf-byte-images-v1','document_sha256':digest,'algorithm':ALGORITHM,
            'status':'partial','complete':False,'sources':[],'tiles':[],'reason_codes':[],
            'limits':asdict(self.limits),'source_selection':'root, raw declarations, decoded streams, admitted artifacts',
            'tile_order':'round robin across sources; alternating head/tail chunks within each source',
            'pixel_mapping':'one source byte per 8-bit grayscale sample; no resizing/normalization',
            'pdf_rendered':False,'native_image_decoding':False,'additional_pdf_decodes':0,
            'encoder':{'format':'PNG','filter':0,'interlace':0,'compression_level':1,
                       'zlib_compile':zlib.ZLIB_VERSION,'zlib_runtime':zlib.ZLIB_RUNTIME_VERSION},
            'cached_source_bytes':0,'source_capture_failures':0,'attempted_tiles':0,
            'mapped_pixels_work':0,'unique_retained_png_bytes':0,
            'scope':'admitted raw/decoded byte spans only; no page appearance or whole-format coverage'}

    def capture(self,data,state):
        """Keep only immutable bytes already admitted to the shared raw transport."""
        try:
            if self.finished: return
            if not isinstance(data,bytes) or not isinstance(state,dict) or state.get('status')!='retained':
                self.capture_failures+=1;return
            digest=state.get('sha256')
            if digest in self.cache: return
            if (state.get('size_bytes')!=len(data) or digest!=sha(data)
                    or len(self.cache)>=self.limits.max_cached_blobs
                    or self.cache_bytes+len(data)>self.limits.max_cached_bytes):
                self.capture_failures+=1;return
            self.cache[digest]=data;self.cache_bytes+=len(data)
        except Exception:
            self.capture_failures+=1

    def problem(self,code):
        self.value['reason_codes']=sorted(set(self.value['reason_codes'])|{code})

    def emit(self):
        self.value.update(cached_source_bytes=self.cache_bytes,source_capture_failures=self.capture_failures)
        size=len(json.dumps(self.value,allow_nan=False,separators=(',',':')).encode())
        if size>self.limits.max_metadata_bytes-1024:
            raise ImageLimit('byte_image_metadata_limit')
        if self.checkpoint: self.checkpoint(deepcopy(self.value))
        self.saved=deepcopy(self.value)

    def register(self,identity,source_id,*,data,space,namespace,start=0,end=None,kind,
                 document_sha256=None,repaired=False,span_complete=True,object_number=None,generation=None):
        if identity in self.source_ids: return
        if len(self.sources)>=self.limits.max_sources:
            self.problem('byte_image_source_limit');return
        self.source_ids.add(identity)
        valid=(isinstance(data,bytes) and type(start) is int and type(end) is int and 0<=start<=end<=len(data))
        record={'id':'byte-source:'+sha((self.digest+'|'+identity).encode()),'source_ref':source_id,
            'kind':kind,'source_space':space,'source_namespace_sha256':namespace,
            'source_document_sha256':document_sha256 or self.digest,
            'source_byte_start':start,'source_byte_end':end,'source_size_bytes':end-start if valid else None,
            'source_sha256':sha(memoryview(data)[start:end]) if valid else None,
            'source_span_complete':span_complete,'object_number':object_number,'generation':generation,
            'is_synthetic_repaired':bool(repaired),'status':'partial','reason_codes':[],
            'planned_tiles':0,'attempted_tiles':0,'encoded_source_bytes':0,'retained_source_bytes':0,'mapping_complete':False}
        if not valid:
            record['reason_codes']=['byte_image_source_unavailable'];self.problem('byte_image_source_unavailable')
        else:
            count=(end-start+self.limits.width*self.limits.rows_per_tile-1)//(self.limits.width*self.limits.rows_per_tile)
            record['planned_tiles']=count
            self.buffers[record['id']]=data
            self.positions[record['id']]=iter(_tile_order(count))
        self.sources.append(record);self.value['sources'].append(record)
        self.emit()

    def register_blob(self,identity,source_id,digest,*,kind,document_sha256=None,repaired=False,start=0,end=None,span_complete=True,
                      object_number=None,generation=None):
        data=self.cache.get(digest)
        if end is None and data is not None: end=len(data)
        self.register(identity,source_id,data=data,space='decoded_bytes' if kind!='artifact_bytes' else 'artifact_bytes',
            namespace=digest,start=start,end=end,kind=kind,document_sha256=document_sha256,
            repaired=repaired,span_complete=span_complete,object_number=object_number,generation=generation)

    def catalog(self,data,profile):
        self.register('original','original:'+self.digest,data=data,space='original_bytes',namespace=self.digest,
            start=0,end=len(data),kind='file_bytes')
        forensic=profile.get('raw_forensic') or {}
        nodes={node['id']:node for node in forensic.get('syntax_nodes',[])}
        objects=list(forensic.get('objects',[]))+list(forensic.get('partial_declarations',[]))
        if forensic.get('active_declaration'): objects.append(forensic['active_declaration'])
        objects.sort(key=lambda item:(item['source_space']!='original',item.get('byte_start') or 0,item['id']))
        for item in objects:
            if item['source_space']=='original':
                end=item.get('byte_end');complete=end is not None
                if not complete:
                    node=nodes.get(item.get('root_node_id'))
                    end=(node or {}).get('end')
                valid_origin=item.get('top_level_confirmed') is True and type(end) is int
                self.register(item['id'],item['id'],data=data if valid_origin else None,
                    space='original_bytes',namespace=self.digest,start=item.get('byte_start'),end=end,
                    kind='object_bytes' if complete else 'object_value_prefix',span_complete=complete,
                    object_number=item.get('object_number'),generation=item.get('generation'))
            else:
                self.register_blob(item['id'],item['id'],item.get('decoded_stream_sha256'),kind='decoded_object_bytes',
                    start=item.get('decoded_start'),end=item.get('decoded_end'),object_number=item.get('object_number'),generation=item.get('generation'))
        def stream_views(analysis,document=None):
            for item in (analysis or {}).get('records',[]):
                decoded=item.get('decode') or {}
                if decoded.get('complete'):
                    self.register_blob(item['id'],item['id'],decoded.get('decoded_sha256'),kind='decoded_stream_bytes',
                        document_sha256=document,repaired=item.get('backend')=='MuPDF',
                        object_number=item.get('object_number'),generation=item.get('generation'))
        stream_views(profile.get('stream_analysis'))
        for item in forensic.get('structural_streams',[]):
            decoded=item.get('decode') or {}
            if decoded.get('complete'):
                self.register_blob(item['id'],item['id'],decoded.get('decoded_sha256'),kind='decoded_stream_bytes')
        carving=profile.get('carving') or {}
        for item in carving.get('records',[]):
            document=item['sha256'] if item['kind']=='pdf' else item.get('source_document_sha256')
            self.register_blob(item['id'],item['id'],item['sha256'],kind='artifact_bytes',
                document_sha256=document,repaired=item['is_synthetic_repaired'])
            child=(carving.get('analyses') or {}).get(item['id'],{})
            if item['kind']=='pdf' and child.get('layout'):
                if child['layout'].get('sha256')!=item['sha256']:
                    self.problem('byte_image_child_identity_unverified')
                else: stream_views(child.get('stream_analysis'),item['sha256'])

    def tile(self,source,index):
        identity=source['id'];capacity=self.limits.width*self.limits.rows_per_tile
        relative=index*capacity;start=source['source_byte_start']+relative
        end=min(source['source_byte_end'],start+capacity)
        count=end-start;height=(count+self.limits.width-1)//self.limits.width
        record={'id':identity+':tile:'+str(index),'source_id':identity,'tile_index':index,
            'source_byte_start':start,'source_byte_end':end,'view_byte_start':relative,
            'source_space':source['source_space'],'source_namespace_sha256':source['source_namespace_sha256'],
            'original_file_byte_start':start if source['source_space']=='original_bytes' else None,
            'width':self.limits.width,'height':height,'valid_pixels':count,
            'padding_pixels':height*self.limits.width-count,'status':'resource_limit',
            'reason_codes':[],'artifact':None,'pixels_sha256':None,'valid_bytes_sha256':None}
        self.value['attempted_tiles']+=1
        source['attempted_tiles']+=1
        pixels=height*self.limits.width
        if self.value['mapped_pixels_work']+pixels>self.limits.max_mapped_pixels:
            record['reason_codes']=['byte_image_pixel_limit'];self.problem('byte_image_pixel_limit')
        else:
            self.value['mapped_pixels_work']+=pixels
            block=bytes(memoryview(self.buffers[identity])[start:end])
            png,metadata=encode_tile(block,width=self.limits.width,rows=self.limits.rows_per_tile)
            digest=sha(png);state=self.png_cache.get(digest)
            if state is None:
                if self.value['unique_retained_png_bytes']+len(png)>self.limits.max_png_bytes:
                    state={'sha256':digest,'size_bytes':len(png),'status':'unavailable','reason_code':'byte_image_png_limit'}
                elif self.retain is None:
                    state={'sha256':digest,'size_bytes':len(png),'status':'not_retained','reason_code':'byte_image_retention_not_configured'}
                else:
                    state=self.retain(png)
                    if (not isinstance(state,dict) or state.get('sha256')!=digest or state.get('size_bytes')!=len(png)
                            or state.get('status') not in {'retained','unavailable','not_retained'}):
                        raise ValueError('byte_image_retention_identity_mismatch')
                self.png_cache[digest]=state
                if state['status']=='retained': self.value['unique_retained_png_bytes']+=len(png)
            record.update(metadata,artifact={**state,'mime_type':'image/png','blob_name':digest+'.bin'},
                byte_entropy=_entropy(block),blob_reused=sum(t.get('artifact',{}).get('sha256')==digest for t in self.value['tiles'] if t.get('artifact'))>0)
            source['encoded_source_bytes']+=count
            if state['status']=='retained':
                record['status']='observed';source['retained_source_bytes']+=count
            else:
                code=state.get('reason_code') or 'byte_image_not_retained'
                record['reason_codes']=[code];self.problem(code)
        self.value['tiles'].append(record)
        self.emit()

    def finish(self,data,profile):
        if self.finished: return self.value
        self.finished=True
        if not isinstance(data,bytes) or len(data)>self.code.max_file_bytes or sha(data)!=self.digest:
            raise ValueError('byte_image_document_mismatch')
        if any((profile.get(key) or {}).get('document_sha256',self.digest)!=self.digest
               for key in ('raw_forensic','stream_analysis','carving','analysis_v9')):
            raise ValueError('byte_image_profile_mismatch')
        try:
            self.emit();self.catalog(data,profile)
            active=[source for source in self.sources if source['id'] in self.buffers and source['planned_tiles']]
            while active and self.value['attempted_tiles']<self.limits.max_tiles:
                pending=[]
                for source in active:
                    if self.value['attempted_tiles']==self.limits.max_tiles:
                        pending.append(source);continue
                    index=next(self.positions[source['id']],None)
                    if index is None: continue
                    self.tile(source,index)
                    if source['attempted_tiles']<source['planned_tiles']: pending.append(source)
                active=pending
            if active: self.problem('byte_image_tile_limit')
            for source in self.sources:
                source['mapping_complete']=(source['source_size_bytes'] is not None and
                    source['retained_source_bytes']==source['source_size_bytes'])
                source['status']='observed' if source['mapping_complete'] else 'partial'
            self.value['complete']=not self.value['reason_codes']
            self.emit()
        except (ImageLimit,MemoryError,RecursionError,ValueError) as error:
            result=deepcopy(self.saved or self.value)
            code=str(error) if isinstance(error,ImageLimit) else 'byte_image_memory_or_recursion_limit' if isinstance(error,(MemoryError,RecursionError)) else 'byte_image_validation_failed'
            result.update(complete=False,counters_are_interrupted_lower_bounds=True,
                reason_codes=sorted(set(result['reason_codes'])|{code}))
            self.value=result
            if self.checkpoint: self.checkpoint(deepcopy(result))
        finally:
            self.cache.clear();self.buffers.clear()
        return self.value
