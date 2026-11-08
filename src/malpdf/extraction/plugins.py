"""Explicit trusted-code extension contracts. PDF bytes never select modules.

Specs pin importable operator-selected classes and configuration identities.
Actual plugin constructors/methods run in the extraction worker. Process limits
bound work; this SDK is not containment for malicious Python plugin code.
"""

from abc import ABC,abstractmethod
from copy import deepcopy
from dataclasses import dataclass,field
import hashlib
import inspect
import json
from pathlib import Path
import re
from types import MappingProxyType

API_VERSION='pdf-static-plugins-v1'
_NAME=re.compile(r'[a-z][a-z0-9_]{0,31}\Z')
_FILTER=re.compile(r'/[A-Za-z][A-Za-z0-9]{0,63}\Z')
_CODE=re.compile(r'[a-z][a-z0-9_]{0,63}\Z')


class BaseParserPlugin(ABC):
    @abstractmethod
    def open(self,data,limits):
        """Return a reader with candidates/object/warnings/close methods.

        object(candidate, allowance) returns (common pypdf projection container,
        complete:bool, reason_codes:list[str]). Allowance.remaining is read-only;
        the wrapper charges returned raw stream bytes. No decoded-stream API.
        """


class BaseDecoderPlugin(ABC):
    @abstractmethod
    def decode(self,data,parameters,output):
        """Write bytes to the bounded output; return None. Never execute payloads."""


class BaseFeaturePlugin(ABC):
    @abstractmethod
    def extract(self,context):
        """Return a PluginContribution with source-linked, namespaced records."""


@dataclass(frozen=True)
class PluginLimits:
    max_plugins:int=8
    max_context_bytes:int=4*1024**2
    max_metadata_bytes:int=512*1024
    max_evidence:int=256
    max_features:int=512
    max_edges:int=1024

    def __post_init__(self):
        from dataclasses import asdict
        if any(type(v) is not int or not 0<v<=cap for v,cap in zip(asdict(self).values(),
                (8,4*1024**2,512*1024,256,512,1024))):raise ValueError('plugin_invalid_limit')


def _json(value):
    pending=[(value,0)];count=0
    while pending:
        item,depth=pending.pop();count+=1
        if depth>8 or count+len(pending)>512:raise ValueError('plugin_configuration_limit')
        if isinstance(item,dict):
            if any(type(k) is not str for k in item):raise ValueError('plugin_configuration_key')
            children=item.values()
        elif isinstance(item,list):children=item
        elif type(item) in (str,int,float,bool,type(None)):continue
        else:raise ValueError('plugin_configuration_type')
        if count+len(pending)+len(item)>512:raise ValueError('plugin_configuration_limit')
        pending.extend((v,depth+1) for v in children)
    raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False,ensure_ascii=True)
    if len(raw)>32768:raise ValueError('plugin_configuration_limit')
    return raw


def _source(path):
    from malpdf.static.safety import read_bounded_bytes
    path=Path(path).absolute()
    if path.suffix!='.py':raise ValueError('plugin_python_source_required')
    return hashlib.sha256(read_bounded_bytes(path,boundary=path.parent,max_bytes=1024**2)).hexdigest()


@dataclass(frozen=True)
class PluginSpec:
    plugin_id:str
    version:str
    implementation:type
    parameters:dict=field(default_factory=dict,repr=False,compare=False)
    filters:tuple=()
    parameter_keys:tuple=()
    kind:str=field(init=False)
    source_path:str=field(init=False)
    source_sha256:str=field(init=False)
    parameters_json:str=field(init=False,repr=False)

    def __post_init__(self):
        if not isinstance(self.plugin_id,str) or not _NAME.fullmatch(self.plugin_id):raise ValueError('plugin_invalid_id')
        if not isinstance(self.version,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+\-]{0,63}',self.version):
            raise ValueError('plugin_invalid_version')
        if not isinstance(self.implementation,type) or inspect.isabstract(self.implementation):raise ValueError('plugin_concrete_class_required')
        matches=[kind for kind,base in (('parser',BaseParserPlugin),('decoder',BaseDecoderPlugin),('feature',BaseFeaturePlugin))
                 if issubclass(self.implementation,base)]
        if len(matches)!=1:raise ValueError('plugin_single_kind_required')
        kind=matches[0]
        if type(self.parameters) is not dict:raise ValueError('plugin_configuration_type')
        params=_json(self.parameters)
        if (type(self.filters) is not tuple or type(self.parameter_keys) is not tuple
                or len(self.filters)>8 or len(self.parameter_keys)>16
                or any(not isinstance(v,str) or not _FILTER.fullmatch(v) for v in (*self.filters,*self.parameter_keys))
                or len(set(self.filters))!=len(self.filters) or len(set(self.parameter_keys))!=len(self.parameter_keys)
                or kind!='decoder' and (self.filters or self.parameter_keys) or kind=='decoder' and not self.filters):
            raise ValueError('plugin_invalid_decoder_registration')
        if kind=='decoder':
            from malpdf.extraction.filters import SUPPORTED,ALIASES
            if set(self.filters)&(set(SUPPORTED)|set(ALIASES)|{'/Crypt'}):raise ValueError('plugin_builtin_decoder_override')
        if self.implementation.__module__=='__main__' or '<locals>' in self.implementation.__qualname__:
            raise ValueError('plugin_importable_source_required')
        try:path=inspect.getsourcefile(self.implementation)
        except (TypeError,OSError):raise ValueError('plugin_importable_source_required') from None
        if not path:raise ValueError('plugin_importable_source_required')
        object.__setattr__(self,'kind',kind);object.__setattr__(self,'source_path',str(Path(path).absolute()))
        object.__setattr__(self,'source_sha256',_source(path));object.__setattr__(self,'parameters_json',params)

        object.__setattr__(self,'parameters',json.loads(params))

    def describe(self):
        return {'api_version':API_VERSION,'plugin_id':self.plugin_id,'kind':self.kind,'version':self.version,
            'module':self.implementation.__module__,'class':self.implementation.__qualname__,
            'source_path':self.source_path,'source_sha256':self.source_sha256,
            'parameters_sha256':hashlib.sha256(self.parameters_json.encode()).hexdigest(),
            'filters':list(self.filters),'parameter_keys':list(self.parameter_keys)}

    def verify(self):
        if _source(self.source_path)!=self.source_sha256:raise ValueError('plugin_source_changed')

    def build(self):
        self.verify()
        return self.implementation(**json.loads(self.parameters_json))


@dataclass(frozen=True)
class PluginRegistry:
    specs:tuple=()
    seed:int=42
    limits:PluginLimits=field(default_factory=PluginLimits)

    def __post_init__(self):
        if type(self.limits) is not PluginLimits:raise ValueError('plugin_invalid_limit')
        if type(self.specs) is not tuple or len(self.specs)>self.limits.max_plugins or any(type(s) is not PluginSpec for s in self.specs):
            raise ValueError('plugin_registry_shape')
        if type(self.seed) is not int or not 0<=self.seed<2**32:raise ValueError('plugin_invalid_seed')
        ids=[s.plugin_id for s in self.specs];filters=[f for s in self.specs for f in s.filters]
        if len(ids)!=len(set(ids)) or len(filters)!=len(set(filters)):raise ValueError('plugin_registry_collision')
        if len(json.dumps(self.describe(),allow_nan=False,separators=(',',':')).encode())>65536:
            raise ValueError('plugin_registry_metadata_limit')

    def __bool__(self):return bool(self.specs)
    def select(self,kind):return tuple(s for s in self.specs if s.kind==kind)
    def decoder(self,name):return next((s for s in self.select('decoder') if name in s.filters),None)
    def verify(self):
        for spec in self.specs:spec.verify()
    def describe(self):
        from dataclasses import asdict
        return {'api_version':API_VERSION,'seed':self.seed,'limits':asdict(self.limits),'specs':[s.describe() for s in self.specs]}
    def wire(self):
        value=self.describe()
        value['specs']=[{'descriptor':s.describe(),'parameters_json':s.parameters_json} for s in self.specs]
        return value


def registry(value):
    if value is None:return None
    if type(value) is not PluginRegistry:raise ValueError('plugin_registry_required')
    value.verify()
    return value if value else None


def from_wire(value):
    """Resolve only operator-pinned modules, after worker OS limits are active.

    Passing class objects to multiprocessing would import their modules during
    unpickling, before the target applies its limits. Only plain data crosses
    that boundary; these imports run later under the original worker caps.
    """
    import importlib
    import importlib.util
    try:
        if (type(value) is not dict or set(value)!={'api_version','seed','limits','specs'}
                or value['api_version']!=API_VERSION or type(value['specs']) is not list or len(value['specs'])>8):
            raise ValueError('plugin_wire_registry')
        limits=PluginLimits(**value['limits']);specs=[]
        for item in value['specs']:
            if type(item) is not dict or set(item)!={'descriptor','parameters_json'}:raise ValueError('plugin_wire_registry')
            desc=item['descriptor'];path=Path(desc['source_path'])
            if not path.is_absolute() or _source(path)!=desc['source_sha256']:raise ValueError('plugin_source_changed')
            module_spec=importlib.util.find_spec(desc['module'])
            if module_spec is None or not module_spec.origin or Path(module_spec.origin).absolute()!=path:
                raise ValueError('plugin_source_path_changed')
            implementation=importlib.import_module(desc['module'])
            for name in desc['class'].split('.'):
                if not name.isidentifier() or name.startswith('__'):raise ValueError('plugin_wire_registry')
                implementation=getattr(implementation,name)
            spec=PluginSpec(desc['plugin_id'],desc['version'],implementation,json.loads(item['parameters_json']),
                tuple(desc['filters']),tuple(desc['parameter_keys']))
            if spec.describe()!=desc or spec.parameters_json!=item['parameters_json']:raise ValueError('plugin_wire_registry')
            specs.append(spec)
        result=PluginRegistry(tuple(specs),value['seed'],limits);result.verify()
        return result if result else None
    except (KeyError,TypeError,AttributeError,ImportError,json.JSONDecodeError) as error:
        raise ValueError('plugin_wire_registry') from error


class PluginDecodeFailure(Exception):
    def __init__(self,status,code):
        if status not in {'unsupported','encrypted','decode_error','resource_limit'} or not isinstance(code,str) or not _CODE.fullmatch(code):
            raise ValueError('plugin_invalid_decoder_failure')
        self.status,self.code=status,code


class BoundedOutput:
    def __init__(self,cap):self._cap,self._data,self._failed=cap,bytearray(),False
    @property
    def limit(self):return self._cap
    @property
    def remaining(self):return self._cap-len(self._data)
    def write(self,data):
        if not isinstance(data,(bytes,bytearray,memoryview)):raise ValueError('plugin_decoder_bytes_required')
        view=memoryview(data)
        if view.ndim!=1 or view.itemsize!=1:raise ValueError('plugin_decoder_bytes_required')
        room=self.remaining;self._data.extend(view[:room])
        if len(view)>room:
            self._failed=True
            raise PluginDecodeFailure('resource_limit','decoded_byte_or_expansion_limit')
        return len(view)
    def prefix(self):return bytes(self._data)
    def finish(self):
        if self._failed:raise PluginDecodeFailure('resource_limit','decoded_byte_or_expansion_limit')
        return self.prefix()


@dataclass(frozen=True)
class RawAllowance:
    remaining:int


@dataclass(frozen=True)
class PluginContribution:
    evidence:tuple=()
    features:tuple=()
    edges:tuple=()


class FeatureContext:
    def __init__(self,data,bundle,spec,limits,seed,buffers):
        self.data,self.bundle,self.spec,self.limits,self.seed=data,deepcopy(bundle),spec,limits,seed
        self._buffers=MappingProxyType(dict(buffers))
        identity=hashlib.sha256(_json({'spec':spec.describe(),'seed':seed}).encode()).hexdigest()[:24]
        self.namespace='plugin:'+spec.plugin_id+':'+identity+':'+bundle['sample_sha256']
    def identifier(self,name):
        if not isinstance(name,str) or not _CODE.fullmatch(name):raise ValueError('plugin_invalid_local_id')
        return self.namespace+':'+name
    def blob(self,digest):
        if not isinstance(digest,str) or not re.fullmatch('[a-f0-9]{64}',digest):raise ValueError('plugin_invalid_blob_id')
        return self._buffers.get(digest)
    def observation(self,name,kind,*,status='partial',details=None,source_ref=None,start=None,end=None):
        from malpdf.extraction.normalize import _record
        item=_record(self.identifier(name),kind,'plugin:'+self.spec.plugin_id,status,details=deepcopy(details or {}))
        if start is not None or end is not None:
            if type(start) is not int or type(end) is not int or not 0<=start<=end<=len(self.data):raise ValueError('plugin_invalid_byte_range')
            item.update(byte_offset_start=start,byte_offset_end=end)
            item['details']['range_sha256']=hashlib.sha256(self.data[start:end]).hexdigest()
            item['details']['range_scope']='original bytes; object identity/reachability unverified'
            item['details']['range_document_sha256']=self.bundle['sample_sha256']
        item['details']['plugin_source_ref']=source_ref or 'original:'+self.bundle['sample_sha256']
        return item
    def measurement(self,name,group,value,status,refs,scope,limitations=(),*,complete=False):
        from malpdf.extraction.contracts import feature
        return feature(self.identifier(name),group,value,status,refs,scope,limitations,complete=complete)


class ParserReader:
    """Adapt a trusted parser to bounded common inventory containers."""
    def __init__(self,spec,data,limits):
        self.reader=spec.build().open(data,limits);self.data=data
        self.version=spec.describe()
        self.repaired=getattr(self.reader,'repaired',True)
        if type(self.repaired) is not bool:raise ValueError('plugin_parser_repair_flag')
    def candidates(self):
        fields={'number','generation','offset','xref_type','object_stream_number','object_stream_index','metadata'}
        for item in self.reader.candidates():
            if type(item) is not dict or not {'number','generation','offset'}<=set(item) or set(item)-fields:
                raise ValueError('plugin_parser_candidate_shape')
            number,generation,offset=item['number'],item['generation'],item['offset']
            if (type(number) is not int or not 0<number<2**63
                    or generation is not None and (type(generation) is not int or not 0<=generation<2**31)
                    or offset is not None and (type(offset) is not int or not 0<=offset<len(self.data))):
                raise ValueError('plugin_parser_candidate_locator')
            _json(item)
            result=deepcopy(item)
            if offset is not None:
                header=re.match(rb'(\d+)\s+(\d+)\s+obj(?:\s|[<\[/])',self.data[offset:offset+128])
                if generation is None or not header or (int(header[1]),int(header[2]))!=(number,generation):
                    result.update(offset=None,metadata={**result.get('metadata',{}),'claimed_offset':offset,'offset_unverified':True})
            yield result
    def object(self,candidate,raw_budget):
        from pypdf.generic import StreamObject
        value,complete,reasons=self.reader.object(candidate,RawAllowance(raw_budget.remaining))
        if type(complete) is not bool or type(reasons) is not list or any(not isinstance(v,str) or not _CODE.fullmatch(v) for v in reasons):
            raise ValueError('plugin_parser_result_shape')
        if isinstance(value,StreamObject):
            if type(value._data) is not bytes:raise ValueError('plugin_parser_stream_type')
            if len(value._data)>raw_budget.remaining:
                raw_budget.remaining=0;value._data=b''
                return value,False,sorted(set(reasons)|{'inventory_raw_byte_limit'})
            raw_budget.remaining-=len(value._data)
        return value,complete,reasons
    def warnings(self):
        value=self.reader.warnings()
        if (type(value) is not dict or set(value)!={'count','codes'} or type(value['count']) is not int or value['count']<0
                or type(value['codes']) is not list or len(value['codes'])>32
                or any(not isinstance(v,str) or not _CODE.fullmatch(v) for v in value['codes'])):
            raise ValueError('plugin_parser_warning_shape')
        return value
    def close(self):self.reader.close()
