"""Private immutable batch exports from existing bundles, without PDF access."""

from collections import Counter
from dataclasses import dataclass,asdict
from datetime import datetime,timezone
import hashlib
import importlib.metadata
import io
import json
from pathlib import Path
import platform
import subprocess

from malpdf.extraction import tabular,graph_exports
from malpdf.extraction.orchestrator import processed_output_root
from malpdf.static.safety import read_bounded_bytes


@dataclass(frozen=True)
class ExportLimits:
    max_bundles: int = 256
    max_bundle_bytes: int = 64*1024**2
    max_input_bytes: int = 512*1024**2
    max_rows_per_bundle: int = 200000
    max_total_rows: int = 2000000
    max_output_bytes: int = 2*1024**3
    max_json_depth: int = 128
    max_json_entries: int = 1000000

    def __post_init__(self):
        ceilings=(256,64*1024**2,512*1024**2,200000,2000000,2*1024**3,128,1000000)
        if any(type(v) is not int or not 0<v<=cap for v,cap in zip(asdict(self).values(),ceilings)):
            raise ValueError('export_invalid_limit')


class ExportFailure(ValueError):
    def __init__(self,directory,reason):
        self.directory,self.reason=directory,reason
        super().__init__('export_failed:'+reason)


def _guard(value,limits):
    pending=[(value,0)];visited=0
    while pending:
        item,depth=pending.pop();visited+=1
        if depth>limits.max_json_depth or visited+len(pending)>limits.max_json_entries:
            raise ValueError('export_json_structure_limit')
        if isinstance(item,dict):
            if any(not isinstance(key,str) for key in item): raise ValueError('export_json_key_type')
            children=item.values()
        elif isinstance(item,(list,tuple)): children=item
        elif type(item) in (str,int,float,bool,type(None)): continue
        else: raise ValueError('export_json_value_type')
        if visited+len(pending)+len(item)>limits.max_json_entries: raise ValueError('export_json_structure_limit')
        pending.extend((child,depth+1) for child in children)


def _unique(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise ValueError('export_duplicate_json_key')
        result[key]=value
    return result


def _constant(value): raise ValueError('export_nonfinite_json')


def _load(path,limits,remaining):
    path=Path(path).absolute()
    if path.suffix.lower()!='.json': raise ValueError('export_json_file_required')
    raw=read_bounded_bytes(path,boundary=path.parent,max_bytes=min(limits.max_bundle_bytes,remaining))
    value=json.loads(raw.decode('utf-8'),object_pairs_hook=_unique,parse_constant=_constant)
    return value,{'path':str(path),'source_sha256':hashlib.sha256(raw).hexdigest(),'source_bytes':len(raw)}


class _Output(io.RawIOBase):
    def __init__(self,path,budget):
        super().__init__();self.file=path.open('xb');self.budget=budget
    def writable(self): return True
    def tell(self): return self.file.tell()
    def write(self,data):
        if self.budget['used']+len(data)>self.budget['limit']: raise ValueError('export_output_byte_limit')
        size=self.file.write(data);self.budget['used']+=size;return size
    def close(self):
        try: self.file.close()
        finally: super().close()


def _checksum(path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        while chunk:=stream.read(1024**2): digest.update(chunk)
    return digest.hexdigest()


def _manifest(directory,value):
    raw=(tabular.canonical(value)+'\n').encode()
    if len(raw)>2*1024**2: raise ValueError('export_manifest_limit')
    pending=directory/'export_manifest.json.new'
    with pending.open('xb') as stream: stream.write(raw)
    pending.replace(directory/'export_manifest.json')


def _run_name(commit):
    return 'run_'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ_')+commit[:12]


def _export(inputs,output_root,repository_root,formats,limits,from_files):
    if not isinstance(inputs,(list,tuple)) or not 0<len(inputs)<=limits.max_bundles:
        raise ValueError('export_input_count_limit')
    if (not isinstance(formats,(list,tuple)) or not formats or any(type(f) is not str for f in formats) or len(set(formats))!=len(formats)
            or not set(formats)<={'jsonl','parquet','graph'}): raise ValueError('export_invalid_formats')
    root=Path(repository_root).absolute();output=processed_output_root(root,output_root)
    commit=subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip()
    from malpdf.experiments.protocol_p import repository_git_state
    from malpdf.extraction import contracts,orchestrator
    import pyarrow as pa
    from pyarrow import parquet as pq
    schemas=tabular.schemas()
    directory=output/_run_name(commit);directory.mkdir(parents=True,exist_ok=False,mode=0o700)
    budget={'used':0,'limit':limits.max_output_bytes}
    manifest={'schema_version':'pdf-batch-export-v1','run_id':directory.name,'tabular_schema':tabular.VERSION,'status':'running',
        'generating_commit':commit,'worktree':repository_git_state(root),'limits':asdict(limits),
        'environment':{'python':platform.python_version(),'packages':{name:importlib.metadata.version(name) for name in ('pyarrow','torch','networkx')}},
        'exporter_code_sha256':{module.__name__:hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
            for module in (tabular,graph_exports,contracts,orchestrator)},
        'formats':list(formats),'expected_inputs':len(inputs),'completed_inputs':0,'input_bytes':0,'total_rows':0,
        'input_sources':[{'index':i,'path':str(Path(p).absolute()) if from_files else None} for i,p in enumerate(inputs)],
        'bundles':[],'files':[],'input_status_counts':{},'errors':[],
        'safety':{'pdf_bytes_read':False,'raw_artifact_references_followed':False,'content_executed':False,
                  'rendering_performed':False,'network_access':False,'fitting_performed':False,'test_selection_performed':False}}
    manifest['exporter_code_sha256'][__name__]=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    _manifest(directory,manifest)
    current=0
    def write(relative,writer,rows=None):
        path=directory/relative;path.parent.mkdir(parents=True,exist_ok=True)
        entry={'path':relative,'status':'writing','rows':rows,'bytes':None,'sha256':None};manifest['files'].append(entry)
        with _Output(path,budget) as stream: writer(stream)
        entry.update(status='complete',bytes=path.stat().st_size,sha256=_checksum(path))
    try:
        definition={name:[{'name':field.name,'type':str(field.type),'nullable':field.nullable} for field in schema]
                    for name,schema in schemas.items()}
        write('table_schemas.json',lambda stream:stream.write((tabular.canonical(definition)+'\n').encode()))
        for current,item in enumerate(inputs):
            if manifest['input_bytes']>=limits.max_input_bytes: raise ValueError('export_input_byte_limit')
            bundle,source=_load(item,limits,limits.max_input_bytes-manifest['input_bytes']) if from_files else (item,{'source_bytes':0})
            _guard(bundle,limits)
            raw=tabular.canonical(bundle).encode()
            size=max(len(raw),source['source_bytes'])
            if len(raw)>limits.max_bundle_bytes: raise ValueError('export_bundle_byte_limit')
            if manifest['input_bytes']+size>limits.max_input_bytes: raise ValueError('export_input_byte_limit')
            # Bound validation/projection work before any record or graph expansion.
            row_count=(1+len(bundle.get('feature_store',{}).get('records',[]))
                +len(bundle.get('evidence_store',{}).get('records',[]))+len(bundle.get('evidence_store',{}).get('edges',[]))
                +len(bundle.get('coverage_report',{}).get('groups',{}))+len(bundle.get('coverage_report',{}).get('backends',{})))
            if row_count>limits.max_rows_per_bundle or manifest['total_rows']+row_count>limits.max_total_rows:
                raise ValueError('export_row_limit')
            tables=tabular.tables_for_bundle(bundle,bundle_index=current,export_id=directory.name)
            identity=f'bundle_{current:06d}'
            for name,rows in tables.items():
                if 'jsonl' in formats:
                    def lines(stream,rows=rows):
                        for row in rows: stream.write((tabular.canonical(row)+'\n').encode())
                    write(f'jsonl/{name}/{identity}.jsonl',lines,len(rows))
                if 'parquet' in formats:
                    table=pa.Table.from_pylist(rows,schema=schemas[name]);table.validate(full=True)
                    write(f'parquet/{name}/{identity}.parquet',lambda stream,table=table:pq.write_table(table,stream,
                        compression='NONE',version='2.6',use_dictionary=False,write_statistics=False,row_group_size=1024),len(rows))
            if 'graph' in formats:
                graph=graph_exports.node_link_data(bundle,bundle_index=current,export_id=directory.name)
                write(f'graphs/{identity}.json',lambda stream:stream.write((tabular.canonical(graph)+'\n').encode()))
            manifest['bundles'].append({'bundle_id':identity,'bundle_index':current,'bundle_sha256':tabular.digest(bundle),
                'sample_sha256':bundle['sample_sha256'],'observation_status':bundle['status'],'source':source,
                'rows':{name:len(rows) for name,rows in tables.items()}})
            manifest['completed_inputs']+=1;manifest['input_bytes']+=size;manifest['total_rows']+=row_count
            manifest['input_status_counts']=dict(Counter(row['observation_status'] for row in manifest['bundles']))
            manifest['data_output_bytes']=budget['used'];_manifest(directory,manifest)
        manifest['status']='completed';_manifest(directory,manifest)
    except BaseException as error:
        reason=str(error) if isinstance(error,ValueError) and str(error).isidentifier() else type(error).__name__
        manifest.update(status='interrupted' if isinstance(error,(KeyboardInterrupt,SystemExit)) else 'failed',
            failure_input_index=current,data_output_bytes=budget['used'],errors=[reason])
        for entry in manifest['files']:
            if entry['status']=='writing': entry['status']='incomplete'
        try: _manifest(directory,manifest)
        except (OSError,ValueError,MemoryError): pass # The prior running manifest still cannot claim completion.
        if isinstance(error,(KeyboardInterrupt,SystemExit)): raise
        raise ExportFailure(directory,reason) from error
    return directory


def export_bundles(bundles,output_root,*,repository_root,formats=('jsonl','parquet','graph'),limits=None):
    """Export bounded explicit occurrences; duplicate hashes and failures survive."""
    return _export(bundles,output_root,repository_root,formats,limits or ExportLimits(),False)


def export_bundle_files(paths,output_root,*,repository_root,formats=('jsonl','parquet','graph'),limits=None):
    """Read explicit JSON files sequentially; never resolve embedded references."""
    return _export(paths,output_root,repository_root,formats,limits or ExportLimits(),True)
