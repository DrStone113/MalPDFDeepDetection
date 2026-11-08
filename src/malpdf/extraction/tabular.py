"""Lossless JSON records beside typed, nullable Arrow projections."""

from copy import deepcopy
import hashlib
import json

from malpdf.extraction.contracts import validate_bundle

VERSION='pdf-tabular-v1'
TABLES=('documents','features','evidence','edges','coverage_groups','backends')
LOCATORS=('object_number','generation','revision','byte_offset_start','byte_offset_end')


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False,ensure_ascii=True)


def digest(bundle):
    return hashlib.sha256(canonical(bundle).encode()).hexdigest()


def schemas():
    """Fixed schemas avoid inference from all-null/empty/heterogeneous columns."""
    import pyarrow as pa
    string,integer,real,boolean=pa.string(),pa.int64(),pa.float64(),pa.bool_()


    strings=pa.list_(pa.field('element',string))
    common=[('export_id',string),('bundle_id',string),('bundle_index',integer),('sample_sha256',string),('record_index',integer)]
    fields={
        'documents':[('bundle_sha256',string),('schema_version',string),('extraction_profile',string),('observation_status',string),
            ('evidence_count',integer),('edge_count',integer),('feature_count',integer),
            *[(k,string) for k in ('envelope_json','evidence_metadata_json','feature_metadata_json','coverage_json')]],
        'features':[('feature_name',string),('feature_group',string),('observation_status',string),
            ('value_type',string),('value_boolean',boolean),('value_int64',integer),('value_float64',real),
            ('value_json',string),('integer_overflow',boolean),('evidence_refs',strings),('scope',string),
            ('scope_complete',boolean),('coverage_ratio',real),('limitations',strings),('record_json',string)],
        'evidence':[('evidence_id',string),('kind',string),('backend',string),('observation_status',string),
            *[(key,integer) for key in LOCATORS],('locator_overflows',strings),('filter_chain',strings),
            ('is_synthetic_repaired',boolean),('record_json',string)],
        'edges':[('edge_id',string),('source',string),('target',string),('source_index',integer),
            ('target_index',integer),('record_json',string)],
        'coverage_groups':[('feature_group',string),('observation_status',string),('feature_count',integer),
            ('scope',string),('limitations',strings),('record_json',string)],
        'backends':[('backend',string),('observation_status',string),('limitations',strings),('record_json',string)],
    }
    return {name:pa.schema(common+columns,metadata={b'malpdf_schema':VERSION.encode(),b'table':name.encode()})
            for name,columns in fields.items()}


def int64(value):
    return value if type(value) is int and -(2**63)<=value<2**63 else None


def _strings(value):
    if not isinstance(value,list) or any(not isinstance(v,str) for v in value):
        raise ValueError('export_string_list_required')
    return deepcopy(value)


def tables_for_bundle(bundle,*,bundle_index=0,export_id=None):
    """Preserve every input occurrence and JSON field; never fit/impute/select."""
    validate_bundle(bundle)
    if type(bundle_index) is not int or not 0<=bundle_index<2**63:
        raise ValueError('export_bundle_index')
    if export_id is not None and (not isinstance(export_id,str) or not 0<len(export_id)<=128):
        raise ValueError('export_run_id')
    common={'export_id':export_id,'bundle_id':f'bundle_{bundle_index:06d}','bundle_index':bundle_index,'sample_sha256':bundle['sample_sha256']}
    result={name:[] for name in TABLES}
    def row(name,index,**fields): result[name].append({**common,'record_index':index,**fields})
    evidence=bundle['evidence_store'];features=bundle['feature_store'];coverage=bundle['coverage_report']
    row('documents',0,bundle_sha256=digest(bundle),schema_version=bundle['schema_version'],
        extraction_profile=bundle['extraction_profile'],observation_status=bundle['status'],
        evidence_count=len(evidence['records']),edge_count=len(evidence['edges']),feature_count=len(features['records']),
        envelope_json=canonical({k:v for k,v in bundle.items() if k not in {'evidence_store','feature_store','coverage_report'}}),
        evidence_metadata_json=canonical({k:v for k,v in evidence.items() if k not in {'records','edges'}}),
        feature_metadata_json=canonical({k:v for k,v in features.items() if k!='records'}),coverage_json=canonical(coverage))
    for i,item in enumerate(features['records']):
        value=item['value'];kind={type(None):'null',bool:'bool',int:'int',float:'float'}[type(value)]
        row('features',i,**{key:item[key] for key in ('feature_name','feature_group','observation_status','scope','scope_complete')},
            coverage_ratio=float(item['coverage_ratio']) if item['coverage_ratio'] is not None else None,
            value_type=kind,value_boolean=value if kind=='bool' else None,
            value_int64=int64(value),value_float64=value if kind=='float' else None,
            value_json=canonical(value),integer_overflow=kind=='int' and int64(value) is None,
            evidence_refs=_strings(item['evidence_refs']),limitations=_strings(item['limitations']),record_json=canonical(item))
    nodes={item['evidence_id']:i for i,item in enumerate(evidence['records'])}
    for i,item in enumerate(evidence['records']):
        row('evidence',i,**{key:item[key] for key in ('evidence_id','kind','backend','observation_status','is_synthetic_repaired')},
            **{key:int64(item[key]) for key in LOCATORS},
            locator_overflows=[key for key in LOCATORS if item[key] is not None and int64(item[key]) is None],
            filter_chain=None if item['filter_chain'] is None else _strings(item['filter_chain']),record_json=canonical(item))
    for i,item in enumerate(evidence['edges']):
        row('edges',i,edge_id=item['id'],source=item['source'],target=item['target'],
            source_index=nodes[item['source']],target_index=nodes[item['target']],record_json=canonical(item))
    for i,(name,item) in enumerate(sorted(coverage['groups'].items())):
        row('coverage_groups',i,feature_group=name,**{key:item[key] for key in ('observation_status','feature_count','scope')},
            limitations=_strings(item['limitations']),record_json=canonical(item))
    for i,(name,item) in enumerate(sorted(coverage['backends'].items())):
        row('backends',i,backend=name,observation_status=item['observation_status'],
            limitations=_strings(item['limitations']),record_json=canonical(item))
    return result


def restore_bundle(tables):
    """Restore one occurrence and reject inconsistent/tampered projections."""
    try:
        if set(tables)!=set(TABLES) or len(tables['documents'])!=1: raise ValueError()
        ordered={name:sorted(rows,key=lambda r:r['record_index']) for name,rows in tables.items()}
        document=ordered['documents'][0]
        value=json.loads(document['envelope_json'])
        value['evidence_store']=json.loads(document['evidence_metadata_json'])
        value['feature_store']=json.loads(document['feature_metadata_json'])
        value['coverage_report']=json.loads(document['coverage_json'])
        for name,store,field in (('features','feature_store','records'),('evidence','evidence_store','records'),('edges','evidence_store','edges')):
            value[store][field]=[json.loads(row['record_json']) for row in ordered[name]]
        expected=tables_for_bundle(value,bundle_index=document['bundle_index'],export_id=document['export_id'])
        if canonical(ordered)!=canonical(expected): raise ValueError()
        return value
    except (KeyError,TypeError,ValueError,IndexError,RecursionError) as error:
        raise ValueError('export_projection_inconsistent') from error
