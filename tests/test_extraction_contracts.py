"""Draft 2020-12 structural validation and additional bundle invariants offline."""

from collections import Counter
from copy import deepcopy
import json
import socket
import urllib.request

from jsonschema import Draft202012Validator
from referencing import Registry
from referencing.exceptions import NoSuchResource,Unresolvable
import pytest

from malpdf.extraction.contracts import GROUPS,ObservationStatus,feature,validate_bundle
from malpdf.extraction.normalize import normalize_profile
from malpdf.extraction.raw import inspect_raw_layout
from malpdf.extraction.schemas import schemas

STORES={'evidence_store':'evidence_store.schema.json','feature_store':'feature_record.schema.json',
        'coverage_report':'coverage_report.schema.json'}


def deny_reference(uri): raise NoSuchResource(ref=uri)


@pytest.fixture(scope='module')
def validators():
    result={}
    for store,name in STORES.items():
        schema=schemas()[name];Draft202012Validator.check_schema(schema)
        result[store]=Draft202012Validator(schema,registry=Registry(retrieve=deny_reference))
    return result


def bundle():
    layout=inspect_raw_layout(b'%PDF-1.7\n/JS\n%%EOF\n')
    value=normalize_profile({'status':'complete','errors':[],'raw_layout':layout},layout['sha256'],'fast-static')
    value['coverage_report']['backends']['fixture']={'observation_status':'partial','limitations':['synthetic_scope'],
        'version':{'binding':'fixture','library':None},'scope':'synthetic version/model/graph coverage',
        'model':{'status':'unavailable','unknown_context':True},'graph_observation_status':'not_run',
        'graph_limitations':['not_run'],'lexical_observation_status':'observed'}
    return validate_bundle(value)


def assert_standard_valid(value,validators):
    for store,validator in validators.items():validator.validate(value[store])


def add_measurement(value,status,raw):
    reference=value['evidence_store']['records'][0]['evidence_id']
    value['feature_store']['records'].append(feature('fixture','objects',raw,status,[reference] if raw is not None else [],
        'synthetic checked source',complete=status=='absent_within_scope'))
    value['coverage_report']['groups']['objects']['feature_count']+=1
    value['coverage_report']['observation_status_counts']=dict(Counter(r['observation_status'] for r in value['feature_store']['records']))


def test_published_schemas_validate_backend_extensions_without_mutating_metadata(validators):
    value=bundle();before=deepcopy(value)
    assert_standard_valid(value,validators)
    assert validate_bundle(value) is value and value==before


@pytest.mark.parametrize('status',[str(s) for s in ObservationStatus])
def test_all_observation_states_keep_null_and_scoped_absence_rules(validators,status):
    value=bundle();raw=0 if status=='absent_within_scope' else 1 if status in {'observed','partial'} else None
    add_measurement(value,status,raw)
    assert_standard_valid(value,validators);validate_bundle(value)
    if raw is None:assert value['feature_store']['records'][-1]['value'] is None


@pytest.mark.parametrize('version',[None,'synthetic-v1',{'binding':'fixture','library':None}])
def test_optional_unknown_scalar_and_structured_versions_are_retained(validators,version):
    value=bundle();value['coverage_report']['backends']['fixture']['version']=version
    assert_standard_valid(value,validators);validate_bundle(value)


@pytest.mark.parametrize('store',list(STORES))
def test_unknown_core_store_keys_are_rejected_instead_of_dropped(validators,store):
    value=bundle();value[store]['typo_field']=7
    assert not validators[store].is_valid(value[store])
    with pytest.raises(ValueError,match='store_shape'):validate_bundle(value)


def bad_feature(value):return value['feature_store']['records'][0]
def bad_node(value):return value['evidence_store']['records'][0]
def bad_backend(value):return value['coverage_report']['backends']['fixture']


@pytest.mark.parametrize('mutate,store',[
    (lambda b:bad_feature(b).update(unknown_field=0),'feature_store'),
    (lambda b:bad_feature(b).update(limitations='bad'),'feature_store'),
    (lambda b:bad_feature(b).update(limitations=[True]),'feature_store'),
    (lambda b:bad_feature(b).update(scope=''),'feature_store'),
    (lambda b:bad_feature(b).update(scope_complete=1),'feature_store'),
    (lambda b:bad_feature(b).update(coverage_ratio=True),'feature_store'),
    (lambda b:bad_feature(b).update(coverage_ratio=2**5000),'feature_store'),
    (lambda b:bad_feature(b).update(evidence_refs=[]),'feature_store'),
    (lambda b:bad_feature(b).update(observation_status='not_a_status'),'feature_store'),
    (lambda b:bad_node(b).update(details=[]),'evidence_store'),
    (lambda b:bad_node(b).update(is_synthetic_repaired=1),'evidence_store'),
    (lambda b:bad_node(b).update(object_number=True),'evidence_store'),
    (lambda b:bad_node(b).update(generation=-1),'evidence_store'),
    (lambda b:bad_node(b).update(filter_chain=[1]),'evidence_store'),
    (lambda b:bad_node(b).update(unknown_field='bad'),'evidence_store'),
    (lambda b:b['evidence_store'].update(capability_checks=['bad']),'evidence_store'),
    (lambda b:b['evidence_store'].update(conflicts=[None]),'evidence_store'),
    (lambda b:b['evidence_store'].update(edges=[{'id':'e','source':1,'target':'bad'}]),'evidence_store'),
    (lambda b:b['coverage_report']['groups']['objects'].update(scope=''),'coverage_report'),
    (lambda b:b['coverage_report']['groups']['objects'].update(limitations=[1]),'coverage_report'),
    (lambda b:b['coverage_report']['groups']['objects'].update(feature_count=True),'coverage_report'),
    (lambda b:b['coverage_report'].update(backends=[]),'coverage_report'),
    (lambda b:bad_backend(b).update(version=7),'coverage_report'),
    (lambda b:bad_backend(b).update(model='bad'),'coverage_report'),
    (lambda b:bad_backend(b).update(scope=None),'coverage_report'),
    (lambda b:bad_backend(b).update(graph_observation_status=[]),'coverage_report'),
    (lambda b:bad_backend(b).update(lexical_observation_status='unknown'),'coverage_report'),
    (lambda b:bad_backend(b).update(graph_limitations=[1]),'coverage_report'),
    (lambda b:bad_backend(b).update(limitations=None),'coverage_report'),
    (lambda b:bad_backend(b).update(unknown_field=True),'coverage_report'),
    (lambda b:b['coverage_report']['backends'].update({'':{'observation_status':'not_run','limitations':[]}}),'coverage_report'),
    (lambda b:b['coverage_report'].update(observation_status_counts={'unknown':0}),'coverage_report'),
    (lambda b:b['coverage_report'].update(observation_status_counts={'observed':True}),'coverage_report'),
    (lambda b:b['coverage_report'].update(limitations={'bad':True}),'coverage_report'),
    (lambda b:b['coverage_report'].update(worker=[]),'coverage_report'),
    (lambda b:b['coverage_report'].update(provenance='bad'),'coverage_report'),
    (lambda b:b['coverage_report'].update(whole_document_complete=True),'coverage_report'),
    (lambda b:b['coverage_report'].update(whole_document_complete=0),'coverage_report'),
])
def test_schema_and_runtime_reject_invalid_published_shapes(validators,mutate,store):
    value=bundle();mutate(value)
    assert not validators[store].is_valid(value[store])
    with pytest.raises(ValueError):validate_bundle(value)


def test_partial_measured_value_cannot_lose_its_evidence(validators):
    value=bundle();add_measurement(value,'partial',7);value['feature_store']['records'][-1]['evidence_refs']=[]
    assert not validators['feature_store'].is_valid(value['feature_store'])
    with pytest.raises(ValueError,match='unattributed_value'):validate_bundle(value)


@pytest.mark.parametrize('change',[
    lambda b:b['coverage_report'].update(observation_status_counts={}),
    lambda b:b['coverage_report']['groups']['raw_layout'].update(feature_count=0),
    lambda b:b['feature_store'].update(sample_sha256='a'*64),
    lambda b:b['evidence_store']['records'].append(deepcopy(b['evidence_store']['records'][0])),
    lambda b:bad_feature(b).update(evidence_refs=['missing']),
])
def test_runtime_adds_cross_store_checks_beyond_json_schema(validators,change):
    value=bundle();change(value);assert_standard_valid(value,validators)
    with pytest.raises(ValueError):validate_bundle(value)


def test_zero_counts_are_explicit_and_do_not_change_observations(validators):
    value=bundle();counts=value['coverage_report']['observation_status_counts']
    for status in ObservationStatus:counts.setdefault(str(status),0)
    assert_standard_valid(value,validators);validate_bundle(value)


def test_json_integer_numeric_equivalence_does_not_relax_runtime_locator_types(validators):
    value=bundle();bad_node(value)['object_number']=1.0


    assert_standard_valid(value,validators)
    with pytest.raises(ValueError,match='locator'):validate_bundle(value)


@pytest.mark.parametrize('extra',[{'nan':float('nan')},{1:'would_be_coerced'},{'nonjson':object()}])
def test_opaque_metadata_still_requires_json_safety(extra):
    value=bundle();value['coverage_report']['provenance']=extra
    with pytest.raises(ValueError,match='json_value'):validate_bundle(value)


def test_json_cycles_fail_without_mutation_or_recursion_error_leaks():
    value=bundle();value['coverage_report']['provenance']['cycle']=value
    with pytest.raises(ValueError,match='json_value'):validate_bundle(value)


def test_edge_attributes_opaque_extensions_and_root_metadata_survive(validators):
    value=bundle();reference=bad_node(value)['evidence_id']
    value['evidence_store']['edges']=[{'id':'e','source':reference,'target':reference,'status':'derived','custom':{'unknown':None}}]
    value['coverage_report']['worker']={'new_backend_flag':None}
    value['coverage_report']['provenance']={'nested':{'unclassified':[None,-1,False]}}
    value['extension']={'caller_data':'inert'}
    before=deepcopy(value);assert_standard_valid(value,validators);validate_bundle(value)
    assert value==before


def test_schemas_are_materialized_independent_trees():
    first=schemas();baseline=schemas()
    status=first['evidence_store.schema.json']['properties']['records']['items']['properties']['observation_status']['enum']
    status.append('bad')
    assert first['feature_record.schema.json']==baseline['feature_record.schema.json']
    assert first['coverage_report.schema.json']==baseline['coverage_report.schema.json']
    assert schemas()==baseline


def test_metaschemas_and_instances_validate_without_network(monkeypatch):
    def forbidden(*a,**k):pytest.fail('Schema validation must remain offline')
    monkeypatch.setattr(socket,'create_connection',forbidden);monkeypatch.setattr(socket,'getaddrinfo',forbidden)
    monkeypatch.setattr(urllib.request,'urlopen',forbidden)
    for store,name in STORES.items():
        schema=schemas()[name];Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema,registry=Registry(retrieve=deny_reference)).validate(bundle()[store])
    validator=Draft202012Validator({'$ref':'https://example.invalid/no-fetch'},registry=Registry(retrieve=deny_reference))
    with pytest.raises(Unresolvable):validator.validate({})
