"""Synthetic cached-table tests; no real PDFs, dataset downloads or Test inference."""

import csv
import hashlib
import json
from pathlib import Path

import numpy as np
import pytest
import yaml

from malpdf.experiments import cic_static_accuracy as study
from malpdf.inference.schema import EXCLUDED_CONSTANT_FEATURES


def write_table(root, name, rows):
    path = root / 'data/processed' / name
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader(); writer.writerows(rows)
    return {'path': str(path.relative_to(root)), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


@pytest.fixture
def tables(tmp_path):
    split, source, normalized, values = [], [], [], []
    for partition in ('train', 'validation', 'test'):
        for label in ('0', '1'):
            for i in range(4):
                identifier = f'{partition}_{label}_{i}'
                digest = hashlib.sha256(identifier.encode()).hexdigest()
                split.append({'sample_id':identifier, 'cohort':'cic', 'split':partition, 'Label':label, 'duplicate_group_id':identifier})
                source.append({'sample_id':identifier, 'Label':label, 'pdf_sha256':digest, 'related_group_id':identifier,
                    'pdf_relative_path':f'data/raw/cic_pdf/{identifier}.pdf'})
                normalized.append({'pdf_sha256':digest, 'pdf_relative_path':source[-1]['pdf_relative_path'],
                    'Label':label, 'target_pdf_byte_verified':'True', 'target_label_source':'synthetic fixture'})
                numeric = {name:0 for name in (*study.CIC_FEATURE_ORDER, *EXCLUDED_CONSTANT_FEATURES)}
                numeric['pdfsize'] = len(values) + 1
                if partition == 'test':
                    numeric = {name:'not-a-number-Test-poison' for name in numeric}
                values.append({'sample_id':identifier, 'Label':label, **numeric})
    cfg={'seed':42, 'threshold':0.5, 'audit_stratum_size':8,
        'expected_counts':{'train/0':4,'train/1':4,'validation/0':4,'validation/1':4}}
    for name, rows in (('split_manifest',split),('source_manifest',source),('normalization_manifest',normalized),('feature_table',values)):
        cfg[name]=write_table(tmp_path, name+'.csv', rows)
    path=tmp_path/'reports/experiments/synthetic/baseline.json'; path.parent.mkdir(parents=True)
    path.write_text('{}')
    cfg['baseline_manifest']={'path':str(path.relative_to(tmp_path)), 'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    return cfg, values


def test_load_discards_test_before_numeric_conversion_and_preserves_measurements(tmp_path, tables):
    cfg, values=tables
    values[0]['images']=-1; values[0]['title length']=''
    cfg['feature_table']=write_table(tmp_path,'feature_table.csv',values)
    frame=study.load_development_tables(tmp_path,cfg)
    assert len(frame)==16 and set(frame.split)=={'train','validation'}
    assert frame.loc[frame.sample_id.eq('train_0_0'),'images'].iloc[0]==-1
    assert np.isnan(frame.loc[frame.sample_id.eq('train_0_0'),'title length'].iloc[0])
    assert 'sample_id' not in study.CIC_FEATURE_ORDER and 'Label' not in study.CIC_FEATURE_ORDER


@pytest.mark.parametrize('change',['vector_overlap','label','constant','infinity'])
def test_cached_evidence_conflicts_refuse_before_model_fit(tmp_path,tables,change):
    cfg, values=tables
    if change=='vector_overlap': values[8]['pdfsize']=values[0]['pdfsize']
    elif change=='label': values[0]['Label']='1'
    elif change=='constant': values[0]['Acroform']=1
    else: values[0]['images']='inf'
    cfg['feature_table']=write_table(tmp_path,'feature_table.csv',values)
    with pytest.raises(ValueError): study.load_development_tables(tmp_path,cfg)


def test_train_only_candidate_retains_model_identity_and_rejects_changed_weights(tmp_path,tables,monkeypatch):
    cfg,_=tables
    monkeypatch.setattr(study,'clean_code',lambda *args:None)
    captured=[]
    real_factory=study.create_model
    def factory(*args):
        model=real_factory(*args); original=model.fit
        def fit(features,labels,*args,**kwargs):
            captured.append(features.copy())
            return original(features,labels,*args,**kwargs)
        model.fit=fit
        return model
    monkeypatch.setattr(study,'create_model',factory)
    class Baseline:
        def set_params(self,**kwargs):return self
        def predict_proba(self,features):return np.tile([0.6,0.4],(len(features),1))
    monkeypatch.setattr(study,'load_profile_model',lambda *args:(Baseline(),{}))
    class Run:
        def __init__(self,root,*args):
            self.identifier='run_fixture'
            self.report=root/'reports/experiments/cic_static_accuracy'/self.identifier
            self.artifacts=root/'artifacts/cic_static_accuracy'/self.identifier
            self.report.mkdir(parents=True);self.artifacts.mkdir(parents=True)
            self.state={'status':'completed','metrics':{},'run_id':self.identifier}
        def __enter__(self):return self
        def __exit__(self,*args):
            (self.report/'run_summary.json').write_text(json.dumps(self.state))
            return False
    monkeypatch.setattr(study,'ResearchRun',Run)
    config=tmp_path/'config.yaml';config.write_text(yaml.safe_dump(cfg))
    state=study.train_cic_static(tmp_path,config)
    assert len(captured)==1 and len(captured[0])==8
    assert list(captured[0].columns)==list(study.CIC_FEATURE_ORDER)
    assert set(captured[0].pdfsize)==set(range(1,9))
    assert set(state['metrics'])=={'RIT_frozen_to_CIC/cic_validation_numeric','CIC_train_static40/cic_validation_numeric'}
    candidate,manifest=study.load_cic_candidate(tmp_path,'run_fixture')
    assert tuple(candidate.get_booster().feature_names)==study.CIC_FEATURE_ORDER
    assert manifest['training_dataset']['training_rows']==8
    comparison=json.loads((tmp_path/'reports/experiments/cic_static_accuracy/run_fixture/validation_comparison.json').read_text())
    assert all(model['validation_planned']==model['classified']==8 for model in comparison['models'].values())
    target=tmp_path/manifest['artifact_relative_path']; target.write_bytes(target.read_bytes()+b' ')
    with pytest.raises(ValueError,match='checksum changed'):study.load_cic_candidate(tmp_path,'run_fixture')


def test_rf_imputation_fits_train_only_and_retains_missing_validation_denominators(tmp_path,tables,monkeypatch):
    import joblib
    from sklearn.ensemble import RandomForestClassifier
    cfg,values=tables
    cfg['candidate_model']='random_forest'
    values[0]['title length']='';values[8]['title length']=''
    cfg['feature_table']=write_table(tmp_path,'feature_table.csv',values)
    original=tmp_path/cfg['feature_table']['path'];original_bytes=original.read_bytes()
    monkeypatch.setattr(study,'clean_code',lambda *args:None)
    captured=[];real_factory=study.create_model
    def factory(family,seed):
        assert family=='random_forest' and seed==42
        return real_factory(family,seed)
    monkeypatch.setattr(study,'create_model',factory)
    original_fit=RandomForestClassifier.fit
    def fit(model,features,labels,*args,**kwargs):
        captured.append(features.copy())
        return original_fit(model,features,labels,*args,**kwargs)
    monkeypatch.setattr(RandomForestClassifier,'fit',fit)
    class Baseline:
        def set_params(self,**kwargs):return self
        def predict_proba(self,features):return np.tile([0.6,0.4],(len(features),1))
    monkeypatch.setattr(study,'load_profile_model',lambda *args:(Baseline(),{}))
    class Run:
        def __init__(self,root,*args):
            assert args[0]=='cic_static_rf_accuracy'
            self.identifier='run_fixture'
            self.report=root/'reports/experiments/cic_static_rf_accuracy'/self.identifier
            self.artifacts=root/'artifacts/cic_static_rf_accuracy'/self.identifier
            self.report.mkdir(parents=True);self.artifacts.mkdir(parents=True)
            self.state={'status':'completed','metrics':{},'run_id':self.identifier}
        def __enter__(self):return self
        def __exit__(self,*args):return False
    monkeypatch.setattr(study,'ResearchRun',Run)
    config=tmp_path/'config.yaml';config.write_text(yaml.safe_dump(cfg))
    state=study.train_cic_static(tmp_path,config)
    assert len(captured)==1 and set(captured[0][:,0])==set(range(1,9))
    assert set(state['metrics'])=={'RIT_frozen_to_CIC/cic_validation_numeric','CIC_train_rf_static40/cic_validation_numeric'}
    report=tmp_path/'reports/experiments/cic_static_rf_accuracy/run_fixture'
    manifest=json.loads((report/'model_manifest.json').read_text())
    assert manifest['model_family']=='random_forest' and manifest['model_id']==study.CIC_RF_MODEL_ID
    assert manifest['training_dataset']['training_rows']==8
    artifact=tmp_path/manifest['artifact_relative_path']
    assert hashlib.sha256(artifact.read_bytes()).hexdigest()==manifest['artifact_sha256']
    # Load only this test's own synthetic model; no supplied binaries or datasets.
    model=joblib.load(artifact);imputer,forest=model.steps[0][1],model.steps[1][1]
    assert imputer.statistics_[0]==4.5
    assert forest.n_estimators==200 and forest.max_depth==12 and forest.min_samples_leaf==2
    assert forest.class_weight=='balanced' and forest.random_state==42 and forest.n_jobs==1
    comparison=json.loads((report/'validation_comparison.json').read_text())
    assert all(m['validation_planned']==8 and m['classified']==7 and m['refusals']==1
               for m in comparison['models'].values())
    assert original.read_bytes()==original_bytes
