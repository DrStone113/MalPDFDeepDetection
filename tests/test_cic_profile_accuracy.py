"""Synthetic saved-profile tests; no PDF/dataset/network dependency."""

import csv
import hashlib
import json

import numpy as np
import pytest
import yaml

from malpdf.experiments import cic_static_accuracy as study
from malpdf.static.code_inspector import _unavailable, SECURITY_NAMES
from malpdf.static.js_ast import CALL_NAMES
from malpdf.static.schema import RIT_FEATURES


def spec(root, path):
    return {"path": str(path.relative_to(root)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


@pytest.fixture
def profiles(tmp_path):
    manifests = {name: [] for name in ("split_manifest", "source_manifest", "normalization_manifest")}
    records = []
    for partition in ("train", "validation"):
        for label in ("0", "1"):
            for number in range(4):
                identifier = f"{partition}_{label}_{number}"
                digest = hashlib.sha256(identifier.encode()).hexdigest()
                path = f"data/raw/cic_pdf/{identifier}.pdf"
                manifests["split_manifest"].append({"sample_id": identifier, "cohort": "cic", "split": partition,
                    "Label": label, "duplicate_group_id": identifier})
                manifests["source_manifest"].append({"sample_id": identifier, "pdf_sha256": digest, "related_group_id": identifier,
                    "pdf_relative_path": path, "Label": label})
                manifests["normalization_manifest"].append({"pdf_sha256": digest, "pdf_relative_path": path,
                    "target_pdf_byte_verified": "True", "target_label_source": "synthetic", "Label": label})
                raw = {name: 0 for name in RIT_FEATURES}
                raw.update(pdfsize=len(records) + 1 + (1000 if partition == "validation" else 0), pdf_ver=1.7)
                ast = {"node_count": 5, "max_depth": 2, "loops": 0, "computed_members": 1,
                    "named_calls": {name: int(name == "eval") for name in CALL_NAMES}, "node_types": {"Literal": 2}}
                structure = {name[1:]: 0 for name in SECURITY_NAMES}
                code = {**_unavailable("synthetic"), "status": "partial", "errors": ["pdf_xref_recovered"],
                    "observed": {"scripts_found": 1, "ast": ast, "structural_indicators": structure}, "scripts_parsed": 1}
                if number == 1:
                    code = _unavailable("pdf_parser_failure")
                code["schema_version"] = "pdf-code-inspection-v5"
                record = {"sample_id": identifier, "pdf_sha256": digest, "pdf_relative_path": path,
                    "Label": label, "split": partition, "cache_mode": "cold", "status": "parser_error" if number == 1 else "partial",
                    "static": {"input": {"size_bytes": 2000, "sha256": digest}, "features": raw,
                        "parser": {"success": number != 1, "structural_complete": False, "resource_limit_reached": False,
                            "encrypted": False}, "reference_parser_repaired": False},
                    "code": code, "timings": {"read_hash": 0.01, "raw_scan": 0.01}}
                records.append(record)
    configuration = {"samples_per_partition": 8, "limits": {"max_file_bytes": 1024**2},
        "rf": {"n_estimators": 3, "max_depth": 3, "min_samples_leaf": 1, "class_weight": "balanced"}}
    for name, rows in manifests.items():
        path = tmp_path / "data/processed" / (name + ".csv")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
        configuration[name] = spec(tmp_path, path)
    report = tmp_path / "reports/experiments/cic_static_profile/run_fixture"
    artifact = tmp_path / "artifacts/cic_static_profile/run_fixture"
    report.mkdir(parents=True); artifact.mkdir(parents=True)
    cfg = {"seed": 42, "threshold": 0.5, "source_profile": "run_fixture", "rf": configuration["rf"],
        "expected_counts": {"train/0": 4, "train/1": 4, "validation/0": 4, "validation/1": 4}}
    values = {"profile_summary": (report / "run_summary.json", {"status": "completed", "run_id": "run_fixture"}),
        "profile_methodology": (report / "locked_methodology.json", {"test_access": False, "seed": 42,
            "configuration": configuration, "fingerprint": {"profile_version": "cic-static-profile-v2", "code_schema": "pdf-code-inspection-v5"}}),
        "profile_comparison": (report / "feature_comparison.json", {"status": "completed", "models": {}})}
    for name, (path, value) in values.items():
        path.write_text(json.dumps(value)); cfg[name] = spec(tmp_path, path)
    path = artifact / "per_file.jsonl"
    path.write_text("\n".join(json.dumps(record) for record in records) + "\n")
    cfg["profile_records"] = spec(tmp_path, path)
    return cfg, records


def save_records(root, cfg, records):
    path = root / cfg["profile_records"]["path"]
    path.write_text("\n".join(json.dumps(row) for row in records) + "\n")
    cfg["profile_records"] = spec(root, path)


def test_partial_lower_bounds_do_not_replace_unknown_totals(profiles):
    cfg, records = profiles
    row = records[0]; row["static"]["features"]["images"] = -1
    values = study.profile_feature_values(row, study.PROFILE_VARIANTS[1])
    assert values["images"] == -1 and values["ast_node_count"] is None
    assert values["observed_ast_node_count"] == 5 and values["observed_ast_type_Literal"] == 2
    assert values["scripts_found"] is None and values["observed_scripts_found"] == 1
    unavailable = study.profile_feature_values(records[1], study.PROFILE_VARIANTS[1])
    assert unavailable["observed_ast_node_count"] is None
    assert unavailable["observed_scripts_found"] is None
    assert not {"sample_id", "pdf_sha256", "pdf_relative_path", "Label", "split"} & set(values)


@pytest.mark.parametrize("change", ["checksum", "label", "test", "snapshot", "execution"])
def test_profile_provenance_changes_fail_before_model_fit(tmp_path, profiles, change):
    cfg, records = profiles
    if change == "checksum":
        (tmp_path / cfg["profile_records"]["path"]).write_text("{}\n")
    else:
        if change == "label": records[0]["Label"] = "1"
        if change == "test": records[0]["split"] = "test"
        if change == "snapshot": records[0]["static"]["input"]["sha256"] = "0" * 64
        if change == "execution": records[0]["code"]["active_content_executed"] = True
        save_records(tmp_path, cfg, records)
    with pytest.raises(ValueError): study.load_profile_development(tmp_path, cfg)


def test_parser_failures_stay_eligible_but_missing_bytes_are_refused(profiles):
    cfg, records = profiles
    assert records[1]["status"] == "parser_error"
    assert study.profile_input_available(records[1], 1024**2)
    records[1]["static"] = None
    assert not study.profile_input_available(records[1], 1024**2)


@pytest.mark.parametrize("schema", ["pdf-code-inspection-v6", "pdf-code-inspection-v7"])
def test_new_profile_requires_explicit_schema_lock_and_preserves_v5_support(tmp_path, profiles, schema):
    cfg, records = profiles
    for row in records:
        row["code"]["schema_version"] = schema
    save_records(tmp_path, cfg, records)
    method_path = tmp_path / cfg["profile_methodology"]["path"]
    method = json.loads(method_path.read_text())
    method["fingerprint"]["code_schema"] = schema
    method_path.write_text(json.dumps(method))
    cfg["profile_methodology"] = spec(tmp_path, method_path)
    with pytest.raises(ValueError, match="methodology differs"):
        study.load_profile_development(tmp_path, cfg)
    cfg["profile_code_schema"] = schema
    loaded, _ = study.load_profile_development(tmp_path, cfg)
    assert len(loaded) == 16


def test_malformed_analysis_flag_is_not_coerced_to_a_measurement(profiles):
    _, records = profiles
    records[0]["code"]["traversal_complete"] = "false"
    with pytest.raises(ValueError, match="Non-boolean"):
        study.profile_feature_values(records[0], study.PROFILE_VARIANTS[1])


def test_offline_job_reuses_ablations_keeps_warm_rows_out_and_retains_refusals(tmp_path, profiles, monkeypatch):
    from types import SimpleNamespace
    from sklearn.ensemble import RandomForestClassifier
    cfg,records=profiles
    records[8]['static']=None;records[8]['code']=None;records[8]['status']='worker_error'
    warm=[{**r,'cache_mode':'warm'} for r in records]
    calls=[];original=RandomForestClassifier.fit
    def fit(model,features,labels,*args,**kwargs):
        calls.append(np.asarray(features).copy())
        return original(model,features,labels,*args,**kwargs)
    monkeypatch.setattr(RandomForestClassifier,'fit',fit)
    report=tmp_path/'reports/offline_fixture';report.mkdir(parents=True)
    artifacts=tmp_path/'artifacts/offline_fixture';artifacts.mkdir(parents=True)
    run=SimpleNamespace(root=tmp_path,identifier='run_fixture',report=report,artifacts=artifacts,state={'metrics':{}})
    study.compare_profile_evidence(run,records+warm,{'rf':cfg['rf'],'limits':{'max_file_bytes':1024**2}})
    scores=json.loads((report/'observed_feature_comparison.json').read_text())
    assert scores['status']=='completed' and set(scores['models'])==set(study.PROFILE_VARIANTS)
    assert len(calls)==3 and all(len(x)==8 and set(x[:,0])==set(range(1,9)) for x in calls)
    assert all(s['planned']==8 and s['classified']==7 and s['refusals']==1 for s in scores['models'].values())
    assert len(run.state['metrics'])==3
    for variant in study.PROFILE_VARIANTS:
        manifest=json.loads((report/(variant+'_manifest.json')).read_text())
        assert manifest['training_rows']==8 and manifest['promotion'] is False
        assert hashlib.sha256((tmp_path/manifest['artifact_relative_path']).read_bytes()).hexdigest()==manifest['artifact_sha256']
    predictions=json.loads((artifacts/'observed_development_predictions.json').read_text())
    assert len(predictions['sample_ids'])==7 and all(x.startswith('validation_') for x in predictions['sample_ids'])


@pytest.mark.parametrize('change',['test','warm','duplicate'])
def test_shared_ablation_refuses_invalid_partitions_or_repeat_records_before_fitting(profiles, monkeypatch, change):
    from sklearn.ensemble import RandomForestClassifier
    cfg,records=profiles
    if change=='test':records[0]['split']='test'
    elif change=='warm':records[0]['cache_mode']='warm'
    else:records.append(records[0])
    monkeypatch.setattr(RandomForestClassifier,'fit',lambda *args,**kwargs:pytest.fail('Invalid records must not fit'))
    with pytest.raises(ValueError,match='unique cold Train/development'):
        study.fit_profile_ablations(records,cfg['rf'],1024**2)


@pytest.mark.parametrize("overlap", [False, True])
def test_fixed_models_fit_train_only_and_keep_missing_input_denominators(tmp_path, profiles, monkeypatch, overlap):
    from sklearn.ensemble import RandomForestClassifier
    cfg, records = profiles
    records[8]["static"] = None; records[8]["code"] = None; records[8]["status"] = "worker_error"
    if overlap:
        records[9]["static"]["features"] = records[0]["static"]["features"].copy()
    save_records(tmp_path, cfg, records)
    monkeypatch.setattr(study, "clean_code", lambda root: None)
    captured = []
    original = RandomForestClassifier.fit
    def fit(model, features, labels, *args, **kwargs):
        captured.append(np.asarray(features).copy())
        return original(model, features, labels, *args, **kwargs)
    monkeypatch.setattr(RandomForestClassifier, "fit", fit)
    class Run:
        def __init__(self, root, *args):
            self.report = root / "reports/experiments/cic_profile_accuracy/run_unit"
            self.artifacts = root / "artifacts/cic_profile_accuracy/run_unit"
            self.report.mkdir(parents=True); self.artifacts.mkdir(parents=True)
            self.state = {"metrics": {}, "status": "completed"}
        def __enter__(self): return self
        def __exit__(self, *args): return False
    monkeypatch.setattr(study, "ResearchRun", Run)
    configuration = tmp_path / "profile.yaml"; configuration.write_text(yaml.safe_dump(cfg))
    if overlap:
        with pytest.raises(ValueError, match="feature-equivalence"):
            study.train_cic_static(tmp_path, configuration)
        assert not captured
        return
    result = study.train_cic_static(tmp_path, configuration)
    assert len(captured) == 3 and all(array.shape[0] == 8 for array in captured)
    assert all(array[:, 0].max() <= 8 for array in captured)
    assert len(result["metrics"]) == 3
    comparison = json.loads((tmp_path / "reports/experiments/cic_profile_accuracy/run_unit/validation_comparison.json").read_text())
    assert all(model["classified"] == 7 and model["planned"] == 8 and model["refusals"] == 1
               for model in comparison["models"].values())
    for model in comparison["models"].values():
        failed = model["by_analysis_status"]["worker_error"]
        assert failed["classified"] == 0 and failed["refusals"] == 1 and failed["metrics_classified"] is None
        assert model["by_analysis_status"]["parser_error"]["classified"] == 2
