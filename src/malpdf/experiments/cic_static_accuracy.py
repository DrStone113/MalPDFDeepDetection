"""Train-only CIC static adaptation using already controlled numeric evidence.

This study reads no PDFs, never scores Test, and keeps the frozen RIT artifact.
Validation is retrospective development evidence, not an independent holdout.
"""

from collections import Counter
import csv
import hashlib
import io
import json
from pathlib import Path
import re

import numpy as np
import pandas as pd
import yaml

from malpdf.experiments.cic_static_benchmark import (
    advanced_features, checked_table, clean_code, load_profile_model, select_subset, verify_label_provenance,
)
from malpdf.inference.schema import DEPLOYMENT_FEATURE_ORDER, EXCLUDED_CONSTANT_FEATURES
from malpdf.models.classical import create_model, model_configurations
from malpdf.evaluation.selective import calibration_metrics
from malpdf.provenance.research_runs import ResearchRun, write_json
from malpdf.reproducibility import set_random_seed
from malpdf.static.safety import read_bounded_bytes
from malpdf.static.schema import RIT_FEATURES
from malpdf.static.code_inspector import SECURITY_NAMES
from malpdf.static.js_ast import CALL_NAMES

CIC_FEATURE_ORDER = (*DEPLOYMENT_FEATURE_ORDER, "script_ratio", "ObfuscationCount")
CIC_FEATURE_SCHEMA = "cic-static-40/v1"
CIC_MODEL_ID = "xgb-cic-train-static40-v1"
PROFILE_FEATURE_SCHEMA = "cic-observed-profile/v1"
PROFILE_VARIANTS = ("P0_rit41_fallback", "P1_observed_static", "P2_observed_plus_status")
AST_NODE_TYPES = ("ArrayExpression", "AssignmentExpression", "BinaryExpression", "BlockStatement",
    "CallExpression", "ConditionalExpression", "ExpressionStatement", "FunctionDeclaration",
    "FunctionExpression", "Identifier", "IfStatement", "Literal", "MemberExpression", "NewExpression",
    "ObjectExpression", "ReturnStatement", "SequenceExpression", "UnaryExpression", "UpdateExpression",
    "VariableDeclaration", "VariableDeclarator", "WhileStatement", "ForStatement", "ForInStatement",
    "DoWhileStatement", "SwitchStatement", "TryStatement", "CatchClause", "ThrowStatement")


def profile_feature_values(row, variant):
    """Keep unknown totals separate from lower bounds on actually seen syntax."""
    if variant not in PROFILE_VARIANTS:
        raise ValueError("Unknown fixed profile feature variant")
    static, code = row.get("static") or {}, row.get("code") or {}
    values = {name: static.get("features", {}).get(name) for name in RIT_FEATURES}
    if variant != PROFILE_VARIANTS[0]:
        values.update(advanced_features(row))
        observed = code.get("observed") or {}
        ast = observed.get("ast")
        structure = observed.get("structural_indicators")
        values.update({"observed_structure_" + name[1:]: None if structure is None else structure.get(name[1:])
                       for name in sorted(SECURITY_NAMES)})
        values.update({"observed_ast_" + name: None if ast is None else ast.get(name)
                       for name in ("node_count", "max_depth", "loops", "computed_members")})
        values.update({"observed_call_" + name: None if ast is None else ast.get("named_calls", {}).get(name, 0)
                       for name in sorted(CALL_NAMES)})
        values.update({"observed_ast_type_" + name: None if ast is None else ast.get("node_types", {}).get(name, 0)
                       for name in AST_NODE_TYPES})
        values["observed_scripts_found"] = observed.get("scripts_found")
        values["observed_scripts_parsed"] = code.get("scripts_parsed")
        for name in ("traversal_complete", "script_extraction_complete"):
            value = code.get(name)
            if value is not None and type(value) is not bool:
                raise ValueError("Non-boolean profile coverage flag")
            values[name] = None if value is None else int(value)
    if variant == PROFILE_VARIANTS[2]:
        parser = static.get("parser") or {}
        for prefix, source, names in (("parser_", parser, ("success", "structural_complete", "resource_limit_reached", "encrypted")),
                                      ("code_", code, ("complete", "parser_recovered"))):
            for name in names:
                value = source.get(name)
                if value is not None and type(value) is not bool:
                    raise ValueError("Non-boolean profile coverage flag")
                values[prefix + name] = None if value is None else int(value)
        values["reference_parser_repaired"] = static.get("reference_parser_repaired")
    for value in values.values():
        if value is not None and (type(value) not in (int, float, bool) or not np.isfinite(value)):
            raise ValueError("Non-finite or nonnumeric saved profile measurement")
    return values


def _profile_content(root, spec, boundary, maximum=32 * 1024**2):
    content = read_bounded_bytes(root / spec["path"], boundary=root / boundary, max_bytes=maximum)
    if hashlib.sha256(content).hexdigest() != spec["sha256"]:
        raise ValueError("Saved profile checksum changed")
    return content


def load_profile_development(root, cfg):
    """Verify the sealed offline run and fixed identities; never reopen a PDF."""
    summary = json.loads(_profile_content(root, cfg["profile_summary"], "reports/experiments"))
    method = json.loads(_profile_content(root, cfg["profile_methodology"], "reports/experiments"))
    if (summary["status"] != "completed" or summary["run_id"] != cfg["source_profile"]
            or method["test_access"] is not False
            or method["seed"] != 42 or method["configuration"]["rf"] != cfg["rf"]
            or method["fingerprint"]["profile_version"] != "cic-static-profile-v2"
            or method["fingerprint"]["code_schema"] != "pdf-code-inspection-v5"):
        raise ValueError("Source profile/methodology differs from the locked study")
    source_cfg = method["configuration"]
    expected = select_subset(checked_table(root, source_cfg["split_manifest"]),
        checked_table(root, source_cfg["source_manifest"]), source_cfg["samples_per_partition"])
    verify_label_provenance(expected, checked_table(root, source_cfg["normalization_manifest"]))
    indexed = {row["sample_id"]: row for row in expected}
    records = []
    for line in _profile_content(root, cfg["profile_records"], "artifacts/cic_static_profile").decode().splitlines():
        row = json.loads(line)
        saved = indexed.get(row.get("sample_id"))
        if (saved is None or row.get("split") not in {"train", "validation"}
                or any(str(row.get(name)) != str(saved[name]) for name in ("pdf_sha256", "Label", "split"))):
            raise ValueError("Profile identity, label or development split changed")
        if row["cache_mode"] == "cold":
            records.append(row)
        elif row["cache_mode"] != "warm":
            raise ValueError("Unknown source profile cache mode")
    if len(records) != len(expected) or len({r["sample_id"] for r in records}) != len(expected):
        raise ValueError("Cold profile rows do not cover the fixed cohort exactly once")
    counts = {f"{part}/{label}": count for (part, label), count in Counter((r["split"], str(r["Label"])) for r in records).items()}
    if counts != cfg["expected_counts"]:
        raise ValueError("Profile development class/partition counts changed")
    for row in records:
        code = row.get("code")
        if code is not None and (code.get("schema_version") != "pdf-code-inspection-v5"
                or code.get("active_content_executed") is not False or code.get("content_redacted") is not True):
            raise ValueError("Unexpected profile code schema or execution state")
        static = row.get("static")
        if static is not None and static.get("input", {}).get("sha256") != row["pdf_sha256"]:
            raise ValueError("Measured snapshot does not match the locked file identity")
    return records, method


def profile_input_available(row, max_bytes):
    """Experimental raw-feature fallback needs measured, checksum-verified bytes."""
    static = row.get("static") or {}
    size = static.get("input", {}).get("size_bytes")
    raw = static.get("features") or {}
    return bool(row["status"] in {"complete", "partial", "parser_error"}
        and type(size) is int and 0 < size <= max_bytes
        and row.get("timings", {}).get("read_hash") is not None
        and row.get("timings", {}).get("raw_scan") is not None
        and all(type(raw.get(name)) in (int, float) and np.isfinite(raw[name])
                for name in ("pdfsize", "pdf_ver", "obj", "endobj", "stream", "endstream", "JS", "JavaScript", "startxref")))


def _profile_scores(labels, probabilities, planned):
    predicted = probabilities >= 0.5
    tp = int(((labels == 1) & predicted).sum()); fp = int(((labels == 0) & predicted).sum())
    positive, negative = int((labels == 1).sum()), int((labels == 0).sum())
    return {"classified": len(labels), "planned": sum(planned.values()), "coverage": len(labels) / sum(planned.values()),
        "refusals": sum(planned.values()) - len(labels), "malicious_classified": positive, "benign_classified": negative,
        "malicious_planned": planned[1], "benign_planned": planned[0], "true_positives": tp, "false_positives": fp,
        "recall_malicious_classified": tp / positive if positive else None, "fpr_classified": fp / negative if negative else None,
        "detected_fraction_all_malicious": tp / planned[1] if planned[1] else None,
        "false_positive_fraction_all_benign": fp / planned[0] if planned[0] else None,
        "metrics_classified": calibration_metrics(labels, probabilities, threshold=0.5) if len(labels) else None}


def train_cic_profile(root, cfg):
    """Fixed Train-only RF ablations over saved v5 evidence, including failures.

    Experimental fallback policies are evaluated here; the production refusal
    gate and original frozen RIT estimator remain unchanged.
    """
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.impute import SimpleImputer
    from sklearn.pipeline import make_pipeline
    import joblib

    root = Path(root).absolute()
    clean_code(root)
    if cfg["seed"] != 42 or cfg["threshold"] != 0.5:
        raise ValueError("Locked seed/threshold changed")

    method = {"protocol": "retrospective CIC observed-evidence and raw-feature fallback ablation",
        "configuration": cfg, "feature_schema": PROFILE_FEATURE_SCHEMA, "variants": list(PROFILE_VARIANTS),
        "feature_orders": {name: list(profile_feature_values({}, name)) for name in PROFILE_VARIANTS},
        "feature_definitions": {"RIT41": "canonical measured features and original -1/null conventions",
            "complete": "existing complete-only structure/AST totals; partial totals stay null",
            "observed": "lower bounds on traversed objects and successfully parsed scripts; null when step unavailable",
            "status": "explicit parser/analysis coverage; ablated separately; no paths/hashes/IDs/dataset/timing predictors"},
        "selection": "three fixed ablations, original RF budget and threshold0.5; no selection/calibration/tuning/Test",
        "eligibility": "known capped, checksum-verified byte snapshot and measured raw features; parser failures retained; no all-null/default-benign vector",
        "preprocessing": "median imputation/missing indicators fit on eligible CIC Train only; original raw null/-1 evidence unchanged",
        "deployment": "experimental LAB-only candidates; no automatic production promotion or RIT advanced-feature padding",
        "subgroups": "fixed source analysis-status strata, with full class/refusal denominators; descriptive only",
        "limitations": "balanced first64 pilot; previously exposed Validation; not independent Test or new raw-to-result timing",
        "test_access": False, "pdf_access": False}
    with ResearchRun(root, "cic_profile_accuracy", method) as run:
        set_random_seed(42)
        records, source_method = load_profile_development(root, cfg)
        labels = np.asarray([int(row["Label"]) for row in records])
        eligible = np.asarray([profile_input_available(row, source_method["configuration"]["limits"]["max_file_bytes"]) for row in records])
        train = eligible & np.asarray([row["split"] == "train" for row in records])
        validation = eligible & np.asarray([row["split"] == "validation" for row in records])
        planned = Counter(int(row["Label"]) for row in records if row["split"] == "validation")
        if set(labels[train]) != {0, 1} or set(labels[validation]) != {0, 1}:
            raise ValueError("Insufficient known-input Train/Validation classes for fixed fallback study")
        output, predictions = {}, {}
        for variant in PROFILE_VARIANTS:
            rows = [profile_feature_values(row, variant) for row in records]
            features = pd.DataFrame(rows, columns=method["feature_orders"][variant], dtype=float)
            vectors = [tuple(None if pd.isna(value) else float(value) for value in row) for row in features.to_numpy()]
            if {v for v, mask in zip(vectors, train) if mask} & {v for v, mask in zip(vectors, validation) if mask}:
                raise ValueError("Derived feature-equivalence groups cross the saved split")
            model = make_pipeline(SimpleImputer(strategy="median", add_indicator=True, keep_empty_features=True),
                RandomForestClassifier(**cfg["rf"], random_state=42, n_jobs=1))
            model.fit(features.loc[train], labels[train])
            probabilities = model.predict_proba(features.loc[validation])[:, 1]
            score = _profile_scores(labels[validation], probabilities, planned)
            score.update(train_available=int(train.sum()), feature_count=features.shape[1], threshold=0.5)
            score["by_analysis_status"] = {}
            for status in sorted({r["status"] for r in records if r["split"] == "validation"}):
                subset = np.asarray([r["status"] == status for r in records])
                subgroup_planned = Counter(int(r["Label"]) for r in records if r["split"] == "validation" and r["status"] == status)
                score["by_analysis_status"][status] = _profile_scores(labels[validation & subset],
                    probabilities[subset[validation]], subgroup_planned)
            output[variant] = score
            run.state["metrics"][variant + "/cic_development_known_input"] = score["metrics_classified"]
            target = run.artifacts / (variant + ".joblib")
            joblib.dump(model, target)
            write_json(run.report / (variant + "_manifest.json"), {"model_id": variant + "-v1", "feature_schema": PROFILE_FEATURE_SCHEMA,
                "feature_order": method["feature_orders"][variant], "artifact_relative_path": str(target.relative_to(root)),
                "artifact_sha256": hashlib.sha256(target.read_bytes()).hexdigest(), "threshold": 0.5, "seed": 42,
                "training_rows": int(train.sum()), "source_profile": cfg["source_profile"], "configuration": cfg["rf"],
                "preprocessing_fit_scope": "eligible CIC Train only", "promotion": False,
                "artifact_scope": "trusted generated LAB-only sklearn binary; never transfer to host for loading"})
            predictions[variant] = probabilities.tolist()
        baseline = json.loads(_profile_content(root, cfg["profile_comparison"], "reports/experiments"))
        write_json(run.report / "validation_comparison.json", {"status": "completed", "models": output,
            "saved_strict_pilot": baseline, "scope": method["limitations"],
            "comparability": "P0/P1/P2 share all eligible Train/dev rows; old C0/C1 used fewer Train rows and have a different refusal policy; compare all-class detection/false-positive fractions and denominators, not only conditional recall"})
        write_json(run.artifacts / "validation_predictions.json", {"sample_ids": [r["sample_id"] for r, keep in zip(records, validation) if keep],
            "probabilities": predictions, "labels": labels[validation].tolist()})
        run.state["notes"] = "Fixed CIC Train-only RF ablations use canonical measurements plus explicitly named observed lower bounds and separately ablated coverage flags. Parser errors remain in evaluation; no fake RIT AST, Test/raw-PDF access, threshold selection or deployment. Validation was already exposed and pilot is small. Raw bytes-to-result timing awaits a separately locked offline job if a candidate warrants it."
    return run.state


def load_development_tables(root, cfg):
    """Discard Test identities before converting any feature values to numbers."""
    split = checked_table(root, cfg["split_manifest"])
    sources = checked_table(root, cfg["source_manifest"])
    select_subset(split, sources, count=cfg.get("audit_stratum_size", 32))
    indexed = {row["sample_id"]: row for row in sources}
    chosen = [{**row, **{key: indexed[row["sample_id"]][key] for key in ("pdf_sha256", "pdf_relative_path", "related_group_id")}}
              for row in split if row["cohort"] == "cic" and row["split"] in {"train", "validation"}]
    verify_label_provenance(chosen, checked_table(root, cfg["normalization_manifest"]))
    selected = {row["sample_id"]: row for row in chosen}
    records = {}
    for row in checked_table(root, cfg["feature_table"]):
        identifier = row["sample_id"]
        if identifier not in selected:
            continue
        if identifier in records or row["Label"] != selected[identifier]["Label"]:
            raise ValueError("Cached feature identity/label changed")
        values = {name: float(row[name]) if row[name] else np.nan for name in CIC_FEATURE_ORDER}
        if any(np.isinf(value) for value in values.values()):
            raise ValueError("Non-finite cached static measurement")
        records[identifier] = {**selected[identifier], **values,
            **{name: float(row[name]) if row[name] else np.nan for name in EXCLUDED_CONSTANT_FEATURES}}
    if set(records) != set(selected):
        raise ValueError("Cached feature table lacks selected CIC development rows")
    frame = pd.DataFrame([records[key] for key in sorted(records)])
    if frame.groupby("duplicate_group_id").split.nunique().max() != 1:
        raise ValueError("Saved groups cross development partitions")
    counts = {f"{part}/{label}": n for (part, label), n in Counter(zip(frame.split, frame.Label)).items()}
    if counts != cfg["expected_counts"]:
        raise ValueError("CIC development class/partition counts changed")
    train = frame.loc[frame.split.eq("train")]
    if any(train[name].nunique(dropna=False) != 1 or train[name].iloc[0] != 0 for name in EXCLUDED_CONSTANT_FEATURES):
        raise ValueError("Previously excluded constants are not zero constants on CIC Train")
    def vector_keys(cell):
        return {tuple(None if pd.isna(value) else float(value) for value in row)
                for row in cell.loc[:, list(CIC_FEATURE_ORDER)].to_numpy()}
    if vector_keys(train) & vector_keys(frame.loc[frame.split.eq("validation")]):
        raise ValueError("Model feature-equivalence groups cross the saved split")
    return frame


def feature_information(frame):
    """Descriptive label collision bound; this is not attainable model accuracy."""
    output = {}
    for partition, rows in frame.groupby("split"):
        vectors = {}
        for _, row in rows.iterrows():
            key = tuple(None if pd.isna(row[name]) else float(row[name]) for name in CIC_FEATURE_ORDER)
            vectors.setdefault(key, Counter())[int(row.Label)] += 1
        output[partition] = {"rows": len(rows), "unique_vectors": len(vectors),
            "conflicting_vectors": sum(len(labels) > 1 for labels in vectors.values()),
            "label_oracle_correct_ceiling": sum(max(labels.values()) for labels in vectors.values()),
            "interpretation": "diagnostic ceiling on these labeled vectors only; no classifier/generalization claim"}
    return output


def load_cic_candidate(root, identifier):
    if re.fullmatch(r"run_[A-Za-z0-9_-]{1,100}", identifier or "") is None:
        raise ValueError("Unsafe CIC candidate run identifier")
    report = root / "reports/experiments/cic_static_accuracy" / identifier
    state = json.loads(read_bounded_bytes(report / "run_summary.json", boundary=root / "reports/experiments", max_bytes=1024**2))
    if state["status"] != "completed":
        raise ValueError("CIC candidate study did not complete")
    spec = json.loads(read_bounded_bytes(report / "model_manifest.json", boundary=root / "reports/experiments", max_bytes=64 * 1024))
    expected = {"model_id": CIC_MODEL_ID, "feature_order": list(CIC_FEATURE_ORDER), "feature_schema": CIC_FEATURE_SCHEMA,
        "threshold": 0.5, "model_configuration": model_configurations(42)["xgboost"]}
    if any(spec.get(name) != value for name, value in expected.items()):
        raise ValueError("CIC candidate contract changed")
    target = root / "artifacts/cic_static_accuracy" / identifier / "cic_xgb40.json"
    if spec["artifact_relative_path"] != str(target.relative_to(root)):
        raise ValueError("CIC candidate artifact path changed")
    content = read_bounded_bytes(target, boundary=root / "artifacts/cic_static_accuracy", max_bytes=64 * 1024**2)
    if hashlib.sha256(content).hexdigest() != spec["artifact_sha256"]:
        raise ValueError("CIC candidate checksum changed")
    from xgboost import XGBClassifier
    model = XGBClassifier()
    model.load_model(bytearray(content))
    if tuple(model.get_booster().feature_names or ()) != CIC_FEATURE_ORDER or not np.array_equal(model.classes_, [0, 1]):
        raise ValueError("CIC candidate binary/feature schema changed")
    model.set_params(n_jobs=1)
    return model, spec


def train_cic_static(root, configuration):
    root = Path(root).absolute()
    clean_code(root)
    cfg = yaml.safe_load(Path(configuration).read_text())
    if cfg["seed"] != 42 or cfg["threshold"] != 0.5:
        raise ValueError("Locked seed/threshold changed")
    if "source_profile" in cfg:
        return train_cic_profile(root, cfg)
    method = {"protocol": "retrospective CIC Train-only static adaptation; saved Protocol G partitions",
        "configuration": cfg, "feature_order": list(CIC_FEATURE_ORDER),
        "model_configuration": model_configurations(42)["xgboost"],
        "selection": "one fixed candidate; no hyperparameter/calibration/threshold selection",
        "baseline": "frozen user-supplied RIT G-drop3constant; original training lineage user-reported",
        "test_access": False, "pdf_access": False,
        "scope": "cached numeric feature classification; raw-to-result coverage/latency require offline PDF benchmark",
        "limitations": "Validation previously exposed; RIT PDF overlap cannot be excluded from CSV-only identities"}
    with ResearchRun(root, "cic_static_accuracy", method) as run:
        set_random_seed(42)
        frame = load_development_tables(root, cfg)
        train = frame.split.eq("train").to_numpy()
        validation = frame.split.eq("validation").to_numpy()
        features = frame.loc[:, list(CIC_FEATURE_ORDER)]
        # Common finite eligibility keeps baseline/candidate denominators equal.
        eligible = np.isfinite(features.to_numpy()).all(axis=1)
        baseline_bytes = read_bounded_bytes(root / cfg["baseline_manifest"]["path"],
            boundary=root / "reports/experiments", max_bytes=64 * 1024)
        if hashlib.sha256(baseline_bytes).hexdigest() != cfg["baseline_manifest"]["sha256"]:
            raise ValueError("Frozen RIT model metadata checksum changed")
        baseline_spec = json.loads(baseline_bytes)
        baseline, _ = load_profile_model(root, baseline_spec)
        baseline.set_params(n_jobs=1)
        candidate = create_model("xgboost", 42)
        candidate.fit(features.loc[train], frame.loc[train, "Label"].astype(int))
        target = run.artifacts / "cic_xgb40.json"
        candidate.save_model(str(target))
        manifest = {"model_id": CIC_MODEL_ID, "artifact_relative_path": str(target.relative_to(root)),
            "artifact_sha256": hashlib.sha256(target.read_bytes()).hexdigest(), "feature_schema": CIC_FEATURE_SCHEMA,
            "feature_order": list(CIC_FEATURE_ORDER), "threshold": 0.5,
            "model_configuration": model_configurations(42)["xgboost"],
            "training_dataset": {"sha256": cfg["feature_table"]["sha256"], "training_rows": int(train.sum()),
                "fit_scope": "saved CIC Train only; no Test rows used"},
            "excluded_train_constants": list(EXCLUDED_CONSTANT_FEATURES), "excluded_nonpredictors": ["sample_id", "Label", "split", "cohort", "path", "hash", "source", "parser_failed"]}
        write_json(run.report / "model_manifest.json", manifest)
        mask = validation & eligible
        output = {}
        probabilities = {}
        for name, model, columns in (("RIT_frozen_to_CIC", baseline, DEPLOYMENT_FEATURE_ORDER),
                                      ("CIC_train_static40", candidate, CIC_FEATURE_ORDER)):
            scores = model.predict_proba(features.loc[mask, list(columns)])[:, 1]
            labels = frame.loc[mask, "Label"].astype(int).to_numpy()
            metrics = calibration_metrics(labels, scores, threshold=0.5)
            predicted = scores >= 0.5
            planned_malicious = int((validation & frame.Label.eq("1").to_numpy()).sum())
            planned_benign = int(validation.sum()) - planned_malicious
            output[name] = {"metrics": metrics, "validation_planned": int(validation.sum()), "classified": int(mask.sum()),
                "coverage_numeric": float(mask.sum() / validation.sum()), "refusals": int((validation & ~eligible).sum()),
                "malicious_planned": planned_malicious, "benign_planned": planned_benign,
                "malicious_classified": int((labels == 1).sum()), "benign_classified": int((labels == 0).sum()),
                "tp": int(((labels == 1) & predicted).sum()), "fp": int(((labels == 0) & predicted).sum()),
                "fpr": float(predicted[labels == 0].mean()), "recall_malicious": metrics["recall_malicious"]}
            probabilities[name] = scores.tolist()
            run.state["metrics"][name + "/cic_validation_numeric"] = metrics
        write_json(run.report / "validation_comparison.json", {"models": output,
            "scope": "same cached CIC Validation rows; numeric eligibility only; no new raw-PDF coverage or independent Test claim"})
        write_json(run.report / "feature_information.json", feature_information(frame))
        write_json(run.artifacts / "validation_predictions.json", {"sample_ids": frame.loc[mask, "sample_id"].tolist(), "probabilities": probabilities})
        run.state["notes"] = "Fixed CIC Train-only XGBoost candidate compared with preserved frozen RIT model on the same cached Validation rows. Native candidate artifact ignored; threshold0.5 unchanged; no tuning/Test/PDF access. Validation was previously exposed; no independent generalization or raw-pipeline improvement claimed."
    return run.state
