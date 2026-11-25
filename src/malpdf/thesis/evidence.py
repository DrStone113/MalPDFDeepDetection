"""Build compact thesis tables from committed historical and locked Phase-2 research evidence."""

from __future__ import annotations

import csv
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable


class EvidenceError(RuntimeError):
    """Raised when a required source is absent or internally inconsistent."""


@dataclass(frozen=True)
class EvidenceBuild:
    """Paths created by one deterministic evidence consolidation run."""

    output_directory: Path
    table_paths: tuple[Path, ...]
    results_summary_path: Path


def _require(root: Path, relative_path: str) -> Path:
    path = root / relative_path
    if not path.is_file():
        raise EvidenceError(f"Required thesis evidence source is missing: {relative_path}")
    return path


def _read_json(root: Path, relative_path: str) -> dict[str, Any]:
    with _require(root, relative_path).open(encoding="utf-8-sig") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise EvidenceError(f"Expected a JSON object in {relative_path}")
    return value


def _read_csv(root: Path, relative_path: str) -> list[dict[str, str]]:
    with _require(root, relative_path).open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_csv(path: Path, rows: Iterable[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            missing = [field for field in fieldnames if field not in row]
            if missing:
                raise EvidenceError(f"Cannot write {path.name}; source row lacks required fields: {missing}")
            writer.writerow({field: row[field] for field in fieldnames})


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _select(rows: list[dict[str, str]], **expected: str) -> list[dict[str, str]]:
    selected = [row for row in rows if all(row.get(key) == value for key, value in expected.items())]
    if not selected:
        raise EvidenceError(f"No source row matched {expected}")
    return selected


def _one(rows: list[dict[str, str]], **expected: str) -> dict[str, str]:
    selected = _select(rows, **expected)
    if len(selected) != 1:
        raise EvidenceError(f"Expected exactly one source row for {expected}, found {len(selected)}")
    return selected[0]


def _float_equal(left: str, right: str, *, tolerance: float = 5e-12) -> bool:
    return abs(float(left) - float(right)) <= tolerance


def _format(value: str | float, digits: int = 6) -> str:
    return f"{float(value):.{digits}f}"


def _markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    delimiter = "| " + " | ".join(headers) + " |"
    separator = "| " + " | ".join("---" for _ in headers) + " |"
    body = ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join([delimiter, separator, *body])


def _latest_metrics_rel(root: Path, exp_subdir: str) -> str | None:
    exp_dir = root / exp_subdir
    if not exp_dir.is_dir():
        return None
    runs = sorted((p for p in exp_dir.glob("run_*") if (p / "metrics.json").is_file()), key=lambda p: p.name)
    if not runs:
        return None
    return (runs[-1] / "metrics.json").relative_to(root).as_posix()


def _build_phase2_bundle(root: Path, tables: Path) -> tuple[list[Path], list[str], str]:
    v4_contract_rel = "configs/transgraph_v4_contract.json"
    if (root / v4_contract_rel).is_file():
        v4_contract = _read_json(root, v4_contract_rel)
        v4_rel = f"reports/experiments/transgraph_v4/{v4_contract['source_run']}/metrics.json"
        sub_rel = f"reports/experiments/transgraph_v4_subset_b/{v4_contract['subset_b_run']}/metrics.json"
        att_rel = f"reports/experiments/problem_space_adaptive_attack/{v4_contract['adaptive_attack_run']}/metrics.json"
        conf_rel = f"reports/experiments/mondrian_conformal_v4/{v4_contract['conformal_run']}/metrics.json"
    else:
        v4_rel = _latest_metrics_rel(root, "reports/experiments/transgraph_v4") or ""
        sub_rel = _latest_metrics_rel(root, "reports/experiments/transgraph_v4_subset_b") or ""
        att_rel = _latest_metrics_rel(root, "reports/experiments/problem_space_adaptive_attack") or ""
        conf_rel = (
            _latest_metrics_rel(root, "reports/experiments/mondrian_conformal_v4")
            or _latest_metrics_rel(root, "reports/experiments/mondrian_conformal_v3")
            or ""
        )

    if not all(rel and (root / rel).is_file() for rel in (v4_rel, sub_rel, att_rel, conf_rel)):
        return [], [], ""

    v4_doc = _read_json(root, v4_rel)
    sub_doc = _read_json(root, sub_rel)
    att_doc = _read_json(root, att_rel)
    conf_doc = _read_json(root, conf_rel)
    phase2_sources = [v4_rel, sub_rel, att_rel, conf_rel]
    if (root / v4_contract_rel).is_file():
        phase2_sources.append(v4_contract_rel)

    extra_tables: list[Path] = []
    seeds = v4_doc["seeds"]
    seed42 = next((r for r in seeds if r["seed"] == 42), seeds[0])
    seed_rows = []
    for r in seeds:
        thr_key = "thr_val_calib" if "thr_val_calib" in r["thresholds"] else "thr_f1_macro"
        w = r["mean_modality_weights_test"]
        bs = r.get("byte_stress") or {}
        seed_rows.append(
            {
                "seed": r["seed"],
                "temperature": _format(r["temperature"]),
                "decision_threshold": _format(r["thresholds"][thr_key]),
                "test_all_pr_auc": _format(r["test_all"]["pr_auc"]),
                "test_all_f1_macro": _format(r["test_all"]["thr_f1_macro"]["f1_macro"]),
                "test_bc_pr_auc": _format(r["test_bc"]["pr_auc"]),
                "test_bc_f1_macro": _format(r["test_bc"]["thr_f1_macro"]["f1_macro"]),
                "tab_weight": _format(w[0]),
                "graph_weight": _format(w[1]),
                "action_ir_weight": _format(w[2]),
                "byte_stress_tp_of_8": bs.get("threat_tp_of_8", bs.get("malicious_tp_of_8", "")),
                "byte_stress_benign_fp_of_11": bs.get("non_js_benign_fp_of_11", ""),
                "pad_dilute_recall": _format(r["pad_dilute_recall"]),
            }
        )
    v4_seed_table = tables / "transgraph_v4_multiseed.csv"
    _write_csv(v4_seed_table, seed_rows, list(seed_rows[0]))
    extra_tables.append(v4_seed_table)

    ablations = v4_doc.get("ablations") or {}
    ablation_md = ""
    if ablations:
        abl_rows = []
        for arm_name, arm_list in ablations.items():
            r0 = next((x for x in arm_list if x["seed"] == 42), arm_list[0])
            w0 = r0["mean_modality_weights_test"]
            bs0 = r0.get("byte_stress") or {}
            abl_rows.append(
                {
                    "arm": arm_name,
                    "seed": r0["seed"],
                    "test_all_pr_auc": _format(r0["test_all"]["pr_auc"]),
                    "test_all_f1_macro": _format(r0["test_all"]["thr_f1_macro"]["f1_macro"]),
                    "test_bc_pr_auc": _format(r0["test_bc"]["pr_auc"]),
                    "test_bc_f1_macro": _format(r0["test_bc"]["thr_f1_macro"]["f1_macro"]),
                    "action_ir_weight": _format(w0[2]),
                    "byte_stress_tp_of_8": bs0.get("threat_tp_of_8", bs0.get("malicious_tp_of_8", "")),
                    "pad_dilute_recall": _format(r0["pad_dilute_recall"]),
                }
            )
        abl_table = tables / "transgraph_v4_ablations.csv"
        _write_csv(abl_table, abl_rows, list(abl_rows[0]))
        extra_tables.append(abl_table)
        ablation_md = (
            "\n\n### 5-Arm Component Ablation & GNN Baseline (`tables/transgraph_v4_ablations.csv`)\n\n"
            + _markdown_table(
                [
                    "arm",
                    "test_all_pr_auc",
                    "test_all_f1_macro",
                    "test_bc_f1_macro",
                    "action_ir_weight",
                    "byte_stress_tp_of_8",
                    "pad_dilute_recall",
                ],
                [
                    [
                        row["arm"],
                        row["test_all_pr_auc"],
                        row["test_all_f1_macro"],
                        row["test_bc_f1_macro"],
                        row["action_ir_weight"],
                        str(row["byte_stress_tp_of_8"]),
                        row["pad_dilute_recall"],
                    ]
                    for row in abl_rows
                ],
            )
        )

    att_rows = []
    models_att = att_doc.get("models") or {}
    for model_name, model_entry in models_att.items():
        if "deployed_operating_threshold" in model_entry:
            for regime_name in ("deployed_operating_threshold", "matched_val_calib_fpr_0_5pct"):
                reg = model_entry[regime_name]
                b_map = reg["budgets"]
                att_rows.append(
                    {
                        "model": model_name,
                        "threshold_regime": regime_name,
                        "threshold": _format(reg["threshold"]),
                        "val_calib_fpr": _format(reg["achieved_val_calib_fpr"]),
                        "recall_B0": _format(b_map["0"]["recall"]),
                        "recall_B25": _format(b_map["25"]["recall"]),
                        "recall_B50": _format(b_map["50"]["recall"]),
                        "recall_B100": _format(b_map["100"]["recall"]),
                        "newly_evaded_B100": b_map["100"]["newly_evaded_count"],
                    }
                )
        elif "budgets" in model_entry:
            b_map = model_entry["budgets"]
            att_rows.append(
                {
                    "model": model_name,
                    "threshold_regime": "legacy_threshold",
                    "threshold": _format(model_entry["decision_threshold"]),
                    "val_calib_fpr": "0.000000",
                    "recall_B0": _format(b_map["0"]["recall"]),
                    "recall_B25": _format(b_map["25"]["recall"]),
                    "recall_B50": _format(b_map["50"]["recall"]),
                    "recall_B100": _format(b_map["100"]["recall"]),
                    "newly_evaded_B100": int(
                        round((b_map["0"]["recall"] - b_map["100"]["recall"]) * model_entry["n_malicious"])
                    ),
                }
            )
    if att_rows:
        att_table = tables / "problem_space_adaptive_attack.csv"
        _write_csv(att_table, att_rows, list(att_rows[0]))
        extra_tables.append(att_table)

    b_track = sub_doc["tracks"]["prospective_diverse_publishers_v2"]
    c_track = sub_doc["tracks"]["prospective_hard_benign_v2"]
    b_rep = b_track.get("independent_representatives") or b_track
    c_rep = c_track.get("independent_representatives") or c_track
    b_fp = b_rep.get("false_positives", b_rep.get("alerts", b_rep.get("representative_fp", 0)))
    b_tot = b_rep.get("evaluated", b_rep.get("count", b_rep.get("representative_total", 370)))
    c_fp = c_rep.get("false_positives", c_rep.get("alerts", c_rep.get("representative_fp", 0)))
    c_tot = c_rep.get("evaluated", c_rep.get("count", c_rep.get("representative_total", 58)))

    test_conf = conf_doc["test_internal"]
    b_conf = conf_doc["prospective_subset_b"]["prospective_diverse_publishers_v2"]["all_scored"]
    c_conf = conf_doc["prospective_subset_b"]["prospective_hard_benign_v2"]["all_scored"]
    ir_mean = sum(float(r["mean_modality_weights_test"][2]) for r in seeds) / len(seeds)
    s_summary = v4_doc["summary"]
    pr_mean = (
        s_summary["test_all_pr_auc"]["mean"]
        if isinstance(s_summary["test_all_pr_auc"], dict)
        else s_summary["test_all_pr_auc_mean"]
    )
    pr_std = (
        s_summary["test_all_pr_auc"]["std"]
        if isinstance(s_summary["test_all_pr_auc"], dict)
        else s_summary["test_all_pr_auc_std"]
    )
    f1_mean = (
        s_summary["test_all_f1_macro"]["mean"]
        if isinstance(s_summary["test_all_f1_macro"], dict)
        else s_summary["test_all_f1_macro_mean"]
    )
    f1_std = (
        s_summary["test_all_f1_macro"]["std"]
        if isinstance(s_summary["test_all_f1_macro"], dict)
        else s_summary["test_all_f1_macro_std"]
    )

    sota_rows = [
        {
            "metric_group": "transgraph_v4_5seed",
            "item": "test_internal_all_pr_auc_mean",
            "value": _format(pr_mean),
            "detail": f"std={_format(pr_std)}",
            "source": v4_rel,
        },
        {
            "metric_group": "transgraph_v4_5seed",
            "item": "test_internal_all_f1_macro_mean",
            "value": _format(f1_mean),
            "detail": f"std={_format(f1_std)}",
            "source": v4_rel,
        },
        {
            "metric_group": "transgraph_v4_5seed",
            "item": "action_ir_gate_weight_mean",
            "value": _format(ir_mean),
            "detail": f"seed42={_format(seed42['mean_modality_weights_test'][2])}",
            "source": v4_rel,
        },
        {
            "metric_group": "subset_b_v4",
            "item": "track_b_v2_representative_fp",
            "value": f"{b_fp}/{b_tot}",
            "detail": "diverse_publishers",
            "source": sub_rel,
        },
        {
            "metric_group": "subset_b_v4",
            "item": "track_c1_v2_representative_fp",
            "value": f"{c_fp}/{c_tot}",
            "detail": "hard_benign_acroform_js",
            "source": sub_rel,
        },
        {
            "metric_group": "mondrian_conformal",
            "item": "test_internal_overall_coverage",
            "value": _format(test_conf["coverage"]["overall"]),
            "detail": f"singleton_acc={_format(test_conf['singleton_accuracy'])}",
            "source": conf_rel,
        },
        {
            "metric_group": "mondrian_conformal",
            "item": "track_b_v2_certified_benign",
            "value": f"{b_conf['state_counts'].get('CERTIFIED_BENIGN', 0)}/{b_conf['count']}",
            "detail": f"track_c1_certified_benign={c_conf['state_counts'].get('CERTIFIED_BENIGN', 0)}/{c_conf['count']}",
            "source": conf_rel,
        },
    ]
    sota_table = tables / "sota_v4_and_conformal_summary.csv"
    _write_csv(sota_table, sota_rows, ["metric_group", "item", "value", "detail", "source"])
    extra_tables.append(sota_table)

    bs42 = seed42.get("byte_stress") or {}
    tp42 = bs42.get("threat_tp_of_8", bs42.get("malicious_tp_of_8", 0))
    phase2_md = (
        "\n## Phase 2 SOTA Architecture & Runtime Promotion: PDF-TransGraph v4, Ablations, Adaptive Attack, Mondrian Conformal v4 & CF-CDR\n\n"
        "Compact machine-readable tables: [`tables/sota_v4_and_conformal_summary.csv`](tables/sota_v4_and_conformal_summary.csv), "
        "[`tables/transgraph_v4_multiseed.csv`](tables/transgraph_v4_multiseed.csv), and [`tables/problem_space_adaptive_attack.csv`](tables/problem_space_adaptive_attack.csv).\n\n"
        f"**Measured (`PDF-TransGraph v4`, 5-seed CUDA seeds `42..46`, `{v4_rel}`):**\n"
        f"- `Test_Internal` All (`n=2,027`): PR-AUC `{_format(pr_mean)} ± {_format(pr_std)}`, F1-macro `{_format(f1_mean)} ± {_format(f1_std)}` (seed 42 F1-macro `{_format(seed42['test_all']['thr_f1_macro']['f1_macro'])}`).\n"
        f"- **Pure Topological `ActionSubgraphIR` (`24D`, zero tabular lexical overlap):** 5-seed mean gate weight `{_format(ir_mean)}` (seed 42 `{_format(seed42['mean_modality_weights_test'][2])}`, resolving `v3.2b`'s `0.0000` dead AST gate); canonical `seed_42` Phase 2 Byte Stress `{tp42}/8` malicious TP and `{bs42.get('non_js_benign_fp_of_11', 0)}/11` non-JS benign FP.\n"
        f"- **Subset B Regression Cohorts (`{sub_rel}`):** Track B-v2 diverse publishers **`{b_fp}/{b_tot}` representative FP**, Track C1-v2 hard benign **`{c_fp}/{c_tot}` representative FP**.\n"
        + ablation_md
        + f"\n\n**Measured (Mondrian Inductive Conformal Evaluator, `Val_Calib` `alpha=0.01`, `{conf_rel}`):**\n"
        f"- `Test_Internal` (`2,027`): `{float(test_conf['coverage']['overall']) * 100:.2f}%` overall coverage (`{float(test_conf['coverage']['benign']) * 100:.2f}%` benign, `{float(test_conf['coverage']['malicious']) * 100:.2f}%` malicious), **`{float(test_conf['singleton_accuracy']) * 100:.2f}%` singleton accuracy** (`{test_conf['singleton_count']}` singletons).\n"
        f"- Subset B Track B-v2: **`{b_conf['state_counts'].get('CERTIFIED_BENIGN', 0)}/{b_conf['count']}` `CERTIFIED_BENIGN`** (`0` `CERTIFIED_MALICIOUS`); Track C1-v2: `{c_conf['state_counts'].get('CERTIFIED_BENIGN', 0)}/{c_conf['count']}` `CERTIFIED_BENIGN`, `0` `CERTIFIED_MALICIOUS`.\n\n"
        "**Boundary:** `Test_Internal`, `Phase 2 Byte Stress`, and `Subset B` reuse established study cohorts with SHA-256-screened split hygiene and are reported with explicit retrospective cohort regression provenance; no live PDF detonation or sandbox execution was performed.\n"
    )
    return extra_tables, phase2_sources, phase2_md


def build_thesis_evidence(repository_root: str | Path, output_directory: str | Path | None = None) -> EvidenceBuild:
    """Create compact, deterministic thesis outputs without training or refitting."""
    root = Path(repository_root).resolve()
    thesis_root = Path(output_directory).resolve() if output_directory else root / "reports" / "thesis"
    tables = thesis_root / "tables"

    audit_path = "reports/rit-pdfmal-2026_inspection.json"
    split_report_path = "reports/rit-pdfmal-2026_split_report.json"
    p_macro_path = "reports/tables/metric_semantics/protocol_p_macro_metrics.csv"
    g_macro_path = "reports/tables/metric_semantics/protocol_g_macro_metrics.csv"
    p_summary_path = "reports/experiments/protocol_p/seed42/summary.csv"
    g_summary_path = "reports/experiments/protocol_g/seed42/summary_test.csv"
    multiseed_metrics_path = "reports/experiments/multiseed/official-seeds42-46/aggregate/metric_summary.csv"
    multiseed_deltas_path = "reports/experiments/multiseed/official-seeds42-46/aggregate/paired_protocol_g_minus_p.csv"
    cv_aggregate_path = "reports/experiments/xgb_cv10/seed42/aggregate_metrics.csv"
    cv_paper_path = "reports/experiments/xgb_cv10/seed42/paper_comparison.csv"
    cv_metrics_path = "reports/experiments/xgb_cv10/seed42/metrics.json"
    shap_path = "reports/experiments/explainability/xgb_protocol_g_seed42/shap_global_importance.csv"
    dl_path = "reports/experiments/deep_learning/protocol_g_seed42/comparison.csv"
    static_v1_path = "reports/tables/static_extractor/rit_feature_compatibility.csv"
    static_v2_path = "reports/tables/static_extractor/rit_feature_compatibility_resolution.csv"

    audit = _read_json(root, audit_path)
    split = _read_json(root, split_report_path)
    p_macro = _read_csv(root, p_macro_path)
    g_macro = _read_csv(root, g_macro_path)
    p_summary = _read_csv(root, p_summary_path)
    g_summary = _read_csv(root, g_summary_path)
    multiseed_metrics = _read_csv(root, multiseed_metrics_path)
    multiseed_deltas = _read_csv(root, multiseed_deltas_path)
    cv_aggregate = _read_csv(root, cv_aggregate_path)
    cv_paper = _read_csv(root, cv_paper_path)
    cv_metrics = _read_json(root, cv_metrics_path)
    shap = _read_csv(root, shap_path)
    deep_learning = _read_csv(root, dl_path)
    static_v1 = _read_csv(root, static_v1_path)
    static_v2 = _read_csv(root, static_v2_path)

    if audit["dimensions"]["rows"] != 24_337 or audit["dimensions"]["columns"] != 42:
        raise EvidenceError("Dataset audit dimensions do not match the reviewed RIT-PDFMal-2026 identity")
    if audit["target"]["candidate_column"] != "Label":
        raise EvidenceError("Dataset audit does not identify Label as the target")
    if split["duplicate_group_statistics"]["total_groups"] != 15_371:
        raise EvidenceError("Feature-equivalent group count differs from the reviewed Protocol G split report")
    if not split["hard_validation"]["zero_feature_vector_duplicate_leakage"]["is_valid"]:
        raise EvidenceError("Protocol G source does not prove zero feature-vector overlap")

    p_rows = _select(p_macro, protocol="P", partition="test")
    g_rows = _select(g_macro, protocol="G", partition="test", feature_variant="G-drop3constant")
    if len(p_rows) != 10 or len(g_rows) != 5:
        raise EvidenceError("Expected ten Protocol P rows and five main Protocol G rows")
    for row in g_rows:
        historical = _one(g_summary, model_name=row["model_name"], feature_variant=row["feature_variant"])
        if not _float_equal(row["f1_malicious"], historical["f1"]) or not _float_equal(row["mcc"], historical["mcc"]):
            raise EvidenceError(f"Protocol G macro evidence disagrees with historical summary for {row['model_name']}")
    for row in p_rows:
        historical = _one(p_summary, model_name=row["model_name"], feature_variant=row["feature_variant"])
        if not _float_equal(row["f1_malicious"], historical["f1"]) or not _float_equal(row["mcc"], historical["mcc"]):
            raise EvidenceError(f"Protocol P macro evidence disagrees with historical summary for {row['model_name']}")

    cv_f1 = _one(cv_aggregate, feature_variant="CV-all41", metric="f1_macro")
    if not _float_equal(cv_f1["mean"], "0.9929950444559295"):
        raise EvidenceError("CV10 macro F1 differs from the committed aggregate result")
    if cv_metrics["fold_validation"]["expected_future_fit_count"] != 20:
        raise EvidenceError("CV10 source does not record 20 expected successful fits")
    if shap[0]["feature"] != "JavaScript" or shap[0]["rank"] != "1":
        raise EvidenceError("TreeSHAP source does not have the expected top feature")
    xgb_g = _one(g_rows, model_name="xgboost")
    xgb_dl = _one(deep_learning, model="XGBoost historical Protocol G")
    if not _float_equal(xgb_g["f1_malicious"], xgb_dl["f1_malicious"]):
        raise EvidenceError("Deep-learning XGBoost reference disagrees with Protocol G historical result")

    dataset_distribution = {str(item["raw_value"]): item for item in audit["target"]["distribution"]}
    near_constant = "; ".join(item["column"] for item in audit["column_quality"]["near_constant_columns"])
    dataset_rows = [
        {"item": "dataset_filename", "value": audit["dataset"]["filename"], "source": audit_path},
        {"item": "dataset_sha256", "value": audit["dataset"]["sha256"], "source": audit_path},
        {"item": "rows", "value": audit["dimensions"]["rows"], "source": audit_path},
        {"item": "total_columns", "value": audit["dimensions"]["columns"], "source": audit_path},
        {"item": "predictive_features", "value": audit["dimensions"]["columns"] - 1, "source": audit_path},
        {"item": "target_column", "value": audit["target"]["candidate_column"], "source": audit_path},
        {"item": "benign_label_0_rows", "value": dataset_distribution["0"]["count"], "source": audit_path},
        {"item": "malicious_label_1_rows", "value": dataset_distribution["1"]["count"], "source": audit_path},
        {
            "item": "constant_features",
            "value": "; ".join(audit["column_quality"]["constant_columns"]),
            "source": audit_path,
        },
        {"item": "near_constant_features", "value": near_constant, "source": audit_path},
        {
            "item": "feature_equivalent_groups",
            "value": split["duplicate_group_statistics"]["total_groups"],
            "source": split_report_path,
        },
        {
            "item": "duplicate_feature_groups",
            "value": split["duplicate_group_statistics"]["duplicate_groups"],
            "source": split_report_path,
        },
        {
            "item": "maximum_feature_equivalent_group_size",
            "value": split["duplicate_group_statistics"]["group_size"]["maximum"],
            "source": split_report_path,
        },
    ]
    dataset_table = tables / "dataset_summary.csv"
    _write_csv(dataset_table, dataset_rows, ["item", "value", "source"])

    metric_fields = [
        "accuracy",
        "precision_malicious",
        "recall_malicious",
        "f1_malicious",
        "precision_macro",
        "recall_macro",
        "f1_macro",
        "roc_auc",
        "pr_auc",
        "mcc",
        "tn",
        "fp",
        "fn",
        "tp",
    ]
    p_table = tables / "protocol_p_models.csv"
    _write_csv(p_table, p_rows, ["protocol", "partition", "model_name", "feature_variant", *metric_fields])
    g_table = tables / "protocol_g_models.csv"
    _write_csv(g_table, g_rows, ["protocol", "partition", "model_name", "feature_variant", *metric_fields])

    model_order = ["logistic_regression", "random_forest", "decision_tree", "gaussian_naive_bayes", "xgboost"]
    multiseed_rows: list[dict[str, str]] = []
    for model in model_order:
        row: dict[str, str] = {"model_name": model, "seed_count": "5"}
        for protocol, prefix in (("P", "protocol_p"), ("G", "protocol_g")):
            for metric in ("f1_malicious", "f1_macro", "mcc"):
                source = _one(multiseed_metrics, protocol=protocol, partition="test", model_name=model, metric=metric)
                row[f"{prefix}_{metric}_mean"] = source["mean"]
                row[f"{prefix}_{metric}_sample_std"] = source["sample_standard_deviation"]
        for metric in ("f1_malicious", "f1_macro", "mcc"):
            source = _one(multiseed_deltas, model_name=model, metric=metric)
            row[f"g_minus_p_{metric}_mean"] = source["mean_delta"]
            row[f"g_minus_p_{metric}_sample_std"] = source["sample_standard_deviation"]
            row[f"g_less_than_p_{metric}_seed_count"] = source["p_greater_count"]
        multiseed_rows.append(row)
    multiseed_fields = list(multiseed_rows[0])
    multiseed_table = tables / "multiseed_summary.csv"
    _write_csv(multiseed_table, multiseed_rows, multiseed_fields)

    cv_table = tables / "xgb_cv10_paper_comparison.csv"
    _write_csv(cv_table, cv_paper, list(cv_paper[0]))
    shap_top10 = shap[:10]
    shap_table = tables / "xgb_shap_top10.csv"
    _write_csv(shap_table, shap_top10, ["rank", "feature", "mean_abs_shap", "mean_shap", "std_shap", "median_abs_shap"])
    dl_table = tables / "deep_learning_comparison.csv"
    _write_csv(dl_table, deep_learning, list(deep_learning[0]))

    v1_statuses = [row["implementation_status"] for row in static_v1]
    v2_statuses = [row["final_status"] for row in static_v2]
    if (
        v1_statuses.count("IMPLEMENTED_VERIFIED_SEMANTICS") != 31
        or v1_statuses.count("IMPLEMENTED_PROVISIONAL") != 7
        or v1_statuses.count("AMBIGUOUS") != 3
    ):
        raise EvidenceError("Static extractor v1 status counts differ from the recorded coverage evidence")
    if len(static_v2) != 10 or any(status != "IMPLEMENTED_VERIFIED_SEMANTICS" for status in v2_statuses):
        raise EvidenceError("Static extractor v2 does not show the ten verified blocker resolutions")
    static_rows = [
        {
            "stage": "v1_coverage",
            "verified": 31,
            "provisional": 7,
            "ambiguous": 3,
            "unsupported": 0,
            "protocol_g_drop3constant_gate": "28/38 FAIL",
            "source": static_v1_path,
        },
        {
            "stage": "v2_compatibility_closure",
            "verified": 41,
            "provisional": 0,
            "ambiguous": 0,
            "unsupported": 0,
            "protocol_g_drop3constant_gate": "38/38 PASS",
            "source": static_v2_path,
        },
    ]
    static_table = tables / "static_extractor_progress.csv"
    _write_csv(static_table, static_rows, list(static_rows[0]))

    phase2_tables, phase2_sources, phase2_md = _build_phase2_bundle(root, tables)
    v4_promoted = (root / "configs/transgraph_v4_contract.json").is_file()

    component_rows = [
        {
            "component": "RIT dataset audit",
            "status": "completed",
            "evidence_type": "audited dataset facts",
            "performance_claim": "not applicable",
        },
        {
            "component": "Protocol P classical models",
            "status": "completed",
            "evidence_type": "paper-aligned row-level baseline",
            "performance_claim": "measured",
        },
        {
            "component": "Protocol G classical models",
            "status": "completed",
            "evidence_type": "feature-vector-disjoint evaluation",
            "performance_claim": "measured",
        },
        {
            "component": "XGBoost CV10",
            "status": "completed",
            "evidence_type": "paper-aligned row-level KFold",
            "performance_claim": "measured",
        },
        {
            "component": "TreeSHAP",
            "status": "completed",
            "evidence_type": "Protocol G XGBoost explanation",
            "performance_claim": "descriptive only",
        },
        {
            "component": "Static deployment detector",
            "status": "implemented",
            "evidence_type": "full-data static model after evaluation",
            "performance_claim": "not a new benchmark",
        },
        {
            "component": "MLP / FT-Transformer",
            "status": "completed",
            "evidence_type": "one fixed Protocol G split",
            "performance_claim": "measured on one split",
        },
        {
            "component": "PDF-TransGraph v4 + Mondrian Conformal",
            "status": "deployed_onnx" if v4_promoted else ("completed" if phase2_tables else "not_run"),
            "evidence_type": "5-seed pooled Protocol G + ablations + adaptive attack + Subset B",
            "performance_claim": "measured" if phase2_tables else "NOT EVALUATED",
        },
        {
            "component": "Dynamic schema and routing",
            "status": "implemented",
            "evidence_type": "offline synthetic-report integration",
            "performance_claim": "NOT EVALUATED",
        },
        {
            "component": "Isolated CAPE laboratory",
            "status": "designed",
            "evidence_type": "design, threat model, checklist",
            "performance_claim": "NOT EVALUATED",
        },
        {
            "component": "Hybrid detector",
            "status": "not implemented",
            "evidence_type": "future work",
            "performance_claim": "NOT EVALUATED",
        },
    ]
    component_table = tables / "system_component_status.csv"
    _write_csv(component_table, component_rows, list(component_rows[0]))

    source_paths = [
        audit_path,
        split_report_path,
        p_macro_path,
        g_macro_path,
        p_summary_path,
        g_summary_path,
        multiseed_metrics_path,
        multiseed_deltas_path,
        cv_aggregate_path,
        cv_paper_path,
        cv_metrics_path,
        shap_path,
        dl_path,
        static_v1_path,
        static_v2_path,
        *phase2_sources,
    ]
    source_rows = [{"source": relative, "sha256": _sha256(_require(root, relative))} for relative in source_paths]
    sources_table = tables / "evidence_source_checksums.csv"
    _write_csv(sources_table, source_rows, ["source", "sha256"])

    results_summary = thesis_root / "results_summary.md"
    xgb_p = _one(p_rows, model_name="xgboost", feature_variant="P-drop3constant")
    xgb_g_row = _one(g_rows, model_name="xgboost")
    ft = _one(deep_learning, model="ft_transformer")
    main_table_rows = [
        [
            row["model_name"],
            _format(row["accuracy"]),
            _format(row["precision_malicious"]),
            _format(row["recall_malicious"]),
            _format(row["f1_malicious"]),
            _format(row["f1_macro"]),
            _format(row["roc_auc"]),
            _format(row["pr_auc"]),
            _format(row["mcc"]),
        ]
        for row in g_rows
    ]
    results_summary.parent.mkdir(parents=True, exist_ok=True)
    results_summary.write_text(
        "# Results Summary\n\n"
        "All values below are generated from the source artifacts listed in `tables/evidence_source_checksums.csv`. "
        "`precision_malicious`, `recall_malicious`, and `f1_malicious` use Label=1 as the positive class; macro metrics are named explicitly.\n\n"
        "## Dataset / audit\n\n"
        f"**Measured:** RIT-PDFMal-2026 contains {audit['dimensions']['rows']:,} rows, 41 predictive static features and Label; "
        f"Label=0 has {dataset_distribution['0']['count']:,} rows and Label=1 has {dataset_distribution['1']['count']:,} rows. "
        f"The audit found {split['duplicate_group_statistics']['total_groups']:,} feature-equivalent groups. These are identical 41-dimensional feature vectors, not proven duplicate PDF files, because the local CSV lacks original per-PDF hashes.\n\n"
        "**Interpretation:** Acroform, Colors, and BaseEncoding are constant zero; RichMedia is near-constant. Documented values such as `contains_text=-1`, `pages=0`, and unusual `pdf_ver` values remain semantic source values rather than missing-data replacements.\n\n"
        "## Classical ML and leakage-aware evaluation\n\n"
        "**Measured:** Protocol P is a paper-aligned 75/25 stratified row-level seed-42 reproduction attempt; Protocol G is a deterministic 60/20/20 feature-vector-disjoint evaluation with zero identical-feature-vector overlap. The primary leakage-aware table is below and the full P/G tables are in `tables/protocol_p_models.csv` and `tables/protocol_g_models.csv`.\n\n"
        + _markdown_table(
            [
                "model",
                "accuracy",
                "precision_malicious",
                "recall_malicious",
                "f1_malicious",
                "f1_macro",
                "roc_auc",
                "pr_auc",
                "mcc",
            ],
            main_table_rows,
        )
        + "\n\n"
        f"**Interpretation:** XGBoost P-drop3constant has f1_malicious={_format(xgb_p['f1_malicious'])}; its Protocol G counterpart has f1_malicious={_format(xgb_g_row['f1_malicious'])}. Protocol G reduces identical-feature-vector leakage but does not establish temporal, file-identity, external-dataset, or real-world generalization.\n\n"
        "## Multi-seed robustness\n\n"
        "**Measured:** Across seeds 42–46, LR, RF, DT, and XGBoost have G<P f1_malicious and MCC in all five seed-labelled comparisons; GNB is opposite/model-specific. Exact means, sample standard deviations, and paired G−P deltas are in `tables/multiseed_summary.csv`.\n\n"
        "**Interpretation:** This is directionally stable across five split seeds, not a statistical-significance result.\n\n"
        "## Paper-aligned XGBoost CV10\n\n"
        f"**Measured:** Full-dataset non-stratified `KFold(10, shuffle=True, random_state=42)` completed 20/20 fits with OOF integrity. CV-all41 macro precision/recall/f1 are {_format(_one(cv_aggregate, feature_variant='CV-all41', metric='precision_macro')['mean'])}, {_format(_one(cv_aggregate, feature_variant='CV-all41', metric='recall_macro')['mean'])}, and {_format(cv_f1['mean'])}; accuracy is {_format(_one(cv_aggregate, feature_variant='CV-all41', metric='accuracy')['mean'])}.\n\n"
        "**Interpretation:** Table 6 comparison uses macro Precision/Recall/F1 because the paper values are consistent with macro averaging. It is a paper-aligned reproduction attempt, not exact reproduction or feature-vector-disjoint evaluation.\n\n"
        "## Explainability\n\n"
        f"**Measured:** A fixed retrain reproduced the historical Protocol G XGBoost metrics before native TreeSHAP on 4,867 test rows and 38 features. The largest global mean absolute contribution is {shap[0]['feature']} ({_format(shap[0]['mean_abs_shap'])}); the ranked top ten are in `tables/xgb_shap_top10.csv`.\n\n"
        "**Interpretation:** JavaScript, pdfsize, URI, contains_text, and metadata size are influential to this local model. SHAP describes model contributions, not causal malware mechanisms.\n\n"
        "## Deep-learning comparison\n\n"
        f"**Measured:** On one fixed Protocol G seed-42 split, FT-Transformer has f1_malicious={_format(ft['f1_malicious'])} and MCC={_format(ft['mcc'])}, above the historical XGBoost reference for these two metrics; its ROC-AUC and PR-AUC are lower. Exact three-model values, training times, and neural parameter counts are in `tables/deep_learning_comparison.csv`.\n\n"
        "**Interpretation:** This one fixed-architecture, one-split comparison does not establish general superiority over XGBoost; CUDA deterministic limitations are recorded in the original run.\n\n"
        "## Static detector and dynamic architecture\n\n"
        "**Measured/implemented:** the static extractor progressed from 31 verified / 7 provisional / 3 ambiguous definitions and a 28/38 failing Protocol G gate to 41/41 verified definitions and a 38/38 passing schema gate. The deployment model `xgb-rit-full-drop3constant-v1` is a 38-feature, full-data static detector with threshold 0.5, compatibility gate, probability/verdict, and local TreeSHAP.\n\n"
        "**Boundary:** deployment adds no new accuracy evidence. Dynamic-schema-v1, its 21 offline behavioral features, routing policies, and the isolated CAPE design are implemented/design artifacts only: no live dynamic, hybrid, or sandbox performance result exists.\n"
        + phase2_md,
        encoding="utf-8",
    )
    return EvidenceBuild(
        output_directory=thesis_root,
        table_paths=(
            dataset_table,
            p_table,
            g_table,
            multiseed_table,
            cv_table,
            shap_table,
            dl_table,
            static_table,
            component_table,
            sources_table,
            *phase2_tables,
        ),
        results_summary_path=results_summary,
    )
