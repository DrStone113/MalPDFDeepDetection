from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
import torch
from torch.utils.data import Dataset

from malpdf.data.graph_contract import NODE_FEATURE_DIM_V2, index_measured_graphs_v2
from malpdf.extraction.graph_projection_v2 import PROJECTION_CONTRACT_VERSION, SCHEMA_VERSION
from malpdf.extraction.quality_gate import GATE_CONTRACT_VERSION_V2, validate_cohort_gate_summary_v2


REQUIRED_EXPORT_FILES = frozenset({
    "hetero_graphs_v2.jsonl.gz",
    "locked_methodology.json",
    "quality_gate_summary.json",
    "tabular_features_v2.jsonl.gz",
    "unavailable_document_ledger.json",
})


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def safe_div_series(num: pd.Series, den: pd.Series) -> pd.Series:
    out = num.astype(float) / np.maximum(den.astype(float).abs(), 1.0)
    return out.replace([np.inf, -np.inf, np.nan], 0.0)


class MultimodalPDFDatasetV2(Dataset):
    def __init__(self, samples: list[dict]):
        self.samples = samples

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> dict:
        return self.samples[idx]


def collate_multimodal_batch_v2(batch: list[dict]) -> dict:
    all_node_feats = []
    all_node_types = []
    all_edge_src = []
    all_edge_dst = []
    all_edge_rel = []
    batch_indices = []
    ast_tokens_list = []
    tab_feats_list = []
    labels_list = []
    sha256_list = []
    indices_list = []
    sample_ids = []
    gnn_eligible_list = []
    current_node_offset = 0
    has_any_missing_graph = False

    for graph_idx, sample in enumerate(batch):
        nf = sample.get("node_features")
        nt = sample.get("node_types")
        if nf is None or nt is None or not sample.get("gnn_message_passing_eligible", False):
            has_any_missing_graph = True
        else:
            num_nodes = nf.size(0)
            if num_nodes <= 0:
                raise ValueError("empty_graph_in_gnn_batch_forbidden")
            all_node_feats.append(nf)
            all_node_types.append(nt)
            batch_indices.append(torch.full((num_nodes,), graph_idx, dtype=torch.long))
            e_src = sample["edge_src"]
            e_dst = sample["edge_dst"]
            if e_src.numel() > 0:
                all_edge_src.append(e_src + current_node_offset)
                all_edge_dst.append(e_dst + current_node_offset)
                all_edge_rel.append(sample["edge_rel"])
            current_node_offset += num_nodes
        ast_tokens_list.append(sample["ast_tokens"])
        tab_feats_list.append(sample["tab_features"])
        labels_list.append(sample["label"])
        sha256_list.append(sample["sha256"])
        indices_list.append(sample["index"])
        sample_ids.append(sample.get("sample_id", ""))
        gnn_eligible_list.append(bool(sample.get("gnn_message_passing_eligible", False)))

    if has_any_missing_graph and len(all_node_feats) > 0:
        raise ValueError("mixed_gnn_and_unavailable_graph_batch_forbidden")

    if len(all_node_feats) > 0:
        batched_node_feats = torch.cat(all_node_feats, dim=0)
        batched_node_types = torch.cat(all_node_types, dim=0)
        batched_batch = torch.cat(batch_indices, dim=0)
        if len(all_edge_src) > 0:
            batched_edge_index = torch.stack(
                [torch.cat(all_edge_src, dim=0), torch.cat(all_edge_dst, dim=0)],
                dim=0,
            )
            batched_edge_rel = torch.cat(all_edge_rel, dim=0)
        else:
            batched_edge_index = torch.zeros((2, 0), dtype=torch.long)
            batched_edge_rel = torch.zeros((0,), dtype=torch.long)
    else:
        batched_node_feats = None
        batched_node_types = None
        batched_edge_index = None
        batched_edge_rel = None
        batched_batch = None

    return {
        "node_features": batched_node_feats,
        "node_types": batched_node_types,
        "edge_index": batched_edge_index,
        "edge_rel": batched_edge_rel,
        "batch": batched_batch,
        "ast_tokens": torch.stack(ast_tokens_list, dim=0),
        "tab_features": torch.stack(tab_feats_list, dim=0),
        "labels": torch.tensor(labels_list, dtype=torch.float32),
        "sha256": sha256_list,
        "indices": indices_list,
        "sample_ids": sample_ids,
        "gnn_message_passing_eligible": gnn_eligible_list,
    }


def collate_non_graph_batch_v2(batch: list[dict]) -> dict:
    return {
        "node_features": None,
        "node_types": None,
        "edge_index": None,
        "edge_rel": None,
        "batch": None,
        "ast_tokens": torch.stack([s["ast_tokens"] for s in batch], dim=0),
        "tab_features": torch.stack([s["tab_features"] for s in batch], dim=0),
        "labels": torch.tensor([s["label"] for s in batch], dtype=torch.float32),
        "sha256": [s["sha256"] for s in batch],
        "indices": [s["index"] for s in batch],
        "sample_ids": [s.get("sample_id", "") for s in batch],
        "gnn_message_passing_eligible": [bool(s.get("gnn_message_passing_eligible", False)) for s in batch],
    }


def verify_graph_export_v2_directory(export_dir: Path | str) -> dict:
    root = Path(export_dir).resolve()
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError("v2_export_manifest_missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    files_meta = manifest.get("files")
    if not isinstance(files_meta, dict) or set(files_meta.keys()) != REQUIRED_EXPORT_FILES:
        raise ValueError("v2_export_manifest_files_mismatch")

    verified_hashes = {}
    for rel_name, meta in files_meta.items():
        fpath = root / rel_name
        if not fpath.is_file():
            raise ValueError(f"v2_export_file_missing:{rel_name}")
        raw = fpath.read_bytes()
        digest = sha256_bytes(raw)
        if isinstance(meta, str):
            expected_sha = meta
            expected_bytes = None
        elif isinstance(meta, dict):
            expected_sha = meta.get("sha256")
            expected_bytes = meta.get("bytes")
        else:
            raise ValueError(f"v2_export_manifest_entry_invalid:{rel_name}")
        if digest != expected_sha or (expected_bytes is not None and len(raw) != expected_bytes):
            raise ValueError(f"v2_export_checksum_mismatch:{rel_name}")
        verified_hashes[rel_name] = {"bytes": len(raw), "sha256": digest}

    gate_summary = validate_cohort_gate_summary_v2(
        json.loads((root / "quality_gate_summary.json").read_text(encoding="utf-8"))
    )
    if (
        gate_summary.get("cohort_gate_verdict") != "ready_for_locked_export"
        or gate_summary.get("v2_graph_model_input_ready") is not True
        or gate_summary.get("training_unlocked") is not True
        or gate_summary.get("legacy_19d_model_input_ready") is not False
        or gate_summary.get("node_feature_dim") != NODE_FEATURE_DIM_V2
    ):
        raise ValueError("v2_quality_gate_not_unlocked_for_training")

    unavail_policy = gate_summary.get("unavailable_document_policy") or {}
    if (
        unavail_policy.get("placeholder_zero_nodes_allowed") is not False
        or unavail_policy.get("eval_denominator_shrinkage_allowed") is not False
        or unavail_policy.get("protocol_g_denominator_preserved") is not True
    ):
        raise ValueError("v2_unavailable_document_policy_violation")

    locked_methodology = json.loads((root / "locked_methodology.json").read_text(encoding="utf-8"))
    if (
        locked_methodology.get("projection_contract_version") != PROJECTION_CONTRACT_VERSION
        or locked_methodology.get("gate_contract_version") != GATE_CONTRACT_VERSION_V2
        or locked_methodology.get("node_feature_dim") != NODE_FEATURE_DIM_V2
    ):
        raise ValueError("v2_locked_methodology_contract_mismatch")

    ledger = json.loads((root / "unavailable_document_ledger.json").read_text(encoding="utf-8"))
    if (
        ledger.get("schema_version") != SCHEMA_VERSION
        or ledger.get("projection_contract_version") != PROJECTION_CONTRACT_VERSION
        or not isinstance(ledger.get("records"), list)
    ):
        raise ValueError("v2_unavailable_ledger_invalid")

    with gzip.open(root / "tabular_features_v2.jsonl.gz", "rt", encoding="utf-8") as stream:
        tabular_rows = [json.loads(line) for line in stream if line.strip()]
    with gzip.open(root / "hetero_graphs_v2.jsonl.gz", "rt", encoding="utf-8") as stream:
        raw_graphs = [json.loads(line) for line in stream if line.strip()]

    planned_denom = gate_summary["cohort"]["planned_denominator"]
    if (
        len(tabular_rows) != planned_denom
        or ledger.get("planned_denominator") != planned_denom
        or ledger.get("gnn_exported_graphs") != len(raw_graphs)
        or ledger.get("unavailable_empty_graphs") != len(ledger["records"])
        or len(raw_graphs) + len(ledger["records"]) != planned_denom
    ):
        raise ValueError("v2_export_denominator_accounting_mismatch")

    ledger_by_sha = {}
    for rec in ledger["records"]:
        if (
            rec.get("placeholder_nodes_inserted") is not False
            or rec.get("evaluation_handling") != "abstention_or_tabular_only_no_placeholder_graph"
            or not str(rec.get("sample_disposition", "")).startswith("unavailable_")
        ):
            raise ValueError("v2_unavailable_record_contract_violation")
        ledger_by_sha[rec["sha256"]] = rec

    expected_gnn_shas = set()
    for pos, row in enumerate(tabular_rows):
        if (
            row.get("index") != pos
            or row.get("schema_version") != SCHEMA_VERSION
            or row.get("projection_contract_version") != PROJECTION_CONTRACT_VERSION
        ):
            raise ValueError("v2_tabular_row_order_or_contract_mismatch")
        sha = row["sha256"]
        if row["gnn_message_passing_eligible"] is True:
            if sha in ledger_by_sha:
                raise ValueError("v2_gnn_and_unavailable_overlap")
            expected_gnn_shas.add(sha)
        else:
            if sha not in ledger_by_sha:
                raise ValueError("v2_unavailable_missing_from_ledger")

    graph_dict = index_measured_graphs_v2(raw_graphs, expected_gnn_shas)
    return {
        "export_dir": str(root),
        "manifest": manifest,
        "verified_hashes": verified_hashes,
        "gate_summary": gate_summary,
        "locked_methodology": locked_methodology,
        "ledger": ledger,
        "ledger_by_sha": ledger_by_sha,
        "tabular_rows": tabular_rows,
        "graph_dict": graph_dict,
    }


def _extract_v2_feature_float(feat_map: dict, key: str, fallback: float = 0.0) -> float:
    item = feat_map.get(key)
    if not isinstance(item, dict):
        return fallback
    val = item.get("value")
    if val is None:
        return fallback
    if isinstance(val, bool):
        return 1.0 if val else 0.0
    if isinstance(val, (int, float)) and np.isfinite(val):
        return float(val)
    return fallback


def load_multimodal_dataset_v2(
    export_dir: Path | str,
    parquet_ours_path: Path | str,
    parquet_cic_path: Path | str,
) -> dict:
    verified = verify_graph_export_v2_directory(export_dir)
    tabular_rows = verified["tabular_rows"]
    graph_dict = verified["graph_dict"]

    df_ours = pd.read_parquet(parquet_ours_path)
    df_cic = pd.read_parquet(parquet_cic_path)
    merged = pd.merge(df_ours, df_cic, left_on="pdf_sha256", right_on="FileName", how="inner")
    if len(merged) != len(tabular_rows):
        raise ValueError("v2_parquet_cohort_size_mismatch")

    v2_by_sha = {r["sha256"]: r for r in tabular_rows}
    if set(merged["pdf_sha256"]) != set(v2_by_sha.keys()):
        raise ValueError("v2_parquet_sha256_set_mismatch")

    merged = merged.set_index("pdf_sha256").loc[[r["sha256"] for r in tabular_rows]].reset_index()
    for pos, row in enumerate(tabular_rows):
        if (
            merged.loc[pos, "pdf_sha256"] != row["sha256"]
            or merged.loc[pos, "split"] != row["split"]
            or int(merged.loc[pos, "Label"]) != int(row["label"])
        ):
            raise ValueError("v2_protocol_g_partition_or_label_mismatch")

    for pos, row in enumerate(tabular_rows):
        fmap = row["features"]
        for ent_col in ("raw_entropy", "raw_prefix_entropy", "raw_suffix_entropy"):
            if ent_col in fmap and fmap[ent_col].get("value") is not None:
                merged.loc[pos, ent_col] = _extract_v2_feature_float(fmap, ent_col, float(merged.loc[pos, ent_col]))
        for ast_col in (
            "legacy_observed_ast_node_count",
            "legacy_observed_ast_max_depth",
            "legacy_observed_ast_loops",
            "legacy_observed_ast_computed_members",
            "legacy_observed_ast_type_CallExpression",
            "legacy_observed_ast_type_Identifier",
        ):
            if ast_col in fmap and fmap[ast_col].get("value") is not None:
                merged.loc[pos, ast_col] = _extract_v2_feature_float(fmap, ast_col, 0.0)

    cic_cols = [c for c in df_cic.columns if c not in {"FileName", "Class"}]
    for c in cic_cols:
        merged[c] = pd.to_numeric(merged[c], errors="coerce").fillna(-1.0)

    merged["density_stream_ratio"] = safe_div_series(merged["Stream"], merged["PdfSize"])
    merged["density_obj_stream_ratio"] = safe_div_series(merged["Obj"], merged["Stream"])
    merged["density_metadata_ratio"] = safe_div_series(merged["MetadataSize"], merged["PdfSize"])
    merged["entropy_gap"] = (merged["raw_prefix_entropy"] - merged["raw_suffix_entropy"]).abs().fillna(0.0)
    merged["ast_complexity_per_node"] = safe_div_series(
        merged["legacy_observed_ast_max_depth"],
        merged["legacy_observed_ast_node_count"],
    )
    merged["ast_call_ratio"] = safe_div_series(
        merged["legacy_observed_ast_type_CallExpression"],
        merged["legacy_observed_ast_node_count"],
    )
    merged["ast_identifier_ratio"] = safe_div_series(
        merged["legacy_observed_ast_type_Identifier"],
        merged["legacy_observed_ast_node_count"],
    )
    merged["ast_computed_ratio"] = safe_div_series(
        merged["legacy_observed_ast_computed_members"],
        merged["legacy_observed_ast_node_count"],
    )

    pillar_engineered_cols = [
        "density_stream_ratio",
        "density_obj_stream_ratio",
        "density_metadata_ratio",
        "entropy_gap",
        "ast_complexity_per_node",
        "ast_call_ratio",
        "ast_identifier_ratio",
        "ast_computed_ratio",
        "byte_image_file_encoded_ratio",
        "byte_image_file_persisted_ratio",
        "stream_truncation_ratio",
        "legacy_observed_ast_node_count",
        "legacy_observed_ast_max_depth",
        "legacy_observed_ast_loops",
        "legacy_observed_ast_computed_members",
    ]
    for c in pillar_engineered_cols:
        merged[c] = pd.to_numeric(merged[c], errors="coerce").replace([np.inf, -np.inf], 0.0).fillna(0.0)

    evasion_cols = [
        "evasive_timeout_anomaly",
        "flag_decompression_ratio_exceeded",
        "is_truncated_stream",
        "flag_spec_violation_flood",
        "flag_excessive_object_graph",
        "flag_ast_complexity_truncated",
    ]
    for c in evasion_cols:
        merged[c] = pd.to_numeric(merged[c], errors="coerce").replace([np.inf, -np.inf], 0.0).fillna(0.0)

    entropy_cols = ["raw_entropy", "raw_prefix_entropy", "raw_suffix_entropy"]
    for c in entropy_cols:
        merged[c] = pd.to_numeric(merged[c], errors="coerce").replace([np.inf, -np.inf], 0.0).fillna(0.0)

    key_cic_cols = [
        "Javascript",
        "JS",
        "Stream",
        "Endstream",
        "Obj",
        "Endobj",
        "MetadataSize",
        "PdfSize",
        "Pages",
        "PageNo",
        "XFA",
        "OpenAction",
        "Colors",
        "Images",
    ]
    tab_cols = key_cic_cols + pillar_engineered_cols + evasion_cols + entropy_cols

    train_mask = merged["split"] == "train"
    scaler = StandardScaler()
    scaler.fit(merged.loc[train_mask, tab_cols].values)
    scaled_tab = scaler.transform(merged[tab_cols].values).astype(np.float32)

    ast_type_cols = sorted([c for c in df_ours.columns if "ast_type_" in c])
    full_split_samples: dict[str, list[dict]] = {"train": [], "validation": [], "test": []}
    gnn_eligible_samples: dict[str, list[dict]] = {"train": [], "validation": [], "test": []}

    for pos, v2_row in enumerate(tabular_rows):
        m_row = merged.iloc[pos]
        sha = v2_row["sha256"]
        split = v2_row["split"]
        label = int(v2_row["label"])
        gnn_ok = bool(v2_row["gnn_message_passing_eligible"])
        tab_feat = torch.tensor(scaled_tab[pos], dtype=torch.float32)

        fmap = v2_row["features"]
        ast_counts = []
        for col in ast_type_cols[:32]:
            if col in fmap and fmap[col].get("value") is not None:
                ast_counts.append(_extract_v2_feature_float(fmap, col, 0.0))
            elif col in m_row and not pd.isna(m_row[col]):
                ast_counts.append(float(m_row[col]))
            else:
                ast_counts.append(0.0)
        if len(ast_counts) < 32:
            ast_counts += [0.0] * (32 - len(ast_counts))
        ast_tokens = torch.tensor([int(c) % 64 for c in ast_counts], dtype=torch.long)

        meta = {
            "index": v2_row["index"],
            "sample_id": str(m_row.get("sample_id", f"cic_{pos:04d}")),
            "status": v2_row["status"],
            "sample_disposition": v2_row["sample_disposition"],
            "evaluation_handling": v2_row["evaluation_handling"],
            "gnn_message_passing_eligible": gnn_ok,
            "PdfSize": float(m_row.get("PdfSize", 0.0)),
            "Stream": float(m_row.get("Stream", 0.0)),
            "JS": float(m_row.get("JS", 0.0)),
            "Javascript": float(m_row.get("Javascript", 0.0)),
            "XFA": float(m_row.get("XFA", 0.0)),
        }

        if gnn_ok:
            g = graph_dict[sha]
            sample_item = {
                "index": v2_row["index"],
                "sha256": sha,
                "sample_id": meta["sample_id"],
                "split": split,
                "label": label,
                "gnn_message_passing_eligible": True,
                "evaluation_handling": v2_row["evaluation_handling"],
                "placeholder_nodes_inserted": False,
                "node_features": torch.tensor(g["node_features"], dtype=torch.float32),
                "node_types": torch.tensor(g["node_types"], dtype=torch.long),
                "edge_src": torch.tensor(g["edge_src"], dtype=torch.long),
                "edge_dst": torch.tensor(g["edge_dst"], dtype=torch.long),
                "edge_rel": torch.tensor(g["edge_rel"], dtype=torch.long),
                "ast_tokens": ast_tokens,
                "tab_features": tab_feat,
                "meta": meta,
            }
            full_split_samples[split].append(sample_item)
            gnn_eligible_samples[split].append(sample_item)
        else:
            sample_item = {
                "index": v2_row["index"],
                "sha256": sha,
                "sample_id": meta["sample_id"],
                "split": split,
                "label": label,
                "gnn_message_passing_eligible": False,
                "evaluation_handling": v2_row["evaluation_handling"],
                "placeholder_nodes_inserted": False,
                "node_features": None,
                "node_types": None,
                "edge_src": None,
                "edge_dst": None,
                "edge_rel": None,
                "ast_tokens": ast_tokens,
                "tab_features": tab_feat,
                "meta": meta,
            }
            full_split_samples[split].append(sample_item)

    return {
        "verified_export": verified,
        "tabular_feature_names": tab_cols,
        "tabular_in_features": len(tab_cols),
        "node_in_dim": NODE_FEATURE_DIM_V2,
        "scaler_mean": [float(x) for x in scaler.mean_],
        "scaler_scale": [float(x) for x in scaler.scale_],
        "full_split_samples": full_split_samples,
        "gnn_eligible_samples": gnn_eligible_samples,
    }
