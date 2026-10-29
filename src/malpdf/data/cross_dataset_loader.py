from __future__ import annotations

from pathlib import Path
from typing import Tuple
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

CANONICAL_FEATURE_MAPPING: dict[str, str] = {
    "pdfsize": "PdfSize",
    "metadata size": "MetadataSize",
    "pages": "Pages",
    "xref length": "XrefLength",
    "title length": "TitleCharacters",
    "isEncrypted": "isEncrypted",
    "embedded files": "EmbeddedFiles",
    "images": "Images",
    "obj": "Obj",
    "endobj": "Endobj",
    "stream": "Stream",
    "endstream": "Endstream",
    "xref": "Xref",
    "trailer": "Trailer",
    "startxref": "StartXref",
    "page_command": "PageNo",
    "Encrypt": "Encrypt",
    "ObjStm": "ObjStm",
    "JS": "JS",
    "JavaScript": "Javascript",
    "AA": "AA",
    "OpenAction": "OpenAction",
    "Acroform": "Acroform",
    "JBIG2Decode": "JBIG2Decode",
    "RichMedia": "RichMedia",
    "Launch": "Launch",
    "EmbeddedFile": "EmbeddedFile",
    "XFA": "XFA",
    "Colors": "Colors",
}

CANONICAL_NAMES: list[str] = list(CANONICAL_FEATURE_MAPPING.keys())


def safe_div(a: pd.Series, b: pd.Series) -> pd.Series:
    res = a.astype(float) / np.maximum(b.astype(float).abs(), 1.0)
    return res.replace([np.inf, -np.inf, np.nan], 0.0)


def load_aligned_datasets(
    repo_root: Path,
    include_ratios: bool = True,
    exclude_startxref: bool = False,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    rit_csv = repo_root / "data/external/rit-pdfmal-2026.csv"
    if not rit_csv.exists():
        rit_csv = repo_root / "data/raw/rit-pdfmal-2026.csv"
    cic_parquet_features = repo_root / "data/processed/cic_full/cic_features_1452.parquet"
    cic_parquet_raw = repo_root / "data/external/cic_evasive_pdfmal2022/PDFMalware2022.parquet"

    df_rit_raw = pd.read_csv(rit_csv)
    df_cic_features = pd.read_parquet(cic_parquet_features)
    df_cic_raw = pd.read_parquet(cic_parquet_raw)

    df_cic_merged = pd.merge(df_cic_features, df_cic_raw, left_on="pdf_sha256", right_on="FileName", how="inner")

    rit_df = pd.DataFrame()
    cic_df = pd.DataFrame()

    for rit_col, cic_col in CANONICAL_FEATURE_MAPPING.items():
        if exclude_startxref and rit_col in {"startxref", "xref"}:
            continue
        col_name = rit_col.replace(" ", "_")
        rit_df[col_name] = pd.to_numeric(df_rit_raw[rit_col], errors="coerce").fillna(0.0)
        cic_df[col_name] = pd.to_numeric(df_cic_merged[cic_col], errors="coerce").fillna(0.0)

    if include_ratios:
        rit_df["density_stream_ratio"] = safe_div(rit_df["stream"], rit_df["pdfsize"])
        rit_df["density_obj_stream_ratio"] = safe_div(rit_df["obj"], rit_df["stream"])
        rit_df["density_metadata_ratio"] = safe_div(rit_df["metadata_size"], rit_df["pdfsize"])

        cic_df["density_stream_ratio"] = safe_div(cic_df["stream"], cic_df["pdfsize"])
        cic_df["density_obj_stream_ratio"] = safe_div(cic_df["obj"], cic_df["stream"])
        cic_df["density_metadata_ratio"] = safe_div(cic_df["metadata_size"], cic_df["pdfsize"])

    rit_df["label"] = df_rit_raw["Label"].astype(int)
    cic_df["label"] = df_cic_merged["Label"].astype(int)
    cic_df["split"] = df_cic_merged["split"].astype(str)
    cic_df["pdf_sha256"] = df_cic_merged["pdf_sha256"].astype(str)

    train_idx, test_idx = train_test_split(
        np.arange(len(rit_df)),
        test_size=0.2,
        random_state=42,
        stratify=rit_df["label"].values,
    )
    rit_split = np.full(len(rit_df), "train", dtype=object)
    rit_split[test_idx] = "test"
    rit_df["split"] = rit_split

    return rit_df, cic_df

