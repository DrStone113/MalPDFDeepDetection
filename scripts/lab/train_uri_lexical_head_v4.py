"""Train, Platt-calibrate, and jointly PDF-calibrate PDFURILexicalHead v4 (uri_lexical_v4.1)."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any
import zipfile

import numpy as np
import pikepdf
from scipy.optimize import minimize
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from malpdf.cdr.fixtures import load_real_benign_bytes
from malpdf.models.uri_lexical_head_v4 import (
    URI_LEXICAL_MODEL_VERSION,
    PDFURILexicalHeadV4,
    URILexicalHeadV4Config,
    save_uri_head_v4_npz,
)
from malpdf.scanner.ingestion import InstantPDFIngestion
from malpdf.scanner.uri_head import URILexicalHeadScorer, validate_uri_lexical_contract
from malpdf.scanner.uri_lexical import (
    URI_LEXICAL_FEATURE_NAMES,
    URI_LEXICAL_SCHEMA_VERSION,
    URI_LOG1P_INDICES,
    _split_url_host,
    extract_tld,
    extract_url_lexical_features,
    is_allowlisted_uri,
    normalize_uri_for_lexical_features,
    registrable_domain,
)

PHIUSIIL_ZIP_PATH = REPO / "data" / "external" / "uri_phishing_open_data" / "phiusiil_uci_967" / "phiusiil_uci_967.zip"
PHIUSIIL_ZIP_SHA256 = "0a639fd03aea6308c5b1c10c92aa23c2ce1505447a9137271865cd0badc9a59a"
PHIUSIIL_CSV_PATH = (
    REPO / "data" / "external" / "uri_phishing_open_data" / "phiusiil_uci_967" / "PhiUSIIL_Phishing_URL_Dataset.csv"
)
DEFAULT_OUT_NPZ = REPO / "artifacts" / "models" / "uri_lexical_head_v4" / "uri_lexical_head_v4.npz"
DEFAULT_OUT_CONTRACT = REPO / "configs" / "uri_lexical_head_v4_contract.json"
DEFAULT_REPORT_ROOT = REPO / "reports" / "experiments" / "uri_lexical_head_v4"

# Retained for backwards compatibility with scripts/lab/evaluate_uri_head_v4.py
_BENIGN_DEEP_PATHS: tuple[str, ...] = (
    "/docs/reference/manual-v2/section-4.pdf",
    "/articles/2025/04/research-summary-1042?page=3&lang=en",
    "/publications/reports/annual_report_2024.pdf#page=12",
    "/wiki/Specification_Overview/Architecture_Notes",
    "/research/datasets/v1/release-notes?format=html&view=full",
    "/index.php/catalog/view/1284",
    "/support/documentation/getting-started/installation-guide",
    "/blog/engineering/2026/02/benchmark-methodology",
)

_NEUTRAL_SUBDOMAINS: tuple[str, ...] = (
    "docs",
    "learn",
    "support",
    "blog",
    "help",
    "dev",
    "wiki",
    "news",
    "en",
    "child",
    "api",
    "catalog",
    "library",
    "archive",
)

_SEG1_POOL: tuple[str, ...] = (
    "about",
    "reference",
    "review",
    "docs",
    "acrobat",
    "support",
    "guide",
    "manual",
    "overview",
    "help",
    "products",
    "services",
    "privacy",
    "terms",
    "contact",
    "faq",
    "download",
    "archive",
    "resources",
    "news",
    "home",
    "team",
    "pricing",
    "features",
    "catalog",
    "research",
    "legal",
    "policy",
)

_SEG_TOPIC_POOL: tuple[str, ...] = (
    "getting-started",
    "installation",
    "release-notes",
    "architecture",
    "desktop",
    "winforms",
    "dotnet",
    "man3.0",
    "windows",
    "en-us",
    "specification",
    "benchmark",
    "engineering",
    "publication",
    "handbook",
    "annual-report",
    "standard",
    "whitepaper",
    "methodology",
    "dataset",
    "notes",
    "examples",
    "project",
    "runtime",
)

_SEG_FILE_POOL: tuple[str, ...] = (
    "README.md",
    "manual-v2.pdf",
    "section-4.pdf",
    "index.html",
    "overview",
    "guide.html",
    "summary",
    "report-2026.pdf",
    "view",
    "edit",
    "detail",
    "Portable_Document_Format",
    "Topic_Overview",
)

_CLEAN_QUERIES: tuple[str, ...] = (
    "?page=2&lang=en",
    "?page=3&lang=en",
    "?format=html&view=full",
    "?tab=overview&version=2",
    "?id=1042&ref=toc",
    "?tab=overview",
    "?format=html",
    "?id=1042",
    "?ref=toc",
    "?version=3",
    "?view=full",
)
_CLEAN_FRAGMENTS: tuple[str, ...] = (
    "#overview",
    "#appendix",
    "#references",
    "#top",
)

_HOSTED_USER_CONTENT_PATTERNS: dict[str, tuple[str, ...]] = {
    "train": (
        "https://{t}.trctrl.workers.dev/reference",
        "https://{t}.trctrl.workers.dev/docs/manual",
        "https://{t}.trctrl.pages.dev/guide",
        "https://{t}.trctrl.netlify.app/overview",
        "https://{t}.trctrl.vercel.app/articles/2025/notes",
        "https://{t}.trctrl.firebaseapp.com/docs",
        "https://{t}.trctrl.firebaseio.com/reference",
        "https://docs.google.com/forms/d/trctrl-{t}/viewform",
        "https://docs.google.com/document/d/trctrl-{t}/edit",
        "https://github.com/trctrl-{t}/project-core/blob/main/README.md",
    ),
    "val": (
        "https://{t}.vactrl.workers.dev/review",
        "https://{t}.vactrl.workers.dev/docs/handbook",
        "https://{t}.vactrl.pages.dev/reference",
        "https://{t}.vactrl.netlify.app/documentation",
        "https://{t}.vactrl.vercel.app/publications/summary",
        "https://{t}.vactrl.firebaseapp.com/reference",
        "https://{t}.vactrl.firebaseio.com/archive",
        "https://docs.google.com/forms/d/vactrl-{t}/viewform",
        "https://docs.google.com/document/d/vactrl-{t}/edit",
        "https://github.com/vactrl-{t}/spec-docs/blob/main/README.md",
    ),
    "test": (
        "https://{t}.tectrl.workers.dev/reference",
        "https://{t}.tectrl.pages.dev/docs/guide",
        "https://{t}.tectrl.netlify.app/release-notes",
        "https://{t}.tectrl.vercel.app/support",
        "https://{t}.tectrl.firebaseapp.com/manual",
        "https://{t}.tectrl.firebaseio.com/reference",
        "https://docs.google.com/forms/d/tectrl-{t}/viewform",
        "https://docs.google.com/document/d/tectrl-{t}/edit",
        "https://github.com/tectrl-{t}/toolkit/blob/main/README.md",
    ),
}

_HOSTED_SPLIT_TOKENS: dict[str, tuple[str, ...]] = {
    "train": (
        "aurora",
        "banyan",
        "cobalt",
        "delphi",
        "ember",
        "falcon",
        "granite",
        "harbor",
        "indigo",
        "juniper",
        "kepler",
        "lantern",
        "maple",
        "nimbus",
        "olivine",
        "photon",
        "quartz",
        "redwood",
        "solstice",
        "timber",
        "umbra",
        "vernal",
        "willow",
        "zephyr",
    ),
    "val": (
        "acorn",
        "birch",
        "cedar",
        "drift",
        "elmwood",
        "fern",
        "glacier",
        "hazel",
        "iris",
        "jasper",
        "kestrel",
        "linden",
        "meadow",
        "nectar",
        "orchid",
        "pebble",
        "quill",
        "river",
        "spruce",
        "thistle",
        "upland",
        "violet",
        "walnut",
        "yarrow",
    ),
    "test": (
        "alder",
        "brook",
        "clover",
        "dune",
        "estuary",
        "fjord",
        "grove",
        "heather",
        "islet",
        "knoll",
        "lagoon",
        "moss",
        "oat",
        "pine",
        "reef",
        "sage",
        "tarn",
        "vale",
        "weir",
        "zenith",
    ),
}


def _git_rev() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "--short=12", "HEAD"], cwd=REPO, text=True).strip()
    except Exception:
        return "unknown"


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _seed_all(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def _strip_leading_www(host: str) -> str:
    reg = registrable_domain(host)
    if host.startswith("www.") and reg and host != reg and (host[4:] == reg or host[4:].endswith(f".{reg}")):
        return host[4:]
    return host


def _load_phiusiil_rows(csv_path: Path) -> tuple[list[tuple[str, int, str]], str]:
    if _sha256_file(PHIUSIIL_ZIP_PATH) != PHIUSIIL_ZIP_SHA256:
        raise ValueError("phiusiil_zip_sha256_mismatch")
    csv_sha = _sha256_file(csv_path)
    with zipfile.ZipFile(PHIUSIIL_ZIP_PATH, "r") as zf:
        csv_members = [name for name in zf.namelist() if name.lower().endswith(".csv")]
        if len(csv_members) != 1:
            raise ValueError("phiusiil_zip_csv_member_invalid")
        zip_csv_sha = hashlib.sha256(zf.read(csv_members[0])).hexdigest()
        if zip_csv_sha != csv_sha:
            raise ValueError("phiusiil_csv_zip_mismatch")
    rows: list[tuple[str, int, str]] = []
    with csv_path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            raw_url = str(row.get("URL") or "").strip()
            raw_lbl = str(row.get("label") or "").strip()
            if not raw_url or raw_lbl not in {"0", "1"}:
                continue
            scheme, _, host, _, _ = _split_url_host(raw_url)
            if scheme not in {"http", "https"} or not host:
                continue
            y = 1 if raw_lbl == "0" else 0
            reg = registrable_domain(host)
            if not reg:
                continue
            rows.append((raw_url, y, reg))
    return rows, csv_sha


def _domain_grouped_split(
    rows: list[tuple[str, int, str]], *, seed: int = 42
) -> tuple[list[int], list[int], list[int]]:
    rng = np.random.default_rng(seed)
    dom_indices: dict[str, list[int]] = defaultdict(list)
    dom_pos_cnt: Counter[str] = Counter()
    for idx, (_u, y, dom) in enumerate(rows):
        dom_indices[dom].append(idx)
        dom_pos_cnt[dom] += y

    phish_doms = sorted(d for d, idxs in dom_indices.items() if dom_pos_cnt[d] * 2 >= len(idxs))
    phish_dom_set = set(phish_doms)
    ben_doms = sorted(d for d in dom_indices if d not in phish_dom_set)
    rng.shuffle(phish_doms)
    rng.shuffle(ben_doms)

    train_idx: list[int] = []
    val_idx: list[int] = []
    test_idx: list[int] = []
    for dom_list in (phish_doms, ben_doms):
        n_dom = len(dom_list)
        n_tr = int(0.80 * n_dom)
        n_val = int(0.10 * n_dom)
        for d in dom_list[:n_tr]:
            train_idx.extend(dom_indices[d])
        for d in dom_list[n_tr : n_tr + n_val]:
            val_idx.extend(dom_indices[d])
        for d in dom_list[n_tr + n_val :]:
            test_idx.extend(dom_indices[d])

    tr_doms = {rows[i][2] for i in train_idx}
    va_doms = {rows[i][2] for i in val_idx}
    te_doms = {rows[i][2] for i in test_idx}
    assert tr_doms.isdisjoint(va_doms) and tr_doms.isdisjoint(te_doms) and va_doms.isdisjoint(te_doms)
    return train_idx, val_idx, test_idx


def _canonical_norm_url(raw_url: str) -> str:
    return normalize_uri_for_lexical_features(raw_url)[5].lower()


def _pick_clean_fragment(rng: np.random.Generator) -> str:
    roll = float(rng.random())
    if roll < 0.45:
        return f"#page={int(rng.integers(1, 100))}"
    if roll < 0.75:
        return f"#section-{int(rng.integers(1, 13))}"
    return _CLEAN_FRAGMENTS[int(rng.integers(0, len(_CLEAN_FRAGMENTS)))]


def _synthesize_benign_url(rng: np.random.Generator, raw_host: str, base_scheme: str) -> str:
    host = _strip_leading_www(raw_host)
    scheme = "http" if float(rng.random()) < 0.20 else base_scheme
    if float(rng.random()) < 0.25:
        host = f"{_NEUTRAL_SUBDOMAINS[int(rng.integers(0, len(_NEUTRAL_SUBDOMAINS)))]}.{host}"
    elif float(rng.random()) < 0.35:
        host = f"www.{host}"

    bucket = float(rng.random())
    if bucket < 0.20:
        suffix = "/" if float(rng.random()) < 0.25 else ""
    elif bucket < 0.34:
        seg1 = _SEG1_POOL[int(rng.integers(0, len(_SEG1_POOL)))]
        trailing = "/" if float(rng.random()) < 0.25 else ""
        suffix = f"/{seg1}{trailing}"
    elif bucket < 0.50:
        s1 = _SEG1_POOL[int(rng.integers(0, len(_SEG1_POOL)))]
        s2 = _SEG_TOPIC_POOL[int(rng.integers(0, len(_SEG_TOPIC_POOL)))]
        if float(rng.random()) < 0.30:
            s2 = f"{s2}-{int(rng.integers(1, 2027))}"
        trailing = "/" if float(rng.random()) < 0.20 else ""
        suffix = f"/{s1}/{s2}{trailing}"
    elif bucket < 0.62:
        s1 = _SEG1_POOL[int(rng.integers(0, len(_SEG1_POOL)))]
        num_id = int(rng.integers(100, 1000000))
        q = _CLEAN_QUERIES[int(rng.integers(0, len(_CLEAN_QUERIES)))] if float(rng.random()) < 0.25 else ""
        suffix = f"/{s1}/view/{num_id}{q}" if float(rng.random()) < 0.50 else f"/{s1}/{num_id}{q}"
    elif bucket < 0.76:
        s1 = _SEG1_POOL[int(rng.integers(0, len(_SEG1_POOL)))]
        year = int(rng.integers(2021, 2027))
        month = int(rng.integers(1, 13))
        if float(rng.random()) < 0.65:
            slug = _SEG_TOPIC_POOL[int(rng.integers(0, len(_SEG_TOPIC_POOL)))]
            if float(rng.random()) < 0.50:
                slug = f"{slug}-{int(rng.integers(1, 2027))}"
        else:
            slug = _SEG_FILE_POOL[int(rng.integers(0, len(_SEG_FILE_POOL)))]
        q = _CLEAN_QUERIES[int(rng.integers(0, len(_CLEAN_QUERIES)))] if float(rng.random()) < 0.40 else ""
        suffix = f"/{s1}/{year}/{month:02d}/{slug}{q}"
    elif bucket < 0.90:
        parts = [_SEG1_POOL[int(rng.integers(0, len(_SEG1_POOL)))]]
        n_mid = int(rng.integers(1, 3))
        for _ in range(n_mid):
            parts.append(_SEG_TOPIC_POOL[int(rng.integers(0, len(_SEG_TOPIC_POOL)))])
        if float(rng.random()) < 0.65:
            parts.append(_SEG_FILE_POOL[int(rng.integers(0, len(_SEG_FILE_POOL)))])
        q = _CLEAN_QUERIES[int(rng.integers(0, len(_CLEAN_QUERIES)))] if float(rng.random()) < 0.30 else ""
        suffix = "/" + "/".join(parts) + q
    else:
        n_extra = int(rng.integers(0, 2))
        parts = [_SEG1_POOL[int(rng.integers(0, len(_SEG1_POOL)))]]
        for _ in range(n_extra):
            parts.append(_SEG_TOPIC_POOL[int(rng.integers(0, len(_SEG_TOPIC_POOL)))])
        parts.append(_SEG_FILE_POOL[int(rng.integers(0, len(_SEG_FILE_POOL)))])
        q = _CLEAN_QUERIES[int(rng.integers(0, len(_CLEAN_QUERIES)))]
        suffix = "/" + "/".join(parts) + q

    if bucket >= 0.20 and float(rng.random()) < 0.14:
        suffix = suffix.rstrip("/") + _pick_clean_fragment(rng)
    return f"{scheme}://{host}{suffix}"


def _build_split_hosted_controls(split_name: str, count: int, rng: np.random.Generator) -> list[tuple[str, int]]:
    patterns = _HOSTED_USER_CONTENT_PATTERNS[split_name]
    tokens = _HOSTED_SPLIT_TOKENS[split_name]
    items: list[tuple[str, int]] = []
    for idx in range(count):
        tok = f"{tokens[idx % len(tokens)]}-{idx // len(tokens) + 1}"
        pat = patterns[idx % len(patterns)]
        url = pat.format(t=tok)
        if float(rng.random()) < 0.20 and url.startswith("https://"):
            url = "http://" + url[8:]
        items.append((url, 0))
    return items


def _augment_split_rows(
    split_rows: list[tuple[str, int, str]],
    *,
    split_name: str,
    seed: int,
    benign_multiplier: int = 1,
    include_phish_aug: bool = False,
    hosted_ratio: float = 0.03,
) -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
    rng = np.random.default_rng(seed)
    out: list[tuple[str, int]] = [(u, y) for u, y, _ in split_rows]
    aug_benign: list[tuple[str, int]] = []

    raw_hosts_seen: dict[str, set[int]] = defaultdict(set)
    for u, y, _ in split_rows:
        raw_hosts_seen[_canonical_norm_url(u)].add(y)
    ben_rows = [(u, y, dom) for u, y, dom in split_rows if y == 0]

    for raw_url, y, reg_dom in split_rows:
        scheme, _nl, host, path, query = _split_url_host(raw_url)
        if y == 0:
            if len(raw_hosts_seen.get(_canonical_norm_url(raw_url), set())) > 1:
                continue
            for _ in range(benign_multiplier):
                cand = _synthesize_benign_url(rng, host, scheme)
                existing_labels = raw_hosts_seen.get(_canonical_norm_url(cand), set())
                if 1 not in existing_labels:
                    aug_benign.append((cand, 0))
                    out.append((cand, 0))
            if float(rng.random()) < 0.15:
                alt_sch = "http" if scheme == "https" else "https"
                q = f"?{query}" if query else ""
                cand = f"{alt_sch}://{_strip_leading_www(host)}{path}{q}"
                existing_labels = raw_hosts_seen.get(_canonical_norm_url(cand), set())
                if 1 not in existing_labels:
                    aug_benign.append((cand, 0))
                    out.append((cand, 0))
        elif include_phish_aug and float(rng.random()) < 0.25:
            mode = int(rng.integers(0, 4))
            if mode == 0:
                tok = f"?session={rng.integers(100000, 999999)}&token=v{rng.integers(10, 99)}x9a2&verify=1"
                cand = f"{scheme}://{host}{path or '/login'}{tok}"
            elif mode == 1:
                brand = ("login-microsoft-secure", "auth-docusign-view", "verify-paypal-id", "booking-confirm")[
                    int(rng.integers(0, 4))
                ]
                cand = f"{scheme}://{brand}.{host}{path or '/signin'}"
            elif mode == 2:
                cand = f"{scheme}://{host}/auth%20portal/verify%2eview?id={rng.integers(100, 999)}"
            else:
                cand = f"{scheme}://xn--lgin-1qa.{reg_dom}{path or '/oauth'}"
            if 0 not in raw_hosts_seen.get(_canonical_norm_url(cand), set()):
                out.append((cand, 1))

    n_hosted = max(20, int(round(len(ben_rows) * hosted_ratio)))
    hosted_items = _build_split_hosted_controls(split_name, n_hosted, rng)
    for cand, lbl in hosted_items:
        if 1 not in raw_hosts_seen.get(_canonical_norm_url(cand), set()):
            aug_benign.append((cand, lbl))
            out.append((cand, lbl))

    return out, aug_benign


def _verify_generated_disjointness(
    tr_items: list[tuple[str, int]],
    va_items: list[tuple[str, int]],
    te_items: list[tuple[str, int]],
    *,
    allowed_raw_conflicts: set[str] | None = None,
) -> None:
    allowed = allowed_raw_conflicts or set()

    def _label_map(items: list[tuple[str, int]], name: str) -> dict[str, set[int]]:
        mapping: dict[str, set[int]] = defaultdict(set)
        for url, y in items:
            mapping[_canonical_norm_url(url)].add(y)
        for norm, ys in mapping.items():
            if len(ys) > 1 and norm not in allowed:
                raise ValueError(f"label_conflict_in_{name}:{norm}")
        return mapping

    tr_map = _label_map(tr_items, "train")
    va_map = _label_map(va_items, "val")
    te_map = _label_map(te_items, "test")

    tr_keys, va_keys, te_keys = set(tr_map), set(va_map), set(te_map)
    if not tr_keys.isdisjoint(va_keys):
        raise ValueError(f"train_val_url_collision:{len(tr_keys & va_keys)}")
    if not tr_keys.isdisjoint(te_keys):
        raise ValueError(f"train_test_url_collision:{len(tr_keys & te_keys)}")
    if not va_keys.isdisjoint(te_keys):
        raise ValueError(f"val_test_url_collision:{len(va_keys & te_keys)}")


def _fit_train_tables(
    raw_train_rows: list[tuple[str, int, str]],
    aug_train_items: list[tuple[str, int]],
) -> tuple[dict[str, float], dict[str, float], float, float]:
    tld_legit: Counter[str] = Counter()
    tld_total: Counter[str] = Counter()
    for raw_url, y, _ in raw_train_rows:
        _sch, _nl, host, _p, _q = _split_url_host(raw_url)
        tld_multi = extract_tld(host)
        tld_single = host.rsplit(".", 1)[-1] if "." in host else ""
        is_legit = 1 - y
        for t in {tld_multi, tld_single}:
            if t:
                tld_total[t] += 1
                tld_legit[t] += is_legit

    char_cnt: Counter[str] = Counter()
    char_total = 0
    for url, y in aug_train_items:
        if y != 0:
            continue
        body_low = _canonical_norm_url(url)
        for ch in body_low:
            char_cnt[ch] += 1
            char_total += 1

    tld_probs = {t: round((tld_legit[t] + 1.0) / (tot + 2.0), 6) for t, tot in tld_total.items() if tot >= 3}
    default_tld_prob = 0.50
    char_probs = {ch: round(cnt / max(char_total, 1), 6) for ch, cnt in char_cnt.items() if cnt >= 20}
    default_char_prob = round(1.0 / max(char_total, 10000), 6)
    return tld_probs, char_probs, default_tld_prob, default_char_prob


def _extract_matrix(
    items: list[tuple[str, int]],
    *,
    tld_probs: dict[str, float],
    char_probs: dict[str, float],
    default_tld_prob: float,
    default_char_prob: float,
) -> tuple[np.ndarray, np.ndarray]:
    n = len(items)
    x = np.zeros((n, len(URI_LEXICAL_FEATURE_NAMES)), dtype=np.float32)
    y = np.zeros((n,), dtype=np.float32)
    for idx, (url, lbl) in enumerate(items):
        x[idx] = extract_url_lexical_features(
            url,
            tld_legit_probs=tld_probs,
            char_probs=char_probs,
            default_tld_prob=default_tld_prob,
            default_char_prob=default_char_prob,
        )
        y[idx] = float(lbl)
    return x, y


def _scale_matrix(x: np.ndarray, center: np.ndarray, scale: np.ndarray) -> np.ndarray:
    mat = x.astype(np.float64, copy=True)
    for col in URI_LOG1P_INDICES:
        mat[:, col] = np.log1p(np.maximum(mat[:, col], 0.0))
    return np.ascontiguousarray(((mat - center) / scale).astype(np.float32), dtype=np.float32)


def _predict_torch_logits(model: PDFURILexicalHeadV4, x_scaled: np.ndarray, device: torch.device) -> np.ndarray:
    model.eval()
    out: list[np.ndarray] = []
    with torch.no_grad():
        for start in range(0, len(x_scaled), 8192):
            xb = torch.from_numpy(x_scaled[start : start + 8192]).to(device)
            out.append(model(xb).detach().cpu().numpy())
    return np.concatenate(out, axis=0).astype(np.float64)


def _fit_platt(logits: np.ndarray, labels: np.ndarray) -> tuple[float, float]:
    y = labels.astype(np.float64)

    def nll(params: np.ndarray) -> float:
        a, b = float(params[0]), float(params[1])
        z = np.clip(a * logits + b, -40.0, 40.0)
        return float(np.mean(np.logaddexp(0.0, z) - y * z) + 1e-4 * ((a - 1.0) ** 2 + b**2))

    res = minimize(nll, x0=np.array([1.0, 0.0]), bounds=[(0.10, 5.0), (-8.0, 8.0)], method="L-BFGS-B")
    return float(res.x[0]), float(res.x[1])


def _expected_calibration_error(y: np.ndarray, probs: np.ndarray, n_bins: int = 10) -> float:
    ece = 0.0
    n = max(len(y), 1)
    for idx in range(n_bins):
        lo, hi = idx / n_bins, (idx + 1) / n_bins
        mask = (probs >= lo) & (probs < hi if idx < n_bins - 1 else probs <= hi)
        if np.any(mask):
            ece += (float(np.sum(mask)) / n) * abs(float(np.mean(probs[mask])) - float(np.mean(y[mask])))
    return round(ece, 6)


def _build_annot_pdf(base_bytes: bytes, urls: list[str]) -> bytes:
    with pikepdf.open(io.BytesIO(base_bytes)) as pdf:
        annots = []
        for idx, url in enumerate(urls):
            annots.append(
                pdf.make_indirect(
                    pikepdf.Dictionary(
                        Type=pikepdf.Name.Annot,
                        Subtype=pikepdf.Name.Link,
                        Rect=pikepdf.Array([40, 620 - (idx % 12) * 24, 320, 640 - (idx % 12) * 24]),
                        A=pikepdf.Dictionary(S=pikepdf.Name.URI, URI=pikepdf.String(url)),
                    )
                )
            )
        pdf.pages[0].obj["/Annots"] = pikepdf.Array(annots)
        buf = io.BytesIO()
        pdf.save(buf)
        return buf.getvalue()


def _build_flate_stream_pdf(base_bytes: bytes, urls: list[str]) -> bytes:
    lines = ["BT /F1 11 Tf 40 700 Td"]
    for url in urls:
        safe = url.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        lines.append(f"0 -14 Td ({safe}) Tj")
    lines.append("ET")
    stream_bytes = "\n".join(lines).encode("latin1", errors="ignore")
    with pikepdf.open(io.BytesIO(base_bytes)) as pdf:
        extra = pdf.make_stream(stream_bytes)
        cur = pdf.pages[0].obj.get("/Contents")
        if isinstance(cur, pikepdf.Array):
            cur.append(extra)
        elif cur is not None:
            pdf.pages[0].obj["/Contents"] = pikepdf.Array([cur, extra])
        else:
            pdf.pages[0].obj["/Contents"] = extra
        buf = io.BytesIO()
        pdf.save(buf, object_stream_mode=pikepdf.ObjectStreamMode.disable)
        return buf.getvalue()


def _build_js_launchurl_pdf(base_bytes: bytes, url: str) -> bytes:
    esc = url.replace("\\", "\\\\").replace('"', '\\"')
    with pikepdf.open(io.BytesIO(base_bytes)) as pdf:
        pdf.Root["/OpenAction"] = pdf.make_indirect(
            pikepdf.Dictionary(
                S=pikepdf.Name.JavaScript,
                JS=pikepdf.String(f'app.launchURL("{esc}");'),
            )
        )
        buf = io.BytesIO()
        pdf.save(buf)
        return buf.getvalue()


def _unrounded_pdf_max_prob(
    extracted_uris: list[dict[str, Any]],
    scorer: URILexicalHeadScorer,
) -> float:
    from malpdf.scanner.uri_lexical import (
        canonicalize_extracted_uri,
        is_bare_dual_use_hosted_uri,
        is_xml_xmp_namespace_uri,
    )

    seen: list[str] = []
    seen_set: set[str] = set()
    for item in extracted_uris:
        cand = str(item.get("raw_uri") or item.get("uri") or "")
        canon = canonicalize_extracted_uri(cand)
        if canon is None:
            continue
        raw_clean, _ = canon
        if is_xml_xmp_namespace_uri(raw_clean) or is_allowlisted_uri(raw_clean) or raw_clean in seen_set:
            continue
        seen_set.add(raw_clean)
        seen.append(raw_clean)
        if len(seen) >= 256:
            break
    if not seen:
        return 0.0
    probs = scorer.score_urls(seen)
    or_probs = [float(probs[i]) for i, url in enumerate(seen) if not is_bare_dual_use_hosted_uri(url)]
    return max(or_probs) if or_probs else 0.0


def _pdf_level_calibration(
    raw_val_rows: list[tuple[str, int, str]],
    val_aug_benign: list[tuple[str, int]],
    raw_val_probs_benign: np.ndarray,
    raw_val_probs_phish: np.ndarray,
    aug_val_probs_benign: np.ndarray,
    scorer: URILexicalHeadScorer,
    seed: int = 42,
) -> dict[str, Any]:
    if not len(raw_val_probs_benign) or not len(raw_val_probs_phish) or not len(aug_val_probs_benign):
        raise ValueError("empty_validation_cohort_for_calibration")

    rng = np.random.default_rng(seed + 303)
    ing = InstantPDFIngestion(v4_contract_path=REPO / "configs" / "transgraph_v4_contract.json", as_numpy=True)
    benign_base = load_real_benign_bytes()

    val_phish = [u for u, y, _ in raw_val_rows if y == 1 and not is_allowlisted_uri(u)]
    val_legit_pool = [u for u, y, _ in raw_val_rows if y == 0 and not is_allowlisted_uri(u)] + [
        u for u, _y in val_aug_benign if not is_allowlisted_uri(u)
    ]
    if not val_phish or not val_legit_pool:
        raise ValueError("empty_pdf_validation_pool")

    rng.shuffle(val_phish)
    rng.shuffle(val_legit_pool)

    phish_pdfs: list[tuple[str, bytes]] = []
    for idx in range(min(50, len(val_phish))):
        phish_pdfs.append(("annot", _build_annot_pdf(benign_base, [val_phish[idx]])))
    for idx in range(50, min(100, len(val_phish))):
        phish_pdfs.append(("flate", _build_flate_stream_pdf(benign_base, [val_phish[idx]])))
    for idx in range(100, min(150, len(val_phish))):
        phish_pdfs.append(("js_launch", _build_js_launchurl_pdf(benign_base, val_phish[idx])))

    benign_pdfs: list[bytes] = [benign_base]
    cursor = 0
    for idx in range(200):
        k = int(rng.integers(5, 16))
        batch_urls = [val_legit_pool[(cursor + j) % len(val_legit_pool)] for j in range(k)]
        cursor += k
        if idx % 2 == 0:
            benign_pdfs.append(_build_annot_pdf(benign_base, batch_urls))
        else:
            benign_pdfs.append(_build_flate_stream_pdf(benign_base, batch_urls))

    phish_scores: list[tuple[str, float]] = []
    for vec_name, pdf_bytes in phish_pdfs:
        d = ing.ingest(pdf_bytes)
        phish_scores.append((vec_name, _unrounded_pdf_max_prob(d.get("extracted_uris") or [], scorer)))

    benign_scores: list[float] = []
    for pdf_bytes in benign_pdfs:
        d = ing.ingest(pdf_bytes)
        benign_scores.append(_unrounded_pdf_max_prob(d.get("extracted_uris") or [], scorer))

    ben_arr = np.asarray(benign_scores, dtype=np.float64)
    phish_pdf_arr = np.asarray([p for _, p in phish_scores], dtype=np.float64)

    candidates = sorted(
        {round(float(x), 4) for x in np.linspace(0.50, 0.90, 81)}
        | {round(float(x), 4) for x in np.linspace(0.902, 0.98, 40)}
    )
    best_thr: float | None = None
    best_key: tuple[float, float, float, float] | None = None

    for thr in candidates:
        raw_fpr = float(np.mean(raw_val_probs_benign >= thr))
        aug_fpr = float(np.mean(aug_val_probs_benign >= thr))
        pdf_fpr = float(np.mean(ben_arr >= thr))
        if raw_fpr <= 0.0005 and aug_fpr <= 0.0005 and pdf_fpr <= 0.01:
            raw_phish_rec = float(np.mean(raw_val_probs_phish >= thr))
            pdf_phish_rec = float(np.mean(phish_pdf_arr >= thr))
            key = (raw_phish_rec, -(raw_fpr + aug_fpr), pdf_phish_rec, -thr)
            if best_key is None or key > best_key:
                best_key = key
                best_thr = float(thr)

    if best_thr is None:
        diag = {
            "raw_val_benign_url_fpr_at_098": float(np.mean(raw_val_probs_benign >= 0.98)),
            "aug_val_benign_url_fpr_at_098": float(np.mean(aug_val_probs_benign >= 0.98)),
            "pdf_val_benign_fpr_at_098": float(np.mean(ben_arr >= 0.98)),
        }
        raise RuntimeError(f"no_feasible_uri_threshold_within_budget:{json.dumps(diag)}")

    per_vec = {}
    for vname in ("annot", "flate", "js_launch"):
        sub = [p for vn, p in phish_scores if vn == vname]
        per_vec[vname] = {
            "count": len(sub),
            "recall_at_t_high": round(float(np.mean(np.asarray(sub) >= best_thr)), 4) if sub else 0.0,
        }

    return {
        "t_low": 0.50,
        "t_high": best_thr,
        "raw_val_benign_url_fpr": round(float(np.mean(raw_val_probs_benign >= best_thr)), 6),
        "raw_val_benign_url_fp": int(np.sum(raw_val_probs_benign >= best_thr)),
        "raw_val_benign_url_total": int(len(raw_val_probs_benign)),
        "aug_val_benign_url_fpr": round(float(np.mean(aug_val_probs_benign >= best_thr)), 6),
        "aug_val_benign_url_fp": int(np.sum(aug_val_probs_benign >= best_thr)),
        "aug_val_benign_url_total": int(len(aug_val_probs_benign)),
        "raw_val_phish_url_recall": round(float(np.mean(raw_val_probs_phish >= best_thr)), 4),
        "val_pdf_phish_count": len(phish_scores),
        "val_pdf_phish_recall": round(float(np.mean(phish_pdf_arr >= best_thr)), 4),
        "val_pdf_phish_per_vector": per_vec,
        "val_pdf_benign_count": len(benign_scores),
        "val_pdf_benign_fp": int(np.sum(ben_arr >= best_thr)),
        "val_pdf_benign_fpr": round(float(np.mean(ben_arr >= best_thr)), 6),
        "val_pdf_benign_max_prob": round(float(np.max(ben_arr)), 6),
        "val_pdf_benign_p99_prob": round(float(np.quantile(ben_arr, 0.99)), 6),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--epochs", type=int, default=24)
    parser.add_argument("--batch-size", type=int, default=2048)
    parser.add_argument("--lr", type=float, default=2e-3)
    parser.add_argument("--out-npz", type=Path, default=DEFAULT_OUT_NPZ)
    parser.add_argument("--out-contract", type=Path, default=DEFAULT_OUT_CONTRACT)
    parser.add_argument("--report-root", type=Path, default=DEFAULT_REPORT_ROOT)
    args = parser.parse_args()

    t0 = time.perf_counter()
    _seed_all(args.seed)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[uri_lexical_v4] Loading PhiUSIIL rows from {PHIUSIIL_CSV_PATH} (device={device})...", flush=True)
    rows, csv_sha = _load_phiusiil_rows(PHIUSIIL_CSV_PATH)
    tr_idx, va_idx, te_idx = _domain_grouped_split(rows, seed=args.seed)
    tr_rows = [rows[i] for i in tr_idx]
    va_rows = [rows[i] for i in va_idx]
    te_rows = [rows[i] for i in te_idx]
    print(
        f"[uri_lexical_v4] Domain-disjoint split: train={len(tr_rows)} val={len(va_rows)} test={len(te_rows)}",
        flush=True,
    )

    raw_norm_labels: dict[str, set[int]] = defaultdict(set)
    for u, y, _ in rows:
        raw_norm_labels[_canonical_norm_url(u)].add(y)
    raw_conflict_norms = {norm for norm, ys in raw_norm_labels.items() if len(ys) > 1}

    aug_train, _ = _augment_split_rows(
        tr_rows, split_name="train", seed=args.seed, benign_multiplier=2, include_phish_aug=True, hosted_ratio=0.03
    )
    aug_val, val_aug_benign = _augment_split_rows(
        va_rows, split_name="val", seed=args.seed + 101, benign_multiplier=1, include_phish_aug=False, hosted_ratio=0.03
    )
    _aug_test_unused, test_aug_benign = _augment_split_rows(
        te_rows,
        split_name="test",
        seed=args.seed + 202,
        benign_multiplier=1,
        include_phish_aug=False,
        hosted_ratio=0.03,
    )
    _verify_generated_disjointness(
        aug_train,
        aug_val,
        [(u, y) for u, y, _ in te_rows] + test_aug_benign,
        allowed_raw_conflicts=raw_conflict_norms,
    )
    _verify_generated_disjointness(
        aug_train[len(tr_rows) :],
        val_aug_benign,
        test_aug_benign,
        allowed_raw_conflicts=set(),
    )
    print(
        f"[uri_lexical_v4] Augmented & verified zero normalized-URL collisions: "
        f"train={len(aug_train)} val={len(aug_val)} val_path_aug={len(val_aug_benign)} test_path_aug={len(test_aug_benign)}",
        flush=True,
    )

    tld_probs, char_probs, default_tld_prob, default_char_prob = _fit_train_tables(tr_rows, aug_train)
    x_tr_raw, y_tr = _extract_matrix(
        aug_train,
        tld_probs=tld_probs,
        char_probs=char_probs,
        default_tld_prob=default_tld_prob,
        default_char_prob=default_char_prob,
    )
    x_va_raw_raw, y_va_raw = _extract_matrix(
        [(u, y) for u, y, _ in va_rows],
        tld_probs=tld_probs,
        char_probs=char_probs,
        default_tld_prob=default_tld_prob,
        default_char_prob=default_char_prob,
    )
    x_va_aug_raw, _y_va_aug = _extract_matrix(
        val_aug_benign,
        tld_probs=tld_probs,
        char_probs=char_probs,
        default_tld_prob=default_tld_prob,
        default_char_prob=default_char_prob,
    )
    x_va_cal_raw, y_va_cal = _extract_matrix(
        aug_val,
        tld_probs=tld_probs,
        char_probs=char_probs,
        default_tld_prob=default_tld_prob,
        default_char_prob=default_char_prob,
    )
    x_te_raw, y_te = _extract_matrix(
        [(u, y) for u, y, _ in te_rows],
        tld_probs=tld_probs,
        char_probs=char_probs,
        default_tld_prob=default_tld_prob,
        default_char_prob=default_char_prob,
    )
    x_te_aug_raw, _y_te_aug = _extract_matrix(
        test_aug_benign,
        tld_probs=tld_probs,
        char_probs=char_probs,
        default_tld_prob=default_tld_prob,
        default_char_prob=default_char_prob,
    )

    tr_log = x_tr_raw.astype(np.float64, copy=True)
    for col in URI_LOG1P_INDICES:
        tr_log[:, col] = np.log1p(np.maximum(tr_log[:, col], 0.0))
    center = tr_log.mean(axis=0)
    scale = np.maximum(tr_log.std(axis=0), 1e-3)

    x_tr = _scale_matrix(x_tr_raw, center, scale)
    x_va_raw_sc = _scale_matrix(x_va_raw_raw, center, scale)
    x_va_aug_sc = _scale_matrix(x_va_aug_raw, center, scale)
    x_va_cal = _scale_matrix(x_va_cal_raw, center, scale)
    x_te = _scale_matrix(x_te_raw, center, scale)
    x_te_aug = _scale_matrix(x_te_aug_raw, center, scale)

    logreg = LogisticRegression(max_iter=400, C=1.0, solver="lbfgs")
    logreg.fit(x_tr, y_tr.astype(np.int64))
    lr_va_probs = logreg.predict_proba(x_va_raw_sc)[:, 1]
    lr_te_probs = logreg.predict_proba(x_te)[:, 1]

    cfg = URILexicalHeadV4Config()
    model = PDFURILexicalHeadV4(cfg).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-3)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=args.epochs)
    loss_fn = nn.BCEWithLogitsLoss()

    loader = DataLoader(
        TensorDataset(torch.from_numpy(x_tr), torch.from_numpy(y_tr)), batch_size=args.batch_size, shuffle=True
    )
    best_state: dict[str, torch.Tensor] | None = None
    best_ap = -1.0
    best_epoch = 0

    for epoch in range(1, args.epochs + 1):
        model.train()
        for xb, yb in loader:
            xb = xb.to(device)
            yb = yb.to(device)
            optimizer.zero_grad(set_to_none=True)
            loss = loss_fn(model(xb), yb)
            loss.backward()
            optimizer.step()
        scheduler.step()

        va_cal_logits = _predict_torch_logits(model, x_va_cal, device)
        va_cal_probs = 1.0 / (1.0 + np.exp(-np.clip(va_cal_logits, -40.0, 40.0)))
        va_ap = float(average_precision_score(y_va_cal, va_cal_probs))
        if va_ap > best_ap:
            best_ap = va_ap
            best_epoch = epoch
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}

    assert best_state is not None
    model.load_state_dict(best_state)
    model.eval()

    va_cal_logits = _predict_torch_logits(model, x_va_cal, device)
    va_raw_logits = _predict_torch_logits(model, x_va_raw_sc, device)
    va_aug_logits = _predict_torch_logits(model, x_va_aug_sc, device)
    te_logits = _predict_torch_logits(model, x_te, device)
    te_aug_logits = _predict_torch_logits(model, x_te_aug, device)

    platt_a, platt_b = _fit_platt(va_cal_logits, y_va_cal)

    def cal_sig(z: np.ndarray, a: float = 1.0, b: float = 0.0) -> np.ndarray:
        return 1.0 / (1.0 + np.exp(-np.clip(a * z + b, -40.0, 40.0)))

    va_cal_probs_raw = cal_sig(va_cal_logits)
    va_cal_probs = cal_sig(va_cal_logits, platt_a, platt_b)
    va_raw_probs = cal_sig(va_raw_logits, platt_a, platt_b)
    va_aug_probs = cal_sig(va_aug_logits, platt_a, platt_b)
    te_probs_cal = cal_sig(te_logits, platt_a, platt_b)
    te_aug_probs_cal = cal_sig(te_aug_logits, platt_a, platt_b)

    print(
        f"[uri_lexical_v4] Training finished best_epoch={best_epoch} best_val_ap={best_ap:.6f}; staging & calibrating...",
        flush=True,
    )
    with tempfile.TemporaryDirectory(prefix=".uri_stage_", dir=REPO / "artifacts") as stage_dir_str:
        stage_dir = Path(stage_dir_str)
        stage_npz = stage_dir / "uri_lexical_head_v4.npz"
        stage_contract = stage_dir / "uri_lexical_head_v4_contract.json"
        save_uri_head_v4_npz(model, stage_npz)
        npz_sha = _sha256_file(stage_npz)

        contract: dict[str, Any] = {
            "schema_version": URI_LEXICAL_SCHEMA_VERSION,
            "model_version": URI_LEXICAL_MODEL_VERSION,
            "model_config": cfg.to_dict(),
            "feature_names": list(URI_LEXICAL_FEATURE_NAMES),
            "log1p_indices": list(URI_LOG1P_INDICES),
            "scaler_center": [round(float(v), 8) for v in center.tolist()],
            "scaler_scale": [round(float(v), 8) for v in scale.tolist()],
            "platt_a": round(platt_a, 8),
            "platt_b": round(platt_b, 8),
            "t_low": 0.50,
            "t_high": 0.96,
            "tld_legit_probs": tld_probs,
            "char_probs": char_probs,
            "default_tld_prob": default_tld_prob,
            "default_char_prob": default_char_prob,
            "weights_npz_sha256": npz_sha,
            "source_dataset_zip_sha256": PHIUSIIL_ZIP_SHA256,
            "source_dataset_csv_sha256": csv_sha,
            "base_git_revision": _git_rev(),
        }
        stage_contract.write_text(
            json.dumps(contract, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        scorer = URILexicalHeadScorer(contract_path=stage_contract, npz_path=stage_npz, prefer_onnx=False)

        pdf_cal = _pdf_level_calibration(
            va_rows,
            val_aug_benign,
            va_raw_probs[y_va_raw == 0],
            va_raw_probs[y_va_raw == 1],
            va_aug_probs,
            scorer,
            seed=args.seed,
        )
        contract["t_low"] = float(pdf_cal["t_low"])
        contract["t_high"] = float(pdf_cal["t_high"])
        validate_uri_lexical_contract(contract)
        stage_contract.write_text(
            json.dumps(contract, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )

        args.out_npz.parent.mkdir(parents=True, exist_ok=True)
        args.out_contract.parent.mkdir(parents=True, exist_ok=True)
        tmp_out_npz = args.out_npz.with_suffix(".npz.tmp")
        shutil.copy2(stage_npz, tmp_out_npz)
        os.replace(tmp_out_npz, args.out_npz)
        tmp_out_contract = args.out_contract.with_suffix(".json.tmp")
        tmp_out_contract.write_text(
            json.dumps(contract, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        os.replace(tmp_out_contract, args.out_contract)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    run_id = f"run_{stamp}_{_git_rev()}"
    run_dir = args.report_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    tr_doms = sorted({rows[i][2] for i in tr_idx})
    va_doms = sorted({rows[i][2] for i in va_idx})
    te_doms = sorted({rows[i][2] for i in te_idx})
    split_digest = hashlib.sha256(
        json.dumps({"train": tr_doms, "val": va_doms, "test": te_doms}, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    metrics = {
        "run_id": run_id,
        "schema_version": URI_LEXICAL_SCHEMA_VERSION,
        "device": str(device),
        "best_epoch": best_epoch,
        "elapsed_sec": round(time.perf_counter() - t0, 2),
        "splits": {
            "train_raw": len(tr_rows),
            "train_augmented": len(aug_train),
            "val_raw": len(va_rows),
            "val_augmented": len(aug_val),
            "val_path_aug_benign": len(val_aug_benign),
            "test_raw": len(te_rows),
            "test_path_aug_benign": len(test_aug_benign),
        },
        "url_metrics": {
            "logistic_val_pr_auc": round(float(average_precision_score(y_va_raw, lr_va_probs)), 6),
            "logistic_test_pr_auc": round(float(average_precision_score(y_te, lr_te_probs)), 6),
            "mlp_val_cal_pr_auc": round(float(average_precision_score(y_va_cal, va_cal_probs)), 6),
            "mlp_val_raw_pr_auc": round(float(average_precision_score(y_va_raw, va_raw_probs)), 6),
            "mlp_test_pr_auc": round(float(average_precision_score(y_te, te_probs_cal)), 6),
            "mlp_test_roc_auc": round(float(roc_auc_score(y_te, te_probs_cal)), 6),
            "val_cal_ece_raw": _expected_calibration_error(y_va_cal, va_cal_probs_raw),
            "val_cal_ece_platt": _expected_calibration_error(y_va_cal, va_cal_probs),
            "test_ece_platt": _expected_calibration_error(y_te, te_probs_cal),
            "test_phishing_recall_at_t_high": round(float(np.mean(te_probs_cal[y_te == 1] >= contract["t_high"])), 4),
            "test_benign_url_fpr_at_t_high": round(float(np.mean(te_probs_cal[y_te == 0] >= contract["t_high"])), 6),
            "test_path_aug_benign_fpr_at_t_high": round(float(np.mean(te_aug_probs_cal >= contract["t_high"])), 6),
            "test_path_aug_benign_fp_at_t_high": int(np.sum(te_aug_probs_cal >= contract["t_high"])),
        },
        "pdf_level_val_calibration": pdf_cal,
        "contract_sha256": _sha256_file(args.out_contract),
        "weights_npz_sha256": npz_sha,
    }
    methodology = {
        "run_id": run_id,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "schema_version": URI_LEXICAL_SCHEMA_VERSION,
        "feature_count": len(URI_LEXICAL_FEATURE_NAMES),
        "scheme_neutral": True,
        "www_stripped_outside_registrable_domain": True,
        "bare_trailing_slash_normalized": True,
        "domain_disjoint_split": "80/10/10 grouped by registrable_domain, seed=42",
        "split_domain_counts": {"train": len(tr_doms), "val": len(va_doms), "test": len(te_doms)},
        "split_manifest_sha256": split_digest,
        "phiusiil_zip_sha256": PHIUSIIL_ZIP_SHA256,
        "phiusiil_csv_sha256": csv_sha,
        "platt_params": {"a": round(platt_a, 8), "b": round(platt_b, 8)},
        "thresholds": {"t_low": contract["t_low"], "t_high": contract["t_high"]},
    }
    (run_dir / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    (run_dir / "locked_methodology.json").write_text(json.dumps(methodology, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metrics, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
