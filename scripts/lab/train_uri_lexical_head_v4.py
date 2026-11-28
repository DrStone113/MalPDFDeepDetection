"""Train, Platt-calibrate, and jointly PDF-calibrate PDFURILexicalHead v4 (uri_lexical_v4.2)."""

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
from urllib.parse import urlsplit
import zipfile

import numpy as np
import pandas as pd
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
    _is_ip_host,
    _parse_ip_address,
    _split_url_host,
    extract_tld,
    extract_url_lexical_features,
    is_allowlisted_uri,
    is_bare_dual_use_hosted_uri,
    is_scorable_http_uri,
    normalize_uri_for_lexical_features,
    registrable_domain,
)

PHIUSIIL_ZIP_PATH = REPO / "data" / "external" / "uri_phishing_open_data" / "phiusiil_uci_967" / "phiusiil_uci_967.zip"
PHIUSIIL_ZIP_SHA256 = "0a639fd03aea6308c5b1c10c92aa23c2ce1505447a9137271865cd0badc9a59a"
PHIUSIIL_CSV_PATH = (
    REPO / "data" / "external" / "uri_phishing_open_data" / "phiusiil_uci_967" / "PhiUSIIL_Phishing_URL_Dataset.csv"
)
EALVARADOB_DIR = REPO / "data" / "external" / "uri_phishing_open_data" / "ealvaradob_urls"
PIROCHETO_DIR = REPO / "data" / "external" / "uri_phishing_open_data" / "pirocheto_url"
DEFAULT_OUT_NPZ = REPO / "artifacts" / "models" / "uri_lexical_head_v4" / "uri_lexical_head_v4.npz"
DEFAULT_OUT_CONTRACT = REPO / "configs" / "uri_lexical_head_v4_contract.json"
DEFAULT_REPORT_ROOT = REPO / "reports" / "experiments" / "uri_lexical_head_v4"

REALWORLD_BENIGN_CHALLENGE_URLS: tuple[str, ...] = (
    "https://www.adobe.com/acrobat",
    "https://learn.microsoft.com/dotnet/desktop/winforms/",
    "https://github.com/example/project/blob/main/README.md",
    "https://docs.google.com/document/d/fixture/edit",
    "https://docs.google.com/forms/d/fixture/viewform",
    "https://fixture.workers.dev/reference",
    "https://fixture.workers.dev/review",
    "https://tenant.firebaseio.com/reference",
    "https://external-review.invalid/reference",
    "https://child.example.invalid/reference",
    "https://en.wikipedia.org/wiki/Portable_Document_Format",
    "https://www.iana.org/",
    "https://github.com/pytorch/pytorch/blob/main/torch/nn/functional.py",
    "https://github.com/google-research/bert/commit/eedf5716ce1268e56f0a50264a88cafad334ac61",
    "https://github.com/openai/whisper/releases/tag/v20231117",
    "https://huggingface.co/datasets/squad",
    "https://huggingface.co/meta-llama/Llama-2-7b-hf",
    "https://pytorch.org/docs/stable/generated/torch.nn.Linear.html",
    "https://proceedings.neurips.cc/paper/2020/file/1457c0d6bfcb4967418bfb8ac142f64a-Paper.pdf",
    "https://openreview.net/forum?id=H1eCW3EKvH",
    "https://zenodo.org/record/5140428#.YQ2x3I5KiUl",
    "https://aclanthology.org/2023.acl-long.123.pdf",
    "https://jmlr.org/papers/v21/20-074.html",
    "https://proceedings.mlr.press/v119/chen20j.html",
    "https://en.wikipedia.org/wiki/PDF/A",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://readthedocs.io/en/latest/index.html",
    "https://scikit-learn.org/stable/modules/generated/sklearn.metrics.roc_auc_score.html",
    "https://pypi.org/project/pikepdf/9.0.0/",
    "https://www.npmjs.com/package/react",
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
    "https://aws.amazon.com/s3/pricing/",
    "https://cloud.google.com/vertex-ai/docs/start/introduction-unified-platform",
    "https://portal.azure.com/",
    "https://www.sec.gov/Archives/edgar/data/320193/000032019323000106/aapl-20230930.htm",
    "https://www.supremecourt.gov/opinions/22pdf/21-1271_3f14.pdf",
    "https://www.who.int/publications/i/item/9789240067530",
    "https://www.un.org/en/about-us/universal-declaration-of-human-rights",
    "https://www.oecd.org/en/publications/2024/05/oecd-economic-outlook-volume-2024-issue-1_52d62e13.html",
    "https://ec.europa.eu/commission/presscorner/detail/en/ip_24_1234",
    "https://www.wipo.int/edocs/pubdocs/en/wipo_pub_941_2023.pdf",
    "https://www.bis.org/publ/arpdf/ar2023e.pdf",
    "https://www.imf.org/en/Publications/WEO/Issues/2023/10/10/world-economic-outlook-october-2023",
    "https://www.worldbank.org/en/publication/wdr/wdr-2023",
    "https://www.reuters.com/technology/artificial-intelligence/2024-05-01/",
    "https://www.nytimes.com/2024/01/15/technology/ai-regulation.html",
    "https://www.bbc.co.uk/news/technology-68123456",
    "https://twitter.com/OpenAI/status/1635687373060317185",
    "https://www.linkedin.com/in/john-doe-123456/",
    "https://medium.com/@author/deep-learning-pdf-security-a1b2c3d4e5f6",
    "https://stackoverflow.com/questions/12345678/how-to-parse-pdf-in-python",
    "https://scholar.google.com/citations?user=ABCDEF1234&hl=en",
    "https://www.researchgate.net/publication/342312345_Title_With_Underscores",
    "https://www.dropbox.com/s/abcd1234efgh5678/supplement.pdf?dl=0",
    "https://drive.google.com/file/d/1A2B3C4D5E6F7G8H9I0J/view?usp=sharing",
    "https://my-lab.github.io/paper-project-2024/",
    "http://www.cs.toronto.edu/~kriz/cifar.html",
    "https://www.example-publisher.org/files/Annual%20Report%202024.pdf",
    "https://www.census.gov/data/tables/2023/demo/popest/2020-2023-popest.html",
    "https://dx.doi.org/10.1109/SP40001.2021.00012",
    "https://link.springer.com/chapter/10.1007/978-3-030-58951-6_12",
    "https://onlinelibrary.wiley.com/doi/abs/10.1002/sec.1234",
    "https://www.tensorflow.org/api_docs/python/tf/keras/Model",
    "https://keras.io/api/layers/core_layers/dense/",
    "https://numpy.org/doc/stable/reference/generated/numpy.linalg.svd.html",
    "https://pandas.pydata.org/docs/reference/api/pandas.DataFrame.merge.html",
    "https://matplotlib.org/stable/api/_as_gen/matplotlib.pyplot.plot.html",
    "https://www.virustotal.com/gui/file/abcdef0123456789",
    "https://pdfa.org/resource/iso-32000-2/",
)

_BENIGN_DEEP_PATHS: tuple[str, ...] = (
    "/docs/reference/manual-v2/section-4.pdf",
    "/articles/2025/04/research-summary-1042?page=3&lang=en",
    "/publications/reports/annual_report_2024.pdf#page=12",
    "/files/Annual%20Report%202024.pdf",
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
    "Annual%20Report%202024.pdf",
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
_CLEAN_FRAGMENTS: tuple[str, ...] = ("#overview", "#appendix", "#references", "#top")

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
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


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


def _canonical_norm_url(raw_url: str) -> str:
    return normalize_uri_for_lexical_features(raw_url)[5].lower()


def _split_canonical_url_key(raw_url: str) -> str:
    """Canonical URL key normalizing default ports, non-registrable www., IPs, and bare trailing slashes."""
    txt = str(raw_url or "").strip()
    if not txt:
        return ""
    prefixed = txt if "://" in txt else f"http://{txt}"
    try:
        parts = urlsplit(prefixed)
    except ValueError:
        return _canonical_norm_url(txt)
    scheme = (parts.scheme or "http").lower()
    raw_netloc = (parts.netloc or "").strip()
    if "@" in raw_netloc:
        raw_netloc = raw_netloc.rsplit("@", 1)[-1]
    host = ""
    port_suffix = ""
    if raw_netloc.startswith("["):
        end_br = raw_netloc.find("]")
        if end_br != -1:
            host = raw_netloc[1:end_br].strip().lower()
            rest = raw_netloc[end_br + 1 :].strip()
            if rest.startswith(":"):
                p = rest[1:].strip()
                if (
                    p.isascii()
                    and p.isdigit()
                    and len(p) <= 5
                    and not ((scheme == "http" and int(p) == 80) or (scheme == "https" and int(p) == 443))
                ):
                    port_suffix = f":{int(p)}"
    elif ":" in raw_netloc:
        h_part, p_part = raw_netloc.rsplit(":", 1)
        host = h_part.strip().lower().rstrip(".")
        p = p_part.strip()
        if (
            p.isascii()
            and p.isdigit()
            and len(p) <= 5
            and not ((scheme == "http" and int(p) == 80) or (scheme == "https" and int(p) == 443))
        ):
            port_suffix = f":{int(p)}"
    else:
        host = raw_netloc.lower().rstrip(".")
    ip_obj = _parse_ip_address(host)
    if ip_obj is not None:
        host_key = f"[{ip_obj.compressed}]" if ip_obj.version == 6 else str(ip_obj)
    else:
        host_key = _strip_leading_www(host)
    path = parts.path or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    query = f"?{parts.query}" if parts.query else ""
    if path == "/" and not query:
        return f"{host_key}{port_suffix}".lower()
    return f"{host_key}{port_suffix}{path}{query}".lower()


def compute_phiusiil_split_manifest_sha256(
    rows: list[tuple[str, int, str]],
    tr_idx: list[int],
    va_idx: list[int],
    te_idx: list[int],
) -> str:
    payload = {
        "train": sorted({rows[i][2] for i in tr_idx}),
        "val": sorted({rows[i][2] for i in va_idx}),
        "test": sorted({rows[i][2] for i in te_idx}),
    }
    return hashlib.sha256(json.dumps(payload, separators=(",", ":")).encode("utf-8")).hexdigest()


def _load_phiusiil_rows(csv_path: Path) -> tuple[list[tuple[str, int, str]], str]:
    if _sha256_file(PHIUSIIL_ZIP_PATH) != PHIUSIIL_ZIP_SHA256:
        raise ValueError("phiusiil_zip_sha256_mismatch")
    csv_sha = _sha256_file(csv_path)
    with zipfile.ZipFile(PHIUSIIL_ZIP_PATH, "r") as zf:
        csv_members = [name for name in zf.namelist() if name.lower().endswith(".csv")]
        if len(csv_members) != 1:
            raise ValueError("phiusiil_zip_csv_member_invalid")
        if hashlib.sha256(zf.read(csv_members[0])).hexdigest() != csv_sha:
            raise ValueError("phiusiil_csv_zip_mismatch")
    rows: list[tuple[str, int, str]] = []
    with csv_path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        for row in csv.DictReader(handle):
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


def _load_external_full_url_rows(
    challenge_norms: set[str],
) -> tuple[list[tuple[str, int, str]], dict[str, Any]]:
    eal_prov = json.loads((EALVARADOB_DIR / "provenance.json").read_text(encoding="utf-8"))
    eal_json = EALVARADOB_DIR / str(eal_prov["file"])
    if _sha256_file(eal_json) != str(eal_prov["sha256"]):
        raise ValueError("ealvaradob_sha256_mismatch")

    pir_prov = json.loads((PIROCHETO_DIR / "provenance.json").read_text(encoding="utf-8"))
    pir_label_map = {"legitimate": 0, "phishing": 1, 0: 0, 1: 1, "0": 0, "1": 1}

    raw_items: list[tuple[str, int]] = []
    for row in json.loads(eal_json.read_text(encoding="utf-8")):
        if isinstance(row, dict) and row.get("label") in (0, 1) and isinstance(row.get("text"), str):
            raw_items.append((row["text"], int(row["label"])))

    for fname, meta in pir_prov["files"].items():
        fpath = PIROCHETO_DIR / fname
        if _sha256_file(fpath) != str(meta["sha256"]):
            raise ValueError(f"pirocheto_sha256_mismatch:{fname}")
        df = pd.read_parquet(fpath, columns=["url", "status"])
        for u, st in zip(df["url"].tolist(), df["status"].tolist(), strict=True):
            lbl = pir_label_map.get(st)
            if lbl is not None and isinstance(u, str):
                raw_items.append((u, lbl))

    norm_labels: dict[str, set[int]] = defaultdict(set)
    deduped: list[tuple[str, int, str, str]] = []
    seen_pairs: set[tuple[str, int]] = set()
    for raw_text, y in raw_items:
        txt = raw_text.strip()
        if not txt or any(c in txt for c in ("\r", "\n", "\x00")):
            continue
        url = txt if "://" in txt else f"http://{txt}"
        if not is_scorable_http_uri(url):
            continue
        norm = _split_canonical_url_key(url)
        if norm in challenge_norms:
            continue
        _, _, host, _, _ = _split_url_host(url)
        reg = registrable_domain(host)
        if not reg:
            continue
        norm_labels[norm].add(y)
        if (norm, y) not in seen_pairs:
            seen_pairs.add((norm, y))
            deduped.append((url, y, reg, norm))

    conflict_norms = {n for n, ys in norm_labels.items() if len(ys) > 1}
    clean = [(u, y, reg) for u, y, reg, norm in deduped if norm not in conflict_norms]
    meta_out = {
        "ealvaradob_sha256": eal_prov["sha256"],
        "pirocheto_files_sha256": {k: v["sha256"] for k, v in pir_prov["files"].items()},
        "external_clean_unique_rows": len(clean),
        "external_conflict_norms_dropped": len(conflict_norms),
    }
    return clean, meta_out


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


def _split_external_aligned(
    ext_rows: list[tuple[str, int, str]],
    *,
    phi_tr_doms: set[str],
    phi_va_doms: set[str],
    phi_te_doms: set[str],
    phi_norm_labels: dict[str, set[int]],
    seed: int,
) -> tuple[list[tuple[str, int, str]], list[tuple[str, int, str]], list[tuple[str, int, str]]]:
    new_rows: list[tuple[str, int, str]] = []
    ext_tr: list[tuple[str, int, str]] = []
    ext_va: list[tuple[str, int, str]] = []
    ext_te: list[tuple[str, int, str]] = []

    for u, y, dom in ext_rows:
        norm = _split_canonical_url_key(u)
        if norm in phi_norm_labels:
            continue
        if dom in phi_te_doms:
            ext_te.append((u, y, dom))
        elif dom in phi_va_doms:
            ext_va.append((u, y, dom))
        elif dom in phi_tr_doms:
            ext_tr.append((u, y, dom))
        else:
            new_rows.append((u, y, dom))

    new_tr_idx, new_va_idx, new_te_idx = _domain_grouped_split(new_rows, seed=seed + 17)
    ext_tr.extend(new_rows[i] for i in new_tr_idx)
    ext_va.extend(new_rows[i] for i in new_va_idx)
    ext_te.extend(new_rows[i] for i in new_te_idx)
    return ext_tr, ext_va, ext_te


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
    if bucket < 0.16:
        suffix = "/" if float(rng.random()) < 0.25 else ""
    elif bucket < 0.30:
        seg1 = _SEG1_POOL[int(rng.integers(0, len(_SEG1_POOL)))]
        trailing = "/" if float(rng.random()) < 0.25 else ""
        suffix = f"/{seg1}{trailing}"
    elif bucket < 0.48:
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
    elif bucket < 0.78:
        s1 = _SEG1_POOL[int(rng.integers(0, len(_SEG1_POOL)))]
        year = int(rng.integers(2021, 2027))
        month = int(rng.integers(1, 13))
        if float(rng.random()) < 0.60:
            slug = f"{_SEG_TOPIC_POOL[int(rng.integers(0, len(_SEG_TOPIC_POOL)))]}-{int(rng.integers(1, 2027))}"
        else:
            slug = _SEG_FILE_POOL[int(rng.integers(0, len(_SEG_FILE_POOL)))]
        q = _CLEAN_QUERIES[int(rng.integers(0, len(_CLEAN_QUERIES)))] if float(rng.random()) < 0.40 else ""
        suffix = f"/{s1}/{year}/{month:02d}/{slug}{q}"
    else:
        parts = [_SEG1_POOL[int(rng.integers(0, len(_SEG1_POOL)))]]
        for _ in range(int(rng.integers(1, 3))):
            parts.append(_SEG_TOPIC_POOL[int(rng.integers(0, len(_SEG_TOPIC_POOL)))])
        parts.append(_SEG_FILE_POOL[int(rng.integers(0, len(_SEG_FILE_POOL)))])
        q = _CLEAN_QUERIES[int(rng.integers(0, len(_CLEAN_QUERIES)))] if float(rng.random()) < 0.35 else ""
        suffix = "/" + "/".join(parts) + q

    if bucket >= 0.16 and float(rng.random()) < 0.14:
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


def _augment_phi_split(
    split_rows: list[tuple[str, int, str]],
    *,
    split_name: str,
    seed: int,
    benign_multiplier: int = 1,
    include_phish_aug: bool = False,
    hosted_ratio: float = 0.0,
    challenge_norms: set[str] | None = None,
) -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
    rng = np.random.default_rng(seed)
    c_norms = challenge_norms or set()
    out: list[tuple[str, int]] = [(u, y) for u, y, _ in split_rows]
    aug_benign: list[tuple[str, int]] = []

    raw_hosts_seen: dict[str, set[int]] = defaultdict(set)
    for u, y, _ in split_rows:
        raw_hosts_seen[_split_canonical_url_key(u)].add(y)
    ben_rows = [(u, y, dom) for u, y, dom in split_rows if y == 0]

    for raw_url, y, reg_dom in split_rows:
        scheme, _nl, host, path, query = _split_url_host(raw_url)
        if y == 0:
            if len(raw_hosts_seen.get(_split_canonical_url_key(raw_url), set())) > 1:
                continue
            for _ in range(benign_multiplier):
                cand = _synthesize_benign_url(rng, host, scheme)
                cnorm = _split_canonical_url_key(cand)
                if cnorm not in c_norms and 1 not in raw_hosts_seen.get(cnorm, set()):
                    aug_benign.append((cand, 0))
                    out.append((cand, 0))
            if float(rng.random()) < 0.12:
                alt_sch = "http" if scheme == "https" else "https"
                q = f"?{query}" if query else ""
                cand = f"{alt_sch}://{_strip_leading_www(host)}{path}{q}"
                cnorm = _split_canonical_url_key(cand)
                if cnorm not in c_norms and 1 not in raw_hosts_seen.get(cnorm, set()):
                    aug_benign.append((cand, 0))
                    out.append((cand, 0))
        elif include_phish_aug and float(rng.random()) < 0.22:
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
            cnorm = _split_canonical_url_key(cand)
            if cnorm not in c_norms and 0 not in raw_hosts_seen.get(cnorm, set()):
                out.append((cand, 1))

    n_hosted = max(20, int(round(len(ben_rows) * hosted_ratio))) if hosted_ratio > 0.0 else 0
    for cand, lbl in _build_split_hosted_controls(split_name, n_hosted, rng):
        cnorm = _split_canonical_url_key(cand)
        if cnorm not in c_norms and 1 not in raw_hosts_seen.get(cnorm, set()):
            aug_benign.append((cand, lbl))
            out.append((cand, lbl))

    return out, aug_benign


def _verify_split_disjointness(
    tr_items: list[tuple[str, int]],
    va_items: list[tuple[str, int]],
    te_items: list[tuple[str, int]],
    *,
    raw_domain_groups: tuple[set[str], set[str], set[str]],
    allowed_raw_conflicts: set[str],
    challenge_norms: set[str],
) -> None:
    raw_tr_doms, raw_va_doms, raw_te_doms = raw_domain_groups
    if (
        not raw_tr_doms.isdisjoint(raw_va_doms)
        or not raw_tr_doms.isdisjoint(raw_te_doms)
        or not raw_va_doms.isdisjoint(raw_te_doms)
    ):
        raise ValueError("cross_split_raw_registrable_domain_collision")

    def _build_map(items: list[tuple[str, int]], split_name: str, check_challenge: bool) -> tuple[set[str], set[str]]:
        url_labels: dict[str, set[int]] = defaultdict(set)
        doms: set[str] = set()
        for url, y in items:
            norm = _split_canonical_url_key(url)
            if check_challenge and norm in challenge_norms:
                raise ValueError(f"challenge_leak_in_{split_name}:{norm}")
            url_labels[norm].add(y)
            _, _, host, _, _ = _split_url_host(url)
            reg = registrable_domain(host)
            if reg:
                doms.add(reg)
        for norm, ys in url_labels.items():
            if len(ys) > 1 and norm not in allowed_raw_conflicts:
                raise ValueError(f"label_conflict_in_{split_name}:{norm}")
        return set(url_labels), doms

    tr_keys, tr_doms = _build_map(tr_items, "train", check_challenge=True)
    va_keys, va_doms = _build_map(va_items, "val", check_challenge=True)
    te_keys, te_doms = _build_map(te_items, "test", check_challenge=False)

    if not tr_keys.isdisjoint(va_keys):
        raise ValueError(f"train_val_url_collision:{len(tr_keys & va_keys)}")
    if not tr_keys.isdisjoint(te_keys):
        raise ValueError(f"train_test_url_collision:{len(tr_keys & te_keys)}")
    if not va_keys.isdisjoint(te_keys):
        raise ValueError(f"val_test_url_collision:{len(va_keys & te_keys)}")
    if not tr_doms.isdisjoint(va_doms) or not tr_doms.isdisjoint(te_doms) or not va_doms.isdisjoint(te_doms):
        raise ValueError("cross_split_registrable_domain_collision")


def _fit_train_tables(
    raw_train_rows: list[tuple[str, int, str]],
    full_path_benign_urls: list[str],
) -> tuple[dict[str, float], dict[str, float], float, float]:
    non_ip_rows: list[tuple[str, str, int]] = []
    for raw_url, y, _ in raw_train_rows:
        _sch, _nl, host, _p, _q = _split_url_host(raw_url)
        if not host or _is_ip_host(host) or _parse_ip_address(host) is not None:
            continue
        non_ip_rows.append((host, raw_url, y))

    n_ben = max(sum(1 for _, _, y in non_ip_rows if y == 0), 1)
    n_phi = max(sum(1 for _, _, y in non_ip_rows if y == 1), 1)
    total_n = n_ben + n_phi
    ben_w = total_n / (2.0 * n_ben)
    phi_w = total_n / (2.0 * n_phi)

    tld_ben_raw: Counter[str] = Counter()
    tld_phi_raw: Counter[str] = Counter()
    for host, _raw_url, y in non_ip_rows:
        tld_multi = extract_tld(host)
        tld_single = host.rsplit(".", 1)[-1] if "." in host else ""
        for t in {tld_multi, tld_single}:
            if t and not t.isdigit():
                if y == 0:
                    tld_ben_raw[t] += 1
                else:
                    tld_phi_raw[t] += 1

    tld_probs: dict[str, float] = {}
    for t in tld_ben_raw.keys() | tld_phi_raw.keys():
        bc, pc = tld_ben_raw[t], tld_phi_raw[t]
        if bc + pc < 5:
            continue
        w_leg = bc * ben_w
        w_tot = w_leg + pc * phi_w
        tld_probs[t] = round((w_leg + 25.0) / (w_tot + 50.0), 6)

    char_cnt: Counter[str] = Counter()
    char_total = 0
    for url in full_path_benign_urls:
        for ch in _canonical_norm_url(url):
            char_cnt[ch] += 1
            char_total += 1

    char_probs = {ch: round(cnt / max(char_total, 1), 6) for ch, cnt in char_cnt.items() if cnt >= 25}
    default_char_prob = max(round(1.0 / max(char_total, 10000), 6), 1e-4)
    return tld_probs, char_probs, 0.50, default_char_prob


def _extract_matrix(
    items: list[tuple[str, int]],
    *,
    tld_probs: dict[str, float],
    char_probs: dict[str, float],
    default_tld_prob: float,
    default_char_prob: float,
    label: str = "split",
) -> tuple[np.ndarray, np.ndarray]:
    n = len(items)
    x = np.zeros((n, len(URI_LEXICAL_FEATURE_NAMES)), dtype=np.float32)
    y = np.zeros((n,), dtype=np.float32)
    for idx, (url, lbl) in enumerate(items):
        if idx > 0 and idx % 250000 == 0:
            print(f"[uri_lexical_v4] Extracted {idx}/{n} ({label})...", flush=True)
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


def _require_loaded_numpy_scorer(scorer: URILexicalHeadScorer, stage: str) -> None:
    if not scorer.model_loaded or scorer.backend != "numpy":
        raise RuntimeError(f"uri_scorer_numpy_not_loaded:{stage}:{scorer.backend}")


def _runtime_pdf_or_gate_prob(extracted_uris: list[dict[str, Any]], scorer: URILexicalHeadScorer) -> float:
    """Measure exact unrounded max OR-gate-eligible URL probability using URILexicalHeadScorer admission logic."""
    return scorer.max_or_eligible_prob(extracted_uris)


def _pdf_level_calibration(
    phi_va_rows: list[tuple[str, int, str]],
    ext_va_rows: list[tuple[str, int, str]],
    val_aug_benign: list[tuple[str, int]],
    phi_va_benign_probs: np.ndarray,
    phi_va_phish_probs: np.ndarray,
    ext_va_benign_probs: np.ndarray,
    ext_va_phish_probs: np.ndarray,
    scorer: URILexicalHeadScorer,
    *,
    base_contract: dict[str, Any],
    stage_npz: Path,
    stage_dir: Path,
    seed: int = 42,
) -> dict[str, Any]:
    if not len(phi_va_benign_probs) or not len(phi_va_phish_probs) or not len(ext_va_benign_probs):
        raise ValueError("empty_validation_cohort_for_calibration")

    rng = np.random.default_rng(seed + 303)
    ing = InstantPDFIngestion(v4_contract_path=REPO / "configs" / "transgraph_v4_contract.json", as_numpy=True)
    benign_base = load_real_benign_bytes()

    val_phish = [u for u, y, _ in phi_va_rows if y == 1 and not is_allowlisted_uri(u)]
    ext_val_legit = [u for u, y, _ in ext_va_rows if y == 0 and not is_allowlisted_uri(u)]
    val_legit_pool = ext_val_legit + [u for u, _ in val_aug_benign if not is_allowlisted_uri(u)]
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
    for idx in range(399):
        k = int(rng.integers(5, 21))
        batch_urls = [val_legit_pool[(cursor + j) % len(val_legit_pool)] for j in range(k)]
        cursor += k
        if idx % 2 == 0:
            benign_pdfs.append(_build_annot_pdf(benign_base, batch_urls))
        else:
            benign_pdfs.append(_build_flate_stream_pdf(benign_base, batch_urls))

    phish_uris_list: list[tuple[str, list[dict[str, Any]]]] = []
    phish_scores: list[tuple[str, float]] = []
    for vec_name, pdf_bytes in phish_pdfs:
        extracted = ing.ingest(pdf_bytes).get("extracted_uris") or []
        phish_uris_list.append((vec_name, extracted))
        phish_scores.append((vec_name, _runtime_pdf_or_gate_prob(extracted, scorer)))

    benign_uris_list: list[list[dict[str, Any]]] = []
    benign_scores: list[float] = []
    for pdf_bytes in benign_pdfs:
        extracted = ing.ingest(pdf_bytes).get("extracted_uris") or []
        benign_uris_list.append(extracted)
        benign_scores.append(_runtime_pdf_or_gate_prob(extracted, scorer))

    ben_arr = np.asarray(benign_scores, dtype=np.float64)
    phish_pdf_arr = np.asarray([p for _, p in phish_scores], dtype=np.float64)
    all_va_phish = (
        np.concatenate([phi_va_phish_probs, ext_va_phish_probs]) if len(ext_va_phish_probs) else phi_va_phish_probs
    )

    candidates = sorted(
        {round(float(x), 4) for x in np.linspace(0.50, 0.90, 81)}
        | {round(float(x), 4) for x in np.linspace(0.902, 0.980, 40)}
        | {round(float(x), 4) for x in np.linspace(0.981, 0.999, 19)}
        | {0.9992, 0.9995}
    )
    best_thr: float | None = None
    best_key: tuple[float, float, float, float] | None = None

    for thr in candidates:
        phi_fpr = float(np.mean(phi_va_benign_probs >= thr))
        ext_fpr = float(np.mean(ext_va_benign_probs >= thr))
        pdf_fp_cnt = int(np.sum(ben_arr >= thr))
        if phi_fpr <= 0.0005 and ext_fpr <= 0.0005 and pdf_fp_cnt <= 2:
            comb_rec = float(np.mean(all_va_phish >= thr))
            pdf_rec = float(np.mean(phish_pdf_arr >= thr))
            key = (pdf_rec, comb_rec, -(phi_fpr + ext_fpr), -thr)
            if best_key is None or key > best_key:
                best_key = key
                best_thr = float(thr)

    if best_thr is None:
        diag = {
            f"at_{t}": {
                "phi_ben_fpr": round(float(np.mean(phi_va_benign_probs >= t)), 6),
                "ext_ben_fpr": round(float(np.mean(ext_va_benign_probs >= t)), 6),
                "pdf_ben_fp": int(np.sum(ben_arr >= t)),
                "pdf_phish_rec": round(float(np.mean(phish_pdf_arr >= t)), 4),
            }
            for t in (0.90, 0.95, 0.98, 0.99, 0.995, 0.999)
        }
        raise RuntimeError(f"no_feasible_uri_threshold_within_budget:{json.dumps(diag)}")

    replay_contract = dict(base_contract)
    replay_contract["t_low"] = 0.50
    replay_contract["t_high"] = best_thr
    validate_uri_lexical_contract(replay_contract)
    replay_contract_path = stage_dir / "uri_lexical_head_v4_replay_contract.json"
    replay_contract_path.write_text(
        json.dumps(replay_contract, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    replay_scorer = URILexicalHeadScorer(contract_path=replay_contract_path, npz_path=stage_npz, prefer_onnx=False)
    _require_loaded_numpy_scorer(replay_scorer, "replay")
    deployed_pdf_ben_fp = sum(1 for u in benign_uris_list if replay_scorer.score_pdf_uris(u)["tier"] == "or_gate")
    deployed_pdf_phish_by_vec: dict[str, list[bool]] = {"annot": [], "flate": [], "js_launch": []}
    for vec_name, u in phish_uris_list:
        deployed_pdf_phish_by_vec[vec_name].append(replay_scorer.score_pdf_uris(u)["tier"] == "or_gate")
    if deployed_pdf_ben_fp > 2:
        raise RuntimeError(f"deployed_pdf_ben_fp_exceeded_budget:{deployed_pdf_ben_fp}")

    per_vec = {
        vname: {"count": len(vals), "recall_at_t_high": round(float(np.mean(vals)), 4) if vals else 0.0}
        for vname, vals in deployed_pdf_phish_by_vec.items()
    }
    return {
        "t_low": 0.50,
        "t_high": best_thr,
        "raw_phi_val_benign_url_fpr": round(float(np.mean(phi_va_benign_probs >= best_thr)), 6),
        "raw_phi_val_benign_url_fp": int(np.sum(phi_va_benign_probs >= best_thr)),
        "raw_phi_val_benign_url_total": int(len(phi_va_benign_probs)),
        "ext_val_benign_url_fpr": round(float(np.mean(ext_va_benign_probs >= best_thr)), 6),
        "ext_val_benign_url_fp": int(np.sum(ext_va_benign_probs >= best_thr)),
        "ext_val_benign_url_total": int(len(ext_va_benign_probs)),
        "raw_phi_val_phish_url_recall": round(float(np.mean(phi_va_phish_probs >= best_thr)), 4),
        "ext_val_phish_url_recall": round(float(np.mean(ext_va_phish_probs >= best_thr)), 4),
        "val_pdf_phish_count": len(phish_scores),
        "val_pdf_phish_recall": round(
            float(np.mean([v for sub in deployed_pdf_phish_by_vec.values() for v in sub])), 4
        ),
        "val_pdf_phish_per_vector": per_vec,
        "val_pdf_benign_count": len(benign_pdfs),
        "val_pdf_benign_fp": deployed_pdf_ben_fp,
        "val_pdf_benign_fpr": round(deployed_pdf_ben_fp / len(benign_pdfs), 6),
        "val_pdf_benign_max_prob": round(float(np.max(ben_arr)), 6),
        "val_pdf_benign_p99_prob": round(float(np.quantile(ben_arr, 0.99)), 6),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--epochs", type=int, default=20)
    parser.add_argument("--batch-size", type=int, default=4096)
    parser.add_argument("--lr", type=float, default=2e-3)
    parser.add_argument("--out-npz", type=Path, default=DEFAULT_OUT_NPZ)
    parser.add_argument("--out-contract", type=Path, default=DEFAULT_OUT_CONTRACT)
    parser.add_argument("--report-root", type=Path, default=DEFAULT_REPORT_ROOT)
    args = parser.parse_args()

    assert len(REALWORLD_BENIGN_CHALLENGE_URLS) == 70
    assert len(set(REALWORLD_BENIGN_CHALLENGE_URLS)) == 70
    challenge_norms = {_split_canonical_url_key(u) for u in REALWORLD_BENIGN_CHALLENGE_URLS}

    t0 = time.perf_counter()
    _seed_all(args.seed)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[uri_lexical_v4] Loading PhiUSIIL + open full-URL corpora (device={device})...", flush=True)
    phi_rows, csv_sha = _load_phiusiil_rows(PHIUSIIL_CSV_PATH)
    tr_idx, va_idx, te_idx = _domain_grouped_split(phi_rows, seed=args.seed)
    phiusiil_split_digest = compute_phiusiil_split_manifest_sha256(phi_rows, tr_idx, va_idx, te_idx)
    phi_tr = [phi_rows[i] for i in tr_idx if _split_canonical_url_key(phi_rows[i][0]) not in challenge_norms]
    phi_va = [phi_rows[i] for i in va_idx if _split_canonical_url_key(phi_rows[i][0]) not in challenge_norms]
    phi_te = [phi_rows[i] for i in te_idx]

    phi_tr_doms = {d for _, _, d in phi_tr}
    phi_va_doms = {d for _, _, d in phi_va}
    phi_te_doms = {d for _, _, d in phi_te}
    phi_norm_labels: dict[str, set[int]] = defaultdict(set)
    for u, y, _ in phi_rows:
        phi_norm_labels[_split_canonical_url_key(u)].add(y)
    phi_conflict_norms = {n for n, ys in phi_norm_labels.items() if len(ys) > 1}

    ext_rows, ext_meta = _load_external_full_url_rows(challenge_norms)
    ext_tr, ext_va, ext_te = _split_external_aligned(
        ext_rows,
        phi_tr_doms=phi_tr_doms,
        phi_va_doms=phi_va_doms,
        phi_te_doms=phi_te_doms,
        phi_norm_labels=phi_norm_labels,
        seed=args.seed,
    )
    print(
        f"[uri_lexical_v4] Splits: phi=({len(phi_tr)},{len(phi_va)},{len(phi_te)}) "
        f"ext=({len(ext_tr)},{len(ext_va)},{len(ext_te)})",
        flush=True,
    )

    aug_phi_tr, aug_phi_tr_ben = _augment_phi_split(
        phi_tr,
        split_name="train",
        seed=args.seed,
        benign_multiplier=1,
        include_phish_aug=True,
        hosted_ratio=0.03,
        challenge_norms=challenge_norms,
    )
    aug_phi_va, aug_phi_va_ben = _augment_phi_split(
        phi_va,
        split_name="val",
        seed=args.seed + 101,
        benign_multiplier=1,
        include_phish_aug=False,
        hosted_ratio=0.0,
        challenge_norms=challenge_norms,
    )

    raw_tr_all = phi_tr + ext_tr
    train_items = aug_phi_tr + [(u, y) for u, y, _ in ext_tr]
    val_items = aug_phi_va + [(u, y) for u, y, _ in ext_va]
    test_all_items = [(u, y) for u, y, _ in phi_te] + [(u, y) for u, y, _ in ext_te]

    _verify_split_disjointness(
        train_items,
        val_items,
        test_all_items,
        raw_domain_groups=(
            {d for _, _, d in raw_tr_all},
            {d for _, _, d in (phi_va + ext_va)},
            {d for _, _, d in (phi_te + ext_te)},
        ),
        allowed_raw_conflicts=phi_conflict_norms,
        challenge_norms=challenge_norms,
    )
    print(
        f"[uri_lexical_v4] Verified domain & canonical-URL disjointness: train={len(train_items)} val={len(val_items)} test={len(test_all_items)}",
        flush=True,
    )

    real_path_tr_benign = [u for u, _ in aug_phi_tr_ben] + [u for u, y, _ in ext_tr if y == 0]
    tld_probs, char_probs, default_tld_prob, default_char_prob = _fit_train_tables(raw_tr_all, real_path_tr_benign)

    ext_tr_kw = dict(
        tld_probs=tld_probs,
        char_probs=char_probs,
        default_tld_prob=default_tld_prob,
        default_char_prob=default_char_prob,
    )
    x_tr_raw, y_tr = _extract_matrix(train_items, label="train", **ext_tr_kw)
    x_va_raw, y_va = _extract_matrix(val_items, label="val", **ext_tr_kw)
    x_va_phi_raw, y_va_phi = _extract_matrix([(u, y) for u, y, _ in phi_va], label="phi_val", **ext_tr_kw)
    x_va_ext_raw, y_va_ext = _extract_matrix([(u, y) for u, y, _ in ext_va], label="ext_val", **ext_tr_kw)
    x_te_phi_raw, y_te_phi = _extract_matrix([(u, y) for u, y, _ in phi_te], label="phi_test", **ext_tr_kw)
    x_te_ext_raw, y_te_ext = _extract_matrix([(u, y) for u, y, _ in ext_te], label="ext_test", **ext_tr_kw)

    tr_log = x_tr_raw.astype(np.float64, copy=True)
    for col in URI_LOG1P_INDICES:
        tr_log[:, col] = np.log1p(np.maximum(tr_log[:, col], 0.0))
    center = tr_log.mean(axis=0)
    scale = np.maximum(tr_log.std(axis=0), 1e-3)

    x_tr = _scale_matrix(x_tr_raw, center, scale)
    x_va = _scale_matrix(x_va_raw, center, scale)
    x_va_phi = _scale_matrix(x_va_phi_raw, center, scale)
    x_va_ext = _scale_matrix(x_va_ext_raw, center, scale)
    x_te_phi = _scale_matrix(x_te_phi_raw, center, scale)
    x_te_ext = _scale_matrix(x_te_ext_raw, center, scale)

    logreg = LogisticRegression(max_iter=300, C=1.0, solver="lbfgs")
    logreg.fit(x_tr, y_tr.astype(np.int64))
    lr_te_phi_probs = logreg.predict_proba(x_te_phi)[:, 1]
    lr_te_ext_probs = logreg.predict_proba(x_te_ext)[:, 1]

    cfg = URILexicalHeadV4Config()
    assert cfg.in_dim == len(URI_LEXICAL_FEATURE_NAMES)
    assert cfg.hidden_dim == 128 and cfg.bottleneck_dim == 64
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

        va_logits = _predict_torch_logits(model, x_va, device)
        va_probs = 1.0 / (1.0 + np.exp(-np.clip(va_logits, -40.0, 40.0)))
        va_ap = float(average_precision_score(y_va, va_probs))
        if va_ap > best_ap:
            best_ap = va_ap
            best_epoch = epoch
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}

    assert best_state is not None
    model.load_state_dict(best_state)
    model.eval()

    va_logits = _predict_torch_logits(model, x_va, device)
    va_phi_logits = _predict_torch_logits(model, x_va_phi, device)
    va_ext_logits = _predict_torch_logits(model, x_va_ext, device)
    te_phi_logits = _predict_torch_logits(model, x_te_phi, device)
    te_ext_logits = _predict_torch_logits(model, x_te_ext, device)

    platt_a, platt_b = _fit_platt(va_logits, y_va)

    def cal_sig(z: np.ndarray, a: float = 1.0, b: float = 0.0) -> np.ndarray:
        return 1.0 / (1.0 + np.exp(-np.clip(a * z + b, -40.0, 40.0)))

    va_probs_raw = cal_sig(va_logits)
    va_probs = cal_sig(va_logits, platt_a, platt_b)
    va_phi_probs = cal_sig(va_phi_logits, platt_a, platt_b)
    va_ext_probs = cal_sig(va_ext_logits, platt_a, platt_b)
    te_phi_probs = cal_sig(te_phi_logits, platt_a, platt_b)
    te_ext_probs = cal_sig(te_ext_logits, platt_a, platt_b)

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
            "external_corpora_sha256": ext_meta,
            "base_git_revision": _git_rev(),
        }
        stage_contract.write_text(
            json.dumps(contract, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        scorer = URILexicalHeadScorer(contract_path=stage_contract, npz_path=stage_npz, prefer_onnx=False)
        _require_loaded_numpy_scorer(scorer, "calibration")

        pdf_cal = _pdf_level_calibration(
            phi_va,
            ext_va,
            aug_phi_va_ben,
            va_phi_probs[y_va_phi == 0],
            va_phi_probs[y_va_phi == 1],
            va_ext_probs[y_va_ext == 0],
            va_ext_probs[y_va_ext == 1],
            scorer,
            base_contract=contract,
            stage_npz=stage_npz,
            stage_dir=stage_dir,
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
        final_scorer = URILexicalHeadScorer(contract_path=stage_contract, npz_path=stage_npz, prefer_onnx=False)
        _require_loaded_numpy_scorer(final_scorer, "final")

        challenge_probs = final_scorer.score_urls(list(REALWORLD_BENIGN_CHALLENGE_URLS))
        challenge_or_fp = sum(
            1
            for u, p in zip(REALWORLD_BENIGN_CHALLENGE_URLS, challenge_probs, strict=True)
            if not is_allowlisted_uri(u) and not is_bare_dual_use_hosted_uri(u) and float(p) >= contract["t_high"]
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

    tr_doms = sorted({d for _, _, d in raw_tr_all})
    va_doms = sorted({d for _, _, d in (phi_va + ext_va)})
    te_doms = sorted({d for _, _, d in (phi_te + ext_te)})
    split_digest = hashlib.sha256(
        json.dumps({"train": tr_doms, "val": va_doms, "test": te_doms}, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    t_high = float(contract["t_high"])
    metrics = {
        "run_id": run_id,
        "schema_version": URI_LEXICAL_SCHEMA_VERSION,
        "model_config": cfg.to_dict(),
        "device": str(device),
        "best_epoch": best_epoch,
        "elapsed_sec": round(time.perf_counter() - t0, 2),
        "splits": {
            "phi_train": len(phi_tr),
            "ext_train": len(ext_tr),
            "train_total": len(train_items),
            "phi_val": len(phi_va),
            "ext_val": len(ext_va),
            "val_total": len(val_items),
            "phi_test": len(phi_te),
            "ext_test": len(ext_te),
        },
        "url_metrics": {
            "logistic_phi_test_pr_auc": round(float(average_precision_score(y_te_phi, lr_te_phi_probs)), 6),
            "logistic_ext_test_pr_auc": round(float(average_precision_score(y_te_ext, lr_te_ext_probs)), 6),
            "mlp_val_cal_pr_auc": round(float(average_precision_score(y_va, va_probs)), 6),
            "mlp_phi_test_pr_auc": round(float(average_precision_score(y_te_phi, te_phi_probs)), 6),
            "mlp_phi_test_roc_auc": round(float(roc_auc_score(y_te_phi, te_phi_probs)), 6),
            "mlp_ext_test_pr_auc": round(float(average_precision_score(y_te_ext, te_ext_probs)), 6),
            "mlp_ext_test_roc_auc": round(float(roc_auc_score(y_te_ext, te_ext_probs)), 6),
            "val_cal_ece_raw": _expected_calibration_error(y_va, va_probs_raw),
            "val_cal_ece_platt": _expected_calibration_error(y_va, va_probs),
            "phi_test_ece_platt": _expected_calibration_error(y_te_phi, te_phi_probs),
            "ext_test_ece_platt": _expected_calibration_error(y_te_ext, te_ext_probs),
            "phi_test_phish_recall_at_t_high": round(float(np.mean(te_phi_probs[y_te_phi == 1] >= t_high)), 4),
            "phi_test_benign_fpr_at_t_high": round(float(np.mean(te_phi_probs[y_te_phi == 0] >= t_high)), 6),
            "ext_test_phish_recall_at_t_high": round(float(np.mean(te_ext_probs[y_te_ext == 1] >= t_high)), 4),
            "ext_test_benign_fpr_at_t_high": round(float(np.mean(te_ext_probs[y_te_ext == 0] >= t_high)), 6),
            "ext_test_benign_fp_at_t_high": int(np.sum(te_ext_probs[y_te_ext == 0] >= t_high)),
            "ext_test_benign_total": int(np.sum(y_te_ext == 0)),
        },
        "pdf_level_val_calibration": pdf_cal,
        "realworld_70_url_probe_or_fp": challenge_or_fp,
        "contract_sha256": _sha256_file(args.out_contract),
        "weights_npz_sha256": npz_sha,
    }
    methodology = {
        "run_id": run_id,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "seed": int(args.seed),
        "schema_version": URI_LEXICAL_SCHEMA_VERSION,
        "feature_count": len(URI_LEXICAL_FEATURE_NAMES),
        "scheme_neutral": True,
        "www_stripped_outside_registrable_domain": True,
        "bare_trailing_slash_normalized": True,
        "domain_disjoint_split": "PhiUSIIL seed=42 frozen first + aligned 80/10/10 external domains",
        "split_domain_counts": {"train": len(tr_doms), "val": len(va_doms), "test": len(te_doms)},
        "split_manifest_sha256": split_digest,
        "phiusiil_split_manifest_sha256": phiusiil_split_digest,
        "weights_npz_sha256": npz_sha,
        "source_dataset_csv_sha256": csv_sha,
        "phiusiil_zip_sha256": PHIUSIIL_ZIP_SHA256,
        "phiusiil_csv_sha256": csv_sha,
        **ext_meta,
        "platt_params": {"a": round(platt_a, 8), "b": round(platt_b, 8)},
        "thresholds": {"t_low": contract["t_low"], "t_high": contract["t_high"]},
    }
    (run_dir / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    (run_dir / "locked_methodology.json").write_text(json.dumps(methodology, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metrics, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
