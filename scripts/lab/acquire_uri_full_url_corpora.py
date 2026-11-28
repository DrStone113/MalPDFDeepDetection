"""Download, SHA-256 pin, and audit ungated open-license full-URL datasets for uri_lexical_v4.2."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any
import urllib.request

import pandas as pd

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from malpdf.scanner.uri_lexical import (
    _ALLOWLISTED_TLDS,
    _split_url_host,
    extract_tld,
    is_scorable_http_uri,
)

BASE_DIR = REPO / "data" / "external" / "uri_phishing_open_data"
EALVARADOB_REV = "55caf9af01ae498d68ff44886ff69a4b165eb54b"
EALVARADOB_URL = f"https://huggingface.co/datasets/ealvaradob/phishing-dataset/resolve/{EALVARADOB_REV}/urls.json"
EALVARADOB_SHA256 = "32cfba42892c915b041a3f0ca6ffd0f484b2590c4c2ca91b13d3ea1330b2c9bd"
PIROCHETO_REV = "1375d450d4540205ac11781b807249c9509739cd"
PIROCHETO_FILES = {
    "train.parquet": (
        f"https://huggingface.co/datasets/pirocheto/phishing-url/resolve/{PIROCHETO_REV}/data/train.parquet",
        "79a776a41e7f5c8a51d24ec6802284887fbdee296c5e09e8d881fc6c4852cc43",
    ),
    "test.parquet": (
        f"https://huggingface.co/datasets/pirocheto/phishing-url/resolve/{PIROCHETO_REV}/data/test.parquet",
        "8131f6e48b58136dac0222b419104d19d7d47938483d0a458403113750222a07",
    ),
}
USER_AGENT = "MalPDFDeepDetection-research/1.0"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _download_file(url: str, dest: Path, expected_sha256: str) -> str:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_file() and dest.stat().st_size > 0:
        actual = _sha256_file(dest)
        if actual != expected_sha256:
            raise ValueError(f"cached_checksum_mismatch:{dest.name}:{actual}")
        return actual
    tmp = dest.with_name(dest.name + ".tmp")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=180) as resp, tmp.open("wb") as out:
            while True:
                chunk = resp.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
        actual = _sha256_file(tmp)
        if actual != expected_sha256:
            raise ValueError(f"downloaded_checksum_mismatch:{dest.name}:{actual}")
        os.replace(tmp, dest)
        return actual
    finally:
        tmp.unlink(missing_ok=True)


def _normalize_candidate_url(raw: str) -> tuple[str, bool] | None:
    text = raw.strip()
    if not text or any(c in text for c in ("\r", "\n", "\x00")):
        return None
    schemeless = "://" not in text
    url = f"http://{text}" if schemeless else text
    if not is_scorable_http_uri(url):
        return None
    return url, schemeless


def _audit_rows(name: str, items: list[tuple[str, int]]) -> dict[str, Any]:
    raw_count = len(items)
    norm_labels: dict[str, set[int]] = defaultdict(set)
    dedup_rows: list[tuple[str, int, bool]] = []
    seen_pairs: set[tuple[str, int]] = set()
    invalid_skipped = 0
    schemeless_cnt = 0

    for raw_url, y in items:
        parsed = _normalize_candidate_url(raw_url)
        if parsed is None:
            invalid_skipped += 1
            continue
        url, was_schemeless = parsed
        key = url.lower()
        norm_labels[key].add(y)
        if (key, y) not in seen_pairs:
            seen_pairs.add((key, y))
            dedup_rows.append((url, y, was_schemeless))

    conflict_keys = {k for k, ys in norm_labels.items() if len(ys) > 1}
    clean_rows = [(u, y, s) for u, y, s in dedup_rows if u.lower() not in conflict_keys]
    schemeless_cnt = sum(1 for _, _, s in clean_rows if s)

    ben = [u for u, y, _ in clean_rows if y == 0]
    phi = [u for u, y, _ in clean_rows if y == 1]

    def _stats(urls: list[str]) -> dict[str, Any]:
        n = max(len(urls), 1)
        path_cnt = query_cnt = dig_cnt = und_cnt = gov_edu_cnt = 0
        for u in urls:
            _, _, host, path, query = _split_url_host(u)
            if path and path != "/":
                path_cnt += 1
            if query:
                query_cnt += 1
            if any(c.isdigit() for c in u):
                dig_cnt += 1
            if "_" in u:
                und_cnt += 1
            tld_single = host.rsplit(".", 1)[-1] if "." in host else ""
            tld_multi = extract_tld(host)
            if tld_single in _ALLOWLISTED_TLDS or tld_multi in _ALLOWLISTED_TLDS:
                gov_edu_cnt += 1
        return {
            "count": len(urls),
            "path_ratio": round(path_cnt / n, 4),
            "query_ratio": round(query_cnt / n, 4),
            "digit_ratio": round(dig_cnt / n, 4),
            "underscore_ratio": round(und_cnt / n, 4),
            "gov_edu_count": gov_edu_cnt,
        }

    return {
        "dataset": name,
        "raw_rows": raw_count,
        "invalid_or_unscorable_skipped": invalid_skipped,
        "exact_conflict_urls_dropped": len(conflict_keys),
        "clean_unique_rows": len(clean_rows),
        "schemeless_prepended_http": schemeless_cnt,
        "benign": _stats(ben),
        "phishing": _stats(phi),
    }


def acquire_all() -> dict[str, Any]:
    eal_dir = BASE_DIR / "ealvaradob_urls"
    eal_path = eal_dir / "urls.json"
    eal_sha = _download_file(EALVARADOB_URL, eal_path, EALVARADOB_SHA256)
    raw_eal = json.loads(eal_path.read_text(encoding="utf-8"))
    eal_items: list[tuple[str, int]] = []
    for row in raw_eal:
        if not isinstance(row, dict):
            continue
        lbl = row.get("label")
        txt = row.get("text")
        if lbl in (0, 1) and isinstance(txt, str):
            eal_items.append((txt, int(lbl)))
    eal_audit = _audit_rows("ealvaradob/phishing-dataset (urls.json)", eal_items)
    eal_prov = {
        "source_repo": "ealvaradob/phishing-dataset",
        "revision": EALVARADOB_REV,
        "license": "apache-2.0",
        "upstream_notes": (
            "Hugging Face card cites compilation from Kaggle/Mendeley/JPCERT URL collections (urls.json split only)."
        ),
        "url": EALVARADOB_URL,
        "file": "urls.json",
        "size_bytes": eal_path.stat().st_size,
        "sha256": eal_sha,
        "acquired_utc": datetime.now(timezone.utc).isoformat(),
        "audit": eal_audit,
    }
    (eal_dir / "provenance.json").write_text(json.dumps(eal_prov, indent=2) + "\n", encoding="utf-8")

    pir_dir = BASE_DIR / "pirocheto_url"
    pir_files_meta: dict[str, Any] = {}
    pir_items: list[tuple[str, int]] = []
    label_map = {"legitimate": 0, "phishing": 1, 0: 0, 1: 1, "0": 0, "1": 1}
    split_counts: Counter[str] = Counter()
    for fname, (url, expected_sha) in PIROCHETO_FILES.items():
        fpath = pir_dir / fname
        sha = _download_file(url, fpath, expected_sha)
        df = pd.read_parquet(fpath, columns=["url", "status"])
        split_counts[fname] = int(len(df))
        for raw_u, raw_st in zip(df["url"].tolist(), df["status"].tolist(), strict=True):
            y = label_map.get(raw_st)
            if y is not None and isinstance(raw_u, str):
                pir_items.append((raw_u, y))
        pir_files_meta[fname] = {"url": url, "size_bytes": fpath.stat().st_size, "sha256": sha, "rows": int(len(df))}
    pir_audit = _audit_rows("pirocheto/phishing-url", pir_items)
    pir_prov = {
        "source_repo": "pirocheto/phishing-url",
        "revision": PIROCHETO_REV,
        "license": "cc-by-4.0",
        "citation": "Hannousse & Yahiouche (2021), arXiv:2010.12847",
        "files": pir_files_meta,
        "acquired_utc": datetime.now(timezone.utc).isoformat(),
        "audit": pir_audit,
    }
    (pir_dir / "provenance.json").write_text(json.dumps(pir_prov, indent=2) + "\n", encoding="utf-8")
    return {"ealvaradob_urls": eal_prov, "pirocheto_url": pir_prov}


if __name__ == "__main__":
    summary = acquire_all()
    print(json.dumps(summary, indent=2))
