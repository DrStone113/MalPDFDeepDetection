"""Discover and HEAD-verify non-overlapping Track B (publisher OOD) and Track C1 (hard-benign) PDFs."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scripts.lab.benign_ood_intake import OCTET_STREAM_ALLOWED_SOURCES, URLS  # noqa: E402

MAX_DOC_BYTES = 12 * 1024 * 1024
MIN_DOC_BYTES = 50
MAX_BATCH_BYTES = 125 * 1024 * 1024
MAX_BATCH_DOCS = 95
UA = "MalPDF research (OOD metadata check)"


def _http_get_text(url: str, timeout: int = 25) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def _head_verify(row: dict[str, Any]) -> dict[str, Any] | None:
    url = row["url"]
    source = row["source"]
    if not re.fullmatch(URLS[source], url):
        return None
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            ctype = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            allowed = {"application/pdf", "application/octet-stream"} if source in OCTET_STREAM_ALLOWED_SOURCES else {"application/pdf"}
            if resp.status != 200 or ctype not in allowed:
                return None
            clen_raw = resp.headers.get("Content-Length")
            clen = int(clen_raw) if clen_raw and clen_raw.isdigit() else row.get("approx_bytes")
            if clen is not None and not (MIN_DOC_BYTES <= int(clen) <= MAX_DOC_BYTES):
                return None
            return {
                "id": row["id"],
                "source": source,
                "track": row["track"],
                "url": url,
                "status": 200,
                "type": ctype,
                "length": str(clen) if clen is not None else None,
                "last_modified": resp.headers.get("Last-Modified"),
                "etag": resp.headers.get("ETag"),
            }
    except (OSError, urllib.error.URLError, ValueError):
        return None


def _load_existing_urls(*paths: Path) -> set[str]:
    urls: set[str] = set()
    for p in paths:
        if not p.is_file():
            continue
        doc = json.loads(p.read_text(encoding="utf-8-sig"))
        for key in ("documents", "entries"):
            for row in doc.get(key, []):
                if row.get("url"):
                    urls.add(row["url"])
    return urls


def _discover_arxiv(excluded: set[str], target: int = 165) -> list[dict[str, Any]]:
    cats = ("cs.CR", "cs.LG", "math.NT", "physics.optics", "q-bio.NC", "stat.ML", "eess.SP", "econ.TH")
    candidates: list[dict[str, Any]] = []
    seen = set(excluded)
    seq = 100
    for cat in cats:
        if len(candidates) >= target + 30:
            break
        try:
            xml = _http_get_text(f"https://export.arxiv.org/api/query?search_query=cat:{cat}&start=40&max_results=35")
        except (OSError, urllib.error.URLError):
            continue
        ids = re.findall(r"<id>http://arxiv\.org/abs/([^<]+)</id>", xml)
        for raw_id in ids:
            clean_id = re.sub(r"v\d+$", "", raw_id.strip())
            url = f"https://arxiv.org/pdf/{clean_id}"
            if url in seen or not re.fullmatch(URLS["arxiv"], url):
                continue
            seen.add(url)
            candidates.append({"id": f"arxiv-{seq:03d}", "source": "arxiv", "track": "prospective_diverse_publishers", "url": url})
            seq += 1
            if len(candidates) >= target + 30:
                break
    return candidates


def _discover_nist(excluded: set[str], target: int = 115) -> list[dict[str, Any]]:
    html = _http_get_text("https://csrc.nist.gov/publications/sp")
    detail_paths = sorted(set(re.findall(r"/pubs/sp/[0-9]+/[A-Za-z0-9_./-]+/final", html)))[: target + 60]
    seen = set(excluded)
    candidates: list[dict[str, Any]] = []

    def _scrape_detail(rel: str) -> str | None:
        try:
            body = _http_get_text("https://csrc.nist.gov" + rel, timeout=15)
        except (OSError, urllib.error.URLError):
            return None
        matches = re.findall(r'https://nvlpubs\.nist\.gov/nistpubs/[^\s"\'<>]+\.pdf', body)
        for u in matches:
            if u not in seen and re.fullmatch(URLS["nist"], u):
                return u
        return None

    with ThreadPoolExecutor(max_workers=10) as ex:
        urls = list(ex.map(_scrape_detail, detail_paths))
    seq = 1
    for u in urls:
        if u and u not in seen:
            seen.add(u)
            candidates.append({"id": f"nist-{seq:03d}", "source": "nist", "track": "prospective_diverse_publishers", "url": u})
            seq += 1
            if len(candidates) >= target + 25:
                break
    return candidates


def _discover_nasa(excluded: set[str], target: int = 85) -> list[dict[str, Any]]:
    queries = (
        "propulsion", "avionics", "robotics", "cryogenic", "photovoltaics",
        "aerodynamics", "turbine", "composite", "navigation", "telemetry", "heat",
    )
    seen = set(excluded)
    candidates: list[dict[str, Any]] = []
    seq = 450
    for q in queries:
        if len(candidates) >= target + 30:
            break
        try:
            raw = _http_get_text(
                f"https://ntrs.nasa.gov/api/citations/search?q={urllib.parse.quote(q)}&downloadsAvailable=true&page[size]=80&page[from]=160"
            )
            data = json.loads(raw)
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            continue
        for item in data.get("results", []):
            for dl in item.get("downloads", []):
                pdf_rel = (dl.get("links") or {}).get("pdf")
                if not pdf_rel:
                    continue
                url = "https://ntrs.nasa.gov" + pdf_rel if pdf_rel.startswith("/") else pdf_rel
                if url in seen or not re.fullmatch(URLS["nasa"], url):
                    continue
                seen.add(url)
                candidates.append({"id": f"nasa-{seq:03d}", "source": "nasa", "track": "prospective_diverse_publishers", "url": url})
                seq += 1
                break
            if len(candidates) >= target + 30:
                break
    return candidates


def _discover_irs(excluded: set[str], target: int = 65) -> list[dict[str, Any]]:
    seen = set(excluded)
    candidates: list[dict[str, Any]] = []
    urls: list[str] = []
    try:
        html = _http_get_text("https://apps.irs.gov/app/picklist/list/formsInstructions.html")
        urls.extend(sorted(set(re.findall(r'https://www\.irs\.gov/pub/irs-pdf/[a-z0-9-]+\.pdf', html))))
    except (OSError, urllib.error.URLError):
        pass
    common_codes = (
        "f1065", "f1120", "f1120s", "f990", "f990ez", "f990pf", "f940", "f941", "f944", "f945",
        "fw2", "fw3", "fw4", "fw4p", "fw7", "fw8ben", "fw8bene", "fw8eci", "fw9",
        "f1096", "f1098", "f1098e", "f1098t", "f1099b", "f1099c", "f1099div", "f1099int", "f1099k",
        "f1099misc", "f1099nec", "f1099r", "f1099s", "f2106", "f2210", "f2290", "f2441", "f2553",
        "f2555", "f2848", "f3115", "f3520", "f3800", "f3903", "f4506", "f4506t", "f4562", "f4684",
        "f4797", "f4868", "f4952", "f4972", "f5329", "f5471", "f5472", "f5498", "f5695", "f6198",
        "f6251", "f6252", "f6765", "f6781", "f7004", "f706", "f709", "f720", "f8027", "f8275",
        "f8283", "f8300", "f8332", "f8379", "f8453", "f8582", "f8606", "f8615", "f8801", "f8814",
        "f8821", "f8822", "f8824", "f8829", "f8832", "f8833", "f8839", "f8853", "f8862", "f8863",
        "f8867", "f8879", "f8880", "f8888", "f8889", "f8915f", "f8917", "f8936", "f8938", "f8949",
        "f8959", "f8960", "f8962", "f8995", "f8995a",
        "p15", "p15a", "p17", "p334", "p501", "p502", "p505", "p515", "p523", "p525",
        "p527", "p535", "p542", "p547", "p550", "p551", "p557", "p590a", "p590b", "p946", "p970",
        "i1040gi", "i1065", "i1120", "i990", "iw9",
    )
    for code in common_codes:
        urls.append(f"https://www.irs.gov/pub/irs-pdf/{code}.pdf")
    seq = 100
    for u in urls:
        if u in seen or not re.fullmatch(URLS["irs"], u):
            continue
        seen.add(u)
        candidates.append({"id": f"irs-{seq:03d}", "source": "irs", "track": "prospective_diverse_publishers", "url": u})
        seq += 1
        if len(candidates) >= target + 35:
            break
    return candidates


def _discover_verapdf(excluded: set[str], target: int = 55) -> list[dict[str, Any]]:
    tree = json.loads(_http_get_text("https://api.github.com/repos/veraPDF/veraPDF-corpus/git/trees/staging?recursive=1"))
    blobs = [
        item for item in tree.get("tree", [])
        if item.get("type") == "blob"
        and item.get("path", "").endswith(".pdf")
        and MIN_DOC_BYTES <= int(item.get("size", 0)) <= MAX_DOC_BYTES
    ]
    keywords = ("acroform", "embeddedfile", "js", "javascript", "jbig2", "objstm", "encrypt", "xfa", "action", "6-9", "6-6", "19005-3", "14289")
    prio = [b for b in blobs if any(k in b["path"].lower() for k in keywords)]
    other = [b for b in blobs if b not in prio]
    step = max(1, len(other) // max(1, target))
    ordered = prio[:: max(1, len(prio) // 35)] + other[::step]
    seen = set(excluded)
    candidates: list[dict[str, Any]] = []
    seq = 1
    for item in ordered:
        enc_path = urllib.parse.quote(item["path"], safe="/")
        url = f"https://raw.githubusercontent.com/veraPDF/veraPDF-corpus/staging/{enc_path}"
        if url in seen or not re.fullmatch(URLS["verapdf"], url):
            continue
        seen.add(url)
        candidates.append({
            "id": f"verapdf-{seq:03d}",
            "source": "verapdf",
            "track": "hard_benign_stress",
            "url": url,
            "approx_bytes": int(item["size"]),
        })
        seq += 1
        if len(candidates) >= target + 15:
            break
    return candidates


def _discover_pdfjs(excluded: set[str], target: int = 55) -> list[dict[str, Any]]:
    items = json.loads(_http_get_text("https://api.github.com/repos/mozilla/pdf.js/contents/test/pdfs"))
    blobs = [
        item for item in items
        if isinstance(item, dict)
        and item.get("type") == "file"
        and item.get("name", "").endswith(".pdf")
        and MIN_DOC_BYTES <= int(item.get("size", 0)) <= MAX_DOC_BYTES
    ]
    keywords = ("js", "acro", "form", "xfa", "annot", "enc", "crypt", "incr", "xref", "issue", "bug", "jbig2", "attach", "link", "action")
    prio = [b for b in blobs if any(k in b["name"].lower() for k in keywords)]
    other = [b for b in blobs if b not in prio]
    ordered = prio + other
    seen = set(excluded)
    candidates: list[dict[str, Any]] = []
    seq = 1
    for item in ordered:
        enc_name = urllib.parse.quote(item["name"], safe="")
        url = f"https://raw.githubusercontent.com/mozilla/pdf.js/master/test/pdfs/{enc_name}"
        if url in seen or not re.fullmatch(URLS["pdfjs"], url):
            continue
        seen.add(url)
        candidates.append({
            "id": f"pdfjs-{seq:03d}",
            "source": "pdfjs",
            "track": "hard_benign_stress",
            "url": url,
            "approx_bytes": int(item["size"]),
        })
        seq += 1
        if len(candidates) >= target + 25:
            break
    return candidates


def pack_batches(verified: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    batches: list[list[dict[str, Any]]] = []
    cur: list[dict[str, Any]] = []
    cur_bytes = 0
    for row in verified:
        sz = int(row["length"]) if row.get("length") else 1_000_000
        if cur and (len(cur) >= MAX_BATCH_DOCS or cur_bytes + sz > MAX_BATCH_BYTES):
            batches.append(cur)
            cur = []
            cur_bytes = 0
        cur.append(row)
        cur_bytes += sz
    if cur:
        batches.append(cur)
    return batches


def main() -> None:
    parser = argparse.ArgumentParser(description="Discover diverse OOD publisher & hard-benign candidate batches")
    parser.add_argument("--out-dir", type=Path, default=REPO / "data/processed/pooled_bulk/benign_ood_diverse")
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    excluded = _load_existing_urls(
        REPO / "data/processed/pooled_bulk/benign_ood/candidates.json",
        REPO / "data/processed/pooled_bulk/benign_ood_expanded/discovery.json",
        REPO / "data/processed/pooled_bulk/benign_ood_expanded/acquisition_v2.json",
    )
    print(f"Loaded {len(excluded)} excluded URLs from v1 + expanded_v1")

    targets = {
        "arxiv": (_discover_arxiv(excluded, 165), 160),
        "nist": (_discover_nist(excluded, 115), 110),
        "nasa": (_discover_nasa(excluded, 85), 80),
        "irs": (_discover_irs(excluded, 65), 60),
        "verapdf": (_discover_verapdf(excluded, 55), 50),
        "pdfjs": (_discover_pdfjs(excluded, 55), 50),
    }

    verified_all: list[dict[str, Any]] = []
    summary: dict[str, int] = {}
    for src, (pool, cap) in targets.items():
        with ThreadPoolExecutor(max_workers=12) as ex:
            checked = [r for r in ex.map(_head_verify, pool) if r is not None]
        chosen = checked[:cap]
        summary[src] = len(chosen)
        verified_all.extend(chosen)
        print(f"  {src:8s}: pool={len(pool):3d} verified={len(checked):3d} kept={len(chosen):3d}")

    batches = pack_batches(verified_all)
    for idx, batch in enumerate(batches, start=1):
        p = args.out_dir / f"batch-{idx:02d}.json"
        p.write_text(json.dumps({"schema_version": 1, "documents": batch}, indent=2) + "\n", encoding="utf-8")

    disc = {
        "schema_version": 1,
        "total_candidates": len(verified_all),
        "source_counts": summary,
        "batch_count": len(batches),
        "documents": verified_all,
    }
    (args.out_dir / "discovery.json").write_text(json.dumps(disc, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(verified_all)} verified candidates across {len(batches)} batches in {args.out_dir}")


if __name__ == "__main__":
    main()
