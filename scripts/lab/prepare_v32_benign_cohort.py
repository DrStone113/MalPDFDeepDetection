"""Discover and HEAD-verify non-overlapping v3.2 benign supplement (Subset A) and prospective holdout (Subset B)."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import random
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scripts.lab.benign_ood_intake import OCTET_STREAM_ALLOWED_SOURCES, URLS, candidate_rows  # noqa: E402

MAX_DOC_BYTES = 12 * 1024 * 1024
TRACK_B_MAX_BYTES = 5 * 1024 * 1024
MIN_DOC_BYTES = 50
MAX_BATCH_BYTES = 120 * 1024 * 1024
MAX_BATCH_DOCS = 95
UA = "MalPDF research (v3.2 multi-source benign metadata check)"


def _http_get_text(url: str, timeout: int = 25) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def _head_verify(row: dict[str, Any]) -> dict[str, Any] | None:
    url = row["url"]
    source = row["source"]
    if not re.fullmatch(URLS[source], url):
        return None
    max_bytes = int(row.get("max_bytes") or MAX_DOC_BYTES)
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            ctype = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            allowed = (
                {"application/pdf", "application/octet-stream"}
                if source in OCTET_STREAM_ALLOWED_SOURCES
                else {"application/pdf"}
            )
            if resp.status != 200 or ctype not in allowed:
                return None
            clen_raw = resp.headers.get("Content-Length")
            clen = int(clen_raw) if clen_raw and clen_raw.isdigit() else row.get("approx_bytes")
            if clen is not None and not (MIN_DOC_BYTES <= int(clen) <= max_bytes):
                return None
            if source == "arxiv" and clen is None:
                return None
            return {
                "id": row["id"],
                "source": source,
                "subset": row["subset"],
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


def load_existing_urls(*paths: Path) -> set[str]:
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


def _stratify_github_blobs(
    blobs: list[dict[str, Any]],
    *,
    keywords: tuple[str, ...],
    count_small: int,
    count_other: int,
    rng: random.Random,
    url_builder,
    excluded: set[str],
    id_prefix: str,
    start_seq: int,
    subset: str,
    track: str,
) -> list[dict[str, Any]]:
    small_prio, small_rest, other_prio, other_rest = [], [], [], []
    for item in blobs:
        url = url_builder(item["path"])
        if url in excluded or not re.fullmatch(URLS[id_prefix], url):
            continue
        sz = int(item.get("size") or 0)
        if not (MIN_DOC_BYTES <= sz <= MAX_DOC_BYTES):
            continue
        has_kw = any(k in item["path"].lower() for k in keywords)
        if sz <= 10240:
            (small_prio if has_kw else small_rest).append((url, sz))
        else:
            (other_prio if has_kw else other_rest).append((url, sz))

    for bucket in (small_prio, small_rest, other_prio, other_rest):
        bucket.sort()
        rng.shuffle(bucket)

    chosen: list[tuple[str, int]] = []
    half_sp = min(len(small_prio), max(1, count_small // 2))
    chosen.extend(small_prio[:half_sp])
    rem_small = small_rest + small_prio[half_sp:]
    need_small = max(0, count_small - len(chosen))
    chosen.extend(rem_small[:need_small])

    half_op = min(len(other_prio), max(1, count_other // 2))
    chosen.extend(other_prio[:half_op])
    rem_other = other_rest + other_prio[half_op:]
    need_other = max(0, count_other - len(chosen))
    chosen.extend(rem_other[:need_other])

    leftovers = rem_small[need_small:] + rem_other[need_other:]
    target_total = count_small + count_other
    if len(chosen) < target_total:
        chosen.extend(leftovers[: target_total - len(chosen)])

    out: list[dict[str, Any]] = []
    for offset, (url, sz) in enumerate(chosen[:target_total]):
        excluded.add(url)
        out.append({
            "id": f"{id_prefix}-{start_seq + offset:03d}",
            "source": id_prefix,
            "subset": subset,
            "track": track,
            "url": url,
            "approx_bytes": sz,
            "max_bytes": MAX_DOC_BYTES,
        })
    return out


def _discover_github_hard_benign(excluded: set[str], rng: random.Random) -> dict[str, list[dict[str, Any]]]:
    vera_tree = json.loads(_http_get_text("https://api.github.com/repos/veraPDF/veraPDF-corpus/git/trees/staging?recursive=1"))
    vera_blobs = [b for b in vera_tree.get("tree", []) if b.get("type") == "blob" and b.get("path", "").endswith(".pdf")]
    vera_kw = ("acroform", "embeddedfile", "js", "javascript", "jbig2", "objstm", "encrypt", "xfa", "action", "6-9", "6-6", "19005-3", "14289")
    vera_url = lambda p: "https://raw.githubusercontent.com/veraPDF/veraPDF-corpus/staging/" + urllib.parse.quote(p, safe="/")

    pdfjs_tree = json.loads(_http_get_text("https://api.github.com/repos/mozilla/pdf.js/git/trees/master?recursive=1"))
    pdfjs_blobs = [
        b for b in pdfjs_tree.get("tree", [])
        if b.get("type") == "blob" and b.get("path", "").startswith("test/pdfs/") and b.get("path", "").endswith(".pdf")
    ]
    pdfjs_kw = ("js", "acro", "form", "xfa", "annot", "enc", "crypt", "incr", "xref", "issue", "bug", "jbig2", "attach", "link", "action")
    pdfjs_url = lambda p: "https://raw.githubusercontent.com/mozilla/pdf.js/master/" + urllib.parse.quote(p, safe="/")

    seen = set(excluded)
    # Allocate disjoint Reserve buffers so HEAD failures do not shrink final counts.
    sub_a_verapdf = _stratify_github_blobs(
        vera_blobs, keywords=vera_kw, count_small=175, count_other=105, rng=rng, url_builder=vera_url,
        excluded=seen, id_prefix="verapdf", start_seq=100, subset="train_val_benign_supplement", track="train_val_benign_supplement",
    )
    sub_a_pdfjs = _stratify_github_blobs(
        pdfjs_blobs, keywords=pdfjs_kw, count_small=175, count_other=105, rng=rng, url_builder=pdfjs_url,
        excluded=seen, id_prefix="pdfjs", start_seq=100, subset="train_val_benign_supplement", track="train_val_benign_supplement",
    )
    sub_b_verapdf = _stratify_github_blobs(
        vera_blobs, keywords=vera_kw, count_small=32, count_other=26, rng=rng, url_builder=vera_url,
        excluded=seen, id_prefix="verapdf", start_seq=380, subset="prospective_hard_benign_v2", track="hard_benign_stress_v2",
    )
    sub_b_pdfjs = _stratify_github_blobs(
        pdfjs_blobs, keywords=pdfjs_kw, count_small=32, count_other=26, rng=rng, url_builder=pdfjs_url,
        excluded=seen, id_prefix="pdfjs", start_seq=380, subset="prospective_hard_benign_v2", track="hard_benign_stress_v2",
    )
    return {
        "sub_a_verapdf": sub_a_verapdf,
        "sub_a_pdfjs": sub_a_pdfjs,
        "sub_b_verapdf": sub_b_verapdf,
        "sub_b_pdfjs": sub_b_pdfjs,
    }


def _discover_arxiv(excluded: set[str], target: int = 230, start_seq: int = 300) -> list[dict[str, Any]]:
    cats = ("cs.SE", "math.NT", "physics.optics", "q-bio.NC", "stat.ML", "eess.SP", "econ.TH", "astro-ph.CO", "cond-mat.mes-hall", "cs.DB")
    seen = set(excluded)
    candidates: list[dict[str, Any]] = []
    seq = start_seq
    for cat in cats:
        if len(candidates) >= target:
            break
        try:
            xml = _http_get_text(f"https://export.arxiv.org/api/query?search_query=cat:{cat}&sortBy=submittedDate&sortOrder=descending&start=120&max_results=35")
        except (OSError, urllib.error.URLError):
            continue
        for raw_id in re.findall(r"<id>http://arxiv\.org/abs/([^<]+)</id>", xml):
            clean_id = re.sub(r"v\d+$", "", raw_id.strip())
            url = f"https://arxiv.org/pdf/{clean_id}"
            if url in seen or not re.fullmatch(URLS["arxiv"], url):
                continue
            seen.add(url)
            candidates.append({
                "id": f"arxiv-{seq:03d}", "source": "arxiv",
                "subset": "prospective_diverse_publishers_v2", "track": "prospective_diverse_publishers_v2",
                "url": url, "max_bytes": TRACK_B_MAX_BYTES,
            })
            seq += 1
            if len(candidates) >= target:
                break
    return candidates


def _discover_nist(excluded: set[str], target: int = 165, start_seq: int = 200) -> list[dict[str, Any]]:
    detail_paths: list[str] = []
    for index_path, pat in (
        ("https://csrc.nist.gov/publications/nistir", r"/pubs/ir/[0-9]+/final"),
        ("https://csrc.nist.gov/publications/fips", r"/pubs/fips/[0-9-]+/final"),
        ("https://csrc.nist.gov/publications/sp", r"/pubs/sp/[0-9]+/[A-Za-z0-9_./-]+/final"),
    ):
        try:
            html = _http_get_text(index_path, timeout=20)
            detail_paths.extend(sorted(set(re.findall(pat, html))))
        except (OSError, urllib.error.URLError):
            continue
    seen = set(excluded)

    def _scrape_detail(rel: str) -> str | None:
        try:
            body = _http_get_text("https://csrc.nist.gov" + rel, timeout=15)
        except (OSError, urllib.error.URLError):
            return None
        for u in re.findall(r'https://nvlpubs\.nist\.gov/nistpubs/[^\s"\'<>]+\.pdf', body):
            if u not in seen and re.fullmatch(URLS["nist"], u):
                return u
        return None

    candidates: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        urls = list(ex.map(_scrape_detail, detail_paths[: target * 3]))
    seq = start_seq
    for u in urls:
        if u and u not in seen:
            seen.add(u)
            candidates.append({
                "id": f"nist-{seq:03d}", "source": "nist",
                "subset": "prospective_diverse_publishers_v2", "track": "prospective_diverse_publishers_v2",
                "url": u, "max_bytes": TRACK_B_MAX_BYTES,
            })
            seq += 1
            if len(candidates) >= target:
                break
    return candidates


def _discover_nasa(excluded: set[str], target: int = 155, start_seq: int = 600) -> list[dict[str, Any]]:
    queries = (
        "propulsion+cryogenic", "orbital+mechanics", "structural+composites",
        "atmospheric+lidar", "avionics+radiation", "robotics+autonomy",
        "heat+shield", "solar+array", "hypersonic+wind",
    )
    seen = set(excluded)
    candidates: list[dict[str, Any]] = []
    seq = start_seq
    for q in queries:
        if len(candidates) >= target:
            break
        try:
            raw = _http_get_text(
                f"https://ntrs.nasa.gov/api/citations/search?q={q}&downloadsAvailable=true&page.size=80"
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
                candidates.append({
                    "id": f"nasa-{seq:03d}", "source": "nasa",
                    "subset": "prospective_diverse_publishers_v2", "track": "prospective_diverse_publishers_v2",
                    "url": url, "max_bytes": TRACK_B_MAX_BYTES,
                })
                seq += 1
                break
            if len(candidates) >= target:
                break
    return candidates


def _discover_court(excluded: set[str], target: int = 75, start_seq: int = 100) -> list[dict[str, Any]]:
    seen = set(excluded)
    candidates: list[dict[str, Any]] = []
    seq = start_seq
    for term in ("25", "24", "23", "22", "21", "20", "19", "18"):
        if len(candidates) >= target:
            break
        try:
            html = _http_get_text(f"https://www.supremecourt.gov/opinions/slipopinion/{term}", timeout=20)
        except (OSError, urllib.error.URLError):
            continue
        for rel in sorted(set(re.findall(r"/opinions/[0-9]{2}pdf/[A-Za-z0-9_-]+\.pdf", html))):
            url = "https://www.supremecourt.gov" + rel
            if url in seen or not re.fullmatch(URLS["court"], url):
                continue
            seen.add(url)
            candidates.append({
                "id": f"court-{seq:03d}", "source": "court",
                "subset": "prospective_diverse_publishers_v2", "track": "prospective_diverse_publishers_v2",
                "url": url, "max_bytes": TRACK_B_MAX_BYTES,
            })
            seq += 1
            if len(candidates) >= target:
                break
    return candidates


def _renumber_subset(rows: list[dict[str, Any]], offsets: dict[str, int]) -> list[dict[str, Any]]:
    out = []
    counts: dict[str, int] = {}
    for r in rows:
        src = r["source"]
        n = counts.get(src, 0)
        counts[src] = n + 1
        out.append({**r, "id": f"{src}-{offsets[src] + n:03d}"})
    return out


def verify_subset_disjointness(all_rows: list[dict[str, Any]], excluded_urls: set[str]) -> None:
    urls = [r["url"] for r in all_rows]
    ids = [r["id"] for r in all_rows]
    if len(set(urls)) != len(urls) or len(set(ids)) != len(ids):
        raise ValueError("duplicate_candidate_url_or_id")
    if set(urls) & excluded_urls:
        raise ValueError("overlap_with_prior_cohorts")
    for r in all_rows:
        if "?" in r["url"]:
            raise ValueError(f"query_string_forbidden:{r['id']}")


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
    parser = argparse.ArgumentParser(description="Discover v3.2 Subset A (hard-benign train supplement) and Subset B (untouched holdout)")
    parser.add_argument("--out-dir", type=Path, default=REPO / "data/processed/pooled_bulk/benign_v32_cohort")
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    excluded = load_existing_urls(
        REPO / "data/processed/pooled_bulk/benign_ood/candidates.json",
        REPO / "data/processed/pooled_bulk/benign_ood_expanded/discovery.json",
        REPO / "data/processed/pooled_bulk/benign_ood_expanded/acquisition_v2.json",
        REPO / "data/processed/pooled_bulk/benign_ood_diverse/discovery.json",
        REPO / "data/processed/pooled_bulk/benign_ood_diverse/acquisition_diverse.json",
    )
    print(f"Loaded {len(excluded)} excluded prior URLs")

    rng = random.Random(42)
    gh = _discover_github_hard_benign(excluded, rng)

    # Check pools against HEAD and assign clean deterministic IDs.
    with ThreadPoolExecutor(max_workers=12) as ex:
        va_checked = [r for r in ex.map(_head_verify, gh["sub_a_verapdf"]) if r is not None][:250]
        pa_checked = [r for r in ex.map(_head_verify, gh["sub_a_pdfjs"]) if r is not None][:250]
        vb_checked = [r for r in ex.map(_head_verify, gh["sub_b_verapdf"]) if r is not None][:50]
        pb_checked = [r for r in ex.map(_head_verify, gh["sub_b_pdfjs"]) if r is not None][:50]

    subset_a = _renumber_subset(va_checked + pa_checked, {"verapdf": 100, "pdfjs": 100})
    track_c1_v2 = _renumber_subset(vb_checked + pb_checked, {"verapdf": 350, "pdfjs": 350})

    arxiv_pool = _discover_arxiv(excluded, target=230, start_seq=300)
    nist_pool = _discover_nist(excluded, target=165, start_seq=200)
    nasa_pool = _discover_nasa(excluded, target=155, start_seq=600)
    court_pool = _discover_court(excluded, target=75, start_seq=100)

    with ThreadPoolExecutor(max_workers=12) as ex:
        arxiv_v = [r for r in ex.map(_head_verify, arxiv_pool) if r is not None]
        nist_v = [r for r in ex.map(_head_verify, nist_pool) if r is not None]
        nasa_v = [r for r in ex.map(_head_verify, nasa_pool) if r is not None]
        court_v = [r for r in ex.map(_head_verify, court_pool) if r is not None]

    kept_court = court_v[:40]
    kept_nist = nist_v[:100]
    kept_nasa = nasa_v[:100]
    kept_arxiv = arxiv_v[:160]
    track_b_raw = kept_arxiv + kept_nist + kept_nasa + kept_court
    if len(track_b_raw) < 400:
        for reserve in (arxiv_v[160:], nasa_v[100:], nist_v[100:], court_v[40:]):
            need = 400 - len(track_b_raw)
            if need <= 0:
                break
            track_b_raw.extend(reserve[:need])
    track_b_v2 = _renumber_subset(track_b_raw, {"arxiv": 300, "nist": 200, "nasa": 600, "court": 100})

    all_rows = subset_a + track_b_v2 + track_c1_v2
    verify_subset_disjointness(all_rows, excluded)

    small_a = sum(1 for r in subset_a if r.get("length") and int(r["length"]) <= 10240)
    print(f"Subset A (train_val_benign_supplement): {len(subset_a)} (<=10KB: {small_a})")
    print(
        f"Track B-v2 (prospective_diverse_publishers_v2): {len(track_b_v2)} "
        f"[arxiv={sum(r['source']=='arxiv' for r in track_b_v2)}, nist={sum(r['source']=='nist' for r in track_b_v2)}, "
        f"nasa={sum(r['source']=='nasa' for r in track_b_v2)}, court={sum(r['source']=='court' for r in track_b_v2)}]"
    )
    print(f"Track C1-v2 (prospective_hard_benign_v2): {len(track_c1_v2)}")
    if len(subset_a) < 480 or len(track_b_v2) < 390 or len(track_c1_v2) < 100:
        raise ValueError("insufficient_v32_candidate_counts")

    batches = pack_batches(all_rows)
    for old_batch in args.out_dir.glob("batch-*.json"):
        old_batch.unlink()
    for idx, batch in enumerate(batches, start=1):
        candidate_rows({"schema_version": 1, "documents": batch})
        (args.out_dir / f"batch-{idx:02d}.json").write_text(
            json.dumps({"schema_version": 1, "documents": batch}, indent=2) + "\n",
            encoding="utf-8",
        )

    assignments = {r["id"]: r["subset"] for r in all_rows}
    (args.out_dir / "subset_assignments.json").write_text(
        json.dumps({"schema_version": 1, "seed": 42, "assignments": assignments}, indent=2) + "\n",
        encoding="utf-8",
    )
    disc = {
        "schema_version": 1,
        "total_candidates": len(all_rows),
        "batch_count": len(batches),
        "subset_counts": {
            "train_val_benign_supplement": len(subset_a),
            "prospective_diverse_publishers_v2": len(track_b_v2),
            "prospective_hard_benign_v2": len(track_c1_v2),
        },
        "subset_a_small_le_10kb": small_a,
        "documents": all_rows,
    }
    (args.out_dir / "discovery.json").write_text(json.dumps(disc, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(all_rows)} verified candidates across {len(batches)} batches to {args.out_dir}")


if __name__ == "__main__":
    main()
