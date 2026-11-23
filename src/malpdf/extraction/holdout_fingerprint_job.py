from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from functools import partial
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from malpdf.extraction.tlsh import TLSH_RE, nearest_distances, screen
from malpdf.static.safety import read_bounded_bytes

INPUT_DIRECTORY = Path("data/processed/holdout_fingerprint/v1")
PLAN_SHA256 = "ead65d3f48dec64641bcebb2dfd836ce068c41372c067cec5f52c5d351da2a37"
PUBLISHER_SHA256 = "822e9f31295b2b4242febb429758c6be2924a2cd348168a281c25088493078b2"
ENGINE_SHA256 = "3a014424253e9198d96543a4a644f3ea98d35bb8cd5301209809edb71eb0bcfe"
GROUPS = {"historical_v4": 21414, "govdocs1_review": 132, "vapd_d1_positive": 13}
TOTAL_BYTES = 1375512890
MAX_FILE_BYTES = 50 * 1024**2
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
HEX160 = re.compile(r"[0-9a-f]{40}\Z")


def contract():
    return {"references": GROUPS["historical_v4"], "candidates": sum(GROUPS.values()) - GROUPS["historical_v4"],
            "total_bytes": TOTAL_BYTES, "manifest_sha256": PLAN_SHA256,
            "publisher_sha256": PUBLISHER_SHA256, "engine_sha256": ENGINE_SHA256,
            "output": "holdout_fingerprints.json", "model_evaluation": False}


def pinned(path, root, expected, limit):
    data = read_bounded_bytes(path, boundary=root, max_bytes=limit)
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("manifest_unavailable")
    return data


def load_inputs(data_root):
    raw = data_root / "data/raw"
    stage = data_root / INPUT_DIRECTORY
    plan = json.loads(pinned(stage / "fingerprint_plan.json", stage, PLAN_SHA256, 8 * 1024**2))
    publisher = json.loads(pinned(stage / "govdocs1_pending_sha1_verification.json", stage, PUBLISHER_SHA256, 128 * 1024))
    engine = pinned(stage / "tlsh_holdout_audit", stage, ENGINE_SHA256, 2 * 1024**2)
    entries = plan["entries"]
    if (plan["schema_version"] != 1 or plan["metadata_only"] is not True or plan["total_bytes"] != TOTAL_BYTES
            or Counter(entry["group"] for entry in entries) != GROUPS
            or len({entry["sha256"] for entry in entries}) != len(entries)
            or sum(entry["bytes"] for entry in entries) != TOTAL_BYTES
            or publisher.keys() != {entry["sha256"] for entry in entries if entry["group"] == "govdocs1_review"}):
        raise ValueError("manifest_unavailable")
    expected_sha1 = {}
    for entry in entries:
        path = raw / entry["path"]
        if (not path.is_relative_to(raw) or path.resolve() != path or not path.is_file()
                or not HEX256.fullmatch(entry["sha256"]) or type(entry["bytes"]) is not int
                or not 0 < entry["bytes"] <= MAX_FILE_BYTES or path.stat().st_size != entry["bytes"]):
            raise ValueError("manifest_unavailable")
        sha = entry["sha256"]
        if sha in publisher:
            digest = publisher[sha]["expected_publisher_sha1"]
            if publisher[sha]["bytes"] != entry["bytes"] or not HEX160.fullmatch(digest):
                raise ValueError("manifest_unavailable")
            expected_sha1[sha] = digest
    return raw, entries, expected_sha1, engine


@contextmanager
def sealed_engine(payload):
    import fcntl

    descriptor = os.memfd_create("malpdf-tlsh", os.MFD_ALLOW_SEALING)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
        os.fchmod(descriptor, 0o500)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        yield descriptor
    finally:
        os.close(descriptor)


def native(descriptor, data, timeout):
    result = subprocess.run([f"/proc/self/fd/{descriptor}", "--digest"], input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=timeout, check=True, pass_fds=(descriptor,))
    code = result.stdout.decode("ascii").strip()
    if code == "TNULL":
        return None
    if not TLSH_RE.fullmatch(code):
        raise ValueError("report_invalid")
    return code


def fingerprint_entry(raw_root, entry, expected_sha1, descriptor, *, timeout=10, include_sha1=False):
    sha = entry["sha256"]
    result = {"sha256": sha, "status": "input_unavailable", "tlsh": None}
    try:
        data = read_bounded_bytes(raw_root / entry["path"], boundary=raw_root, max_bytes=entry["bytes"])
    except (OSError, ValueError):
        return result
    if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != sha:
        return {**result, "status": "sha256_mismatch"}
    if sha in expected_sha1 and hashlib.sha1(data, usedforsecurity=False).hexdigest() != expected_sha1[sha]:
        return {**result, "status": "publisher_sha1_mismatch"}
    digest = native(descriptor, data, timeout)
    if include_sha1:
        result['sha1'] = hashlib.sha1(data, usedforsecurity=False).hexdigest()
    return {**result, "status": "measured" if digest is not None else "tlsh_unavailable", "tlsh": digest}


def fingerprint_plan(inputs, *, timeout, progress):
    raw, entries, expected_sha1, engine = inputs
    reference, candidates, fingerprints = {}, {}, []
    with sealed_engine(engine) as descriptor:
        for index, entry in enumerate(entries, start=1):
            result = fingerprint_entry(raw, entry, expected_sha1, descriptor, timeout=timeout)
            fingerprints.append(result)
            target = reference if entry["group"] == "historical_v4" else candidates
            target[result["sha256"]] = result["tlsh"]
            if index % 128 == 0 or index == len(entries):
                progress(index)
        distances = partial(nearest_distances, f"/proc/self/fd/{descriptor}", pass_fds=(descriptor,))
        comparison = screen(reference, candidates, distances)
    counts = Counter(item["status"] for item in fingerprints)
    return {
        "schema_version": 1, "inputs": contract(), "fingerprints": fingerprints,
        "fingerprint_status_counts": dict(counts),
        "publisher_sha1_matches": sum(item["sha256"] in expected_sha1
                                       and item["status"] in ("measured", "tlsh_unavailable") for item in fingerprints),
        "candidate_comparison": comparison, "new_malware_labels": 0,
    }
