"""Bounded numeric byte-profile inputs and a separate Validation-role design."""
from concurrent.futures import ProcessPoolExecutor
import hashlib
import io
import json
import multiprocessing
import os
from pathlib import Path
import zipfile

import numpy as np
import pandas as pd

from malpdf.data.kaggle_notebook import find_kaggle_bundle
from malpdf.data.markov_arrays import MAX_CACHE_BYTES, load_markov_npy
from malpdf.static.markov_profiles import MARKOV_PROFILE_FEATURES, markov_profile
from malpdf.reproducibility import set_random_seed

DEVELOPMENT_ROLES = ("base_selection", "meta_fit", "calibration_fit", "threshold_selection")


def diverse_validation_roles(rows):
    """Seed42 group-count quotas, then greedy class/row balance per cohort.

    New development-role allocation only: never change established partitions
    or groups. Feature values and model probabilities are not consulted. Keep
    the original role file immutable. Both classes and at least ten groups per
    cohort/role are required; impossible designs fail instead of splitting a
    group or relabeling samples. Equivalent features do not prove file identity.
    """
    if (rows.empty or not rows.split.eq("validation").all() or not rows.sample_id.is_unique
            or rows.group_id.isna().any() or not rows.Label.isin([0, 1]).all()
            or set(rows.cohort) != {"source_raw", "cic"}
            or rows.groupby("group_id").cohort.nunique().max() != 1):
        raise ValueError("New roles require complete Validation-only cohort groups")
    allocation = {}
    set_random_seed(42)
    for cohort, frame in rows.groupby("cohort", sort=True):
        groups = []
        for gid, group in frame.groupby("group_id", sort=True):
            classes = np.bincount(group.Label.to_numpy(int), minlength=2).astype(float)
            tie = hashlib.sha256(("42:" + cohort + ":" + str(gid)).encode()).hexdigest()
            groups.append((gid, classes, tie))
        if len(groups) < 40:
            raise ValueError("Each cohort needs at least forty Validation groups")
        groups.sort(key=lambda g: (-g[1].sum(), g[2]))
        quotas = np.full(4, len(groups) // 4, dtype=int)
        quotas[:len(groups) % 4] += 1
        counts, classes = np.zeros(4, int), np.zeros((4, 2), float)
        target = np.maximum(np.bincount(frame.Label.to_numpy(int), minlength=2) / 4, 1)
        for gid, labels, _ in groups:
            eligible = np.flatnonzero(counts < quotas)
            # Spread groups before refining class balance; an oversized group
            # cannot monopolize a role and leave its other examples unrepresented.
            lowest = counts[eligible].min()
            eligible = eligible[counts[eligible] == lowest]
            index = min(eligible, key=lambda i: (float(np.sum(((classes[i] + labels) / target) ** 2)), int(i)))
            allocation[gid] = DEVELOPMENT_ROLES[index]
            counts[index] += 1
            classes[index] += labels
        if (classes == 0).any():
            raise ValueError("Whole-group allocation cannot supply both classes to each role")
    result = rows.copy()
    result["role"] = result.group_id.map(allocation)
    if result.groupby("group_id").role.nunique().max() != 1:
        raise ValueError("A group crossed new Validation roles")
    return result


_SOURCES = None
_THREAD_LIMIT = None


def _open_sources(sources):
    global _SOURCES, _THREAD_LIMIT
    for name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS"):
        os.environ[name] = "1"
    from threadpoolctl import threadpool_limits
    _THREAD_LIMIT = threadpool_limits(limits=1)
    _SOURCES = [(Path(root) if root else None, zipfile.ZipFile(archive) if archive else None)
                for root, archive in sources]


def _profile_chunk(items):
    values = []
    for sid, source_index, name, digest in items:
        root, archive = _SOURCES[source_index]
        relative = Path(name)
        if (relative.is_absolute() or ".." in relative.parts or "\\" in name
                or name != "markov_cache/" + sid + ".npy"):
            raise ValueError("Unsafe numeric matrix identity")
        if archive is None:
            path = root / relative
            if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
                raise ValueError("Unsafe expanded matrix path")
            with path.open("rb") as stream:
                content = stream.read(MAX_CACHE_BYTES + 1)
        else:
            member = archive.getinfo(name)
            if (member.file_size > MAX_CACHE_BYTES or member.flag_bits & 1
                    or member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                    or member.external_attr >> 16 & 0o170000 == 0o120000):
                raise ValueError("Unsafe numeric matrix ZIP member")
            with archive.open(member) as stream:
                content = stream.read(MAX_CACHE_BYTES + 1)
        if len(content) > MAX_CACHE_BYTES or hashlib.sha256(content).hexdigest() != digest:
            raise ValueError("Numeric matrix checksum or byte cap differs")
        values.append(markov_profile(load_markov_npy(content)))
    return np.stack(values)


def load_development_profiles(input_root, bundle_root, rows, metadata, *, workers=2):
    """Read only Train/Validation matrices from the two existing private inputs.

    Independent processes open their own ZIP handles. At most two chunks are
    in flight, each with 64 small records; no full cache expansion or PDF reads.
    Only compact float32 profiles are preloaded into RAM for numeric training.
    """
    if (rows.empty or not rows.sample_id.is_unique or not rows.split.isin(["train", "validation"]).all()
            or workers not in (1, 2) or workers > len(os.sched_getaffinity(0))):
        raise ValueError("Profiles require unique Train/Validation rows and a bounded CPU budget")
    quota = Path("/sys/fs/cgroup/cpu.max")
    if quota.exists():
        amount, period = quota.read_text().split()
        if amount != "max" and workers > max(1, int(amount) // int(period)):
            raise ValueError("Profile workers exceed the container CPU quota")
    from malpdf.experiments.kaggle_vision_runner import available_ram_bytes
    if available_ram_bytes() < 512 * 1024**2 + len(rows) * len(MARKOV_PROFILE_FEATURES) * 4:
        raise ValueError("Insufficient RAM reserve for bounded profile workers")
    sources = [find_kaggle_bundle(input_root, hashlib.sha256((bundle_root / "bundle_metadata.json").read_bytes()).hexdigest()),
               find_kaggle_bundle(input_root, metadata["source_bundle_metadata_sha256"])]
    for index, (expanded, archive) in enumerate(sources):
        if archive:
            with zipfile.ZipFile(archive) as handle:
                names = handle.namelist()
                if len(names) != len(set(names)):
                    raise ValueError("Duplicate numeric ZIP members")
            if index == 1:
                digest = hashlib.sha256()
                with archive.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024**2), b""):
                        digest.update(block)
                if digest.hexdigest() != metadata["source_bundle_archive_sha256"]:
                    raise ValueError("Pinned original numeric archive differs")
    reuse = pd.read_csv(bundle_root / "source_matrix_reuse.csv").set_index("sample_id").legacy_sample_id.to_dict()
    records = []
    for row in rows.itertuples():
        sid = reuse.get(row.sample_id, row.sample_id)
        if (not isinstance(sid, str) or len(sid) != 13 or not sid.startswith("sample_") or not sid[7:].isdigit()
                or row.cache_relative_path != "markov_cache/" + row.sample_id + ".npy"):
            raise ValueError("Opaque numeric matrix mapping differs")
        records.append((sid, int(row.sample_id in reuse), "markov_cache/" + sid + ".npy", row.npy_sha256))
    chunks = [records[i:i + 64] for i in range(0, len(records), 64)]
    result = np.empty((len(rows), len(MARKOV_PROFILE_FEATURES)), dtype=np.float32)
    with ProcessPoolExecutor(max_workers=workers, mp_context=multiprocessing.get_context("fork"),
                             initializer=_open_sources, initargs=(sources,)) as pool:
        position = 0
        for start in range(0, len(chunks), workers):
            futures = [pool.submit(_profile_chunk, items) for items in chunks[start:start + workers]]
            for future in futures:
                values = future.result(timeout=120)
                result[position:position + len(values)] = values
                position += len(values)
            if start % 32 == 0:
                print(json.dumps({"event": "byte_profiles", "rows": position, "total": len(rows)}), flush=True)
    return pd.DataFrame(result, index=rows.sample_id, columns=MARKOV_PROFILE_FEATURES)
