"""User-authorized Cloud ephemeral hybrid CPU+GPU acquisition and bulk static extraction."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import numpy as np

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(1, str(REPO / "scripts" / "lab"))

import acquire_bulk_pdf_corpus as acq
from malpdf.extraction.arlington_model import SOURCE as ARLINGTON_URL, load_model
from malpdf.extraction.bulk_pipeline import (
    build_clean_corpus_manifest,
    default_bulk_limits,
    run_hybrid_bulk_extraction,
)
from malpdf.extraction.gpu_accel import (
    byte_transition_matrices_batch,
    compute_rwse_batch_torch,
    hardware_profile,
)
from malpdf.static.execution import available_cpus


ARLINGTON_LOCK_REL = "configs/arlington.lock.json"
ARLINGTON_LOCK_PATH = REPO / ARLINGTON_LOCK_REL
ARLINGTON_DIR = REPO / "third_party" / "arlington-pdf-model"


def setup_arlington() -> dict:
    lock = json.loads(ARLINGTON_LOCK_PATH.read_text(encoding="utf-8"))
    target_commit = lock["commit"]
    if not ARLINGTON_DIR.is_dir():
        ARLINGTON_DIR.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", ARLINGTON_URL, str(ARLINGTON_DIR)],
            check=True,
        )
    subprocess.run(
        ["git", "-C", str(ARLINGTON_DIR), "checkout", "--detach", target_commit],
        check=True,
    )
    catalog = load_model(REPO, ARLINGTON_LOCK_REL)
    return {"status": "verified", "commit": target_commit, "tables": len(catalog.tables)}


def run_acquire(raw_dir: Path, *, workers: int, include_existing_zenodo: bool, hard_cap_gb: float) -> dict:
    hard_cap = int(hard_cap_gb * 1_000_000_000)
    target_bytes = int(hard_cap * 0.975)
    queue_path = raw_dir / "queue_manifest.json"
    if queue_path.is_file():
        queue = json.loads(queue_path.read_text(encoding="utf-8"))
    else:
        queue = acq.build_queue(
            hard_cap=hard_cap,
            target_bytes=target_bytes,
            include_existing_zenodo=include_existing_zenodo,
        )
        raw_dir.mkdir(parents=True, exist_ok=True)
        queue_path.write_text(json.dumps(queue, indent=2) + "\n", encoding="utf-8")
    return acq.execute_queue(raw_dir, REPO, queue, workers=max(1, min(workers, 4)))


def run_benchmark(device: str) -> dict:
    hw = hardware_profile(device)
    rng = np.random.default_rng(42)
    sample_bufs = [rng.integers(0, 256, size=512 * 1024, dtype=np.uint8).tobytes() for _ in range(32)]
    graphs = []
    for _ in range(128):
        n = 180
        src = rng.integers(0, n, size=600, dtype=np.int64).tolist()
        dst = rng.integers(0, n, size=600, dtype=np.int64).tolist()
        graphs.append((n, src, dst))

    results: dict = {"hardware": hw, "timings_seconds": {}}
    targets = ["cpu", hw["resolved_device"]] if hw["resolved_device"].startswith("cuda") else ["cpu"]
    for target in targets:
        warmup_sec = 0.0
        if target.startswith("cuda"):
            import torch

            tw0 = time.monotonic()
            byte_transition_matrices_batch(sample_bufs[:2], device=target)
            compute_rwse_batch_torch(graphs[:4], steps=16, device=target)
            torch.cuda.synchronize()
            warmup_sec = round(time.monotonic() - tw0, 4)

        t0 = time.monotonic()
        byte_transition_matrices_batch(sample_bufs, device=target)
        if target.startswith("cuda"):
            import torch

            torch.cuda.synchronize()
        t1 = time.monotonic()
        compute_rwse_batch_torch(graphs, steps=16, device=target)
        if target.startswith("cuda"):
            import torch

            torch.cuda.synchronize()
        t2 = time.monotonic()
        entry = {
            "markov_32x512KiB": round(t1 - t0, 4),
            "rwse_128x180nodes": round(t2 - t1, 4),
        }
        if target.startswith("cuda"):
            entry["one_time_cuda_warmup"] = warmup_sec
        results["timings_seconds"][target] = entry
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", type=Path, default=REPO / "outputs" / "ephemeral_raw")
    parser.add_argument("--output-dir", type=Path, default=REPO / "outputs" / "bulk_extract")
    parser.add_argument("--cic-manifest", type=Path, default=None)
    parser.add_argument("--workers", type=int, default=None)
    parser.add_argument("--download-workers", type=int, default=3)
    parser.add_argument("--chunk-size", type=int, default=500)
    parser.add_argument("--wall-seconds", type=int, default=45)
    parser.add_argument("--cpu-seconds", type=int, default=35)
    parser.add_argument("--memory-mb", type=int, default=2048)
    parser.add_argument("--max-file-mb", type=int, default=50)
    parser.add_argument("--device", default="auto")
    parser.add_argument("--hard-cap-gb", type=float, default=24.0)
    parser.add_argument("--include-existing-zenodo", action="store_true")
    parser.add_argument("--no-markov", action="store_true")
    parser.add_argument("--skip-arlington", action="store_true")
    parser.add_argument("--prune-raw-after-chunk", action="store_true")
    parser.add_argument("--setup-arlington", action="store_true")
    parser.add_argument("--acquire", action="store_true")
    parser.add_argument("--extract", action="store_true")
    parser.add_argument("--benchmark-only", action="store_true")
    parser.add_argument("--execute-cloud-extraction", action="store_true")
    args = parser.parse_args(argv)

    if args.benchmark_only:
        print(json.dumps(run_benchmark(args.device), indent=2))
        return 0

    if not args.execute_cloud_extraction:
        parser.error("Cloud raw acquisition/extraction requires explicit --execute-cloud-extraction authorization")

    if sys.platform != "linux":
        raise SystemExit("Bulk PDF extraction must run in Linux Cloud/LAB environment, never on Windows DEV")

    os.environ["MALPDF_LAB_ISOLATED"] = "1"
    for var in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
        os.environ[var] = "1"

    receipt: dict = {"hardware": hardware_profile(args.device), "available_cpus": available_cpus()}
    if args.setup_arlington:
        receipt["arlington"] = setup_arlington()

    if args.acquire:
        receipt["acquisition"] = run_acquire(
            args.raw_dir,
            workers=args.download_workers,
            include_existing_zenodo=args.include_existing_zenodo,
            hard_cap_gb=args.hard_cap_gb,
        )

    if args.extract:
        manifest_path = args.raw_dir / "manifest.csv"
        entries, manifest_stats = build_clean_corpus_manifest(
            [manifest_path],
            base_dir=args.raw_dir,
            cic_manifest_csv=args.cic_manifest,
        )
        catalog = None
        if not args.skip_arlington:
            if not ARLINGTON_DIR.is_dir():
                setup_arlington()
            catalog = load_model(REPO, ARLINGTON_LOCK_REL)

        limits = default_bulk_limits(
            wall_seconds=args.wall_seconds,
            cpu_seconds=args.cpu_seconds,
            memory_mb=args.memory_mb,
            max_file_mb=args.max_file_mb,
        )
        receipt["extraction"] = run_hybrid_bulk_extraction(
            entries,
            base_dir=args.raw_dir,
            output_dir=args.output_dir,
            workers=args.workers,
            chunk_size=args.chunk_size,
            limits=limits,
            device=args.device,
            arlington_catalog=catalog,
            include_markov=not args.no_markov,
            prune_raw_after_chunk=args.prune_raw_after_chunk,
            manifest_stats=manifest_stats,
            progress=lambda ev: print(json.dumps(ev), flush=True),
        )

    print(json.dumps(receipt, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
