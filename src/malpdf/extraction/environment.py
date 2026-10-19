"""Effective software and hardware metadata for static research outputs."""

from functools import cache
import importlib.metadata
import os
from pathlib import Path
import platform

from malpdf.static.execution import available_cpus


@cache
def environment_metadata() -> dict:
    import pikepdf
    import pymupdf
    import torch

    memory = next((int(line.split()[1]) * 1024 for line in Path("/proc/meminfo").read_text().splitlines()
                   if line.startswith("MemTotal:")), None)
    return {"python": platform.python_version(), "platform": platform.platform(),
        "packages": {name: importlib.metadata.version(name) for name in
            ("numpy", "pandas", "scikit-learn", "pypdf", "PyMuPDF", "pikepdf", "esprima", "torch", "torchvision")},
        "native_libraries": {"QPDF": pikepdf.__libqpdf_version__, "MuPDF": pymupdf.VersionFitz},
        "hardware": {"machine": platform.machine(), "logical_cpus": os.cpu_count(),
            "available_cpus": available_cpus(), "memory_bytes": memory,
            "cuda_available": torch.cuda.is_available(), "torch_cuda_build": torch.version.cuda,
            "cudnn_version": torch.backends.cudnn.version(),
            "gpus": [{"name": torch.cuda.get_device_properties(index).name,
                      "memory_bytes": torch.cuda.get_device_properties(index).total_memory}
                     for index in range(torch.cuda.device_count())]},
        "thread_environment": {name: os.environ.get(name) for name in
            ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS")}}
