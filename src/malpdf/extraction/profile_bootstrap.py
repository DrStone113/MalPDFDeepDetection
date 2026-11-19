"""Start the bounded bulk profile worker from the verified source release."""

import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace


def main():
    config = json.loads(sys.argv[1])
    if sys.stdin.buffer.read(1) != b"1" or os.getppid() != config["parent_pid"]:
        return
    sys.stdin.close()
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from malpdf.static.worker_limits import apply_code_limits

    applied = apply_code_limits(SimpleNamespace(**config["limits"]))
    from multiprocessing.connection import Connection
    from malpdf.static.code_inspector import CodeInspectionLimits
    from malpdf.static.profile_worker import _profile_child
    from malpdf.static.worker_diagnostics import run_child

    result = Connection(config["result_fd"], readable=False)
    diagnostic = Connection(config["diagnostic_fd"], readable=False)

    def profile():
        catalog = None
        if config["snapshot"] is not None:
            from malpdf.extraction.arlington_model import read_catalog_snapshot
            catalog = read_catalog_snapshot(*config["snapshot"])
        _profile_child(
            result, config["path"], config["boundary"], config["digest"],
            CodeInspectionLimits(**config["limits"]), None, None, True, "v9", "deep-static",
            catalog, include_byte_images=config["include_byte_images"],
            coalesce_checkpoints=config["coalesce_checkpoints"], applied_limits=applied,
        )

    try:
        run_child(diagnostic, profile, ())
    finally:
        result.close()


if __name__ == "__main__":
    main()
