"""Benign regressions for benchmark CLI spawn startup and failure evidence."""

import io
import json
import os
from pathlib import Path
import subprocess
import sys

from pypdf import PdfWriter
import pytest

from malpdf.experiments import static_benchmark as benchmark
from malpdf.static.code_inspector import _unavailable


def test_benchmark_spawn_replay_keeps_parser_startup_lightweight(tmp_path):
    writer = PdfWriter()
    writer.add_blank_page(72, 72)
    writer.add_js('var count=1; util["pri"+"ntf"]("test");')
    pdf = tmp_path / "benign.pdf"
    output = io.BytesIO()
    writer.write(output)
    pdf.write_bytes(output.getvalue())
    script = Path(__file__).resolve().parents[1] / "scripts/14_benchmark_static.py"
    launcher = tmp_path / "spawn_replay.py"
    # Replay the actual CLI in the child, as multiprocessing.spawn does. The
    # parent can load models; the capped child must not import that stack.
    launcher.write_text(f'''
import json, runpy, sys
if __name__ == "__mp_main__":
    runpy.run_path({str(script)!r}, run_name=__name__)
    assert "malpdf.experiments.static_benchmark" not in sys.modules
    assert "numpy" not in sys.modules
from malpdf.static.code_inspector import inspect_pdf_code
if __name__ == "__main__":
    from malpdf.experiments.static_benchmark import benchmark_static
    print(json.dumps(inspect_pdf_code({str(pdf)!r})))
''', encoding="utf-8")
    environment = dict(os.environ)
    environment.update({name: "1" for name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS")})
    completed = subprocess.run([sys.executable, str(launcher)], env=environment,
        capture_output=True, text=True, timeout=30, check=True)
    result = json.loads(completed.stdout)
    (tmp_path / "worker_evidence.json").write_text(completed.stdout, encoding="utf-8")
    assert result["complete"], (result, completed.stderr)
    assert result["scripts_parsed"] == 1
    assert result["ast"]["named_calls"]["util.printf"] == 1
    assert result["resource_limits"]["cpu_seconds"] == [4, 4]
    assert result["resource_limits"]["address_space_bytes"] == [1024**3, 1024**3]
    assert result["active_content_executed"] is False


@pytest.mark.parametrize("syntax,reason", [
    (_unavailable("parser_exit_or_timeout"), "parser_exit_or_timeout"),
    ({"complete": True, "ast": {"named_calls": {"util.printf": 0}}, "errors": []},
     "unexpected_syntax_evidence"),
])
def test_failed_ast_smoke_preserves_evidence_before_raising(tmp_path, monkeypatch, syntax, reason):
    class Run:
        def __init__(self, root, study, methodology, **kwargs):
            self.report, self.artifacts = root / "report", root / "artifacts"
            self.report.mkdir()
            self.artifacts.mkdir()
            self.state = {}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    # Only this synthetic runner fixture bypasses Git/provenance setup.
    monkeypatch.setattr(benchmark, "ResearchRun", Run)
    monkeypatch.setattr(benchmark.subprocess, "check_output", lambda *args, **kwargs: "")
    monkeypatch.setattr(benchmark, "inspect_pdf_codes", lambda *args, **kwargs: iter([(0, syntax)]))
    with pytest.raises(ValueError, match="Isolated synthetic AST smoke failed: " + reason):
        benchmark.benchmark_static(tmp_path, tmp_path, samples=16, repeats=3, batch_size=8)
    saved = json.loads((tmp_path / "report/synthetic_ast_evidence.json").read_text())
    assert saved["evidence"] == syntax
    assert saved["elapsed_seconds"] >= 0
