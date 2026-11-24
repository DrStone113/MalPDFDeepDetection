import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "autofix_and_check.py"
RUFF = Path(sys.executable).parent / ("ruff.exe" if os.name == "nt" else "ruff")
HAS_RUFF = RUFF.is_file() or shutil.which("ruff") is not None


def run_autofix(*args: str | Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, SCRIPT, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


@pytest.mark.skipif(not HAS_RUFF, reason="Ruff is an optional developer tool")
def test_autofix_removes_unused_import_and_formats_python(tmp_path):
    path = tmp_path / "example.py"
    path.write_text("import sys\nimport os\nimport math\nx=1\nprint(sys.version, math.pi)\n", encoding="utf-8")

    result = run_autofix(path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert path.read_text(encoding="utf-8") == "import math\nimport sys\n\nx = 1\nprint(sys.version, math.pi)\n"
    assert result.stdout.splitlines() == ["OK: autofix_and_check verified 1 file(s) (1 py, 0 web)"]
    assert result.stderr == ""


def test_autofix_reports_unfixable_python_syntax_and_undefined_name(tmp_path):
    broken = tmp_path / "broken.py"
    broken.write_text("def broken(\n", encoding="utf-8")
    cases = [(broken, "SyntaxError")]
    if HAS_RUFF:
        undefined = tmp_path / "undefined.py"
        undefined.write_text("print(undefined_symbol_xyz)\n", encoding="utf-8")
        cases.append((undefined, "F821"))

    for path, code in cases:
        result = run_autofix(path, "--quiet")
        diagnostics = (result.stdout + result.stderr).splitlines()

        assert result.returncode == 1, diagnostics
        assert 1 <= len(diagnostics) <= 30
        assert all(f"{path.name}:" in line for line in diagnostics)
        assert any(code in line for line in diagnostics)


def test_autofix_detects_invalid_json(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text('{"a": 1,}', encoding="utf-8-sig")

    result = run_autofix(path)

    assert result.returncode == 1
    assert (result.stdout + result.stderr).splitlines()[0].startswith(f"{path}:1:9: JSONDecodeError ")
