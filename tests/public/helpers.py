from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUTPUT_NAMES = {
    "project-model.yaml",
    "process-flow.mmd",
    "diagnostic-balance.yaml",
    "review-report.md",
}


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def run_cli(output_dir: Path, *, decisions: Path | None = None):
    command = [
        sys.executable,
        "-m",
        "chemical_eia.cli",
        "examples/minimal/model.json",
        "--output-dir",
        str(output_dir),
    ]
    if decisions is not None:
        command.extend(("--decisions", str(decisions)))
    environment = os.environ.copy()
    source_root = str(ROOT / "src")
    environment["PYTHONPATH"] = source_root
    environment["PYTHONUTF8"] = "1"
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
