#!/usr/bin/env python3
"""Build `spore`, run `status -json` in an isolated home, and validate its schema."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError as exc:
    raise SystemExit(
        "status schema verification requires Python package 'jsonschema' "
        "(Draft 2020-12 support)"
    ) from exc


ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "docs" / "status-v1.schema.json"


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    go = shutil.which("go")
    if go is None:
        raise SystemExit("status schema verification requires Go on PATH")

    with tempfile.TemporaryDirectory(prefix="spore-status-schema-") as temp:
        temp_path = Path(temp)
        binary = temp_path / ("spore.exe" if os.name == "nt" else "spore")
        env = os.environ.copy()
        env["SPORE_HOME"] = str(temp_path / "home")
        env.pop("SPORE_CONFIG", None)
        Path(env["SPORE_HOME"]).mkdir()

        subprocess.run(
            [go, "build", "-o", str(binary), "./cmd/spore"],
            cwd=ROOT,
            env=env,
            check=True,
        )
        result = subprocess.run(
            [str(binary), "status", "-json"],
            cwd=ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )

    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"spore status -json emitted invalid JSON: {exc}") from exc

    errors = sorted(validator.iter_errors(report), key=lambda error: list(error.absolute_path))
    if errors:
        for error in errors:
            location = ".".join(map(str, error.absolute_path)) or "$"
            print(f"{location}: {error.message}", file=sys.stderr)
        return 1

    print(f"status JSON conforms to {SCHEMA_PATH.relative_to(ROOT)}")
    if result.returncode != 0:
        print(
            f"spore status exited {result.returncode}; the JSON still conforms "
            "to schema",
            file=sys.stderr,
        )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
