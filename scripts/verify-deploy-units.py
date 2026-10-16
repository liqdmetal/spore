#!/usr/bin/env python3
"""Verify deploy/spore-*.service units against the real `spore` CLI.

For each unit, the ExecStart subcommand is run with -h on a freshly built
binary so the flags it defines come from the CLI itself, not from a copy that
could drift. Every flag in ExecStart must be one of them, and secret-bearing
flags may not appear in ExecStart at all; argv is visible via ps.
Standard library only.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"
SECRET_FLAGS = {"token", "rpc-login", "store-token", "api-key", "totp"}
FLAG_LINE = re.compile(r"^\s{1,4}-([A-Za-z0-9][A-Za-z0-9-]*)\b", re.MULTILINE)


def parse_exec_start(text: str, unit: Path) -> list[str]:
    starts = [
        line.split("=", 1)[1].strip()
        for line in text.splitlines()
        if line.startswith("ExecStart=")
    ]
    if len(starts) != 1:
        raise SystemExit(f"{unit.name}: want exactly one ExecStart, found {len(starts)}")
    return shlex.split(starts[0])


def subcommand_of(argv: list[str], unit: Path) -> list[str]:
    words: list[str] = []
    for token in argv[1:]:
        if token.startswith("-"):
            break
        words.append(token)
    if not words:
        raise SystemExit(f"{unit.name}: ExecStart names no spore subcommand")
    return words


def defined_flags(binary: str, subcommand: list[str]) -> set[str]:
    proc = subprocess.run(
        [binary, *subcommand, "-h"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=30,
    )
    usage = proc.stderr + proc.stdout
    flags = set(FLAG_LINE.findall(usage))
    if not flags:
        raise SystemExit(
            f"`spore {' '.join(subcommand)} -h` defined no flags (exit {proc.returncode})"
        )
    return flags


def check_unit(unit: Path, binary: str) -> list[str]:
    problems: list[str] = []
    text = unit.read_text(encoding="utf-8")
    argv = parse_exec_start(text, unit)
    subcommand = subcommand_of(argv, unit)
    flags = defined_flags(binary, subcommand)

    if "NoNewPrivileges=true" not in text:
        problems.append("missing NoNewPrivileges=true hardening")
    if not re.search(r"^User=", text, re.MULTILINE):
        problems.append("missing non-root User=")

    args = argv[1 + len(subcommand):]
    i = 0
    while i < len(args):
        token = args[i]
        if not token.startswith("-"):
            i += 1
            continue
        name = token.lstrip("-")
        if "=" in name:
            name, value = name.split("=", 1)
        else:
            value = args[i + 1] if i + 1 < len(args) and not args[i + 1].startswith("-") else None
            if value is not None:
                i += 1
        if name not in flags:
            problems.append(f"flag -{name} is not defined by `spore {' '.join(subcommand)}`")
            i += 1
            continue
        if name in SECRET_FLAGS:
            problems.append(
                f"secret flag -{name} must not appear in ExecStart (argv is visible via ps); "
                "supply it through EnvironmentFile instead"
            )
        i += 1
    return problems


def main() -> int:
    units = sorted(DEPLOY.glob("spore-*.service"))
    if not units:
        raise SystemExit("no deploy/spore-*.service units found")
    go = shutil.which("go")
    if go is None:
        raise SystemExit("deploy unit verification requires Go on PATH")

    failures = 0
    with tempfile.TemporaryDirectory(prefix="spore-deploy-units-") as temp:
        binary = str(Path(temp) / ("spore.exe" if os.name == "nt" else "spore"))
        subprocess.run(
            [go, "build", "-o", binary, "./cmd/spore"],
            cwd=ROOT,
            check=True,
        )
        for unit in units:
            problems = check_unit(unit, binary)
            rel = unit.relative_to(ROOT)
            if problems:
                failures += 1
                for problem in problems:
                    print(f"{rel}: {problem}", file=sys.stderr)
            else:
                print(f"{rel}: every ExecStart flag is defined by the CLI; no secret flags in argv")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
