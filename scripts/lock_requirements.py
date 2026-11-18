#!/usr/bin/env python3
"""Regenerate the hash-locked requirements every runtime image installs.

Each image directory keeps its direct dependencies in requirements.txt and
installs requirements.lock.txt with `pip install --require-hashes --only-binary
:all:`, so a build only accepts the exact wheels recorded here: a newer or
substituted release on the index fails the build instead of reaching the
runtime role. Edit requirements.txt, then rerun this; versions already in the
lock are kept unless --upgrade is given. Needs uv (`pip install uv`).

A package with no usable wheel is listed in SOURCE_BUILDS. Its image passes
`--no-binary <pkg> --no-build-isolation` and first installs the build backend
from build-requirements.lock.txt, so the sdist build never fetches an
unverified setuptools.

    lock_requirements.py            # rewrite every lock
    lock_requirements.py --upgrade  # also move pins to the newest allowed
    lock_requirements.py --check    # exit 1 if a lock no longer matches
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCKS = {
    "requirements.txt": "requirements.lock.txt",
    "build-requirements.txt": "build-requirements.lock.txt",
}
COMPILE_COMMAND = "python scripts/lock_requirements.py"

# The adapter installs into whatever python3 the customer image provides, so
# its lock targets the lowest Python bedrock-agentcore supports.
FIXED_PYTHON = {"migration/adapter": "3.10"}
EXTRA_IMAGES = ("migration/adapter", "migration/simulation/existing-ec2-agent")
# halo (required by strands-agents-builder) publishes only a py2 wheel.
SOURCE_BUILDS = {"agent-code/strands-agent": ("halo",)}

_PYTHON_BASE = re.compile(r"^FROM\s+\S*python:(\d+\.\d+)", re.MULTILINE)


def image_dirs() -> list[Path]:
    dirs = [
        path.parent
        for path in sorted((ROOT / "agent-code").glob("*/requirements.txt"))
        if (path.parent / "Dockerfile").is_file()
    ]
    dirs.extend(ROOT / rel for rel in EXTRA_IMAGES)
    return dirs


def _rel(image: Path) -> str:
    return image.relative_to(ROOT).as_posix()


def python_version(image: Path) -> str:
    rel = _rel(image)
    if rel in FIXED_PYTHON:
        return FIXED_PYTHON[rel]
    match = _PYTHON_BASE.search((image / "Dockerfile").read_text())
    if not match:
        raise SystemExit(f"{rel}/Dockerfile: no python:X.Y base image to lock for")
    return match.group(1)


def one_line_per_requirement(text: str) -> str:
    """Join pip continuation lines so each pin sits on one line with its hashes."""
    out: list[str] = []
    pending = ""
    for line in text.splitlines():
        if pending:
            line = f"{pending} {line.strip()}"
        if line.endswith("\\"):
            pending = line[:-1].rstrip()
            continue
        pending = ""
        out.append(line)
    if pending:
        out.append(pending)
    return "\n".join(out) + "\n"


def compile_lock(image: Path, source: str, output: Path, upgrade: bool) -> None:
    uv = shutil.which("uv")
    if not uv:
        raise SystemExit("uv is required: pip install uv")
    command = [
        uv,
        "pip",
        "compile",
        "--quiet",
        "--universal",
        "--generate-hashes",
        # Building an sdist would fetch its build backend without a hash check.
        "--only-binary",
        ":all:",
        "--python-version",
        python_version(image),
        "--custom-compile-command",
        COMPILE_COMMAND,
        source,
        "--output-file",
        str(output),
    ]
    if source == "requirements.txt":
        for package in SOURCE_BUILDS.get(_rel(image), ()):
            command += ["--no-binary", package]
    if upgrade:
        command.append("--upgrade")
    subprocess.run(command, cwd=image, check=True)
    output.write_text(one_line_per_requirement(output.read_text()))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--upgrade", action="store_true")
    args = parser.parse_args()

    stale: list[str] = []
    for image in image_dirs():
        if (
            _rel(image) in SOURCE_BUILDS
            and not (image / "build-requirements.txt").is_file()
        ):
            stale.append(f"{_rel(image)}: SOURCE_BUILDS needs build-requirements.txt")
        for source, lock_name in LOCKS.items():
            if not (image / source).is_file():
                continue
            lock = image / lock_name
            rel = lock.relative_to(ROOT).as_posix()
            if not args.check:
                compile_lock(image, source, lock, args.upgrade)
                print(f"wrote {rel}")
                continue
            if not lock.is_file():
                stale.append(f"{rel}: missing")
                continue
            with tempfile.TemporaryDirectory() as tmp:
                candidate = Path(tmp) / lock_name
                shutil.copyfile(lock, candidate)
                compile_lock(image, source, candidate, upgrade=False)
                if candidate.read_text() != lock.read_text():
                    stale.append(f"{rel}: does not match {source}")
    for problem in stale:
        print(problem, file=sys.stderr)
    if stale:
        print(f"run: {COMPILE_COMMAND}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
