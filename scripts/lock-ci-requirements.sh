#!/usr/bin/env bash
# Regenerate the hash-pinned CI lockfiles in .github/requirements/ from their
# .in files. CI installs them with `pip install --require-hashes --only-binary
# :all:`, so a dependency bump means editing the .in (or requirements.txt) and
# re-running this, never editing a .txt by hand.
#
# --universal --python-version 3.11 covers every interpreter CI uses: 3.13 on
# GitHub and the GitLab python image, Debian's 3.11 in the GitLab cdk-synth job.
# Wheels only: building an sdist would fetch its build backend without a hash.
#
# Usage: scripts/lock-ci-requirements.sh [--upgrade]   (needs uv on PATH)
set -euo pipefail

cd "$(dirname "$0")/../.github/requirements"

for input in *.in; do
    uv pip compile "$input" \
        --universal \
        --python-version 3.11 \
        --generate-hashes \
        --only-binary :all: \
        --custom-compile-command "scripts/lock-ci-requirements.sh" \
        --output-file "${input%.in}.txt" \
        "$@"
done
