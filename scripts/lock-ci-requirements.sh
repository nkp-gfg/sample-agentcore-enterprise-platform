#!/usr/bin/env bash
# Regenerate the hashed Python locks the CI jobs install from
# (.github/requirements/*.txt). Run after changing requirements.txt or a
# .github/requirements/*.in file, and commit the result.
#
# CI installs with --require-hashes --only-binary=:all: against these files, so
# a job only executes the exact wheels recorded here. A package or version that
# is not in the lock fails the install instead of being fetched from the index.
# Hashes from a constraints file are only honoured by pip 26.1 and newer; older
# pips refuse the install rather than skip the check.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v uv >/dev/null 2>&1; then
    echo "uv is required: https://docs.astral.sh/uv/getting-started/installation/" >&2
    exit 1
fi

# Universal resolution from 3.11 up: the GitHub jobs and most GitLab jobs run
# 3.13, the GitLab cdk-synth job uses the node image's Debian python3.
compile() {
    uv pip compile "$1" \
        --universal \
        --python-version 3.11 \
        --generate-hashes \
        --only-binary :all: \
        --quiet \
        --output-file "$2"
}

compile .github/requirements/app.in .github/requirements/app.txt
compile .github/requirements/checkov.in .github/requirements/checkov.txt
compile .github/requirements/ruff.in .github/requirements/ruff.txt
