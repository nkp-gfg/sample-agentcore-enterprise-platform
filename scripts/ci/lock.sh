#!/usr/bin/env bash
# Regenerate the hash-pinned dependency files the GitLab jobs install from.
#
# Every job installs with `pip install --require-hashes --only-binary=:all:`
# and `npm ci`, so a registry release that is not in these files never reaches
# a job. Bump a version by editing the .in file (or requirements.txt for the
# cdk-synth job), run this script, and review the diff.
#
# Needs uv (https://docs.astral.sh/uv/) and npm.
set -euo pipefail
cd "$(dirname "$0")"

compile() {
    local python="$1" input="$2" output="$3"
    uv pip compile --quiet --universal --python-version "$python" \
        --generate-hashes --only-binary :all: \
        --custom-compile-command "scripts/ci/lock.sh" \
        "$input" -o "$output"
}

# python:3.13-slim jobs
for job in ruff shell control-library pytest; do
    compile 3.13 "requirements-$job.in" "requirements-$job.txt"
done
# cdk-synth runs Debian's python3 in node:22-slim; 3.11 is the oldest it ships.
compile 3.11 ../../requirements.txt requirements-cdk-synth.txt

(cd ../.. && npm install --package-lock-only --ignore-scripts --no-audit --no-fund)
