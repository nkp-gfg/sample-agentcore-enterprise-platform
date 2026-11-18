#!/usr/bin/env bash
# Install the CDK CLI pinned in .github/ci/cdk/package-lock.json as npm's
# global cdk. npm ci refuses a tarball whose sha512 differs from the lockfile;
# the global install then links that verified folder, fetching nothing.
# Global, because scripts/check-contract.sh and scripts/deploy.sh resolve the
# CLI with `npx --no-install cdk`, which looks only in node_modules/.bin and
# npm's global bin — and deploy.sh falls back to an unpinned
# `npm install -g aws-cdk` when that lookup fails.
set -euo pipefail
dir="$(cd "$(dirname "$0")/cdk" && pwd)"
npm ci --prefix "$dir" --ignore-scripts --no-audit --no-fund
npm install --global --ignore-scripts --no-audit --no-fund "$dir/node_modules/aws-cdk"
npx --no-install cdk --version
