#!/usr/bin/env bash
# Install a hash-locked requirements file and fail unless the environment
# matches it.
#
#   bash scripts/pip-install-locked.sh LOCKFILE [PYTHON]
#
# --require-hashes makes pip refuse, before unpacking, any file whose sha256 is
# not in the lock, including a different release served under a locked name
# and any dependency the lock does not list. --only-binary keeps sdists out:
# their build backends would be fetched without a hash. Regenerate the locks
# with `make lock`.
set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 LOCKFILE [PYTHON]" >&2
    exit 2
fi
lock="$1"
python="${2:-python3}"

if [ ! -f "$lock" ]; then
    echo "lock file not found: $lock" >&2
    exit 2
fi

"$python" -m pip install -q --require-hashes --only-binary :all: -r "$lock"

# Offline re-resolve: anything missing or at a version other than the locked
# one would need a download, which --no-index refuses.
if ! "$python" -m pip install -q --dry-run --no-index --require-hashes \
        --only-binary :all: -r "$lock"; then
    echo "installed distributions do not match $lock" >&2
    exit 1
fi
"$python" -m pip check
