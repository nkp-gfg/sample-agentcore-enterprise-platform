#!/usr/bin/env bash
# Preset ↔ synth parity: the deployment contract must match what app.py builds.
#
# For every presets/*.yaml: ask the contract for its expected stack list
# (platform_config --stacks), synthesize the app with that preset, and fail on
# any difference. This is what keeps expected_stacks() honest — add a stack to
# app.py without teaching the contract (or vice versa) and this goes red.
#
# No AWS credentials needed: account is a placeholder and the networking VPC's
# AZ lookup is pre-seeded via cdk.context.json (docs/TESTING.md A7b).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO"

PY="${PY:-$REPO/.venv/bin/python}"
[ -x "$PY" ] || PY=python3

export CDK_DEFAULT_ACCOUNT="${CDK_DEFAULT_ACCOUNT:-111111111111}"
export CDK_DEFAULT_REGION="${CDK_DEFAULT_REGION:-us-east-1}"
# security-focused ships org_id EMPTY (a placeholder must not validate, so it
# cannot ship a real-looking one) but its memory stack hard-fails resource
# policies without an org id. Env beats platform.yaml, so this satisfies the
# synth; real deploys still prompt.
export ORG_ID="${ORG_ID:-o-paritycheck123}"
# The shipped presets carry placeholders (REPLACE_ME client ids, sentinel
# account ids) on purpose; a real deploy refuses them. The gate only proves the
# presets synthesize, so it downgrades those refusals to warnings.
export PLATFORM_ALLOW_PLACEHOLDERS=1
export JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION=1

# The networking VPC's AZ lookup needs context to synth offline; CDK only
# reads it from ./cdk.context.json (docs/TESTING.md A7b). Preserve any
# existing file and put ours in place for the duration of the run.
[ -f cdk.context.json ] && mv cdk.context.json cdk.context.json.check-contract-bak
restore_context() {
    rm -f cdk.context.json
    # Plain `[ -f ] && mv` would end the trap with status 1 when no backup
    # exists (fresh checkout, CI) and set -e turns that into the script's
    # exit code — every preset PASSed and the job still failed. If/fi is the
    # always-zero form.
    if [ -f cdk.context.json.check-contract-bak ]; then
        mv cdk.context.json.check-contract-bak cdk.context.json
    fi
}
# PIPE included: `check-contract.sh | head` must not skip the restore.
trap restore_context EXIT INT TERM PIPE
# Presets are the shipped profiles; tests/fixtures/contract/ holds extra
# footprints worth pinning (e.g. a use case enabled), same parity rules.
CONFIGS=(presets/*.yaml)
[ -d tests/fixtures/contract ] && CONFIGS+=(tests/fixtures/contract/*.yaml)
# Account ids come from raw YAML (the schema's 12-digit check has not run) and
# end up in cdk.context.json and the synth environment, so each one must be
# exactly 12 digits before anything uses it.
require_account() {
    if ! [[ "$1" =~ ^[0-9]{12}$ ]]; then
        printf 'FAIL: %s — account id is not 12 digits: %q\n' "$2" "$1" >&2
        exit 1
    fi
}
# Fills the named array with one entry per output line of the command, and
# fails the script when the command fails (process substitution would not).
read_lines() {
    local -n _into="$1"; shift
    local out
    out="$("$@")"
    _into=()
    if [ -n "$out" ]; then
        mapfile -t _into <<< "$out"
    fi
}

require_account "$CDK_DEFAULT_ACCOUNT" "CDK_DEFAULT_ACCOUNT"

# A federated preset is synthesized from BOTH of its accounts (below), so the
# AZ context covers every account id a preset names, not just the default.
preset_accounts() {
    "$PY" - "$@" <<'PYEOF'
import sys, yaml
seen = []
for f in sys.argv[1:]:
    dep = (yaml.safe_load(open(f)) or {}).get("deployment") or {}
    for a in [dep.get("platform_account", ""), *(dep.get("workload_accounts") or [])]:
        if a and str(a) not in seen:
            seen.append(str(a))
for a in seen:
    print(a)
PYEOF
}
read_lines PRESET_ACCOUNTS preset_accounts "${CONFIGS[@]}"
for acct in "${PRESET_ACCOUNTS[@]}"; do
    require_account "$acct" "a deployment account in presets/ or tests/fixtures/contract/"
done
{
    echo '{'
    for acct in "$CDK_DEFAULT_ACCOUNT" "${PRESET_ACCOUNTS[@]}"; do
        printf '  "availability-zones:account=%s:region=%s": ["%sa","%sb"],\n' \
            "$acct" "$CDK_DEFAULT_REGION" "$CDK_DEFAULT_REGION" "$CDK_DEFAULT_REGION"
    done
    echo '  "_": null'
    echo '}'
} > cdk.context.json

# The account you deploy into decides a federated footprint, so a federated
# preset is checked once per side; every other preset once, from the default.
sides_of() {
    "$PY" - "$1" <<'PYEOF'
import sys, yaml
dep = (yaml.safe_load(open(sys.argv[1])) or {}).get("deployment") or {}
if dep.get("strategy") == "federated":
    for a in [dep.get("platform_account", ""), *(dep.get("workload_accounts") or [])]:
        if a:
            print(a)
PYEOF
}
RUN_PRESETS=()
RUN_ACCOUNTS=()
for preset in "${CONFIGS[@]}"; do
    read_lines sides sides_of "$preset"
    if [ "${#sides[@]}" -gt 0 ]; then
        for acct in "${sides[@]}"; do
            require_account "$acct" "$preset"
            RUN_PRESETS+=("$preset"); RUN_ACCOUNTS+=("$acct")
        done
    else
        RUN_PRESETS+=("$preset"); RUN_ACCOUNTS+=("$CDK_DEFAULT_ACCOUNT")
    fi
done

# The CDK CLI runs --app through a shell, so the command must stay a fixed
# string: the preset path and account reach it only as environment variables,
# expanded inside double quotes. CDK_DEFAULT_ACCOUNT is re-set inside the app
# command because the CLI overwrites it when it can resolve credentials.
APP_CMD='env PLATFORM_CONFIG="$CHECK_CONTRACT_PRESET" CDK_DEFAULT_ACCOUNT="$CHECK_CONTRACT_ACCOUNT" "$CHECK_CONTRACT_PY" app.py'

fail=0
for i in "${!RUN_PRESETS[@]}"; do
    preset="${RUN_PRESETS[$i]}"; acct="${RUN_ACCOUNTS[$i]}"
    name="$(basename -- "$preset" .yaml)"
    [ "$acct" != "$CDK_DEFAULT_ACCOUNT" ] && name="$name@$acct"
    workdir="$(mktemp -d)"

    CDK_DEFAULT_ACCOUNT="$acct" "$PY" -m infra_utils.platform_config --stacks "$preset" 2>/dev/null | sort > "$workdir/expected"

    if ! CDK_DEFAULT_ACCOUNT="$acct" CHECK_CONTRACT_ACCOUNT="$acct" \
        CHECK_CONTRACT_PRESET="$preset" CHECK_CONTRACT_PY="$PY" \
        npx --no-install cdk ls \
        --app "$APP_CMD" \
        --output "$workdir/cdk.out" 2> "$workdir/synth.log" \
        | sort > "$workdir/actual"; then
        echo "FAIL: $name — synth broke:" >&2
        tail -5 "$workdir/synth.log" >&2
        fail=1
        rm -rf "$workdir"
        continue
    fi

    if ! diff -u "$workdir/expected" "$workdir/actual" > "$workdir/diff"; then
        echo "FAIL: $name — contract and synth disagree (expected vs synthesized):" >&2
        cat "$workdir/diff" >&2
        fail=1
    else
        printf 'PASS: %-18s %s stack(s)\n' "$name" "$(wc -l < "$workdir/expected" | tr -d ' ')"
    fi
    rm -rf "$workdir"
done

[ "$fail" = 0 ] && echo "OK: every preset matches the contract"
exit "$fail"
