#!/usr/bin/env bash
# The IdP and 3LO client secrets must not appear in the arguments of the
# secretsmanager create-secret / put-secret-value processes that deploy.sh and
# migration/simulation/run-workshop.sh start.
#
# These tests fail while that value is an argument. They pass when each of
# those calls passes the trimmed value only on standard input and sets
# --secret-string to file:///dev/stdin (the pattern deploy.sh already prints
# for migration secrets).
set -euo pipefail

if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ]; then
    echo "needs bash 4+" >&2
    exit 1
fi

for tool in flock ps stat sudo timeout; do
    command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 1; }
done
sudo -n -u nobody true || { echo "cannot run commands as nobody" >&2; exit 1; }

REPO="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Obvious placeholders. They are not credentials.
IDP_PLACEHOLDER='PLACEHOLDER_IDP_CLIENT_SECRET'
GOOGLE_PLACEHOLDER='PLACEHOLDER_GOOGLE_CLIENT_SECRET'
GITHUB_PLACEHOLDER='PLACEHOLDER_GITHUB_CLIENT_SECRET'
NOTION_PLACEHOLDER='PLACEHOLDER_NOTION_CLIENT_SECRET'
PLACEHOLDERS=(
    "$IDP_PLACEHOLDER"
    "$GOOGLE_PLACEHOLDER"
    "$GITHUB_PLACEHOLDER"
    "$NOTION_PLACEHOLDER"
)

STUB_BIN="$TMP/bin"
mkdir -p "$STUB_BIN" "$TMP/calls"
printf '0\n' > "$TMP/n"
export AWS_STUB_DIR="$TMP"
export AWS_STUB_DESCRIBE=missing
export AWS_STUB_CREATE_FAIL=0
export PATH="$STUB_BIN:$PATH"

cat > "$STUB_BIN/aws" <<'STUB'
#!/usr/bin/env bash
set -u
root="${AWS_STUB_DIR:?}"
exec 9>>"$root/lock"
flock 9
n=$(cat "$root/n")
n=$((n + 1))
printf '%s\n' "$n" > "$root/n"
flock -u 9
exec 9>&-
call="$root/calls/$n"
mkdir -p "$call"
printf '%s\0' "$@" > "$call/argv"
stat -c '%a' "/proc/$$/cmdline" > "$call/cmdline-mode"
if sudo -n -u nobody cat "/proc/$$/cmdline" > "$call/nobody-cmdline"; then
    printf 'ok\n' > "$call/nobody-read"
else
    printf 'fail\n' > "$call/nobody-read"
fi
if sudo -n -u nobody ps -ww -p "$$" -o args= > "$call/nobody-ps"; then
    printf 'ok\n' > "$call/nobody-ps-read"
else
    printf 'fail\n' > "$call/nobody-ps-read"
fi
if sudo -n -u nobody cat "/proc/$$/environ" >/dev/null 2>&1; then
    printf 'yes\n' > "$call/environ-other-user"
else
    printf 'no\n' > "$call/environ-other-user"
fi
# Capture whatever the caller passed on stdin. /dev/null yields an empty file.
cat > "$call/stdin" || true
case "$1 ${2:-}" in
    "sts get-caller-identity")
        printf '%s\n' "111111111111"
        exit 0
        ;;
    "secretsmanager describe-secret")
        if [ "${AWS_STUB_DESCRIBE:-missing}" = "exists" ]; then
            exit 0
        fi
        exit 254
        ;;
    "secretsmanager create-secret")
        if [ "${AWS_STUB_CREATE_FAIL:-0}" = "1" ]; then
            exit 254
        fi
        exit 0
        ;;
    "secretsmanager put-secret-value")
        exit 0
        ;;
    *)
        printf 'unexpected aws command\n' >&2
        exit 1
        ;;
esac
STUB
chmod +x "$STUB_BIN/aws"

cat > "$STUB_BIN/cdk" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${AWS_STUB_DIR:?}/cdk.args"
exit 1
STUB
chmod +x "$STUB_BIN/cdk"

failures=0
note_fail() {
    echo "FAIL: $*" >&2
    failures=$((failures + 1))
}
note_pass() {
    echo "PASS: $*"
}

reset_calls() {
    rm -rf "$TMP/calls"
    mkdir -p "$TMP/calls"
    printf '0\n' > "$TMP/n"
    rm -f "$TMP/cdk.args"
}

# Argument immediately following a flag in a NUL-delimited argv file.
arg_after() {
    local flag="$1" file="$2" prev="" arg
    prev=""
    while IFS= read -r -d '' arg || [ -n "$arg" ]; do
        if [ "$prev" = "$flag" ]; then
            printf '%s' "$arg"
            return 0
        fi
        prev="$arg"
    done < "$file"
    return 1
}

file_contains() {
    local needle="$1" file="$2"
    grep -a -F -q -- "$needle" "$file"
}

assert_channel_open() {
    local call="$1" label="$2" mode read_state environ_state ps_state
    mode="$(cat "$call/cmdline-mode")"
    read_state="$(cat "$call/nobody-read")"
    environ_state="$(cat "$call/environ-other-user")"
    ps_state="$(cat "$call/nobody-ps-read")"
    # Other users can read argv on this host. The mode is the kernel's
    # permission on /proc/<pid>/cmdline while the aws process is alive.
    case "$mode" in
        *4|*5|*6|*7) ;;
        *) note_fail "$label: cmdline mode $mode is not world-readable"; return 1 ;;
    esac
    [ "$read_state" = "ok" ] || { note_fail "$label: another user could not read /proc/pid/cmdline"; return 1; }
    [ "$environ_state" = "no" ] || { note_fail "$label: another user could read /proc/pid/environ"; return 1; }
    [ "$ps_state" = "ok" ] || { note_fail "$label: another user could not read ps args"; return 1; }
    return 0
}

assert_placeholder_hidden() {
    local call="$1" label="$2" placeholder
    for placeholder in "${PLACEHOLDERS[@]}"; do
        if file_contains "$placeholder" "$call/argv" \
            || file_contains "$placeholder" "$call/nobody-cmdline" \
            || file_contains "$placeholder" "$call/nobody-ps"; then
            note_fail "$label: another local user can read the client secret from the aws process arguments"
            return 1
        fi
    done
    return 0
}

assert_stdin_secret() {
    local call="$1" label="$2" placeholder="$3" secret_arg expected
    if ! secret_arg="$(arg_after --secret-string "$call/argv")"; then
        note_fail "$label: aws invocation has no --secret-string argument"
        return 1
    fi
    if [ "$secret_arg" != "file:///dev/stdin" ]; then
        note_fail "$label: --secret-string is not file:///dev/stdin"
        return 1
    fi
    printf '%s' "$placeholder" > "$TMP/expected-stdin"
    if ! cmp -s "$TMP/expected-stdin" "$call/stdin"; then
        note_fail "$label: trimmed client secret was not passed on standard input"
        return 1
    fi
    return 0
}

# Inspect every recorded aws process. Mutation calls (create/put) must carry
# the trimmed secret on stdin. Every call must keep every placeholder out of
# argv, including describe-secret and the failing create-secret that precedes
# a put-secret-value.
placeholder_for_secret_name() {
    local name="$1"
    case "$name" in
        *idp*) printf '%s' "$IDP_PLACEHOLDER" ;;
        *google*) printf '%s' "$GOOGLE_PLACEHOLDER" ;;
        *github*) printf '%s' "$GITHUB_PLACEHOLDER" ;;
        *notion*) printf '%s' "$NOTION_PLACEHOLDER" ;;
        *) return 1 ;;
    esac
}

inspect_calls() {
    local label="$1"
    shift
    local -a expected_mutations=("$@")
    local -A seen_mutation=()
    local call op name placeholder arg prev saw=0 expected

    shopt -s nullglob
    for call in "$TMP/calls"/*; do
        saw=1
        op=""
        name=""
        prev=""
        while IFS= read -r -d '' arg || [ -n "$arg" ]; do
            case "$arg" in
                create-secret|put-secret-value|describe-secret|get-caller-identity)
                    op="$arg"
                    ;;
            esac
            if [ "$prev" = "--name" ] || [ "$prev" = "--secret-id" ]; then
                name="$arg"
            fi
            prev="$arg"
        done < "$call/argv"

        assert_channel_open "$call" "$label $op" || true
        assert_placeholder_hidden "$call" "$label $op ${name:-}" || true

        if [ "$op" = "create-secret" ] || [ "$op" = "put-secret-value" ]; then
            if ! placeholder="$(placeholder_for_secret_name "$name")"; then
                note_fail "$label: mutation $op has unexpected secret name"
            else
                assert_stdin_secret "$call" "$label $op ${name}" "$placeholder" || true
                seen_mutation["$op $name"]=1
            fi
            if ! file_contains "$op" "$call/nobody-cmdline"; then
                note_fail "$label: other user did not observe $op in process arguments"
            fi
        fi
    done
    shopt -u nullglob

    [ "$saw" = 1 ] || note_fail "$label: aws was not invoked"

    for expected in "${expected_mutations[@]}"; do
        [ "${seen_mutation[$expected]:-}" = 1 ] || note_fail "$label: missing aws call: $expected"
    done
}

load_deploy_functions() {
    # shellcheck disable=SC2317
    log_info() { :; }
    log_error() { printf '%s\n' "$*" >&2; }
    # shellcheck disable=SC1091
    eval "$(sed -n \
        '/^upsert_oauth_secret()/,/^}/p; /^upsert_idp_secret()/,/^}/p; /^upsert_3lo_secrets()/,/^}/p' \
        "$REPO/scripts/deploy.sh")"
    declare -F upsert_oauth_secret >/dev/null
    declare -F upsert_idp_secret >/dev/null
    declare -F upsert_3lo_secrets >/dev/null
}

load_deploy_functions

PREFIX="argv-check"
AWS_REGION="us-east-1"
export PREFIX AWS_REGION

run_idp() {
    local describe="$1"
    reset_calls
    AWS_STUB_DESCRIBE="$describe"
    unset IDP_CLIENT_SECRET_NAME || true
    # Trailing newline and surrounding spaces are what a pasted or piped
    # secret looks like. The stored bytes must be the trimmed placeholder.
    # Command substitution would eat the trailing newline, so keep it quoted.
    IDP_CLIENT_SECRET="  ${IDP_PLACEHOLDER}"$'\n'
    # Subshell so a failing upsert cannot exit this test. Stdin is /dev/null
    # unless the function itself pipes the secret.
    ( upsert_idp_secret ) >/dev/null 2>&1 </dev/null || true
}

run_idp missing
inspect_calls "deploy idp create" \
    "create-secret ${PREFIX}-idp-client-secret"

run_idp exists
inspect_calls "deploy idp update" \
    "put-secret-value ${PREFIX}-idp-client-secret"

run_3lo() {
    local describe="$1"
    reset_calls
    AWS_STUB_DESCRIBE="$describe"
    unset GOOGLE_CLIENT_SECRET_NAME GITHUB_CLIENT_SECRET_NAME NOTION_CLIENT_SECRET_NAME || true
    # Read by the eval'd upsert_3lo_secrets via the variable name, not a direct expansion.
    # shellcheck disable=SC2034
    GOOGLE_CLIENT_SECRET="  ${GOOGLE_PLACEHOLDER}"$'\n'
    # shellcheck disable=SC2034
    GITHUB_CLIENT_SECRET="  ${GITHUB_PLACEHOLDER}"$'\n'
    # shellcheck disable=SC2034
    NOTION_CLIENT_SECRET="  ${NOTION_PLACEHOLDER}"$'\n'
    ( upsert_3lo_secrets ) >/dev/null 2>&1 </dev/null || true
}

run_3lo missing
inspect_calls "deploy 3lo create" \
    "create-secret ${PREFIX}-google-oauth-secret" \
    "create-secret ${PREFIX}-github-oauth-secret" \
    "create-secret ${PREFIX}-notion-oauth-secret"

run_3lo exists
inspect_calls "deploy 3lo update" \
    "put-secret-value ${PREFIX}-google-oauth-secret" \
    "put-secret-value ${PREFIX}-github-oauth-secret" \
    "put-secret-value ${PREFIX}-notion-oauth-secret"

run_workshop() {
    local create_fail="$1" label="$2"
    shift 2
    reset_calls
    AWS_STUB_CREATE_FAIL="$create_fail"
    # The simulation's documented entry point exports the client secret.
    (
        export IDP_TENANT_ID="placeholder-tenant"
        export IDP_CLIENT_ID="placeholder-client-id"
        export IDP_CLIENT_SECRET="  ${IDP_PLACEHOLDER}"$'\n'
        export IDP_TYPE="entra_id"
        export AWS_STUB_CREATE_FAIL="$create_fail"
        timeout 20 bash "$REPO/migration/simulation/run-workshop.sh" \
            >"$TMP/workshop.log" 2>&1 </dev/null
    ) || true
    if [ -s "$TMP/cdk.args" ]; then
        note_fail "$label: workshop reached cdk; secret assertions would be incomplete"
    fi
    inspect_calls "$label" "$@"
}

run_workshop 0 "workshop idp create" \
    "create-secret agentcore-workshop-dev-idp-client-secret"
run_workshop 1 "workshop idp update" \
    "create-secret agentcore-workshop-dev-idp-client-secret" \
    "put-secret-value agentcore-workshop-dev-idp-client-secret"

if [ "$failures" -ne 0 ]; then
    echo "$failures assertion(s) failed" >&2
    exit 1
fi
echo "PASS: client secrets stay off the aws process arguments"
