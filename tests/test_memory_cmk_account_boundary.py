"""Account boundary for the memory CMK service control policy.

Plans ``control-library/terraform/org-guardrails`` and evaluates the policy
document that plan would attach. ``StringNotLike`` / ``Null`` follow the IAM
condition rules cited on the helpers below. The tests fail while the default
``kms_key_arn_pattern`` matches a customer managed key in any account.

CreateGateway and UpdateGateway are not covered. The service authorization
reference registers ``bedrock-agentcore:KmsKeyArn`` on CreateMemory only, so a
key ARN on those gateway actions does not reach this pattern. UpdateMemory is
not covered for the same reason.
"""

from __future__ import annotations

import fcntl
import json
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

from infra_utils.policy_loader import load_control

REPO = Path(__file__).resolve().parents[1]
MODULE = REPO / "control-library" / "terraform" / "org-guardrails"
TARGET_ID = "123456789012"
KEY_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
NAMED_ACCOUNT = "111122223333"
FOREIGN_ACCOUNT = "999999999999"
CREATE_MEMORY = "bedrock-agentcore:CreateMemory"
KMS_KEY = "bedrock-agentcore:KmsKeyArn"

# Patterns that StringLike-match key ARNs in more than one account, including
# shapes that still match after a check that only inspects one colon field.
ACCOUNT_WILDCARD_PATTERNS = [
    "arn:aws:kms:*:*:key/*",
    "arn:aws:kms:us-east-1:*:key/*",
    "arn:aws:kms:*:111*:key/*",
    "arn:aws:kms:*:????????????:key/*",
    "arn:aws:kms:*:key/*",
    "arn:aws:kms:*:?????????*:key/*",
]
NAMED_PATTERN = f"arn:aws:kms:*:{NAMED_ACCOUNT}:key/*"
EXACT_KEY_PATTERN = (
    f"arn:aws:kms:eu-west-1:{NAMED_ACCOUNT}:key/{KEY_ID}"
)


def key_arn(region: str, account: str, key_id: str = KEY_ID) -> str:
    return f"arn:aws:kms:{region}:{account}:key/{key_id}"


NAMED_KEY = key_arn("eu-west-1", NAMED_ACCOUNT)
FOREIGN_KEY = key_arn("us-west-2", FOREIGN_ACCOUNT)
SECOND_NAMED_PREFIX_KEY = key_arn("us-east-1", "111000000000")


def string_like(pattern: str, value: str) -> bool:
    """IAM ``StringLike`` glob.

    ``*`` is any combination of characters, including none, and ``?`` is one
    character. String operators are patternless: ``*`` is not confined to an
    ARN component (that restriction is ``ArnLike``). Matching is case-sensitive.
    """
    # IAM JSON policy elements: Resource, "Using wildcards in resource ARNs"
    # (* is "any combination of characters", and a trailing * matches an empty
    # remainder in the published amzn-s3-demo-bucket/*/test/* examples).
    # IAM JSON policy elements: Condition operators, StringLike / "Wildcard
    # matching" (patternless; wildcards anywhere in the string).
    plen, vlen = len(pattern), len(value)
    prev = [False] * (vlen + 1)
    prev[0] = True
    for pc in pattern:
        cur = [False] * (vlen + 1)
        if pc == "*":
            cur[0] = prev[0]
            for j in range(1, vlen + 1):
                cur[j] = cur[j - 1] or prev[j]
        else:
            for j in range(1, vlen + 1):
                if prev[j - 1] and (pc == "?" or pc == value[j - 1]):
                    cur[j] = True
        prev = cur
    return prev[vlen]


def _values(raw: object) -> list[str]:
    if isinstance(raw, list):
        return [str(item) for item in raw]
    return [str(raw)]


def _lookup(context: dict[str, str], key: str) -> str | None:
    # Condition key names are not case-sensitive.
    # IAM JSON policy elements: Condition.
    for name, value in context.items():
        if name.lower() == key.lower():
            return value
    return None


def _operator_matches(operator: str, mapping: dict, context: dict[str, str]) -> bool:
    """Evaluate one condition operator.

    Absent keys make a negated operator true and every other operator here
    false. ``Null`` is the exception: it tests presence itself. Several
    operators on one statement are AND. Several values of one operator are OR
    for a positive operator and "matches none of them" for a negated operator.
    """
    # IAM JSON policy elements: Condition operators (the Important note on
    # missing keys, StringNotLike, and Null).
    # Creating a condition with multiple keys or values (AND across operators
    # and keys; OR across values; negated operators match only when the value
    # matches none of the listed values).
    if operator.startswith("ForAllValues:") or operator.startswith("ForAnyValue:"):
        raise NotImplementedError(operator)
    if operator.endswith("IfExists"):
        raise NotImplementedError(operator)

    negated = operator in {
        "StringNotLike",
        "StringNotEquals",
        "ArnNotLike",
        "ArnNotEquals",
    }
    for key, raw in mapping.items():
        present_value = _lookup(context, key)
        present = present_value is not None
        if operator == "Null":
            want_absent = str(_values(raw)[0]).lower() == "true"
            matched = (not present) if want_absent else present
        elif not present:
            matched = negated
        elif operator in {"StringLike", "StringNotLike"}:
            liked = any(string_like(pattern, present_value) for pattern in _values(raw))
            matched = (not liked) if negated else liked
        elif operator in {"StringEquals", "StringNotEquals"}:
            equal = any(pattern == present_value for pattern in _values(raw))
            matched = (not equal) if negated else equal
        else:
            raise NotImplementedError(operator)
        if not matched:
            return False
    return True


def statement_denies(statement: dict, action: str, context: dict[str, str]) -> bool:
    if statement.get("Effect") != "Deny":
        return False
    # Action prefix and name are case-insensitive.
    # IAM JSON policy elements: Action.
    requested = action.casefold()
    actions = statement.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]
    if not any(string_like(item.casefold(), requested) for item in actions):
        return False
    resources = statement.get("Resource", [])
    if isinstance(resources, str):
        resources = [resources]
    # CreateMemory is authorized against Resource "*". A "*" resource matches
    # every resource ARN.
    if not any(string_like(item, "*") or item == "*" for item in resources):
        return False
    condition = statement.get("Condition") or {}
    return all(
        _operator_matches(operator, mapping, context)
        for operator, mapping in condition.items()
    )


def scp_denies(policy: dict, action: str, kms_key_arn: str | None) -> bool:
    context: dict[str, str] = {}
    if kms_key_arn is not None:
        context[KMS_KEY] = kms_key_arn
    return any(
        statement_denies(statement, action, context)
        for statement in policy["Statement"]
    )


def _hcl_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return json.dumps(value)
    return json.dumps(str(value))


def _cli_value(value: object) -> str:
    # terraform console -var takes a raw string, not an HCL literal. Quoting a
    # string here would inject the quote characters into the SCP.
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return json.dumps(value)
    return str(value)


def _terraform(args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    lock = MODULE / ".cmk-boundary.lock"
    with lock.open("w") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        return subprocess.run(
            args,
            cwd=MODULE,
            input=stdin,
            capture_output=True,
            text=True,
            check=False,
        )


@pytest.fixture(scope="module", autouse=True)
def terraform_initialized():
    if shutil.which("terraform") is None:
        pytest.fail("terraform is not installed")
    proc = _terraform(["terraform", "init", "-backend=false", "-input=false", "-no-color"])
    if proc.returncode != 0:
        pytest.fail(proc.stdout + proc.stderr)
    yield
    (MODULE / ".cmk-boundary.lock").unlink(missing_ok=True)


def terraform_plan(variables: dict[str, object]) -> subprocess.CompletedProcess[str]:
    """Plan the module with a mocked AWS provider. Returns the combined output."""
    relative = Path("tests") / f"cmk-{uuid.uuid4().hex}"
    directory = MODULE / relative
    directory.mkdir(parents=True)
    assignments = "\n".join(
        f"  {name} = {_hcl_value(value)}" for name, value in variables.items()
    )
    (directory / "plan.tftest.hcl").write_text(
        "mock_provider \"aws\" {}\n\n"
        "variables {\n"
        f"{assignments}\n"
        "}\n\n"
        "run \"plan\" {\n"
        "  command = plan\n"
        "}\n"
    )
    try:
        proc = _terraform(
            [
                "terraform",
                "test",
                "-test-directory",
                relative.as_posix(),
                "-verbose",
                "-no-color",
            ]
        )
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    proc.stdout = proc.stdout + proc.stderr
    return proc


def _memory_policy_planned(output: str) -> bool:
    return "aws_organizations_policy.memory_enforce_cmk[0] will be created" in output


def _memory_policy_attached(output: str) -> bool:
    return (
        'aws_organizations_policy_attachment.memory_enforce_cmk["'
        in output
        and "will be created" in output
    )


def assert_pattern_rejected(proc: subprocess.CompletedProcess[str]) -> None:
    output = proc.stdout
    if proc.returncode == 0 or _memory_policy_planned(output):
        pytest.fail(
            "enable_scp_memory_enforce_cmk planned the memory SCP for an "
            "account-wildcard kms_key_arn_pattern.\n"
            + output
        )
    if "kms_key_arn_pattern" not in output:
        pytest.fail(
            "plan failed without naming kms_key_arn_pattern, so this was not "
            "the account-wildcard rejection.\n"
            + output
        )


def rendered_policy(variables: dict[str, object]) -> dict:
    """Evaluate local.cmk_scp_rendered through Terraform's replace()."""
    variables = {"target_ids": [TARGET_ID], **variables}
    args = ["terraform", "console", "-no-color"]
    for name, value in variables.items():
        args.extend(["-var", f"{name}={_cli_value(value)}"])
    proc = _terraform(args, stdin="local.cmk_scp_rendered\n")
    if proc.returncode != 0:
        pytest.fail(proc.stdout + proc.stderr)
    text = proc.stdout.strip()
    if text.startswith("<<EOT"):
        text = text.removeprefix("<<EOT").removesuffix("EOT").strip()
    policy = json.loads(text)
    assert "<<" not in json.dumps(policy)
    return policy


def _pattern_of(policy: dict) -> str:
    for statement in policy["Statement"]:
        condition = statement.get("Condition") or {}
        like = condition.get("StringNotLike") or {}
        if KMS_KEY in like:
            return str(like[KMS_KEY])
    pytest.fail(f"rendered policy has no StringNotLike {KMS_KEY}: {policy}")


def test_string_like_follows_published_wildcard_examples():
    bucket = "arn:aws:s3:::amzn-s3-demo-bucket"
    pattern = bucket + "/*/test/*"
    assert string_like(pattern, bucket + "/1/test/object.jpg")
    assert string_like(pattern, bucket + "/1/2/test/object.jpg")
    assert string_like(pattern, bucket + "/1/test/")
    assert not string_like(pattern, bucket + "/1-test/object.jpg")
    assert not string_like(pattern, bucket + "/test/object.jpg")
    assert string_like("t1.*", "t1.micro")
    assert not string_like("t2.*", "m2.micro")
    assert string_like("*", "")

    assert string_like("arn:aws:kms:*:*:key/*", NAMED_KEY)
    assert string_like("arn:aws:kms:*:*:key/*", FOREIGN_KEY)
    assert string_like(NAMED_PATTERN, NAMED_KEY)
    assert not string_like(NAMED_PATTERN, FOREIGN_KEY)
    assert string_like("arn:aws:kms:*:key/*", FOREIGN_KEY)
    assert string_like("arn:aws:kms:*:111*:key/*", SECOND_NAMED_PREFIX_KEY)
    assert not string_like("arn:aws:kms:*:111*:key/*", FOREIGN_KEY)


def test_module_defaults_do_not_attach_the_memory_scp():
    proc = terraform_plan({"target_ids": [TARGET_ID]})
    assert proc.returncode == 0, proc.stdout
    assert not _memory_policy_planned(proc.stdout)


@pytest.mark.parametrize("pattern", ACCOUNT_WILDCARD_PATTERNS)
def test_enabled_control_rejects_account_wildcard_pattern(pattern: str):
    matched = [
        arn
        for account in (NAMED_ACCOUNT, FOREIGN_ACCOUNT, "111000000000", "210987654321")
        for region in ("us-east-1", "eu-west-1", "us-west-2")
        if string_like(pattern, (arn := key_arn(region, account)))
    ]
    assert len(matched) >= 2, (pattern, matched)
    proc = terraform_plan(
        {
            "target_ids": [TARGET_ID],
            "enable_scp_memory_enforce_cmk": True,
            "kms_key_arn_pattern": pattern,
        }
    )
    assert_pattern_rejected(proc)


def test_enabled_default_pattern_denies_a_foreign_account_key():
    proc = terraform_plan(
        {
            "target_ids": [TARGET_ID],
            "enable_scp_memory_enforce_cmk": True,
        }
    )
    if proc.returncode != 0:
        assert_pattern_rejected(proc)
        return
    assert _memory_policy_planned(proc.stdout)
    assert _memory_policy_attached(proc.stdout)
    policy = rendered_policy({"enable_scp_memory_enforce_cmk": True})
    pattern = _pattern_of(policy)
    assert pattern in proc.stdout
    if not scp_denies(policy, CREATE_MEMORY, FOREIGN_KEY):
        pytest.fail(
            "CreateMemory with a KMS key in an account the operator did not "
            f"name is not denied (pattern {pattern!r}, key {FOREIGN_KEY})."
        )
    assert scp_denies(policy, CREATE_MEMORY, None)


def test_narrowed_pattern_denies_only_keys_outside_the_named_account():
    proc = terraform_plan(
        {
            "target_ids": [TARGET_ID],
            "enable_scp_memory_enforce_cmk": True,
            "kms_key_arn_pattern": NAMED_PATTERN,
        }
    )
    assert proc.returncode == 0, proc.stdout
    assert _memory_policy_planned(proc.stdout)
    assert _memory_policy_attached(proc.stdout)
    policy = rendered_policy(
        {
            "enable_scp_memory_enforce_cmk": True,
            "kms_key_arn_pattern": NAMED_PATTERN,
        }
    )
    assert _pattern_of(policy) == NAMED_PATTERN
    assert NAMED_PATTERN in proc.stdout
    assert scp_denies(policy, CREATE_MEMORY, FOREIGN_KEY)
    assert scp_denies(policy, CREATE_MEMORY, key_arn("us-east-1", TARGET_ID))
    assert scp_denies(policy, CREATE_MEMORY, None)
    assert scp_denies(
        policy,
        CREATE_MEMORY,
        f"arn:aws:kms:eu-west-1:{NAMED_ACCOUNT}:alias/memory",
    )
    assert not scp_denies(policy, CREATE_MEMORY, NAMED_KEY)
    assert not scp_denies(
        policy, CREATE_MEMORY, key_arn("ap-southeast-2", NAMED_ACCOUNT)
    )

    exact = rendered_policy({"kms_key_arn_pattern": EXACT_KEY_PATTERN})
    assert not scp_denies(exact, CREATE_MEMORY, NAMED_KEY)
    assert scp_denies(
        exact, CREATE_MEMORY, key_arn("eu-west-1", NAMED_ACCOUNT, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    )


def test_catalog_default_does_not_allow_a_foreign_account_key():
    try:
        policy = load_control("scp.memory.enforce-cmk")
    except ValueError as exc:
        message = str(exc)
        if "kms_key_arn_pattern" in message or "unresolved" in message:
            return
        raise
    if not scp_denies(policy, CREATE_MEMORY, FOREIGN_KEY):
        pytest.fail(
            "load_control('scp.memory.enforce-cmk') allows CreateMemory with "
            f"{FOREIGN_KEY} (pattern {_pattern_of(policy)!r})."
        )
    assert scp_denies(policy, CREATE_MEMORY, None)


def test_catalog_narrowed_pattern_keeps_the_named_account_usable():
    policy = load_control(
        "scp.memory.enforce-cmk",
        {"kms_key_arn_pattern": NAMED_PATTERN},
    )
    assert scp_denies(policy, CREATE_MEMORY, FOREIGN_KEY)
    assert not scp_denies(policy, CREATE_MEMORY, NAMED_KEY)
    assert scp_denies(policy, CREATE_MEMORY, None)
