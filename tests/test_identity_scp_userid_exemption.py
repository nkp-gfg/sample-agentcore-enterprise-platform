"""Default GetWorkloadAccessTokenForUserId SCP must deny roles a member admin can create.

The org-guardrails module attaches this SCP by default. The policy is a Deny with an
ArnNotLike exemption. A member-account administrator who can create and assume an IAM role,
and who can allow the action on that role, must still be denied. That includes a role whose
name is whatever literal the default exemption names, because CreateRole does not reserve it.

These checks fail while the shipped default exemption matches such a role. They pass when the
default policy denies the action for every role that administrator can create.

IAM and Organizations behavior below is the published rule set, not a live API call:
- ArnLike compares the six colon-delimited ARN components separately; ``*`` and ``?`` are
  wildcards inside a component. ArnNotLike is the negation. Multiple patterns are NOR.
  https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
  https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-logic-multiple-context-keys-or-values.html
- For an assumed IAM role, aws:PrincipalArn is the role ARN
  ``arn:aws:iam::ACCOUNT:role/role-name``, not the sts assumed-role session ARN.
  https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
- CreateRole RoleName is ``[\\w+=,.@-]+``, 1-64 characters. Path defaults to ``/``.
  https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html
- SCPs deny even when the identity policy allows the action. A default ``Allow *`` SCP is
  what makes an action allowed when no SCP denies it.
  https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html
  https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_syntax.html
- GetWorkloadAccessTokenForUserId takes caller-supplied userId and workloadName and returns
  a workload access token. userId is not verified. Runtime- and Gateway-linked workload
  identities are refused separately; other workload identities are not.
  https://docs.aws.amazon.com/bedrock-agentcore/latest/APIReference/API_GetWorkloadAccessTokenForUserId.html
  https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/get-workload-access-token.html
- Terraform ``replace`` of a substring that is not slash-wrapped replaces every occurrence
  (hashicorp/terraform v1.10.5 internal/lang/funcs/string.go, ReplaceFunc).

GetResourceOauth2Token is not an SCP statement in this module. It is the documented vault
read that uses the workload access token's user identity, so these tests stop at whether
that token is issued. No other SCP in the module names GetWorkloadAccessTokenForUserId.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from infra_utils.policy_loader import load_control

REPO = Path(__file__).resolve().parents[1]
MODULE = REPO / "control-library" / "terraform" / "org-guardrails"

# A member account covered by the SCP. The account id is not special; any 12-digit
# member account the administrator controls would do.
MEMBER_ACCOUNT = "210987654321"
REGION = "us-east-1"
ACTION = "bedrock-agentcore:GetWorkloadAccessTokenForUserId"
WORKLOAD_NAME = "finance-agent"

# CreateRole RoleName pattern from the IAM API reference. ``\w`` there is ASCII.
_ROLE_NAME = re.compile(r"[A-Za-z0-9_+=,.@-]{1,64}\Z")
_USER_ID = re.compile(r".{1,128}\Z", re.DOTALL)

# Default SCP quoted by the Organizations SCP syntax page as the attached ``Allow *``.
FULL_AWS_ACCESS = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}

# Identity policy the member administrator attaches to the role they create.
ATTACKER_ROLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ACTION, "Resource": "*"}],
}


@dataclass(frozen=True)
class TokenRequest:
    principal_arn: str
    user_id: str
    workload_name: str
    workload_linked_to_service: bool
    resources: tuple[str, ...]

    @property
    def context(self) -> dict[str, str]:
        return {
            "aws:PrincipalArn": self.principal_arn,
            "bedrock-agentcore:userid": self.user_id,
        }


def _resources() -> tuple[str, ...]:
    directory = (
        f"arn:aws:bedrock-agentcore:{REGION}:{MEMBER_ACCOUNT}:"
        "workload-identity-directory/default"
    )
    workload = f"{directory}/workload-identity/{WORKLOAD_NAME}"
    return (directory, workload)


def request_for(
    principal_arn: str, user_id: str, *, linked: bool = False
) -> TokenRequest:
    if not _USER_ID.fullmatch(user_id):
        raise ValueError(f"userId {user_id!r} is outside the API length constraint")
    return TokenRequest(
        principal_arn=principal_arn,
        user_id=user_id,
        workload_name=WORKLOAD_NAME,
        workload_linked_to_service=linked,
        resources=_resources(),
    )


# ── ARN and policy evaluation (published IAM / Organizations rules) ──


def split_arn(arn: str) -> list[str] | None:
    parts = arn.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn":
        return None
    return parts


def _glob_regex(pattern: str, *, case_insensitive: bool) -> re.Pattern[str]:
    body = []
    for char in pattern:
        if char == "*":
            body.append(".*")
        elif char == "?":
            body.append(".")
        else:
            body.append(re.escape(char))
    flags = re.DOTALL | (re.IGNORECASE if case_insensitive else 0)
    return re.compile("".join(body), flags)


def glob_match(pattern: str, value: str, *, case_insensitive: bool = False) -> bool:
    return (
        _glob_regex(pattern, case_insensitive=case_insensitive).fullmatch(value)
        is not None
    )


def arn_like(pattern: str, value: str) -> bool:
    """ArnLike / ArnEquals. Components are compared independently and case-sensitively."""
    left, right = split_arn(pattern), split_arn(value)
    if left is None or right is None:
        return False
    return all(glob_match(part, actual) for part, actual in zip(left, right))


def _as_list(value: object) -> list:
    if isinstance(value, list):
        return value
    return [value]


def resource_matches(pattern: str, resource: str) -> bool:
    if pattern == "*":
        return True
    if pattern.startswith("arn:"):
        return arn_like(pattern, resource)
    return glob_match(pattern, resource)


def action_matches(patterns: object, action: str) -> bool:
    # SCP and IAM action names are case-insensitive; ``*`` and ``?`` apply to the whole string.
    return any(
        glob_match(str(pattern), action, case_insensitive=True)
        for pattern in _as_list(patterns)
    )


_NEGATED = {
    "ArnNotLike",
    "ArnNotEquals",
    "StringNotLike",
    "StringNotEquals",
    "StringNotEqualsIgnoreCase",
}
_ARN_OPS = {"ArnLike", "ArnEquals", "ArnNotLike", "ArnNotEquals"}
_STRING_OPS = {
    "StringEquals",
    "StringNotEquals",
    "StringLike",
    "StringNotLike",
    "StringEqualsIgnoreCase",
    "StringNotEqualsIgnoreCase",
}


def _value_matches(operator: str, pattern: str, actual: str) -> bool:
    base = operator.split(":", 1)[-1]
    if base in _ARN_OPS:
        return arn_like(pattern, actual)
    if base in {"StringLike", "StringNotLike"}:
        return glob_match(pattern, actual)
    if base in {"StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase"}:
        return pattern.casefold() == actual.casefold()
    if base in {"StringEquals", "StringNotEquals"}:
        return pattern == actual
    raise AssertionError(f"unsupported condition operator {operator}")


def condition_matches(condition: dict, context: dict[str, str]) -> bool:
    """Every operator and every key must match. Missing keys follow the IAM rule."""
    if not condition:
        return True
    for operator, keys in condition.items():
        if operator.startswith(("ForAllValues:", "ForAnyValue:")):
            raise AssertionError(f"set operator {operator} is not used by this SCP")
        negated = operator in _NEGATED or operator.split(":", 1)[-1] in _NEGATED
        for key, patterns in keys.items():
            if key not in context:
                if not negated:
                    return False
                continue
            actual = context[key]
            matched = any(
                _value_matches(operator, str(pattern), actual)
                for pattern in _as_list(patterns)
            )
            # Positive operators are OR. Negated operators are NOR.
            if negated:
                if matched:
                    return False
            elif not matched:
                return False
    return True


def _statement_covers_action(statement: dict, action: str) -> bool:
    if "NotAction" in statement:
        return not action_matches(statement["NotAction"], action)
    return action_matches(statement["Action"], action)


def _statement_covers_resource(statement: dict, resource: str) -> bool:
    if "NotResource" in statement:
        return not any(
            resource_matches(str(pattern), resource)
            for pattern in _as_list(statement["NotResource"])
        )
    return any(
        resource_matches(str(pattern), resource)
        for pattern in _as_list(statement["Resource"])
    )


def _statements(policy: dict) -> list[dict]:
    return _as_list(policy["Statement"])


def _effect_matches(
    policies: list[dict], effect: str, request: TokenRequest, resource: str
) -> bool:
    for policy in policies:
        for statement in _statements(policy):
            if statement.get("Effect") != effect:
                continue
            if not _statement_covers_action(statement, ACTION):
                continue
            if not _statement_covers_resource(statement, resource):
                continue
            condition = statement.get("Condition")
            if condition is not None and not condition_matches(
                condition, request.context
            ):
                continue
            return True
    return False


def iam_call_permitted(
    scps: list[dict], identity_policy: dict, request: TokenRequest
) -> bool:
    """True when every required resource is SCP-allowed, identity-allowed, and not denied.

    ``scps`` must include the organization's default Allow * policy plus every SCP the
    module attaches by default. An explicit Deny in either layer blocks the call.
    """
    layers = [*scps, identity_policy]
    for resource in request.resources:
        if _effect_matches(layers, "Deny", request, resource):
            return False
        if not _effect_matches(scps, "Allow", request, resource):
            return False
        if not _effect_matches([identity_policy], "Allow", request, resource):
            return False
    return True


def workload_token_issued(
    scps: list[dict], identity_policy: dict, request: TokenRequest
) -> bool:
    """Whether GetWorkloadAccessTokenForUserId returns a token for ``request.user_id``.

    The data-plane API returns ``workloadAccessToken`` when the IAM call is permitted and
    the workload identity is not linked to Runtime or Gateway. The token is scoped to the
    caller-supplied userId; the service does not verify that string.
    """
    if request.workload_linked_to_service:
        return False
    return iam_call_permitted(scps, identity_policy, request)


# ── Which role ARNs a member administrator can create to satisfy a pattern ──


def legal_role_arns_matching(pattern: str, account: str) -> list[str]:
    """Default-path role ARNs in ``account`` that ArnLike-match ``pattern``.

    Only names CreateRole accepts are returned. The administrator chooses the default
    path ``/``, whose PrincipalArn form is ``arn:aws:iam::ACCOUNT:role/NAME``.
    """
    parts = split_arn(pattern)
    if parts is None:
        return []
    expected = ["arn", "aws", "iam", "", account]
    if not all(glob_match(parts[index], value) for index, value in enumerate(expected)):
        return []
    found = []
    for resource in _expand_globs(parts[5]):
        if not resource.startswith("role/") or "/" in resource[5:]:
            continue
        name = resource[5:]
        if _ROLE_NAME.fullmatch(name) is None:
            continue
        arn = f"arn:aws:iam::{account}:{resource}"
        if arn_like(pattern, arn):
            found.append(arn)
    return found


def _expand_globs(pattern: str) -> list[str]:
    pattern = pattern.replace("?", "a")
    pieces = pattern.split("*")
    # The account id is a filler so a string wildcard in the account position becomes
    # a real member-account ARN, not only an ArnLike component match.
    fillers = ("Admin", "a", MEMBER_ACCOUNT) if len(pieces) <= 5 else (MEMBER_ACCOUNT,)
    expanded = [pieces[0]]
    for piece in pieces[1:]:
        expanded = [
            prefix + filler + piece for prefix in expanded for filler in fillers
        ]
    return expanded


def _principal_patterns(policies: list[dict]) -> list[tuple[str, str]]:
    """(operator, pattern) pairs on aws:PrincipalArn in Deny statements for the action.

    ArnNotLike is the operator this module ships. StringNotLike exempts the same way
    if a fix only renames the operator, so those patterns are candidates too.
    """
    found = []
    for policy in policies:
        for statement in _statements(policy):
            if statement.get("Effect") != "Deny":
                continue
            if not _statement_covers_action(statement, ACTION):
                continue
            condition = statement.get("Condition") or {}
            for operator, keys in condition.items():
                base = operator.split(":", 1)[-1]
                if base not in _ARN_OPS and base not in _STRING_OPS:
                    continue
                principal = keys.get("aws:PrincipalArn")
                if principal is None:
                    continue
                for pattern in _as_list(principal):
                    found.append((operator, str(pattern)))
    return found


def _pattern_matches(operator: str, pattern: str, arn: str) -> bool:
    base = operator.split(":", 1)[-1]
    if base in _ARN_OPS:
        return arn_like(pattern, arn)
    if "IgnoreCase" in base and "Like" not in base:
        return pattern.casefold() == arn.casefold()
    if "Like" in base:
        return glob_match(pattern, arn, case_insensitive="IgnoreCase" in base)
    if "IgnoreCase" in base:
        return pattern.casefold() == arn.casefold()
    return pattern == arn


def creatable_exempt_roles(
    policies: list[dict], account: str = MEMBER_ACCOUNT
) -> list[str]:
    """Role ARNs in ``account`` that satisfy a Deny principal pattern the admin can create.

    Satisfying an ArnNotLike / StringNotLike pattern makes that Deny statement miss.
    The caller still checks the full decision, so a second unconditional Deny keeps
    the role denied.
    """
    roles: list[str] = []
    for operator, pattern in _principal_patterns(policies):
        candidates = list(legal_role_arns_matching(pattern, account))
        for expanded in _expand_globs(pattern):
            role = _role_arn_if_legal(expanded, account)
            if role is not None:
                candidates.append(role)
        for arn in candidates:
            if _pattern_matches(operator, pattern, arn) and arn not in roles:
                roles.append(arn)
    return roles


def _role_arn_if_legal(arn: str, account: str) -> str | None:
    prefix = f"arn:aws:iam::{account}:role/"
    if not arn.startswith(prefix) or "/" in arn[len(prefix) :]:
        return None
    if _ROLE_NAME.fullmatch(arn[len(prefix) :]) is None:
        return None
    return arn


# ── Render the module the way identity.tf does ──


def _scan_string(text: str, start: int) -> tuple[str, int]:
    if text[start] != '"':
        raise ValueError("expected a quoted string")
    index = start + 1
    chars: list[str] = []
    while index < len(text):
        char = text[index]
        if char == "\\":
            escaped = text[index + 1]
            chars.append(
                {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}.get(
                    escaped, escaped
                )
            )
            index += 2
            continue
        if char == '"':
            return "".join(chars), index + 1
        if char == "$" and text[index : index + 2] == "${":
            raise ValueError(
                "interpolation in a default string is not a literal exemption"
            )
        chars.append(char)
        index += 1
    raise ValueError("unterminated HCL string")


def _matching_brace(text: str, open_at: int) -> int:
    depth = 0
    index = open_at
    while index < len(text):
        char = text[index]
        if char == '"':
            _, index = _scan_string(text, index)
            continue
        if char == "#":
            index = text.find("\n", index)
            if index < 0:
                return len(text)
            continue
        if char == "/" and text[index : index + 2] == "//":
            index = text.find("\n", index)
            if index < 0:
                return len(text)
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    raise ValueError("unterminated HCL block")


def variable_defaults(text: str) -> dict[str, object]:
    defaults: dict[str, object] = {}
    for match in re.finditer(r'variable\s+"([^"]+)"\s*\{', text):
        open_at = match.end() - 1
        close_at = _matching_brace(text, open_at)
        body = text[open_at + 1 : close_at]
        parsed = _top_level_default(body)
        if parsed is not None:
            defaults[match.group(1)] = parsed
    return defaults


def _top_level_default(body: str) -> object | None:
    depth = 0
    index = 0
    while index < len(body):
        char = body[index]
        if char == '"':
            _, index = _scan_string(body, index)
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        elif (
            depth == 0
            and body.startswith("default", index)
            and (
                index == 0 or not (body[index - 1].isalnum() or body[index - 1] == "_")
            )
        ):
            after = index + len("default")
            if after < len(body) and (body[after].isalnum() or body[after] == "_"):
                index += 1
                continue
            rest = body[after:].lstrip()
            if rest.startswith("="):
                return _parse_literal(rest[1:].lstrip())
        index += 1
    return None


def _parse_literal(text: str) -> object:
    if text.startswith("true") and (
        len(text) == 4 or not (text[4].isalnum() or text[4] == "_")
    ):
        return True
    if text.startswith("false") and (
        len(text) == 5 or not (text[5].isalnum() or text[5] == "_")
    ):
        return False
    if text.startswith('"'):
        value, _ = _scan_string(text, 0)
        return value
    raise ValueError(f"unsupported HCL literal: {text[:40]!r}")


def terraform_replace(string: str, substring: str, replacement: str) -> str:
    """hashicorp/terraform v1.10.5 ReplaceFunc for a non-regex substring."""
    if len(substring) > 1 and substring[0] == "/" and substring[-1] == "/":
        raise AssertionError("regex replace is not what identity.tf uses")
    return string.replace(substring, replacement)


def render_module_identity_scp(module: Path = MODULE) -> dict | None:
    """Return the identity SCP document the module attaches when variables are left default.

    None when the enable flag's default does not create the policy. The file path and the
    ``replace`` arguments are read from identity.tf; the substituted value is that file's
    variable default.
    """
    variables = (module / "variables.tf").read_text()
    identity = (module / "identity.tf").read_text()
    defaults = variable_defaults(variables)
    if defaults.get("enable_scp_identity_deny_token_for_userid") is not True:
        return None
    if "content     = local.identity_userid_scp_rendered" not in identity:
        raise AssertionError("identity SCP content is not the rendered local")
    file_call = re.search(
        r"identity_userid_scp_source\s*=\s*file\(\s*"
        r'"\$\{path\.module\}/\$\{var\.control_library_path\}/([^"]+)"\s*\)',
        identity,
    )
    if file_call is None:
        raise AssertionError(
            "identity.tf no longer loads the SCP via control_library_path"
        )
    library = defaults.get("control_library_path")
    if not isinstance(library, str):
        raise TypeError("control_library_path default is not a string")
    source_path = (module / library / file_call.group(1)).resolve()
    source = source_path.read_text()
    replace_call = re.search(
        r"identity_userid_scp_rendered\s*=\s*replace\(\s*"
        r"local\.identity_userid_scp_source\s*,\s*"
        r'"([^"]+)"\s*,\s*'
        r"var\.([A-Za-z0-9_]+)\s*\)",
        identity,
    )
    if replace_call:
        sentinel, var_name = replace_call.group(1), replace_call.group(2)
        replacement = defaults[var_name]
        if not isinstance(replacement, str):
            raise TypeError(f"{var_name} default is not a string")
        source = terraform_replace(source, sentinel, replacement)
    return json.loads(source)


def default_attached_scps(module: Path = MODULE) -> list[dict]:
    identity = render_module_identity_scp(module)
    attached = [FULL_AWS_ACCESS]
    if identity is not None:
        attached.append(identity)
    return attached


def _permitted(scps: list[dict], principal_arn: str, user_id: str) -> bool:
    return workload_token_issued(
        scps,
        ATTACKER_ROLE_POLICY,
        request_for(principal_arn, user_id, linked=False),
    )


# ── Matcher pinned to the published examples ──


def test_arn_like_is_per_component_and_principal_arn_is_the_role_arn():
    # Six components: arn, aws, iam, empty region, account, role/name.
    # The account wildcard matches a concrete account and does not cross the colon.
    assert arn_like(
        "arn:aws:iam::*:role/role-to-deny",
        "arn:aws:iam::210987654321:role/role-to-deny",
    )
    assert not arn_like(
        "arn:aws:iam::*:role/role-to-deny",
        "arn:aws:iam::210987654321:role/other",
    )
    # Assumed-role session ARN is a different principal shape. aws:PrincipalArn does not use it.
    assert not arn_like(
        "arn:aws:iam::*:role/role-to-deny",
        "arn:aws:sts::210987654321:assumed-role/role-to-deny/session",
    )


def test_arn_not_like_multiple_patterns_are_nor():
    # Documented example: ArnNotLike of Ana and Mary matches Nikki and does not match Mary.
    condition = {
        "ArnNotLike": {
            "aws:PrincipalArn": [
                "arn:aws:iam::222222222222:user/Ana",
                "arn:aws:iam::222222222222:user/Mary",
            ]
        }
    }
    nikki = {"aws:PrincipalArn": "arn:aws:iam::222222222222:user/Nikki"}
    mary = {"aws:PrincipalArn": "arn:aws:iam::222222222222:user/Mary"}
    assert condition_matches(condition, nikki)
    assert not condition_matches(condition, mary)


def test_concretizer_accepts_only_creatable_default_path_roles():
    pattern = "arn:aws:iam::*:role/__no_principal_may_mint_tokens_by_userid__"
    assert legal_role_arns_matching(pattern, MEMBER_ACCOUNT) == [
        f"arn:aws:iam::{MEMBER_ACCOUNT}:role/__no_principal_may_mint_tokens_by_userid__"
    ]
    assert _ROLE_NAME.fullmatch("__no_principal_may_mint_tokens_by_userid__")
    assert len("__no_principal_may_mint_tokens_by_userid__") <= 64
    # A wildcard resource still yields a legal name the administrator can create.
    assert f"arn:aws:iam::{MEMBER_ACCOUNT}:role/Admin" in legal_role_arns_matching(
        "arn:aws:iam::*:role/*", MEMBER_ACCOUNT
    )
    # A specific other account is not a role this member administrator can create.
    assert (
        legal_role_arns_matching(
            "arn:aws:iam::111122223333:role/break-glass", MEMBER_ACCOUNT
        )
        == []
    )
    # Characters CreateRole rejects are not a bypass the administrator can mint.
    assert (
        legal_role_arns_matching("arn:aws:iam::*:role/not a role", MEMBER_ACCOUNT) == []
    )


def test_service_linked_workload_does_not_receive_a_caller_minted_token():
    # Runtime- and Gateway-linked identities are refused by the service even when IAM
    # allows the call. Closing the SCP exemption must keep that refusal.
    scps = default_attached_scps()
    principals = creatable_exempt_roles(scps) or [
        f"arn:aws:iam::{MEMBER_ACCOUNT}:role/OrganizationAccountAccessRole"
    ]
    linked = request_for(principals[0], "victim-user", linked=True)
    assert not workload_token_issued(scps, ATTACKER_ROLE_POLICY, linked)


# ── The security property. These fail while the default exemption is creatable. ──


def test_default_module_denies_token_for_role_matching_its_exemption():
    scps = default_attached_scps()
    for role_arn in creatable_exempt_roles(scps):
        assert not _permitted(scps, role_arn, "victim-user"), (
            f"{role_arn} is a role a member administrator can create and assume. "
            "The default SCP does not deny GetWorkloadAccessTokenForUserId for it, "
            "so the API returns a workload access token for the caller-supplied userId."
        )


def test_default_module_denies_token_for_ordinary_member_principals():
    scps = default_attached_scps()
    ordinary = [
        f"arn:aws:iam::{MEMBER_ACCOUNT}:role/OrganizationAccountAccessRole",
        f"arn:aws:iam::{MEMBER_ACCOUNT}:user/admin",
        f"arn:aws:iam::{MEMBER_ACCOUNT}:root",
    ]
    for principal in ordinary:
        assert not _permitted(scps, principal, "victim-user"), principal


def test_catalog_default_denies_token_for_role_matching_its_exemption():
    # policy_loader applies the catalog.yaml default. Terraform keeps a second copy.
    document = load_control("scp.identity.deny-workload-token-for-userid")
    scps = [FULL_AWS_ACCESS, document]
    for role_arn in creatable_exempt_roles(scps):
        assert not _permitted(scps, role_arn, "victim-user"), role_arn


def test_user_id_does_not_choose_whose_vault_entry_the_token_opens():
    scps = default_attached_scps()
    principals = [
        *creatable_exempt_roles(scps),
        f"arn:aws:iam::{MEMBER_ACCOUNT}:role/OrganizationAccountAccessRole",
    ]
    for principal in principals:
        for user_id in ("victim-user", "other-user"):
            assert not _permitted(scps, principal, user_id), (principal, user_id)
