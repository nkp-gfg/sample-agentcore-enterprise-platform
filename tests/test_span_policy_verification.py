"""Span-delivery verification must require a real PutLogEvents allow.

check_span_resource_policy is the gate scripts/verify.py and module 9 of
scripts/deploy.sh run for the observability footprint. It reads account
CloudWatch Logs resource policies (DescribeResourcePolicies) and decides
whether X-Ray can deliver spans.

These tests are the spec for that decision. They fail while the gate treats
any statement whose principal is xray.amazonaws.com and whose resource text
merely contains the span log group names as success. They pass once the gate:

* requires an Allow of logs:PutLogEvents on the exact span log group ARNs
  xray_logs_resource_policy publishes for this caller account and region,
  including that statement's aws:SourceAccount and aws:SourceArn conditions
* rejects the result when any statement, on any page, denies logs:PutLogEvents
  for xray.amazonaws.com, even if a valid allow is also present

The Logs client here returns the wire shape from botocore's logs service
model (policyDocument is a JSON string; pages carry nextToken). It does not
reimplement IAM evaluation.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO))

import check_observability

from infra_utils.transaction_search import (
    SPAN_LOG_GROUPS,
    xray_logs_resource_policy,
)

ACCOUNT = "123456789012"
OTHER_ACCOUNT = "999999999999"
REGION = "us-east-1"


class FakePaginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self):
        return iter(self.pages)


class LogsApi:
    """DescribeResourcePolicies pages, in the shape botocore returns.

    policyDocument is a string. A non-empty nextToken means another page
    exists; the paginator config names that token nextToken and the result
    key resourcePolicies.
    """

    def __init__(self, policy_pages: list[list[dict]]):
        self.policy_pages = policy_pages

    def describe_resource_policies(self, nextToken=None, **kwargs):
        index = 0 if nextToken is None else int(nextToken)
        page = {
            "resourcePolicies": [
                {
                    "policyName": item["policyName"],
                    "policyDocument": json.dumps(item["document"]),
                    "policyScope": "ACCOUNT",
                }
                for item in self.policy_pages[index]
            ]
        }
        if index + 1 < len(self.policy_pages):
            page["nextToken"] = str(index + 1)
        return page

    def get_paginator(self, operation):
        if operation == "describe_resource_policies":
            pages = []
            token = None
            while True:
                page = self.describe_resource_policies(
                    **({} if token is None else {"nextToken": token})
                )
                pages.append(page)
                token = page.get("nextToken")
                if not token:
                    break
            return FakePaginator(pages)
        if operation == "describe_delivery_sources":
            return FakePaginator(
                [
                    {
                        "deliverySources": [
                            {"name": "agentcore-workshop-dev-runtime-app-logs"}
                        ]
                    }
                ]
            )
        if operation == "describe_deliveries":
            return FakePaginator(
                [
                    {
                        "deliveries": [
                            {
                                "deliverySourceName": (
                                    "agentcore-workshop-dev-runtime-app-logs"
                                )
                            }
                        ]
                    }
                ]
            )
        raise AssertionError(operation)


class XRayApi:
    def get_trace_segment_destination(self):
        return {"Destination": "CloudWatchLogs", "Status": "ACTIVE"}


class StsApi:
    def get_caller_identity(self):
        return {
            "Account": ACCOUNT,
            "Arn": f"arn:aws:iam::{ACCOUNT}:user/deploy-verify",
            "UserId": "AIDEXAMPLE",
        }


def install(monkeypatch, policy_pages: list[list[dict]]) -> None:
    logs = LogsApi(policy_pages)

    def client(service, *args, **kwargs):
        if service == "logs":
            return logs
        if service == "sts":
            return StsApi()
        if service == "xray":
            return XRayApi()
        raise AssertionError(service)

    monkeypatch.setattr(check_observability.boto3, "client", client)
    monkeypatch.setattr(check_observability, "REGION", REGION)
    monkeypatch.setattr(check_observability, "PROJECT", "agentcore-workshop")
    monkeypatch.setattr(check_observability, "ENVIRONMENT", "dev")
    monkeypatch.setenv("AWS_REGION", REGION)


def published_policy(account: str = ACCOUNT, region: str = REGION) -> dict:
    """The document the observability stack writes for this account."""
    return xray_logs_resource_policy(account, region)


def retitled(policy: dict, **changes) -> dict:
    statement = dict(policy["Statement"][0])
    statement.update(changes)
    return {"Version": policy["Version"], "Statement": [statement]}


def span_resources(account: str = ACCOUNT) -> list[str]:
    return list(published_policy(account)["Statement"][0]["Resource"])


def named(policy_name: str, document: dict) -> dict:
    return {"policyName": policy_name, "document": document}


def expect_rejected(capsys) -> None:
    """The gate must exit non-zero and must not report traces accepted."""
    try:
        check_observability.check_span_resource_policy()
    except SystemExit as exc:
        captured = capsys.readouterr()
        assert exc.code == 1
        assert "PASS: X-Ray span delivery policy present" not in captured.out
        assert "OK: logs and traces are being accepted" not in captured.out
        return
    captured = capsys.readouterr()
    pytest.fail(
        "span policy check accepted a document that does not let "
        f"xray.amazonaws.com call logs:PutLogEvents:\n{captured.out}"
    )


def expect_accepted(capsys) -> None:
    check_observability.check_span_resource_policy()
    captured = capsys.readouterr()
    assert "PASS: X-Ray span delivery policy present" in captured.out
    assert "FAIL:" not in captured.err


def test_published_allow_is_accepted(monkeypatch, capsys):
    install(
        monkeypatch,
        [[named("transaction-search-xray", published_policy())]],
    )
    expect_accepted(capsys)


def test_put_log_events_in_an_action_list_is_accepted(monkeypatch, capsys):
    """PutResourcePolicy documents often send Action as a list of strings."""
    document = retitled(
        published_policy(),
        Action=["logs:CreateLogStream", "logs:PutLogEvents"],
    )
    install(monkeypatch, [[named("transaction-search-xray", document)]])
    expect_accepted(capsys)


def test_extra_unrelated_statement_does_not_hide_the_allow(monkeypatch, capsys):
    document = published_policy()
    document["Statement"].append(
        {
            "Sid": "OtherService",
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "logs:PutLogEvents",
            "Resource": span_resources(),
        }
    )
    install(monkeypatch, [[named("transaction-search-xray", document)]])
    expect_accepted(capsys)


def test_additional_create_log_stream_allow_keeps_the_put_allow(monkeypatch, capsys):
    """An extra allow of a different action does not remove PutLogEvents."""
    allow = published_policy()
    create_only = retitled(
        published_policy(),
        Sid="CreateStreamOnly",
        Action="logs:CreateLogStream",
    )
    install(
        monkeypatch,
        [
            [
                named("transaction-search-xray", allow),
                named("added-create-stream", create_only),
            ]
        ],
    )
    expect_accepted(capsys)


def test_deny_of_create_log_stream_does_not_block_put_log_events(monkeypatch, capsys):
    allow = published_policy()
    deny_create = retitled(
        published_policy(),
        Sid="DenyCreateStream",
        Effect="Deny",
        Action="logs:CreateLogStream",
    )
    document = {
        "Version": "2012-10-17",
        "Statement": [deny_create["Statement"][0], allow["Statement"][0]],
    }
    install(monkeypatch, [[named("transaction-search-xray", document)]])
    expect_accepted(capsys)


def test_create_log_stream_allow_alone_is_rejected(monkeypatch, capsys):
    document = retitled(published_policy(), Action="logs:CreateLogStream")
    install(monkeypatch, [[named("transaction-search-xray", document)]])
    expect_rejected(capsys)


def test_create_log_stream_action_list_alone_is_rejected(monkeypatch, capsys):
    document = retitled(published_policy(), Action=["logs:CreateLogStream"])
    install(monkeypatch, [[named("transaction-search-xray", document)]])
    expect_rejected(capsys)


def test_missing_action_is_rejected(monkeypatch, capsys):
    statement = dict(published_policy()["Statement"][0])
    statement.pop("Action")
    document = {"Version": "2012-10-17", "Statement": [statement]}
    install(monkeypatch, [[named("transaction-search-xray", document)]])
    expect_rejected(capsys)


def test_deny_of_put_log_events_alone_is_rejected(monkeypatch, capsys):
    document = retitled(published_policy(), Effect="Deny")
    install(monkeypatch, [[named("deny-spans", document)]])
    expect_rejected(capsys)


def test_deny_after_the_allow_in_the_same_document_is_rejected(monkeypatch, capsys):
    allow = published_policy()["Statement"][0]
    deny = retitled(published_policy(), Sid="DenySpans", Effect="Deny")["Statement"][0]
    document = {"Version": "2012-10-17", "Statement": [allow, deny]}
    install(monkeypatch, [[named("transaction-search-xray", document)]])
    expect_rejected(capsys)


def test_deny_before_the_allow_in_the_same_document_is_rejected(monkeypatch, capsys):
    allow = published_policy()["Statement"][0]
    deny = retitled(published_policy(), Sid="DenySpans", Effect="Deny")["Statement"][0]
    document = {"Version": "2012-10-17", "Statement": [deny, allow]}
    install(monkeypatch, [[named("transaction-search-xray", document)]])
    expect_rejected(capsys)


def test_deny_in_a_second_policy_overrides_the_published_allow(monkeypatch, capsys):
    deny = retitled(published_policy(), Sid="DenySpans", Effect="Deny")
    install(
        monkeypatch,
        [
            [
                named("transaction-search-xray", published_policy()),
                named("added-deny", deny),
            ]
        ],
    )
    expect_rejected(capsys)


def test_list_service_principal_deny_overrides_the_published_allow(monkeypatch, capsys):
    """PutResourcePolicy examples send Principal.Service as a list."""
    deny_statement = retitled(published_policy(), Sid="DenySpans", Effect="Deny")[
        "Statement"
    ][0]
    deny_statement["Principal"] = {"Service": ["xray.amazonaws.com"]}
    deny = {"Version": "2012-10-17", "Statement": [deny_statement]}
    install(
        monkeypatch,
        [
            [
                named("transaction-search-xray", published_policy()),
                named("added-deny", deny),
            ]
        ],
    )
    expect_rejected(capsys)


def test_deny_action_list_overrides_the_published_allow(monkeypatch, capsys):
    deny = retitled(
        published_policy(),
        Sid="DenySpans",
        Effect="Deny",
        Action=["logs:PutLogEvents", "logs:CreateLogStream"],
    )
    install(
        monkeypatch,
        [
            [
                named("transaction-search-xray", published_policy()),
                named("added-deny", deny),
            ]
        ],
    )
    expect_rejected(capsys)


def test_substring_resources_are_not_the_span_log_group_arns(monkeypatch, capsys):
    document = retitled(
        published_policy(),
        Resource=[
            (f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:decoy-aws/spans:*"),
            (
                f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:"
                "decoy-/aws/application-signals/data:*"
            ),
        ],
    )
    for group in SPAN_LOG_GROUPS:
        assert any(
            group in resource for resource in document["Statement"][0]["Resource"]
        )
    install(monkeypatch, [[named("looks-close", document)]])
    expect_rejected(capsys)


def test_other_accounts_published_policy_is_rejected(monkeypatch, capsys):
    install(
        monkeypatch,
        [[named("other-account", published_policy(OTHER_ACCOUNT))]],
    )
    expect_rejected(capsys)


def test_allow_without_the_published_source_condition_is_rejected(monkeypatch, capsys):
    statement = dict(published_policy()["Statement"][0])
    statement.pop("Condition")
    document = {"Version": "2012-10-17", "Statement": [statement]}
    install(monkeypatch, [[named("no-condition", document)]])
    expect_rejected(capsys)


def test_allow_with_the_wrong_source_account_is_rejected(monkeypatch, capsys):
    statement = dict(published_policy()["Statement"][0])
    statement["Condition"] = {
        "ArnLike": statement["Condition"]["ArnLike"],
        "StringEquals": {"aws:SourceAccount": OTHER_ACCOUNT},
    }
    document = {"Version": "2012-10-17", "Statement": [statement]}
    install(monkeypatch, [[named("wrong-account", document)]])
    expect_rejected(capsys)


def test_allow_with_the_wrong_source_arn_is_rejected(monkeypatch, capsys):
    statement = dict(published_policy()["Statement"][0])
    statement["Condition"] = {
        "ArnLike": {"aws:SourceArn": f"arn:aws:xray:eu-west-1:{ACCOUNT}:*"},
        "StringEquals": statement["Condition"]["StringEquals"],
    }
    document = {"Version": "2012-10-17", "Statement": [statement]}
    install(monkeypatch, [[named("wrong-source-arn", document)]])
    expect_rejected(capsys)


def test_deny_on_a_later_page_overrides_the_allow(monkeypatch, capsys):
    deny = retitled(published_policy(), Sid="DenySpans", Effect="Deny")
    install(
        monkeypatch,
        [
            [named("transaction-search-xray", published_policy())],
            [named("added-deny", deny)],
        ],
    )
    expect_rejected(capsys)


def test_verify_gate_rejects_create_log_stream_only_policy(monkeypatch, capsys):
    """The operator path: check_observability.main, which verify.py executes."""
    document = retitled(published_policy(), Action="logs:CreateLogStream")
    install(monkeypatch, [[named("transaction-search-xray", document)]])
    try:
        check_observability.main()
    except SystemExit as exc:
        captured = capsys.readouterr()
        assert exc.code == 1
        assert "OK: logs and traces are being accepted" not in captured.out
        return
    captured = capsys.readouterr()
    pytest.fail(
        "deploy verification reported traces accepted for a policy that "
        f"only allows logs:CreateLogStream:\n{captured.out}"
    )


def test_verify_gate_rejects_deny_that_overrides_the_published_allow(
    monkeypatch, capsys
):
    deny = retitled(published_policy(), Sid="DenySpans", Effect="Deny")
    install(
        monkeypatch,
        [
            [
                named("transaction-search-xray", published_policy()),
                named("added-deny", deny),
            ]
        ],
    )
    try:
        check_observability.main()
    except SystemExit as exc:
        captured = capsys.readouterr()
        assert exc.code == 1
        assert "OK: logs and traces are being accepted" not in captured.out
        return
    captured = capsys.readouterr()
    pytest.fail(
        "deploy verification reported traces accepted while a deny of "
        f"logs:PutLogEvents for xray.amazonaws.com is present:\n{captured.out}"
    )
