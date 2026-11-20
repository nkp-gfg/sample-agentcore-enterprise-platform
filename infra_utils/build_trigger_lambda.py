"""Build trigger Lambda handler — starts CodeBuild and waits for completion."""

import json
import time
import urllib.request

import boto3

codebuild = boto3.client("codebuild")


def handler(event, context):
    response_url = event["ResponseURL"]
    try:
        if event["RequestType"] == "Delete":
            return _send(response_url, event, "SUCCESS", {})

        project_name = event["ResourceProperties"]["ProjectName"]
        env_overrides = event["ResourceProperties"].get("EnvironmentOverrides", [])

        build = codebuild.start_build(
            projectName=project_name,
            environmentVariablesOverride=env_overrides,
        )
        build_id = build["build"]["id"]

        # Poll until complete (max ~14 min)
        for _ in range(28):
            time.sleep(30)
            resp = codebuild.batch_get_builds(ids=[build_id])
            status = resp["builds"][0]["buildStatus"]
            if status == "SUCCEEDED":
                return _send(response_url, event, "SUCCESS", {"BuildId": build_id})
            if status in ("FAILED", "FAULT", "STOPPED", "TIMED_OUT"):
                return _send(response_url, event, "FAILED", {}, f"Build {status}")

        return _send(response_url, event, "FAILED", {}, "Build timed out")
    except Exception as e:  # noqa: BLE001 — CloudFormation must still receive a response
        return _send(response_url, event, "FAILED", {}, str(e))


def on_event(event, context):
    """Start the image build and return. The provider polls is_complete.

    A Lambda invocation cannot outlast 15 minutes. The frontend image build
    is allowed 30, so this handler must not wait for CodeBuild.
    """
    request_type = event["RequestType"]
    physical_id = event.get("PhysicalResourceId") or "bff-image-build"
    if request_type == "Delete":
        return {"PhysicalResourceId": physical_id}
    props = event["ResourceProperties"]
    build = codebuild.start_build(
        projectName=props["ProjectName"],
        environmentVariablesOverride=props.get("EnvironmentOverrides", []),
    )
    build_id = build["build"]["id"]
    return {"PhysicalResourceId": physical_id, "Data": {"BuildId": build_id}}


def is_complete(event, context):
    """Return whether the CodeBuild project started by on_event has finished."""
    if event.get("RequestType") == "Delete":
        return {"IsComplete": True}
    build_id = (event.get("Data") or {}).get("BuildId")
    if not build_id:
        raise RuntimeError("Image build did not return a BuildId.")
    resp = codebuild.batch_get_builds(ids=[build_id])
    builds = resp.get("builds") or []
    if not builds:
        raise RuntimeError(f"CodeBuild build {build_id} was not found.")
    status = builds[0]["buildStatus"]
    if status == "SUCCEEDED":
        return {"IsComplete": True, "Data": {"BuildId": build_id}}
    if status in ("FAILED", "FAULT", "STOPPED", "TIMED_OUT"):
        raise RuntimeError(f"Build {status}: {build_id}")
    return {"IsComplete": False}


def _send(url, event, status, data, reason=""):
    body = json.dumps(
        {
            "Status": status,
            "Reason": reason or "See CloudWatch",
            "PhysicalResourceId": event.get(
                "PhysicalResourceId", event["LogicalResourceId"]
            ),
            "StackId": event["StackId"],
            "RequestId": event["RequestId"],
            "LogicalResourceId": event["LogicalResourceId"],
            "Data": data,
        }
    ).encode()
    if not url.startswith("https://"):
        raise ValueError(f"Response URL must use HTTPS scheme, got: {url[:20]}")
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": ""}, method="PUT"
    )
    urllib.request.urlopen(req)  # nosec B310 — URL validated above, CloudFormation pre-signed S3 URL
