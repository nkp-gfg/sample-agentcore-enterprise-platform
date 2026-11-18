"""Build trigger Lambda handler — builds the image, then releases it only if its scan is clean.

The runtime starts `REPO_URI:IMAGE_TAG`. The repository's tags are immutable,
so this handler resolves that tag to a digest once, checks the ECR scan of that
digest, and refuses the release if the scan is not complete, reports a
critical finding, or the tag no longer names the digest that was checked.
"""

import json
import time
import urllib.request

import boto3

codebuild = boto3.client("codebuild")

# Lambda's hard limit is 15 minutes; leave room to send the response.
DEADLINE_SECONDS = 14 * 60
BUILD_POLL_SECONDS = 30
SCAN_POLL_SECONDS = 10
SCAN_DONE = {"COMPLETE", "ACTIVE"}
SCAN_PENDING = {"IN_PROGRESS", "PENDING"}
BLOCKING_SEVERITY = "CRITICAL"


class ReleaseBlocked(Exception):
    pass


def handler(event, context):
    response_url = event["ResponseURL"]
    try:
        if event["RequestType"] == "Delete":
            return _send(response_url, event, "SUCCESS", {})

        project_name = event["ResourceProperties"]["ProjectName"]
        env_overrides = event["ResourceProperties"].get("EnvironmentOverrides", [])
        repository, tag = _image_reference(env_overrides)
        deadline = time.monotonic() + DEADLINE_SECONDS
        ecr = boto3.client("ecr")

        data = {}
        # Tags are immutable: an image already under this source-hash tag was
        # built from this source, and pushing it again would be refused (for
        # example when CloudFormation rolls back to the previous hash).
        if _tag_digest(ecr, repository, tag) is None:
            build = codebuild.start_build(
                projectName=project_name,
                environmentVariablesOverride=env_overrides,
            )
            build_id = build["build"]["id"]
            data["BuildId"] = build_id
            status = _wait_for_build(build_id, deadline)
            if status != "SUCCEEDED":
                return _send(response_url, event, "FAILED", {}, f"Build {status}")

        digest = _tag_digest(ecr, repository, tag)
        if digest is None:
            raise ReleaseBlocked(f"{repository}:{tag} is not in ECR after the build")
        _require_clean_scan(ecr, repository, digest, deadline)
        current = _tag_digest(ecr, repository, tag)
        if current != digest:
            raise ReleaseBlocked(
                f"{repository}:{tag} now names digest {current}, not the scanned digest {digest}"
            )

        data["ImageDigest"] = digest
        return _send(response_url, event, "SUCCESS", data)
    # CloudFormation waits up to an hour for a custom resource that never answers.
    except Exception as e:  # noqa: BLE001
        return _send(response_url, event, "FAILED", {}, str(e))


def _image_reference(env_overrides):
    values = {item.get("name"): item.get("value") for item in env_overrides}
    repo_uri = values.get("REPO_URI") or ""
    tag = values.get("IMAGE_TAG") or ""
    if "/" not in repo_uri or not tag:
        raise ReleaseBlocked(
            "REPO_URI and IMAGE_TAG are required to check the image scan"
        )
    return repo_uri.split("/", 1)[1], tag


def _error_code(exc):
    return getattr(exc, "response", {}).get("Error", {}).get("Code", "")


def _tag_digest(ecr, repository, tag):
    try:
        resp = ecr.describe_images(
            repositoryName=repository, imageIds=[{"imageTag": tag}]
        )
    except Exception as e:
        if _error_code(e) == "ImageNotFoundException":
            return None
        raise
    details = resp.get("imageDetails") or []
    if len(details) != 1:
        return None
    return details[0]["imageDigest"]


def _wait_for_build(build_id, deadline):
    for _ in range(DEADLINE_SECONDS // BUILD_POLL_SECONDS):
        time.sleep(BUILD_POLL_SECONDS)
        resp = codebuild.batch_get_builds(ids=[build_id])
        status = resp["builds"][0]["buildStatus"]
        if status in ("SUCCEEDED", "FAILED", "FAULT", "STOPPED", "TIMED_OUT"):
            return status
        if time.monotonic() >= deadline:
            break
    return "timed out"


def _scan_pages(ecr, repository, digest):
    """All findings pages for one digest, or None while ECR has no scan yet."""
    pages = []
    request = {"repositoryName": repository, "imageId": {"imageDigest": digest}}
    while True:
        try:
            page = ecr.describe_image_scan_findings(**request)
        except Exception as e:
            if _error_code(e) == "ScanNotFoundException":
                return None
            raise
        pages.append(page)
        token = page.get("nextToken")
        if not token:
            return pages
        request["nextToken"] = token


def _require_clean_scan(ecr, repository, digest, deadline):
    for _ in range(DEADLINE_SECONDS // SCAN_POLL_SECONDS):
        pages = _scan_pages(ecr, repository, digest)
        if pages is not None:
            scan = pages[0].get("imageScanStatus") or {}
            status = scan.get("status")
            if status in SCAN_DONE:
                break
            if status not in SCAN_PENDING:
                raise ReleaseBlocked(
                    f"image scan of {digest} ended {status}: {scan.get('description', '')}"
                )
        if time.monotonic() >= deadline:
            raise ReleaseBlocked(f"image scan of {digest} did not complete in time")
        time.sleep(SCAN_POLL_SECONDS)
    else:
        raise ReleaseBlocked(f"image scan of {digest} did not complete in time")

    blocked = False
    for page in pages:
        scanned = (page.get("imageId") or {}).get("imageDigest")
        if scanned != digest:
            raise ReleaseBlocked(
                f"scan findings are for digest {scanned}, not {digest}"
            )
        if (page.get("imageScanStatus") or {}).get("status") not in SCAN_DONE:
            raise ReleaseBlocked(
                f"image scan of {digest} changed state while reading findings"
            )
        findings = page.get("imageScanFindings") or {}
        listed = (findings.get("findings") or []) + (
            findings.get("enhancedFindings") or []
        )
        if (findings.get("findingSeverityCounts") or {}).get(BLOCKING_SEVERITY) or any(
            finding.get("severity") == BLOCKING_SEVERITY for finding in listed
        ):
            blocked = True
    if blocked:
        raise ReleaseBlocked(
            f"image scan of {digest} reports {BLOCKING_SEVERITY} findings; runtime not updated"
        )


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
