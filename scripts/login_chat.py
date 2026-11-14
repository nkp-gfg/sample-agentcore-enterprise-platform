#!/usr/bin/env python3
"""Sign in as a real user (through Cognito and your IdP) and chat with the agent.

invoke.py tests with a machine (M2M) token. This script tests what a person
gets: it opens the Cognito sign-in page, catches the redirect on the app
client's localhost callback, exchanges the code (with PKCE) for the user's
tokens, and sends prompts to the orchestrator runtime as that user.

Tokens and the app client secret stay in memory and are never printed.

Usage:
    .venv/bin/python scripts/login_chat.py              # sign in, then chat
    .venv/bin/python scripts/login_chat.py --url-only   # only print the sign-in link
    .venv/bin/python scripts/login_chat.py --prompt "Hello"   # one prompt, then exit

Reads project, environment, and region from platform.yaml unless PROJECT_NAME,
ENVIRONMENT, or AWS_REGION are set.
"""

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
import threading
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import boto3

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from infra_utils.platform_config import load_platform_config, resolve_region

REGION = resolve_region()
LOGIN_TIMEOUT_SECONDS = 300
MAX_RESPONSE_BYTES = 1024 * 1024


def _project_and_env() -> tuple[str, str]:
    project = os.environ.get("PROJECT_NAME")
    env = os.environ.get("ENVIRONMENT")
    manifest = Path(os.environ.get("PLATFORM_CONFIG") or REPO / "platform.yaml")
    if (not project or not env) and manifest.exists():
        config = load_platform_config(manifest)
        project = project or config.project
        env = env or config.environment
    if not project or not env:
        sys.exit(
            "Set PROJECT_NAME and ENVIRONMENT, or run from a repo with platform.yaml"
        )
    return project, env


def _ssm(prefix: str, name: str) -> str:
    ssm = boto3.client("ssm", region_name=REGION)
    return ssm.get_parameter(Name=f"{prefix}/{name}")["Parameter"]["Value"]


def _login_settings(prefix: str) -> dict:
    pool_id = _ssm(prefix, "auth/user-pool-id")
    client_id = _ssm(prefix, "auth/app-client-id")
    cognito = boto3.client("cognito-idp", region_name=REGION)
    pool = cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    if pool.get("CustomDomain"):
        domain = f"https://{pool['CustomDomain']}"
    elif pool.get("Domain"):
        domain = f"https://{pool['Domain']}.auth.{REGION}.amazoncognito.com"
    else:
        sys.exit("The user pool has no sign-in domain")
    client = cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)[
        "UserPoolClient"
    ]
    callback = next(
        (u for u in client.get("CallbackURLs", []) if u.startswith("http://localhost")),
        None,
    )
    if not callback:
        sys.exit("The app client has no http://localhost callback URL to listen on")
    providers = [
        p for p in client.get("SupportedIdentityProviders", []) if p != "COGNITO"
    ]
    return {
        "domain": domain,
        "client_id": client_id,
        "client_secret": client.get("ClientSecret"),
        "callback": callback,
        # Skip the Cognito chooser when exactly one external IdP is offered.
        "identity_provider": providers[0] if len(providers) == 1 else None,
    }


def _authorize_url(settings: dict, state: str, challenge: str) -> str:
    query = {
        "response_type": "code",
        "client_id": settings["client_id"],
        "redirect_uri": settings["callback"],
        "scope": "openid email profile",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if settings["identity_provider"]:
        query["identity_provider"] = settings["identity_provider"]
    return f"{settings['domain']}/oauth2/authorize?{urllib.parse.urlencode(query)}"


def _wait_for_code(callback: str, state: str) -> str:
    parsed = urllib.parse.urlsplit(callback)
    result: dict = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            url = urllib.parse.urlsplit(self.path)
            params = urllib.parse.parse_qs(url.query)
            if url.path != parsed.path:
                self.send_response(404)
                self.end_headers()
                return
            if params.get("state", [""])[0] != state:
                result["error"] = "state mismatch (possible forged redirect)"
            elif "error" in params:
                result["error"] = params.get("error_description", params["error"])[0]
            else:
                result["code"] = params.get("code", [""])[0]
            ok = "code" in result
            self.send_response(200 if ok else 400)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                b"Signed in. You can close this tab and go back to the terminal."
                if ok
                else b"Sign-in failed. See the terminal."
            )
            threading.Thread(target=self.server.shutdown, daemon=True).start()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", parsed.port or 80), Handler)
    timer = threading.Timer(LOGIN_TIMEOUT_SECONDS, server.shutdown)
    timer.start()
    try:
        server.serve_forever()
    finally:
        timer.cancel()
        server.server_close()
    if "code" not in result:
        sys.exit(f"Sign-in did not complete: {result.get('error', 'timed out')}")
    return result["code"]


def _exchange_code(settings: dict, code: str, verifier: str) -> dict:
    body = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "client_id": settings["client_id"],
            "code": code,
            "redirect_uri": settings["callback"],
            "code_verifier": verifier,
        }
    ).encode()
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if settings["client_secret"]:
        basic = f"{settings['client_id']}:{settings['client_secret']}".encode()
        headers["Authorization"] = f"Basic {base64.b64encode(basic).decode()}"
    request = urllib.request.Request(
        f"{settings['domain']}/oauth2/token", data=body, headers=headers
    )
    with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310 — https
        return json.loads(response.read())


def _claims(jwt: str) -> dict:
    payload = jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def _reply_text(body: str) -> str:
    """Join streamed text chunks (both HTTP Strands and AG-UI SSE); surface interrupts/errors."""
    text, errors, interrupts = [], [], []
    for line in body.splitlines():
        if not line.startswith("data:"):
            continue
        try:
            event = json.loads(line[len("data:") :].strip())
        except json.JSONDecodeError:
            continue
        if isinstance(event, str):
            text.append(event)
        elif isinstance(event, dict):
            if isinstance(event.get("data"), str):
                text.append(event["data"])
            elif event.get("type") == "TEXT_MESSAGE_CONTENT" and isinstance(
                event.get("delta"), str
            ):
                text.append(event["delta"])
            if event.get("status") == "error":
                errors.append(str(event.get("error")))
            elif event.get("type") == "RUN_ERROR":
                errors.append(str(event.get("message") or event.get("code") or "error"))
            elif event.get("type") == "RUN_FINISHED":
                outcome = event.get("outcome") or {}
                if isinstance(outcome, dict) and outcome.get("type") == "interrupt":
                    for item in outcome.get("interrupts") or []:
                        raw = (
                            ((item.get("metadata") or {}).get("langgraph") or {}).get(
                                "raw"
                            )
                            if isinstance(item, dict)
                            else None
                        )
                        interrupts.append(json.dumps(raw or item))
    if errors:
        return "ERROR: " + "; ".join(errors)
    joined = "".join(text)
    if interrupts:
        pause_note = "\n[PAUSED FOR REVIEW] " + "; ".join(interrupts)
        return (joined + pause_note).strip()
    return joined or body


def _ask(
    runtime_arn: str,
    token: str,
    session_id: str,
    prompt: str,
    *,
    resume: dict | None = None,
) -> str:
    url = (
        f"https://bedrock-agentcore.{REGION}.amazonaws.com/runtimes/"
        f"{urllib.parse.quote(runtime_arn, safe='')}/invocations?qualifier=DEFAULT"
    )
    payload: dict = {"prompt": prompt, "runtimeSessionId": session_id}
    if resume is not None:
        payload["resume"] = [resume]
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "text/event-stream, application/json",
            "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": session_id,
        },
    )
    with urllib.request.urlopen(request, timeout=180) as response:  # nosec B310 — https
        return _reply_text(response.read(MAX_RESPONSE_BYTES).decode())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--url-only", action="store_true", help="Print the sign-in link and exit"
    )
    parser.add_argument("--prompt", help="Send one prompt after sign-in, then exit")
    parser.add_argument(
        "--session", help="Reuse an existing runtimeSessionId (>=33 chars)"
    )
    parser.add_argument(
        "--resume",
        choices=("approve", "reject"),
        help="Resume an open confirmation/review pause on --session",
    )
    parser.add_argument(
        "--request-id",
        help="Pending leave request_id when resuming a manager review from the CLI",
    )
    parser.add_argument(
        "--no-browser", action="store_true", help="Do not open a browser"
    )
    args = parser.parse_args()

    project, env = _project_and_env()
    prefix = f"/{project}/{env}"
    settings = _login_settings(prefix)

    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    state = secrets.token_urlsafe(24)
    url = _authorize_url(settings, state, challenge)

    if args.url_only:
        print(url)
        return

    print(f"Region: {REGION}   Project: {project}/{env}")
    print(f"Sign-in link (opening in your browser):\n\n  {url}\n")
    print(
        f"Waiting up to {LOGIN_TIMEOUT_SECONDS // 60} minutes for {settings['callback']} ..."
    )
    if not args.no_browser:
        webbrowser.open(url)
    code = _wait_for_code(settings["callback"], state)
    tokens = _exchange_code(settings, code, verifier)
    access_token = tokens["access_token"]
    claims = _claims(tokens.get("id_token") or access_token)
    print(f"Signed in as: {claims.get('email') or claims.get('cognito:username')}")

    runtime_arn = _ssm(prefix, "runtimes/orchestrator/arn")
    session_id = args.session or f"session-{secrets.token_hex(16)}"
    print(f"Session ID:   {session_id}\n")

    if args.resume:
        resume_payload: dict = {"decision": args.resume}
        if args.request_id:
            resume_payload["kind"] = "manager_review"
            resume_payload["request_id"] = args.request_id
        else:
            resume_payload["kind"] = "employee_confirm"
        print(_ask(runtime_arn, access_token, session_id, "", resume=resume_payload))
        return

    if args.prompt:
        print(_ask(runtime_arn, access_token, session_id, args.prompt))
        return
    print("Chat with the agent. Press Enter on an empty line to quit.")
    while True:
        try:
            prompt = input("\nyou> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not prompt:
            break
        print(f"agent> {_ask(runtime_arn, access_token, session_id, prompt)}")


if __name__ == "__main__":
    main()
