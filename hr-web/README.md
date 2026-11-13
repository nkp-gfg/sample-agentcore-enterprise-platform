# hr-web — the local HR assistant UI

Layer 3 of the HR plan ([`custom-app-plan/phases.md`](../custom-app-plan/phases.md)).
A static frontend plus a loopback-only Python server that lets a facilitator talk
to the already-deployed god agent in a browser. The conversation uses the AG-UI
SSE protocol that the module 6 runtime already exposes, with a short-lived
Cognito access token the browser obtained itself.

This is not a hosted application. It never becomes a stack. If somebody asks to
host it, the answer is in `custom-app-plan/phases.md` § "Not in these modules".

## Who runs this

The facilitator, on their own laptop, against an already-deployed platform
footprint. The server binds to `127.0.0.1:8899`. It has no sign-in and no
multi-user auth of its own: the browser does the Cognito-hosted UI redirect
with PKCE and keeps the access token in memory.

## What is here

| File | Role |
|---|---|
| `server.py` | `http.server` on `127.0.0.1:8899`. Serves `public/` and one `/config.json` endpoint built from four non-secret SSM parameters. No create/update/delete routes. |
| `public/index.html` | Shell with sign-in, chat pane, leave-balance card, allowance card, direct-reports card, and the two review cards from [`custom-app-plan/human-review.md`](../custom-app-plan/human-review.md). |
| `public/app.js` | Opens an AG-UI SSE stream to the runtime with the Cognito access token; renders cards from `TOOL_CALL_RESULT` events; gates `submit_leave_request` behind the employee confirmation card and `record_leave_decision` behind the manager review card. |
| `public/styles.css` | Minimal zinc-cards look, matched to `dashboard/public/app.css`. |
| `tests/test_server_boundary.py` | Boots `server.py` on `127.0.0.1:0` and asserts loopback-only, no-mutation, and no-secret behaviour. SSM is mocked. |

## What it reads

At startup the server reads these parameters from SSM in the configured
region, and only these:

- `/{project}/{environment}/runtimes/orchestrator/arn`
- `/{project}/{environment}/auth/web-client-id`
- `/{project}/{environment}/auth/issuer-url`
- `/{project}/{environment}/gateway/url`

Each value is non-secret. The `/config.json` endpoint returns them, along with
the region derived from the runtime ARN. The server never reads a client
secret, a database password, an IAM credential, or a user token.

The browser uses OIDC discovery (`{issuer-url}/.well-known/openid-configuration`)
to find the Cognito hosted-UI authorization and token endpoints.

## What it does NOT do

- It does **not** proxy AWS calls. The browser talks directly to the module 6
  runtime over AG-UI SSE with a Bearer access token the Cognito web client
  issued.
- It has **no** create, update, or delete route. Only `GET /`, the static
  files, and `GET /config.json` answer.
- It imports no CDK and no stack code. It does not import the agent package.
- It does **not** hold any state across restarts. Chat lives in memory.

## Run it

Prerequisites, already true for the platform deployer:

1. Layer 1 (H1–H4) is deployed, so the SSM parameters above exist.
2. Layer 2 is deployed, so the god agent runtime is live.
3. The Cognito web client registered in `auth` has `http://127.0.0.1:8899/`
   as a callback URL. If the current deployment only registered
   `http://localhost:3000/...`, redeploy the `auth` stack with the extra
   callback URL (via the `callback_urls` constructor arg in
   [`stacks/auth_stack.py`](../stacks/auth_stack.py)) before using this UI.

Then, from the repository root with AWS credentials that can read SSM in the
deployment region:

```bash
AWS_PROFILE=<profile> .venv/bin/python hr-web/server.py
```

Open `http://127.0.0.1:8899/`, click **Sign in**, and authenticate through the
Cognito hosted UI. The browser caches the access token in memory for the life
of the tab. Ctrl+C the server to stop.

The sign-in button and all review decisions happen in the browser. The server
is a static file host plus `/config.json`; the agent conversation never flows
through it.

## Tests

```bash
pytest hr-web/tests/ -q
```

The tests boot the server on `127.0.0.1:0` with mocked SSM and assert:

- Non-loopback `Host` headers are rejected (`403`).
- Every mutation verb on every path returns `404`/`405`.
- `/config.json` carries only the four non-secret URLs and the derived region,
  and never leaks SSM secret values that might sit under unrelated paths.
