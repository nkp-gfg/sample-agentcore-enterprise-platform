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
| `server.py` | `http.server` on `127.0.0.1:8899`. Serves `public/`, one `GET /config.json` endpoint built from four non-secret SSM parameters plus the pinned A2UI protocol version, and a zero-AWS-credential same-origin `POST /invocations` SSE passthrough that forwards only the browser's Cognito Bearer JWT to the AgentCore Runtime (avoiding browser cross-origin CORS preflight blocks). No create/update/delete routes. |
| `public/index.html` | Shell with sign-in, chat pane, and one A2UI surfaces mount point. The side cards from [`custom-app-plan/human-review.md`](../custom-app-plan/human-review.md) are rendered dynamically by the A2UI processor. |
| `public/a2ui.js` | Minimal, no-build [A2UI v1.0](https://a2ui.org/specification/v1_0/) `MessageProcessor`: `createSurface`, `updateComponents`, `updateDataModel`, `deleteSurface`, outbound `action` + `error`. Hand-rolled instead of imported via CDN; see "A2UI design choice" below. |
| `public/hr-catalog.json` | A2UI catalog listing the components the renderer draws. The catalog is the guardrail; a component outside this list is refused with a renderer error. |
| `public/hr-primitives.js` | DOM implementations of each catalog component: `LeaveBalanceCard`, `AllowanceCard`, `DirectReportsTable`, `ProbationNotice`, `EmployeeConfirmForm`, `ManagerReviewCard`, `Notice`, plus layout primitives. |
| `public/hr-tool-adapter.js` | Maps AG-UI `TOOL_CALL_RESULT` and `RUN_FINISHED(outcome.type === "interrupt")` events into A2UI wire messages. |
| `public/enterprise-catalog.js` | Static catalog of God Bot roster entries, marketplace agents, prompt templates, and guide sections rendered in the workspace drawers. |
| `public/ui-primitives.md` | Catalog documentation: fields each primitive reads, action events each one emits. |
| `public/app.js` | Opens the AG-UI SSE stream, pipes tool-result events through the adapter into the A2UI processor, and routes A2UI `action` events into AG-UI `forwardedProps.resume` posts. Keeps tokens in closure memory only (revoking refresh tokens and purging storage on sign-out). Gates `submit_leave_request` behind `EmployeeConfirmForm`'s Confirm button and `record_leave_decision` behind `ManagerReviewCard`'s Approve / Reject buttons. |
| `public/styles.css` | Minimal zinc-cards look, matched to `dashboard/public/app.css`. |
| `tests/test_server_boundary.py` | Boots `server.py` on `127.0.0.1:0` and asserts loopback-only, no-mutation, and no-secret behaviour; also pins the A2UI protocol version field and refuses adjacent `secret`-shaped strings. SSM is mocked. |

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

- It holds **zero** AWS credentials on the request path. `POST /invocations` forwards only the browser's Cognito `Authorization: Bearer <token>` and `X-Amzn-Bedrock-AgentCore-Runtime-Session-Id` headers to the AgentCore Runtime HTTPS endpoint so browser `fetch()` never hits cross-origin CORS preflight failures.
- It has **no** create, update, or delete route. Only `GET /`, static files, `GET /config.json`, and `POST /invocations` answer.
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

The sign-in button and all review decisions happen in the browser. `server.py`
only serves static files, `/config.json`, and same-origin `/invocations` Bearer
passthrough with zero server-side sessions or credentials.

## Tests

```bash
pytest hr-web/tests/ -q
```

The tests boot the server on `127.0.0.1:0` with mocked SSM and assert:

- Non-loopback `Host` headers are rejected (`403`).
- Every mutation verb on every path returns `404`/`405`.
- `/config.json` carries only the four non-secret URLs, the derived region
  and the pinned A2UI protocol version, and never leaks SSM secret values
  that might sit under unrelated paths.

## A2UI design choice

The renderer speaks [A2UI v1.0](https://a2ui.org/specification/v1_0/) on the
client. There are two realistic places this UI could adopt A2UI:

1. **A2UI as the transport**, replacing the AG-UI SSE stream from the module 6
   runtime.
2. **A2UI as the payload shape**, carried inside the AG-UI stream the module 6
   runtime already emits.

This layer does (2). Rationale:

- The module 6 orchestrator is shipped separately (Layer 2). Adopting A2UI as
  the transport would require the orchestrator to speak A2UI directly — a
  change out of scope for this layer, which must not fork other layers' wire
  formats.
- AG-UI is already the human-review protocol
  ([`custom-app-plan/human-review.md`](../custom-app-plan/human-review.md)).
  `RUN_FINISHED` with `outcome.type === "interrupt"` carries the review
  payload the manager card needs; `forwardedProps.resume` carries the
  decision back. Keeping AG-UI as transport preserves that contract.
- A2UI as payload shape keeps the migration one-way: the agent can start
  emitting A2UI wire messages as tool-call content when it is ready, and
  `hr-tool-adapter.js` collapses to a pass-through. No renderer change.

A2UI's web SDK (`@a2ui/web_core@0.15.0` plus `@a2ui/react@0.15.0`) depends on
`lit`, `zod`, `@preact/signals-core`, `@lit/context`, `redos-detector`,
`validate-color` and `zod-to-json-schema`, and expects a vite build. Importing
all of that via esm.sh in a no-build Python-first repo is heavy. Instead,
`public/a2ui.js` is a minimal implementation of the v1.0 wire schema
(`createSurface`, `updateComponents`, `updateDataModel`, `deleteSurface`
inbound; `action`, `error` outbound; `{"@path": ...}` + `{"@call": ...}`
bindings). The upstream spec files at
`https://github.com/a2ui-project/a2ui/tree/main/specification/v1_0/json` are
the contract this file implements; when it ever grows a schema rule the HR
catalog needs, the loyal-to-spec implementation can be swapped for the SDK
without changing `hr-primitives.js`, `hr-tool-adapter.js`, or `app.js`.
