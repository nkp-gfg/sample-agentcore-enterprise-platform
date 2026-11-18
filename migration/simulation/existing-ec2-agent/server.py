"""HTTP front for the simulated customer agent — the migration story's "before".

This is what the customer's agent looks like as a service today: its own HTTP
contract (POST /run, GET /healthz) on its own port. The migration adapter
(migration/adapter/) fronts this unchanged with the AgentCore contract.

    POST /run      {"prompt": "..."}  →  {"answer": "..."}
    GET  /healthz                     →  {"status": "ok"}

Port from PORT (default 8000). Honours MODEL_ID when set (so a migrated deploy
can lift the agent off its hard-coded Legacy model id without editing agent.py,
which keeps the "legacy code untouched" story intact).
"""

import json
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

log = logging.getLogger("acme-agent-server")

_agent = None


def get_agent():
    """Lazy so the server starts (and /healthz answers) without AWS access."""
    global _agent
    if _agent is None:
        model_id = os.environ.get("MODEL_ID", "")
        if model_id:
            from strands import Agent
            from strands.models.bedrock import BedrockModel

            _agent = Agent(
                model=BedrockModel(
                    model_id=model_id,
                    region_name=os.environ.get("AWS_REGION", "us-east-1"),
                ),
                system_prompt="You are a helpful assistant for ACME Corp. "
                "You help employees with research and code tasks.",
            )
        else:
            from agent import create_agent

            _agent = create_agent()
    return _agent


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: dict):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/healthz":
            self._send(200, {"status": "ok"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/run":
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length) or b"{}")
            prompt = payload.get("prompt", "")
            answer = str(get_agent()(prompt))
        except Exception:  # request handler boundary
            # Exception text can carry AWS account, role, and model details;
            # it goes to the server log only, never the response body.
            log.exception("POST /run failed")
            self._send(500, {"error": "internal error"})
            return
        self._send(200, {"answer": answer})

    def log_message(self, fmt, *args):
        print(f"[server] {fmt % args}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="[server] %(levelname)s %(message)s")
    port = int(os.environ.get("PORT", "8000"))
    print(f"ACME Corp Agent serving HTTP on :{port} (POST /run, GET /healthz)")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()  # nosec B104 — container service
