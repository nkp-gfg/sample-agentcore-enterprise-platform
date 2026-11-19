"""The published docs shell must not run a substituted CDN script.

docs/index.html is the documentation entry page. It loads Docsify, its
plugins, Prism, and Mermaid from cdn.jsdelivr.net on floating major versions
and does not set a subresource integrity hash. A browser then runs whatever
body that URL currently returns, in the origin that served the page.

These tests open the repository HTML in Chrome. Every external script
response is replaced with a marker body. The marker runs while the page
trusts that response. Vendoring the script, or pinning it with an integrity
hash the marker does not match, makes the marker stop running. A
Content-Security-Policy that still allows the CDN host does not, because the
browser would still execute the substituted body.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import queue
import shutil
import socket
import subprocess
import threading
import time
from html.parser import HTMLParser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

REPO = Path(__file__).resolve().parents[1]
DOCS_INDEX = REPO / "docs" / "index.html"
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
PROBE_PREFIX = "/__cdn_probe/"


class _ScriptParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.scripts: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "script":
            return
        values = {key: value for key, value in attrs if value is not None}
        if "src" in values:
            self.scripts.append(values)


def _external_script_srcs(html: str) -> list[str]:
    parser = _ScriptParser()
    parser.feed(html)
    sources: list[str] = []
    for script in parser.scripts:
        src = script["src"]
        parsed = urlsplit(src)
        if parsed.scheme in {"http", "https"} or src.startswith("//"):
            sources.append(src)
    return sources


def _pages_with_external_scripts() -> list[tuple[Path, list[str]]]:
    pages: list[tuple[Path, list[str]]] = []
    for path in sorted(REPO.rglob("*.html")):
        sources = _external_script_srcs(path.read_text(encoding="utf-8"))
        if sources:
            pages.append((path, sources))
    return pages


def _marker(url: str, nonce: str) -> bytes:
    payload = (
        "globalThis.__cdnProbe = globalThis.__cdnProbe || {nonce: null, urls: []};"
        f"globalThis.__cdnProbe.nonce = {json.dumps(nonce)};"
        f"globalThis.__cdnProbe.urls.push({json.dumps(url)});"
    )
    return payload.encode()


def _page_state_expression() -> str:
    return """JSON.stringify({
      name: globalThis.$docsify && globalThis.$docsify.name || null,
      nonce: globalThis.__cdnProbe && globalThis.__cdnProbe.nonce || null,
      executed: globalThis.__cdnProbe && globalThis.__cdnProbe.urls || []
    })"""


class _WebSocket:
    def __init__(self, host: str, port: int, path: str) -> None:
        self._sock = socket.create_connection((host, port), timeout=10)
        self._sock.settimeout(10)
        key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        self._sock.sendall(request.encode())
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise RuntimeError("Chrome closed the DevTools handshake")
            response += chunk
        head = response.split(b"\r\n\r\n", 1)[0].decode()
        accept = base64.b64encode(
            hashlib.sha1((key + WS_GUID).encode()).digest()
        ).decode()
        if f"Sec-WebSocket-Accept: {accept}" not in head:
            raise RuntimeError(f"DevTools handshake was rejected: {head}")
        self._sock.settimeout(None)
        self._send_lock = threading.Lock()

    def send_text(self, text: str) -> None:
        payload = text.encode()
        mask = os.urandom(4)
        header = bytearray([0x81])
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header.extend(length.to_bytes(2, "big"))
        else:
            header.append(0x80 | 127)
            header.extend(length.to_bytes(8, "big"))
        header.extend(mask)
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        with self._send_lock:
            self._sock.sendall(header + masked)

    def _read_exact(self, size: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < size:
            chunk = self._sock.recv(size - len(chunks))
            if not chunk:
                raise RuntimeError("Chrome closed the DevTools socket")
            chunks.extend(chunk)
        return bytes(chunks)

    def next_text(self) -> str:
        while True:
            first, second = self._read_exact(2)
            opcode = first & 0x0F
            length = second & 0x7F
            if length == 126:
                length = int.from_bytes(self._read_exact(2), "big")
            elif length == 127:
                length = int.from_bytes(self._read_exact(8), "big")
            if second & 0x80:
                mask = self._read_exact(4)
                payload = bytes(
                    byte ^ mask[index % 4]
                    for index, byte in enumerate(self._read_exact(length))
                )
            else:
                payload = self._read_exact(length)
            if opcode == 0x9:
                self._send_pong(payload)
                continue
            if opcode == 0x8:
                raise RuntimeError("Chrome closed the DevTools session")
            if opcode == 0x1:
                return payload.decode()

    def _send_pong(self, payload: bytes) -> None:
        mask = os.urandom(4)
        header = bytearray([0x8A, 0x80 | len(payload)])
        header.extend(mask)
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        with self._send_lock:
            self._sock.sendall(header + masked)

    def close(self) -> None:
        self._sock.close()


class _Browser:
    def __init__(self) -> None:
        self._user_data = (
            Path(os.environ.get("TMPDIR", "/tmp")) / f"docs-cdn-chrome-{os.getpid()}"
        )
        if self._user_data.exists():
            shutil.rmtree(self._user_data)
        self._user_data.mkdir()
        self._port = _free_port()
        chrome = os.environ.get("CHROME_BIN", "google-chrome")
        self._proc = subprocess.Popen(
            [
                chrome,
                "--headless=new",
                "--disable-gpu",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                f"--remote-debugging-port={self._port}",
                "--remote-allow-origins=*",
                f"--user-data-dir={self._user_data}",
                "--no-first-run",
                "--disable-extensions",
                "--disable-sync",
                "--disable-background-networking",
                "--disable-component-update",
                "--disable-default-apps",
                "--no-default-browser-check",
                # Keep speculative connections off the public network. Script
                # responses are fulfilled inside Chrome and never use this mapping.
                (
                    "--host-resolver-rules=MAP cdn.jsdelivr.net 127.0.0.1, "
                    "MAP fonts.googleapis.com 127.0.0.1, MAP fonts.gstatic.com 127.0.0.1"
                ),
                "about:blank",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._ws = _WebSocket(*_devtools_endpoint(self._port))
        self._messages: queue.Queue[dict] = queue.Queue()
        self._pending: dict[int, queue.Queue[dict]] = {}
        self._next_id = 0
        self._id_lock = threading.Lock()
        self._session_id = ""
        self._probe: dict | None = None
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        try:
            while True:
                message = json.loads(self._ws.next_text())
                if "id" in message:
                    pending = self._pending.get(message["id"])
                    if pending is not None:
                        pending.put(message)
                    continue
                if (
                    message.get("method") == "Fetch.requestPaused"
                    and message.get("sessionId") == self._session_id
                    and self._probe is not None
                ):
                    self._fulfill(message["params"])
                    continue
                self._messages.put(message)
        except (OSError, RuntimeError, json.JSONDecodeError, UnicodeError) as error:
            self._messages.put(
                {"method": "harness.error", "params": {"error": str(error)}}
            )

    def call(
        self, method: str, params: dict | None = None, session: bool = False
    ) -> dict:
        mailbox: queue.Queue[dict] = queue.Queue()
        self._send(method, params, session, mailbox)
        try:
            response = mailbox.get(timeout=15)
        except queue.Empty as error:
            raise TimeoutError(method) from error
        if "error" in response:
            raise RuntimeError(f"{method} failed: {response['error']}")
        return response.get("result", {})

    def _send(
        self,
        method: str,
        params: dict | None,
        session: bool,
        mailbox: queue.Queue[dict] | None,
    ) -> int:
        with self._id_lock:
            self._next_id += 1
            message_id = self._next_id
            if mailbox is not None:
                self._pending[message_id] = mailbox
        message: dict = {"id": message_id, "method": method, "params": params or {}}
        if session:
            message["sessionId"] = self._session_id
        self._ws.send_text(json.dumps(message))
        return message_id

    def open_page(self, url: str, nonce: str) -> dict:
        created = self.call("Target.createTarget", {"url": "about:blank"})
        target_id = created["targetId"]
        try:
            attached = self.call(
                "Target.attachToTarget",
                {"targetId": target_id, "flatten": True},
            )
            self._session_id = attached["sessionId"]
            self.call("Page.enable", session=True)
            self.call(
                "Fetch.enable",
                {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]},
                session=True,
            )
            probe: dict = {
                "nonce": nonce,
                "requested": [],
                "fulfilled": [],
            }
            self._probe = probe
            self.call("Page.navigate", {"url": url}, session=True)
            deadline = time.monotonic() + 20
            loaded = False
            harness_error = ""
            while time.monotonic() < deadline and not loaded:
                try:
                    event = self._messages.get(timeout=0.2)
                except queue.Empty:
                    continue
                method = event.get("method")
                if method == "harness.error":
                    harness_error = event["params"]["error"]
                    break
                if event.get("sessionId") != self._session_id:
                    continue
                if method == "Page.loadEventFired":
                    loaded = True
            if harness_error:
                raise RuntimeError(harness_error)
            if not loaded:
                raise TimeoutError(
                    f"page did not load: {url}; scripts seen: {probe['fulfilled']}"
                )
            raw = self.call(
                "Runtime.evaluate",
                {"expression": _page_state_expression(), "returnByValue": True},
                session=True,
            )
            state = json.loads(raw["result"]["value"])
            state["requested"] = list(probe["requested"])
            state["fulfilled"] = list(probe["fulfilled"])
            return state
        finally:
            self._probe = None
            self.call("Target.closeTarget", {"targetId": target_id})

    def _fulfill(self, params: dict) -> None:
        probe = self._probe
        if probe is None:
            return
        request = params["request"]
        url = request["url"]
        parsed = urlsplit(url)
        external = parsed.hostname not in {None, "127.0.0.1", "localhost"}
        is_script = params.get("resourceType") == "Script" or parsed.path.endswith(
            ".js"
        )
        if external and is_script:
            body = _marker(url, probe["nonce"])
            probe["requested"].append(url)
            probe["fulfilled"].append(url)
            response = {
                "requestId": params["requestId"],
                "responseCode": 200,
                "responseHeaders": [
                    {"name": "Content-Type", "value": "text/javascript; charset=utf-8"},
                    {"name": "Cache-Control", "value": "no-store"},
                ],
                "body": base64.b64encode(body).decode(),
            }
            self._send("Fetch.fulfillRequest", response, session=True, mailbox=None)
            return
        if external:
            response = {
                "requestId": params["requestId"],
                "responseCode": 200,
                "responseHeaders": [
                    {"name": "Content-Type", "value": "text/plain; charset=utf-8"},
                    {"name": "Cache-Control", "value": "no-store"},
                ],
                "body": base64.b64encode(b"").decode(),
            }
            self._send("Fetch.fulfillRequest", response, session=True, mailbox=None)
            return
        self._send(
            "Fetch.continueRequest",
            {"requestId": params["requestId"]},
            session=True,
            mailbox=None,
        )

    def close(self) -> None:
        self._ws.close()
        self._proc.terminate()
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()
        shutil.rmtree(self._user_data, ignore_errors=True)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _devtools_endpoint(port: int) -> tuple[str, int, str]:
    deadline = time.monotonic() + 15
    last_error = ""
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5) as sock:
                sock.sendall(b"GET /json/version HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                payload = b""
                while b"\r\n\r\n" not in payload:
                    payload += sock.recv(4096)
                header, rest = payload.split(b"\r\n\r\n", 1)
                length = 0
                for line in header.decode().split("\r\n"):
                    if line.lower().startswith("content-length:"):
                        length = int(line.split(":", 1)[1].strip())
                while len(rest) < length:
                    rest += sock.recv(4096)
            version = json.loads(rest[:length])
            parsed = urlsplit(version["webSocketDebuggerUrl"])
            return parsed.hostname or "127.0.0.1", parsed.port or port, parsed.path
        except (OSError, json.JSONDecodeError, KeyError) as error:
            last_error = str(error)
            time.sleep(0.1)
    raise RuntimeError(f"Chrome DevTools did not start: {last_error}")


class _RepositoryServer(ThreadingHTTPServer):
    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.controls: dict[str, bytes] = {}


class _Handler(SimpleHTTPRequestHandler):
    def __init__(self, request, client_address, server: _RepositoryServer) -> None:
        self._repo_server = server
        super().__init__(request, client_address, server, directory=str(REPO))

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        body = self._repo_server.controls.get(path)
        if body is None:
            super().do_GET()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        return


@pytest.fixture(scope="module")
def lab():
    server = _RepositoryServer()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    browser = _Browser()
    try:
        yield server, browser
    finally:
        browser.close()
        server.shutdown()


def _origin(server: _RepositoryServer) -> str:
    host, port = server.server_address[:2]
    return f"http://{host}:{port}"


def _open(server: _RepositoryServer, browser: _Browser, url: str) -> dict:
    nonce = base64.b16encode(os.urandom(16)).decode()
    state = browser.open_page(url, nonce)
    assert state["nonce"] in {None, nonce}
    if state["executed"]:
        assert state["nonce"] == nonce
    return state


def test_substituted_script_runs_when_the_page_sets_no_integrity(lab) -> None:
    server, browser = lab
    url = "https://cdn.jsdelivr.net/npm/docsify@4/lib/docsify.min.js"
    page = f"{PROBE_PREFIX}no-integrity.html"
    server.controls[page] = (
        f'<!doctype html><html><body><script src="{url}"></script></body></html>'
    ).encode()
    state = _open(server, browser, f"{_origin(server)}{page}")
    assert state["executed"] == [url]


def test_substituted_script_does_not_run_when_integrity_does_not_match(lab) -> None:
    server, browser = lab
    url = "https://cdn.jsdelivr.net/npm/docsify@4/lib/docsify.min.js"
    digest = base64.b64encode(
        hashlib.sha384(b"not-the-substituted-body").digest()
    ).decode()
    page = f"{PROBE_PREFIX}integrity.html"
    server.controls[page] = (
        "<!doctype html><html><body>"
        f'<script src="{url}" integrity="sha384-{digest}" crossorigin="anonymous"></script>'
        "</body></html>"
    ).encode()
    state = _open(server, browser, f"{_origin(server)}{page}")
    assert state["executed"] == []
    assert url in state["fulfilled"]


def test_repository_html_does_not_run_substituted_external_scripts(lab) -> None:
    server, browser = lab
    pages = {DOCS_INDEX}
    discovered = dict(_pages_with_external_scripts())
    pages.update(discovered)
    origin = _origin(server)
    for path in sorted(pages):
        sources = _external_script_srcs(path.read_text(encoding="utf-8"))
        relative = path.relative_to(REPO).as_posix()
        state = _open(server, browser, f"{origin}/{relative}")
        if path == DOCS_INDEX:
            assert state["name"] == "Agentic AI Platform EBA"
        missing = [src for src in sources if src not in state["fulfilled"]]
        assert missing == [], (
            f"{relative} did not request {missing}; saw {state['fulfilled']}"
        )
        assert state["executed"] == [], (
            f"{relative} ran substituted external scripts in the page origin: "
            + ", ".join(state["executed"])
        )
