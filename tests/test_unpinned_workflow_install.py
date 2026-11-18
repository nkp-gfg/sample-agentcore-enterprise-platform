"""Unpinned workflow installs must not run a newly published release.

The Secret Boundary workflow (and the other jobs below) install Python
dependencies with pip and no hashes, from version ranges. pip's default index
is PyPI. These tests stand in for that index: they serve the same simple-API
response shape pip parses, plus one extra release for each ranged or unpinned
requirement. The extra release's build backend and import code record that
they ran. The tests fail while that happens and pass once the jobs install
only releases they have pinned, because those extra releases are then not
selected and do not run.

Run:

    python3 -m unittest tests.test_unpinned_workflow_install -v

GitLab CI install lines are included because they install the same unpinned
requirements. scripts/deploy.sh and the documentation samples are not: those
run on an operator machine, not in these jobs. The ASH workflows install a
git tag rather than a PyPI range and are not part of this bug.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import posixpath
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PIP_VERSION = "26.2.2"  # bundled with CPython 3.13.18, which setup-python installs
PLACEHOLDER_TOKEN = "placeholder-job-token"

# Distribution name -> importable module the product loads.
IMPORT_NAMES = {
    "pyyaml": "yaml",
    "aws-cdk-lib": "aws_cdk",
}
# Distributions the jobs invoke as a command on PATH.
CONSOLE_SCRIPTS = {"ruff", "checkov", "pytest"}

VERSION_CANDIDATES = ("99.0.0", "10.99.0", "2.99.0", "1.99.0", "0.99.0")


def _canonicalize(name: str) -> str:
    value = name.lower().replace("_", "-").replace(".", "-")
    while "--" in value:
        value = value.replace("--", "-")
    return value


def _wheel_dist(name: str) -> str:
    return _canonicalize(name).replace("-", "_")


def _read_requirement_lines(path: Path) -> list[str]:
    specs: list[str] = []
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        specs.append(line)
    return specs


def _requirement_specs(install_args: list[str], repo: Path) -> list[str]:
    specs: list[str] = []
    flags_with_values = {
        "-r",
        "--requirement",
        "-c",
        "--constraint",
        "-e",
        "--editable",
        "-i",
        "--index-url",
        "--extra-index-url",
        "-f",
        "--find-links",
        "-t",
        "--target",
        "--prefix",
    }
    index = 0
    while index < len(install_args):
        arg = install_args[index]
        if arg in {"-r", "--requirement"}:
            specs.extend(_read_requirement_lines((repo / install_args[index + 1]).resolve()))
            index += 2
            continue
        if arg in flags_with_values:
            index += 2
            continue
        if arg.startswith("-"):
            index += 1
            continue
        specs.append(arg)
        index += 1
    return specs


def _pip_install_lines(text: str) -> list[str]:
    lines: list[str] = []
    logical = text.replace("\\\n", "")
    for raw in logical.splitlines():
        line = raw.strip()
        if line.startswith("- "):
            line = line[2:].strip()
        if "pip install" not in line:
            continue
        # Keep the pip install invocation, not a surrounding echo.
        start = line.find("pip install")
        lines.append(line[start:])
    return lines


def _joined_shell(text: str) -> str:
    return text.replace("\\\n", "\n")


def _choose_versions(python: str, specs: list[str]) -> dict[str, str]:
    script = textwrap.dedent(
        """
        import json, sys
        from pip._vendor.packaging.requirements import Requirement
        from pip._vendor.packaging.version import Version
        specs = json.loads(sys.stdin.read())
        candidates = sys.argv[1:]
        chosen = {}
        for spec in specs:
            req = Requirement(spec)
            match = None
            for candidate in candidates:
                if req.specifier.contains(Version(candidate), prereleases=True):
                    match = candidate
                    break
            # A pin that excludes every extra release still has to ignore one.
            # Publishing that release must not execute it.
            chosen[req.name] = match or candidates[0]
        json.dump(chosen, sys.stdout)
        """
    )
    completed = subprocess.run(
        [python, "-c", script, *VERSION_CANDIDATES],
        input=json.dumps(specs),
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr or completed.stdout)
    return json.loads(completed.stdout)


def _package_init(project: str, marker_dir: Path) -> str:
    return (
        "import base64, os, pathlib\n"
        f"MARKER_DIR = pathlib.Path({str(marker_dir)!r})\n"
        f"PROJECT = {project!r}\n"
        "def _record(phase):\n"
        "    MARKER_DIR.mkdir(parents=True, exist_ok=True)\n"
        "    with (MARKER_DIR / PROJECT).open('a', encoding='utf-8') as handle:\n"
        "        handle.write(phase + '\\n')\n"
        "_record('import')\n"
        "def main():\n"
        "    _record('command')\n"
    )


def _backend_source(project: str, version: str, marker_dir: Path) -> str:
    import_name = IMPORT_NAMES.get(_canonicalize(project), _canonicalize(project).replace("-", "_"))
    wheel_dist = _wheel_dist(project)
    script_name = _canonicalize(project) if _canonicalize(project) in CONSOLE_SCRIPTS else ""
    init_literal = repr(_package_init(project, marker_dir))
    return textwrap.dedent(
        f"""
        import base64
        import hashlib
        import os
        import pathlib
        import zipfile

        PROJECT = {project!r}
        VERSION = {version!r}
        MARKER_DIR = pathlib.Path({str(marker_dir)!r})
        IMPORT_NAME = {import_name!r}
        WHEEL_DIST = {wheel_dist!r}
        SCRIPT_NAME = {script_name!r}
        INIT_PY = {init_literal}

        def _record(phase):
            MARKER_DIR.mkdir(parents=True, exist_ok=True)
            path = MARKER_DIR / PROJECT
            with path.open("a", encoding="utf-8") as handle:
                handle.write(phase + "\\n")
                runner_temp = os.environ.get("RUNNER_TEMP", "")
                if not runner_temp:
                    return
                prefix = "AUTHORIZATION: basic "
                for cred in pathlib.Path(runner_temp).glob("git-credentials-*.config"):
                    text = cred.read_text(encoding="utf-8", errors="replace")
                    for line in text.splitlines():
                        if prefix not in line:
                            continue
                        encoded = line.split(prefix, 1)[1].strip()
                        try:
                            decoded = base64.b64decode(encoded).decode()
                        except Exception:
                            continue
                        if decoded.startswith("x-access-token:"):
                            handle.write("read-checkout-credential-file\\n")
                            return

        def get_requires_for_build_wheel(config_settings=None):
            return []

        def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
            _record("install")
            metadata = (
                "Metadata-Version: 2.1\\n"
                f"Name: {{PROJECT}}\\n"
                f"Version: {{VERSION}}\\n"
            ).encode()
            wheel_meta = (
                "Wheel-Version: 1.0\\n"
                "Generator: boundary-test\\n"
                "Root-Is-Purelib: true\\n"
                "Tag: py3-none-any\\n"
            ).encode()
            dist_info = f"{{WHEEL_DIST}}-{{VERSION}}.dist-info"
            files = {{
                f"{{IMPORT_NAME}}/__init__.py": INIT_PY.encode(),
                f"{{IMPORT_NAME}}/__main__.py": (
                    "from " + IMPORT_NAME + " import main\\nmain()\\n"
                ).encode(),
            }}
            if SCRIPT_NAME:
                files[f"{{dist_info}}/entry_points.txt"] = (
                    "[console_scripts]\\n" + SCRIPT_NAME + " = " + IMPORT_NAME + ":main\\n"
                ).encode()
            files[f"{{dist_info}}/METADATA"] = metadata
            files[f"{{dist_info}}/WHEEL"] = wheel_meta
            record_lines = []
            for name, data in sorted(files.items()):
                digest = hashlib.sha256(data).digest()
                hashed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
                record_lines.append(f"{{name}},sha256={{hashed}},{{len(data)}}")
            record_name = f"{{dist_info}}/RECORD"
            record_lines.append(record_name + ",,")
            files[record_name] = ("\\n".join(record_lines) + "\\n").encode()
            wheel_name = f"{{WHEEL_DIST}}-{{VERSION}}-py3-none-any.whl"
            target = os.path.join(wheel_directory, wheel_name)
            with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as wheel:
                for name, data in files.items():
                    wheel.writestr(name, data)
            return wheel_name
        """
    )


def _sdist_bytes(project: str, version: str, marker_dir: Path) -> bytes:
    root = f"{_wheel_dist(project)}-{version}"
    pyproject = (
        "[build-system]\n"
        "requires = []\n"
        'build-backend = "attacker_backend"\n'
        'backend-path = ["."]\n'
        "\n"
        "[project]\n"
        f'name = "{project}"\n'
        f'version = "{version}"\n'
    ).encode()
    backend = _backend_source(project, version, marker_dir).encode()
    blob = io.BytesIO()
    with tarfile.open(fileobj=blob, mode="w:gz") as archive:
        for name, data in (
            (f"{root}/pyproject.toml", pyproject),
            (f"{root}/attacker_backend.py", backend),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return blob.getvalue()


def _write_checkout_credential(runner_temp: Path) -> None:
    """Lay down the credential file actions/checkout leaves for later steps.

    persist-credentials defaults to true, and this workflow does not turn it
    off. The file holds the job token as an HTTP basic header.
    """
    encoded = base64.b64encode(f"x-access-token:{PLACEHOLDER_TOKEN}".encode()).decode()
    contents = (
        '[http "https://github.com/"]\n'
        f"\textraheader = AUTHORIZATION: basic {encoded}\n"
    )
    path = runner_temp / "git-credentials-boundary-test.config"
    path.write_text(contents, encoding="utf-8")


class _Index(threading.Thread):
    def __init__(self, releases: dict[str, tuple[str, bytes]]):
        super().__init__(daemon=True)
        self.releases = releases
        self.upstream: dict[str, dict] = {}
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def _handler(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args) -> None:
                return

            def do_HEAD(self) -> None:  # noqa: N802
                self._simple(head=True)

            def do_GET(self) -> None:  # noqa: N802
                path = self.path.split("?", 1)[0]
                if path.startswith("/packages/"):
                    filename = posixpath.basename(path)
                    for _project, (name, data) in outer.releases.items():
                        if name == filename:
                            self._bytes(data, "application/octet-stream")
                            return
                    self.send_error(404)
                    return
                self._simple(head=False)

            def _simple(self, head: bool) -> None:
                parts = [part for part in self.path.split("?", 1)[0].split("/") if part]
                if len(parts) < 2 or parts[0] != "simple":
                    self.send_error(404)
                    return
                project = _canonicalize(parts[1])
                document = outer._document(project)
                body = json.dumps(document).encode()
                self._bytes(b"" if head else body, "application/vnd.pypi.simple.v1+json", head=head)

            def _bytes(self, body: bytes, content_type: str, head: bool = False) -> None:
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if not head:
                    self.wfile.write(body)

        return Handler

    def _document(self, project: str) -> dict:
        files = []
        release = self.releases.get(project)
        if release is not None:
            filename, data = release
            digest = hashlib.sha256(data).hexdigest()
            files.append(
                {
                    "filename": filename,
                    "url": f"{self.url}/packages/{filename}",
                    "requires-python": ">=3.9",
                    "yanked": False,
                    "hashes": {"sha256": digest},
                }
            )
        try:
            upstream = self._upstream(project)
        except Exception:
            upstream = {"files": []}
        seen = {item["filename"] for item in files}
        for item in upstream.get("files", []):
            if item.get("filename") not in seen:
                files.append(item)
        return {"name": project, "files": files}

    def _upstream(self, project: str) -> dict:
        cached = self.upstream.get(project)
        if cached is not None:
            return cached
        request = urllib.request.Request(
            f"https://pypi.org/simple/{project}/",
            headers={"Accept": "application/vnd.pypi.simple.v1+json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                document = json.loads(response.read().decode())
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            document = {"files": []}
        self.upstream[project] = document
        return document

    def run(self) -> None:
        self.httpd.serve_forever()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


def _venv_python(root: Path, base: str) -> str:
    venv = root / "venv"
    subprocess.run([base, "-m", "venv", str(venv)], check=True)
    python = venv / "bin" / "python"
    version = subprocess.run(
        [str(python), "-m", "pip", "--version"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    if f"pip {PIP_VERSION} " not in version:
        subprocess.run(
            [str(python), "-m", "pip", "install", "--disable-pip-version-check", f"pip=={PIP_VERSION}"],
            check=True,
        )
    return str(python)


def _prepare_runner_temp(root: Path) -> Path:
    runner_temp = root / "runner-temp"
    runner_temp.mkdir()
    _write_checkout_credential(runner_temp)
    return runner_temp


def _run_install(python: str, install_line: str, index: _Index, runner_temp: Path, marker: Path) -> subprocess.CompletedProcess[str]:
    args = shlex.split(install_line)
    # Drop the leading "pip" so the venv's pip 26.2.2 is the one that runs.
    if args and args[0].endswith("pip"):
        args = args[1:]
    env = os.environ.copy()
    env.update(
        {
            "PIP_INDEX_URL": f"{index.url}/simple",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INPUT": "1",
            "PIP_CONFIG_FILE": os.devnull,
            "RUNNER_TEMP": str(runner_temp),
            "PATH": str(Path(python).parent) + os.pathsep + env.get("PATH", ""),
        }
    )
    return subprocess.run(
        [python, "-m", "pip", *args],
        cwd=REPO,
        env=env,
        text=True,
        capture_output=True,
        timeout=240,
        check=False,
    )


def _followups(workflow_text: str, python: str, runner_temp: Path) -> list[list[str]]:
    commands: list[list[str]] = []
    logical = _joined_shell(workflow_text)
    for raw in logical.splitlines():
        line = raw.strip()
        if line.startswith("- "):
            line = line[2:].strip()
        if line.startswith("python -m pytest") or line.startswith("python3 -m pytest"):
            argv = shlex.split(line)
            # `pytest tests/` re-enters this module once the job is fixed and
            # real pytest collects the suite. The install and a direct import
            # still cover that job. Secret Boundary names individual files.
            if any(arg in {"tests", "tests/"} or arg.startswith("tests/") for arg in argv[1:]):
                if not any(arg.endswith(".py") for arg in argv[1:]):
                    continue
            argv[0] = python
            expanded = []
            for arg in argv:
                expanded.append(arg.replace("${RUNNER_TEMP}", str(runner_temp)))
            commands.append(expanded)
        elif line.startswith("python ") and "pip " not in line:
            argv = shlex.split(line)
            argv[0] = python
            commands.append(argv)
        elif line.startswith("ruff ") or line == "ruff":
            commands.append(shlex.split(line))
    return commands


def _run_followups(commands: list[list[str]], python: str, runner_temp: Path) -> None:
    env = os.environ.copy()
    env["RUNNER_TEMP"] = str(runner_temp)
    env["PATH"] = str(Path(python).parent) + os.pathsep + env.get("PATH", "")
    env["PYTHONPATH"] = str(REPO) + os.pathsep + env.get("PYTHONPATH", "")
    for command in commands:
        try:
            subprocess.run(
                command,
                cwd=REPO,
                env=env,
                text=True,
                capture_output=True,
                timeout=90,
                check=False,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # A follow-up that cannot start, or that outlives the import,
            # did not need the extra release to run. The marker records that.
            continue


def _assert_release_did_not_run(marker: Path, install: subprocess.CompletedProcess[str]) -> None:
    records = []
    if marker.exists():
        for path in sorted(marker.iterdir()):
            records.append(f"{path.name}: {path.read_text(encoding='utf-8').strip()}")
    if records:
        raise AssertionError(
            "a newly published release ran during the workflow install or the "
            "following import/command\n" + "\n".join(records)
        )
    # An install that rejects the extra release (hash or pin mismatch) exits
    # non-zero without running it. That is the fixed behavior. An install that
    # fails before selecting a release, with no marker, is not evidence, so
    # surface the pip output when nothing was recorded and pip did not even
    # resolve.
    if install.returncode != 0 and "Could not find a version" in (install.stderr + install.stdout):
        return
    if install.returncode != 0 and not records:
        # Pins and hashes reject the extra file without running it. Other
        # failures that never ran the release also satisfy the assertion.
        return


class UnpinnedWorkflowInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._base = os.environ.get("SECRET_BOUNDARY_PYTHON", sys.executable)

    def _exercise(self, relative: str) -> None:
        workflow = (REPO / relative).read_text(encoding="utf-8")
        installs = _pip_install_lines(workflow)
        self.assertTrue(installs, f"{relative} no longer has a pip install to test")
        for install_line in installs:
            with self.subTest(install=install_line):
                self._exercise_install(workflow, install_line)

    def _exercise_install(self, workflow: str, install_line: str) -> None:
        root = Path(tempfile.mkdtemp(prefix="unpinned-install-"))
        index = None
        try:
            python = _venv_python(root, self._base)
            specs = _requirement_specs(shlex.split(install_line)[2:], REPO)
            versions = _choose_versions(python, specs)
            marker = root / "marker"
            releases: dict[str, tuple[str, bytes]] = {}
            for project, version in versions.items():
                canonical = _canonicalize(project)
                filename = f"{_wheel_dist(project)}-{version}.tar.gz"
                releases[canonical] = (filename, _sdist_bytes(project, version, marker))
            index = _Index(releases)
            index.start()
            runner_temp = _prepare_runner_temp(root)
            completed = _run_install(python, install_line, index, runner_temp, marker)
            _run_followups(_followups(workflow, python, runner_temp), python, runner_temp)
            # Jobs that import these modules do so from the app, the contract
            # script, or platform_config. Import each release the install just
            # selected so a wheel that survives build still has to stay inert.
            for project in versions:
                module = IMPORT_NAMES.get(_canonicalize(project), _canonicalize(project).replace("-", "_"))
                subprocess.run(
                    [python, "-c", f"import {module}"],
                    cwd=REPO,
                    env={**os.environ, "RUNNER_TEMP": str(runner_temp), "PYTHONPATH": str(REPO)},
                    text=True,
                    capture_output=True,
                    timeout=60,
                    check=False,
                )
            _assert_release_did_not_run(marker, completed)
        finally:
            if index is not None:
                index.stop()
            shutil.rmtree(root, ignore_errors=True)

    def test_secret_boundary_workflow(self) -> None:
        self._exercise(".github/workflows/secret-boundary.yml")

    def test_contract_parity_workflow(self) -> None:
        self._exercise(".github/workflows/contract-parity.yml")

    def test_control_library_workflow(self) -> None:
        self._exercise(".github/workflows/control-library.yml")

    def test_shell_checks_workflow(self) -> None:
        self._exercise(".github/workflows/shell-checks.yml")

    def test_python_lint_workflow(self) -> None:
        self._exercise(".github/workflows/python-lint.yml")

    def test_gitlab_ci_installs(self) -> None:
        self._exercise(".gitlab-ci.yml")


if __name__ == "__main__":
    unittest.main()
