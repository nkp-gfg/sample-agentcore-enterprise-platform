"""GitLab CI job images must be immutable digests.

These tests fail while `.gitlab-ci.yml` points a job at a moving tag. They pass
once every job image is pinned to `name@sha256:<64 hex>` (a tag may remain
beside the digest). Pinning is the fix: a later publish of the same tag must
not be what the job executes.

The execution model follows the code that actually starts the container:

- GitLab inherits `default.image` and sends `before_script` ahead of `script`
  (`lib/gitlab/ci/config/entry/default.rb`, `lib/gitlab/ci/build/step.rb` at
  v19.5.6-ee). The job request includes `CI_JOB_TOKEN`
  (`app/models/ci/build.rb`).
- Runner v19.5.3 pulls that reference with the default `always` policy and
  starts the build container with the job variables in the environment and
  `sh -c` as the command (`executors/docker/internal/pull/manager.go`,
  `executors/docker/docker.go`, `shells/bash.go`). The job script is written to
  stdin after the container is started (`executors/docker/internal/exec/exec.go`).
- Docker v29.10.0 keeps the image entrypoint when the job does not set one,
  and treats `entrypoint: [""]` as clearing it (`daemon/commit.go` `merge`,
  `daemon/create.go` `mergeAndVerifyConfig`). A tag moves to a new manifest;
  a digest does not (`daemon/internal/refstore/store.go` `favorDigest`).
"""

from __future__ import annotations

import os
import re
import subprocess
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
GITLAB_CI = REPO_ROOT / ".gitlab-ci.yml"

# Obvious placeholder. Not a credential.
JOB_TOKEN = "placeholder-ci-job-token"

PINNED_IMAGE = re.compile(r"^(.+)@(sha256:[a-f0-9]{64})$")

# shells/bash.go BashDetectShellScript with $@ cleared (NormalShell on Docker).
BASH_DETECT = """if [ -x /usr/local/bin/bash ]; then
	exec /usr/local/bin/bash 
elif [ -x /usr/bin/bash ]; then
	exec /usr/bin/bash 
elif [ -x /bin/bash ]; then
	exec /bin/bash 
elif [ -x /usr/local/bin/sh ]; then
	exec /usr/local/bin/sh 
elif [ -x /usr/bin/sh ]; then
	exec /usr/bin/sh 
elif [ -x /bin/sh ]; then
	exec /bin/sh 
elif [ -x /busybox/sh ]; then
	exec /busybox/sh 
else
	echo shell not found
	exit 1
fi

"""

RUNNER_CMD = ["sh", "-c", BASH_DETECT]


@dataclass(frozen=True)
class JobImage:
    job: str
    name: str
    entrypoint: tuple[str, ...] | None


@dataclass
class PublishedImage:
    """One manifest. `entrypoint` None is a nil Docker entrypoint, not []."""

    root: Path
    entrypoint: tuple[str, ...] | None


class Registry:
    """Tag pointer versus digest, matching OCI distribution and Docker refstore.

    `publish` moves the tag and stores a new digest. Existing digests stay.
    """

    def __init__(self) -> None:
        self.tags: dict[str, str] = {}
        self.manifests: dict[str, PublishedImage] = {}
        self._n = 0

    def publish(self, tag: str, image: PublishedImage) -> str:
        self._n += 1
        digest = f"sha256:{self._n:064x}"
        self.manifests[digest] = image
        self.tags[tag] = digest
        return digest

    def pull_always(self, reference: str) -> PublishedImage:
        pinned = PINNED_IMAGE.fullmatch(reference)
        if pinned:
            digest = pinned.group(2)
            try:
                return self.manifests[digest]
            except KeyError as exc:
                raise AssertionError(f"pinned digest {digest} is not a stored manifest") from exc
        try:
            return self.manifests[self.tags[reference]]
        except KeyError as exc:
            raise AssertionError(f"tag {reference} was not published") from exc


def load_ci() -> dict:
    return yaml.safe_load(GITLAB_CI.read_text())


def job_images(document: dict | None = None) -> list[JobImage]:
    document = load_ci() if document is None else document
    default_image = document.get("default", {}).get("image")
    found: list[JobImage] = []
    for name, body in document.items():
        if not isinstance(body, dict) or name.startswith("."):
            continue
        if "script" not in body and "run" not in body:
            continue
        image = body.get("image", default_image)
        image_name, entrypoint = split_image(image)
        found.append(JobImage(name, image_name, entrypoint))
    return found


def split_image(image) -> tuple[str, tuple[str, ...] | None]:
    if isinstance(image, str):
        return image, None
    if isinstance(image, dict) and isinstance(image.get("name"), str):
        entrypoint = image.get("entrypoint")
        if entrypoint is None:
            return image["name"], None
        return image["name"], tuple(entrypoint)
    raise AssertionError(f"job image must be a string or a name mapping, got {image!r}")


def job_script(document: dict, job: str) -> str:
    body = document[job]
    commands = list(body.get("before_script") or []) + list(body.get("script") or [])
    lines = []
    for command in commands:
        lines.append(command if isinstance(command, str) else str(command))
    return "\n".join(lines) + "\n"


def merge_entrypoint(job_entrypoint, job_cmd, image_entrypoint, image_cmd):
    """daemon/commit.go merge, then create.go's reset of entrypoint [""]."""
    user_entrypoint = None if job_entrypoint is None else list(job_entrypoint)
    user_cmd = list(job_cmd)
    if user_entrypoint is None or len(user_entrypoint) == 0:
        if len(user_cmd) == 0:
            user_cmd = list(image_cmd or [])
        if user_entrypoint is None:
            user_entrypoint = list(image_entrypoint) if image_entrypoint else None
    if user_entrypoint is not None and len(user_entrypoint) == 1 and user_entrypoint[0] == "":
        user_entrypoint = None
    return user_entrypoint, user_cmd


def argv_for(image: PublishedImage, job_entrypoint: tuple[str, ...] | None) -> list[str]:
    entrypoint, cmd = merge_entrypoint(job_entrypoint, RUNNER_CMD, image.entrypoint, None)
    return _argv(image.root, entrypoint, cmd)


def _argv(root: Path, entrypoint: list[str] | None, cmd: list[str]) -> list[str]:
    if entrypoint:
        executable, args = entrypoint[0], entrypoint[1:] + cmd
    else:
        if not cmd:
            raise AssertionError("Docker rejects a container with no entrypoint and no command")
        executable, args = cmd[0], cmd[1:]
    if executable.startswith("/"):
        host_exe = root / executable.lstrip("/")
    else:
        host_exe = root / "bin" / executable
    return [str(host_exe), *args]


def _write_exe(path: Path, source: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source)
    path.chmod(0o755)


LEAK_PROGRAM = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import os, select, sys
    ready = False
    if not sys.stdin.closed:
        readable, _, _ = select.select([sys.stdin], [], [], 0)
        ready = bool(readable)
    with open(os.environ["LEAK_FILE"], "w", encoding="utf-8") as handle:
        handle.write(f"token={os.environ.get('CI_JOB_TOKEN', '')}\\n")
        handle.write(f"stdin_ready={int(ready)}\\n")
    raise SystemExit(0)
    """
)

BENIGN_SHELL = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import os, sys
    script = sys.stdin.read()
    with open(os.environ["SCRIPT_MARKER"], "w", encoding="utf-8") as handle:
        handle.write(script)
    raise SystemExit(0)
    """
)


def make_reviewed_image(root: Path) -> PublishedImage:
    _write_exe(root / "bin" / "sh", BENIGN_SHELL)
    return PublishedImage(root, None)


def make_republished_image(root: Path) -> PublishedImage:
    _write_exe(root / "bin" / "sh", LEAK_PROGRAM)
    _write_exe(root / "bin" / "pwn", LEAK_PROGRAM)
    return PublishedImage(root, ("/bin/pwn",))


def run_build_container(image: PublishedImage, job_entrypoint, script: str, work: Path) -> tuple[str | None, str]:
    work.mkdir(parents=True, exist_ok=True)
    leak = work / "leak"
    marker = work / "script"
    env = os.environ.copy()
    env["CI_JOB_TOKEN"] = JOB_TOKEN
    env["LEAK_FILE"] = str(leak)
    env["SCRIPT_MARKER"] = str(marker)
    proc = subprocess.Popen(
        argv_for(image, job_entrypoint),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
    )
    # Image code is PID 1 and can run before the runner copies the script to stdin.
    deadline = time.monotonic() + 0.2
    while time.monotonic() < deadline and not leak.exists() and proc.poll() is None:
        time.sleep(0.01)
    if leak.exists() or proc.poll() is not None:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)
    else:
        assert proc.stdin is not None
        proc.stdin.write(script)
        proc.stdin.close()
        proc.wait(timeout=5)
    stderr = proc.stderr.read() if proc.stderr else ""
    if proc.returncode not in (0, None) and not leak.exists():
        raise AssertionError(f"image process exited {proc.returncode}: {stderr}")
    leaked = leak.read_text(encoding="utf-8") if leak.exists() else None
    received = marker.read_text(encoding="utf-8") if marker.exists() else ""
    return leaked, received


def republish_and_run(reference: str, job_entrypoint, script: str, tmp: Path):
    """Publisher ships a reviewed image, then moves the tag to a new one."""
    registry = Registry()
    tag = PINNED_IMAGE.fullmatch(reference).group(1) if PINNED_IMAGE.fullmatch(reference) else reference
    reviewed = registry.publish(tag, make_reviewed_image(tmp / "reviewed"))
    registry.publish(tag, make_republished_image(tmp / "republished"))
    if PINNED_IMAGE.fullmatch(reference):
        digest = PINNED_IMAGE.fullmatch(reference).group(2)
        # A digest names one manifest. The tag move above stored a different
        # digest, so bind this pin to the reviewed manifest it names.
        if digest not in registry.manifests:
            registry.manifests[digest] = registry.manifests[reviewed]
    pulled = registry.pull_always(reference)
    return run_build_container(pulled, job_entrypoint, script, tmp / "run")


def test_digest_pin_ignores_a_republished_tag(tmp_path: Path):
    """Control: the same runner path keeps the reviewed manifest when the reference has a digest."""
    reference = "registry.example/library/python:3.13-slim@sha256:" + "ab" * 32
    leaked, received = republish_and_run(reference, None, "echo pinned-script\n", tmp_path)
    assert leaked is None
    assert received == "echo pinned-script\n"


def test_cleared_entrypoint_still_runs_the_image_shell(tmp_path: Path):
    """Control: entrypoint [""] does not select a different manifest. An unpinned tag still runs the new shell."""
    leaked, received = republish_and_run(
        "registry.example/hashicorp/terraform:1.9",
        ("",),
        "terraform validate\n",
        tmp_path,
    )
    assert leaked is not None
    assert "token=placeholder-ci-job-token" in leaked
    assert "stdin_ready=0" in leaked
    assert received == ""


@pytest.mark.parametrize("job", job_images(), ids=lambda job: job.job)
def test_job_image_is_digest_pinned(job: JobImage):
    assert PINNED_IMAGE.fullmatch(job.name), (
        f"{job.job} image {job.name!r} is a moving tag. "
        "Pin it to name@sha256:<64 lowercase hex> so a later publish of the tag is not pulled."
    )


@pytest.mark.parametrize("job", job_images(), ids=lambda job: job.job)
def test_republished_tag_does_not_run_before_the_job_script(job: JobImage, tmp_path: Path):
    document = load_ci()
    script = job_script(document, job.job)
    leaked, received = republish_and_run(job.name, job.entrypoint, script, tmp_path)
    assert leaked is None, (
        f"{job.job} pulled {job.name!r} after that tag was republished. "
        f"Image code read CI_JOB_TOKEN before the job script was written to stdin: {leaked!r}"
    )
    assert received == script
