"""Source hashing must refuse symlinks and files past a fixed byte cap.

``compute_source_hash`` and ``component_image_tag`` are the hash used for
runtime image tags. ``RuntimeStack`` calls them while the CDK app is loading
(pattern builds and migration build contexts). These tests exercise those
functions on trees that contain the inputs a merge request can check in.

They fail while hashing follows symbolic links or reads a file to EOF. They
pass when both functions raise ``infra_utils.source_hash.SourceHashError``
before an unbounded read, including when a path that looked like a regular
file is a symlink by the time it is opened.

Contract for the fix:

- Raise ``SourceHashError`` (a new exception on that module) with the
  relative path in the message. Do not return a digest.
- Refuse every symbolic link that ``os.walk`` visits, including links whose
  names end in ``.pyc``, ``.log``, or ``.DS_Store``, and links to directories.
  A name-based skip that never opens the link is not enough: the link itself
  must fail the hash.
- Refuse a regular file larger than ``MAX_HASH_BYTES`` (1 MiB).
- A path check followed by ``open`` of that same path is not enough. Opening
  must not follow a symlink that appears at open time (``O_NOFOLLOW``, or an
  equivalent check of the file descriptor) and must not read past the cap.
"""

import os
import signal
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
MAX_HASH_BYTES = 1_048_576
TIMEOUT_SECONDS = 2

# Replaces RACE_TARGET with a symlink to /dev/zero inside the real open, after
# any earlier stat/lstat of the same path, then calls the real libc open.
_RACE_PRELOAD = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void swap_target(int dirfd, const char *pathname) {
    const char *dest = getenv("RACE_FOLLOW_TARGET");
    if (!pathname || !strstr(pathname, "RACE_TARGET"))
        return;
    if (!dest || !dest[0])
        dest = "/dev/zero";
    if (pathname[0] == '/' || dirfd == AT_FDCWD) {
        unlink(pathname);
        symlink(dest, pathname);
        return;
    }
    unlinkat(dirfd, pathname, 0);
    symlinkat(dest, dirfd, pathname);
}

static int call_open(int (*real_open)(const char *, int, ...),
                     const char *pathname, int flags, mode_t mode) {
    swap_target(AT_FDCWD, pathname);
    if (flags & (O_CREAT | O_TMPFILE))
        return real_open(pathname, flags, mode);
    return real_open(pathname, flags);
}

static int call_openat(int (*real_openat)(int, const char *, int, ...),
                       int dirfd, const char *pathname, int flags, mode_t mode) {
    swap_target(dirfd, pathname);
    if (flags & (O_CREAT | O_TMPFILE))
        return real_openat(dirfd, pathname, flags, mode);
    return real_openat(dirfd, pathname, flags);
}

#define WRAP_OPEN(name) \
    int name(const char *pathname, int flags, ...) { \
        static int (*real_open)(const char *, int, ...) = NULL; \
        mode_t mode = 0; \
        if (!real_open) \
            real_open = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, #name); \
        if (flags & (O_CREAT | O_TMPFILE)) { \
            va_list ap; \
            va_start(ap, flags); \
            mode = (mode_t)va_arg(ap, int); \
            va_end(ap); \
        } \
        return call_open(real_open, pathname, flags, mode); \
    }

#define WRAP_OPENAT(name) \
    int name(int dirfd, const char *pathname, int flags, ...) { \
        static int (*real_openat)(int, const char *, int, ...) = NULL; \
        mode_t mode = 0; \
        if (!real_openat) \
            real_openat = (int (*)(int, const char *, int, ...))dlsym(RTLD_NEXT, #name); \
        if (flags & (O_CREAT | O_TMPFILE)) { \
            va_list ap; \
            va_start(ap, flags); \
            mode = (mode_t)va_arg(ap, int); \
            va_end(ap); \
        } \
        return call_openat(real_openat, dirfd, pathname, flags, mode); \
    }

WRAP_OPEN(open)
WRAP_OPEN(open64)
WRAP_OPENAT(openat)
WRAP_OPENAT(openat64)
"""

_HASH_SCRIPT = """
import sys
sys.path.insert(0, sys.argv[1])
from infra_utils import source_hash
fn = getattr(source_hash, sys.argv[2])
err = getattr(source_hash, "SourceHashError", None)
try:
    result = fn(sys.argv[3], *sys.argv[4:])
except Exception as exc:
    sys.stderr.write(f"{type(exc).__name__}: {exc}")
    if err is not None and isinstance(exc, err):
        raise SystemExit(2)
    raise SystemExit(3)
sys.stdout.write(result if isinstance(result, str) else repr(result))
raise SystemExit(0)
"""


@pytest.fixture(scope="session")
def race_preload(tmp_path_factory):
    work = tmp_path_factory.mktemp("race-preload")
    source = work / "race.c"
    library = work / "race.so"
    source.write_text(_RACE_PRELOAD)
    subprocess.check_call(
        ["gcc", "-shared", "-fPIC", "-o", str(library), str(source), "-ldl"],
        stdout=subprocess.DEVNULL,
    )
    return str(library)


def _regular_file(directory: Path, name: str, content: bytes = b"kept\n") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_bytes(content)
    return path


def _run_hash(
    fn: str,
    source: Path,
    *extra: str,
    preload: str | None = None,
    env_extra: dict | None = None,
):
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    if preload:
        env["LD_PRELOAD"] = preload
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            textwrap.dedent(_HASH_SCRIPT),
            str(REPO),
            fn,
            str(source),
            *extra,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        start_new_session=True,
    )
    try:
        out, err = proc.communicate(timeout=TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=5)
        pytest.fail(
            f"{fn} did not finish within {TIMEOUT_SECONDS}s; "
            "hashing is still reading without a bound"
        )
    return proc.returncode, out.decode(), err.decode()


def _assert_refused(
    fn: str,
    source: Path,
    *extra: str,
    name: str,
    preload: str | None = None,
    env_extra: dict | None = None,
):
    code, out, err = _run_hash(fn, source, *extra, preload=preload, env_extra=env_extra)
    assert code == 2, (
        f"{fn} should raise SourceHashError for {name}, "
        f"exit {code}, stdout={out!r}, stderr={err!r}"
    )
    assert name in err, f"SourceHashError should name {name}, got {err!r}"


def test_symlink_to_regular_file_is_refused(tmp_path):
    """A link to a normal file must not be hashed as that file's bytes."""
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"UNIQUE_OUTSIDE_BYTES")
    tree = tmp_path / "tree"
    _regular_file(tree, "keep.txt")
    (tree / "via_link.txt").symlink_to(outside)
    _assert_refused("compute_source_hash", tree, name="via_link.txt")


def test_component_image_tag_refuses_symlink_to_regular_file(tmp_path):
    """RuntimeStack tags images through component_image_tag, not only the raw hash."""
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"UNIQUE_OUTSIDE_BYTES")
    tree = tmp_path / "tree"
    _regular_file(tree, "keep.txt")
    (tree / "via_link.txt").symlink_to(outside)
    _assert_refused(
        "component_image_tag",
        tree,
        "orchestrator",
        name="via_link.txt",
    )


def test_symlink_to_endless_device_does_not_block(tmp_path):
    tree = tmp_path / "tree"
    _regular_file(tree, "keep.txt")
    (tree / "endless").symlink_to("/dev/zero")
    _assert_refused("compute_source_hash", tree, name="endless")


def test_component_image_tag_refuses_symlink_to_endless_device(tmp_path):
    tree = tmp_path / "tree"
    _regular_file(tree, "keep.txt")
    (tree / "endless").symlink_to("/dev/zero")
    _assert_refused(
        "component_image_tag",
        tree,
        "orchestrator",
        name="endless",
    )


def test_nested_symlink_to_endless_device_does_not_block(tmp_path):
    tree = tmp_path / "tree"
    nested = tree / "pkg"
    _regular_file(nested, "keep.txt")
    (nested / "endless").symlink_to("/dev/zero")
    _assert_refused("compute_source_hash", tree, name="endless")


def test_directory_symlink_is_refused(tmp_path):
    tree = tmp_path / "tree"
    real = tree / "real"
    _regular_file(real, "a.txt", b"alpha\n")
    (tree / "linked_dir").symlink_to(real, target_is_directory=True)
    _assert_refused("compute_source_hash", tree, name="linked_dir")


@pytest.mark.parametrize("suffix", [".pyc", ".log", ".DS_Store"])
def test_excluded_suffix_symlink_is_refused(tmp_path, suffix):
    tree = tmp_path / "tree"
    _regular_file(tree, "keep.txt")
    link = tree / f"skipped{suffix}"
    link.symlink_to("/dev/zero")
    _assert_refused("compute_source_hash", tree, name=link.name)


def test_broken_symlink_is_refused(tmp_path):
    tree = tmp_path / "tree"
    _regular_file(tree, "keep.txt")
    (tree / "broken").symlink_to(tmp_path / "missing")
    _assert_refused("compute_source_hash", tree, name="broken")


def test_oversized_regular_file_is_refused(tmp_path):
    tree = tmp_path / "tree"
    _regular_file(tree, "keep.txt")
    huge = tree / "huge.bin"
    with huge.open("wb") as handle:
        handle.seek(MAX_HASH_BYTES)
        handle.write(b"x")
    _assert_refused("compute_source_hash", tree, name="huge.bin")


def _race_env(tmp_path: Path) -> dict[str, str]:
    followed = tmp_path / "followed.txt"
    followed.write_bytes(b"FOLLOWED_SECRET_BYTES")
    return {"RACE_FOLLOW_TARGET": str(followed)}


def test_symlink_swapped_in_before_open_is_refused(tmp_path, race_preload):
    """A path check that saw a regular file must not authorize reading a link.

    The preload turns RACE_TARGET into a symlink inside libc open, after any
    stat or lstat of that path, and then performs the real open.
    """
    tree = tmp_path / "tree"
    _regular_file(tree, "keep.txt")
    _regular_file(tree, "RACE_TARGET", b"small regular file\n")
    _assert_refused(
        "compute_source_hash",
        tree,
        name="RACE_TARGET",
        preload=race_preload,
        env_extra=_race_env(tmp_path),
    )


def test_component_image_tag_refuses_symlink_swapped_in_before_open(
    tmp_path, race_preload
):
    tree = tmp_path / "tree"
    _regular_file(tree, "keep.txt")
    _regular_file(tree, "RACE_TARGET", b"small regular file\n")
    _assert_refused(
        "component_image_tag",
        tree,
        "orchestrator",
        name="RACE_TARGET",
        preload=race_preload,
        env_extra=_race_env(tmp_path),
    )
