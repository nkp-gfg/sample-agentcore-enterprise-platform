"""Confined snapshots of a migration Docker build context.

The migration manifest names a directory that is zipped and uploaded for
CodeBuild. Everything in that upload must come from inside the repository, so
the directory is never handed to the CDK asset uploader by path. Instead it is
copied into a private snapshot: every lookup is made relative to an open
directory descriptor with O_NOFOLLOW, and symbolic links are resolved here, one
component at a time, against the snapshot root. A link that is absolute, climbs
above the root, or loops is refused, and the snapshot holds only regular files
and directories. The asset is then built from the snapshot, so what was checked
is exactly what is uploaded.

Deliberately free of CDK imports so it stays unit-testable without aws-cdk-lib.
"""

from __future__ import annotations

import os
import shutil
import stat

_MAX_SYMLINK_HOPS = 40
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class BuildContextError(ValueError):
    """The build context or Dockerfile would reach outside its root."""


def relative_parts(value: str, label: str) -> list[str]:
    """Split a manifest path into components, refusing anything that could
    leave the directory it is relative to (absolute paths, '..', NUL)."""
    if not isinstance(value, str) or not value.strip():
        raise BuildContextError(f"{label} must be a non-empty relative path")
    if "\0" in value or "\\" in value:
        raise BuildContextError(f"{label} {value!r} contains an invalid character")
    if value.startswith("/") or os.path.isabs(value):
        raise BuildContextError(f"{label} {value!r} must be relative, not absolute")
    parts = [p for p in value.split("/") if p not in ("", ".")]
    if ".." in parts:
        raise BuildContextError(f"{label} {value!r} must not contain '..'")
    if not parts:
        raise BuildContextError(f"{label} {value!r} does not name a path")
    return parts


def _open_beneath(
    root_fd: int, parts: list[str], label: str
) -> tuple[int, os.stat_result, list[str]]:
    """Open root/parts without the kernel following any symlink.

    Returns an owned descriptor, its fstat, and the link-free component path of
    the object relative to the root. Links are expanded here; '..' pops this
    function's own component stack, so it can never rise above root_fd.
    """
    stack: list[tuple[str, int]] = []
    pending = list(parts)
    hops = 0
    try:
        while pending:
            name = pending.pop(0)
            if name in ("", "."):
                continue
            if name == "..":
                if not stack:
                    raise BuildContextError(f"{label} resolves outside its root")
                os.close(stack.pop()[1])
                continue
            parent = stack[-1][1] if stack else root_fd
            st = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode):
                hops += 1
                if hops > _MAX_SYMLINK_HOPS:
                    raise BuildContextError(f"{label} has a symbolic link loop")
                target = os.readlink(name, dir_fd=parent)
                if not target or target.startswith("/") or "\0" in target:
                    raise BuildContextError(
                        f"{label} has a symbolic link that resolves outside its root"
                    )
                pending[:0] = target.split("/")
                continue
            if stat.S_ISDIR(st.st_mode):
                stack.append((name, os.open(name, _DIR_FLAGS, dir_fd=parent)))
                continue
            if pending:
                raise BuildContextError(f"{label}: {name!r} is not a directory")
            if not stat.S_ISREG(st.st_mode):
                raise BuildContextError(f"{label}: {name!r} is not a regular file")
            fd = os.open(name, _FILE_FLAGS, dir_fd=parent)
            fst = os.fstat(fd)
            if not stat.S_ISREG(fst.st_mode):
                os.close(fd)
                raise BuildContextError(f"{label}: {name!r} is not a regular file")
            return fd, fst, [n for n, _ in stack] + [name]
        if stack:
            name, fd = stack.pop()
            return fd, os.fstat(fd), [n for n, _ in stack] + [name]
        fd = os.dup(root_fd)
        return fd, os.fstat(fd), []
    finally:
        for _, fd in stack:
            os.close(fd)


def _copy_file(src_fd: int, dest: str) -> None:
    out = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        while chunk := os.read(src_fd, 1 << 20):
            os.write(out, chunk)
    finally:
        os.close(out)


def _copy_dir(
    root_fd: int,
    dir_fd: int,
    dir_parts: list[str],
    dest: str,
    active: frozenset[tuple[int, int]],
    label: str,
) -> None:
    with os.scandir(dir_fd) as it:
        names = sorted(entry.name for entry in it)
    for name in names:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if stat.S_ISLNK(st.st_mode):
            fd, fst, real_parts = _open_beneath(root_fd, dir_parts + [name], label)
        elif stat.S_ISDIR(st.st_mode):
            fd = os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
            fst, real_parts = os.fstat(fd), dir_parts + [name]
        elif stat.S_ISREG(st.st_mode):
            fd = os.open(name, _FILE_FLAGS, dir_fd=dir_fd)
            fst, real_parts = os.fstat(fd), dir_parts + [name]
        else:
            raise BuildContextError(
                f"{label}: {'/'.join(dir_parts + [name])!r} is not a regular file or directory"
            )
        try:
            target = os.path.join(dest, name)
            if stat.S_ISDIR(fst.st_mode):
                key = (fst.st_dev, fst.st_ino)
                if key in active:
                    raise BuildContextError(f"{label} has a symbolic link loop")
                os.mkdir(target, 0o755)
                _copy_dir(root_fd, fd, real_parts, target, active | {key}, label)
            elif stat.S_ISREG(fst.st_mode):
                _copy_file(fd, target)
            else:
                raise BuildContextError(
                    f"{label}: {'/'.join(real_parts)!r} is not a regular file or directory"
                )
        finally:
            os.close(fd)


def snapshot_build_context(
    repo_root: str, context: str, dockerfile: str, dest: str
) -> str:
    """Copy repo_root/context into dest (which must not exist) and return dest.

    The context may be reached through in-repository links; links inside it
    must stay inside it. The Dockerfile must be a regular file inside the
    snapshot. Nothing outside the repository is opened, and on any refusal
    dest is removed.
    """
    context_parts = relative_parts(context, "migration build context")
    dockerfile_parts = relative_parts(dockerfile, "migration Dockerfile")
    repo_fd = os.open(repo_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        ctx_fd, ctx_st, _ = _open_beneath(
            repo_fd, context_parts, f"migration build context {context!r}"
        )
    finally:
        os.close(repo_fd)
    try:
        if not stat.S_ISDIR(ctx_st.st_mode):
            raise BuildContextError(
                f"migration build context {context!r} is not a directory"
            )
        os.mkdir(dest, 0o755)
        try:
            _copy_dir(
                ctx_fd,
                ctx_fd,
                [],
                dest,
                frozenset({(ctx_st.st_dev, ctx_st.st_ino)}),
                f"migration build context {context!r}",
            )
            # The snapshot holds no links, so this lookup cannot leave dest.
            if not os.path.isfile(os.path.join(dest, *dockerfile_parts)):
                raise BuildContextError(
                    f"migration Dockerfile {dockerfile!r} is not a file inside "
                    f"the build context {context!r}"
                )
        except BaseException:
            shutil.rmtree(dest, ignore_errors=True)
            raise
    finally:
        os.close(ctx_fd)
    return dest
