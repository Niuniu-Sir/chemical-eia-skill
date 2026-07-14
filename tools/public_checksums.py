"""Generate and verify strict SHA-256 release manifests."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


_LINE_RE = re.compile(rb"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]*)\n")


class ChecksumError(RuntimeError):
    """Raised when a checksum manifest or release artifact is invalid."""


@dataclass(frozen=True)
class ChecksumEntry:
    digest: str
    name: str


def _safe_basename(name: str) -> bool:
    return (
        bool(name)
        and name not in {".", "..", "SHA256SUMS.txt"}
        and "/" not in name
        and "\\" not in name
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", name) is not None
    )


def sha256_file(path: Path) -> str:
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ChecksumError("checksum input must be one regular file")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_sha256s(artifacts: Sequence[Path], destination: Path) -> Path:
    destination = Path(destination)
    resolved_destination = destination.resolve()
    entries: list[ChecksumEntry] = []
    names: list[str] = []
    for artifact_value in artifacts:
        artifact = Path(artifact_value)
        if artifact.resolve() == resolved_destination:
            raise ChecksumError("checksum manifest must not checksum itself")
        name = artifact.name
        if not _safe_basename(name):
            raise ChecksumError("artifact name must be one safe basename")
        names.append(name)
        entries.append(ChecksumEntry(sha256_file(artifact), name))
    if not entries:
        raise ChecksumError("at least one artifact is required")
    if len(names) != len(set(names)) or len(names) != len(
        {name.casefold() for name in names}
    ):
        raise ChecksumError("artifact basenames must be unique")
    entries.sort(key=lambda entry: entry.name)
    payload = "".join(
        f"{entry.digest}  {entry.name}\n" for entry in entries
    ).encode("ascii")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    try:
        temporary.write_bytes(payload)
        temporary.replace(destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    return destination


def parse_sha256s(manifest: Path) -> list[ChecksumEntry]:
    raw = Path(manifest).read_bytes()
    if not raw or bytes((13,)) in raw or not raw.endswith(b"\n"):
        raise ChecksumError("checksum manifest must be non-empty LF text")
    entries: list[ChecksumEntry] = []
    offset = 0
    for match in _LINE_RE.finditer(raw):
        if match.start() != offset:
            raise ChecksumError("checksum manifest line format is invalid")
        digest = match.group(1).decode("ascii")
        name = match.group(2).decode("ascii")
        if not _safe_basename(name):
            raise ChecksumError("checksum entry name is unsafe")
        entries.append(ChecksumEntry(digest, name))
        offset = match.end()
    if offset != len(raw) or not entries:
        raise ChecksumError("checksum manifest line format is invalid")
    names = [entry.name for entry in entries]
    if names != sorted(names):
        raise ChecksumError("checksum entries must be sorted by basename")
    if len(names) != len(set(names)) or len(names) != len(
        {name.casefold() for name in names}
    ):
        raise ChecksumError("checksum entry names must be unique")
    return entries


def verify_sha256s(
    manifest: Path,
    base_dir: Path,
    expected_names: Sequence[str],
) -> None:
    entries = parse_sha256s(manifest)
    expected = list(expected_names)
    if any(not _safe_basename(name) for name in expected):
        raise ChecksumError("expected artifact name is unsafe")
    if len(expected) != len(set(expected)) or len(expected) != len(
        {name.casefold() for name in expected}
    ):
        raise ChecksumError("expected artifact names must be unique")
    actual_names = [entry.name for entry in entries]
    if set(actual_names) != set(expected) or len(actual_names) != len(expected):
        raise ChecksumError("checksum manifest names do not match expected artifacts")

    base = Path(base_dir).resolve()
    for entry in entries:
        artifact = base / entry.name
        if artifact.parent.resolve() != base:
            raise ChecksumError("artifact escapes checksum base directory")
        actual_digest = sha256_file(artifact)
        if not hmac.compare_digest(actual_digest, entry.digest):
            raise ChecksumError("artifact checksum mismatch")