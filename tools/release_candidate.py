"""Create and verify immutable GitHub release-candidate identities."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import platform
import re
import stat
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from typing import Any, Iterable, Sequence

from tools.public_checksums import ChecksumError, verify_sha256s


SCHEMA_VERSION = 1
RETENTION_DAYS = 30
WORKFLOW_NAME = "test.yml"
CANONICAL_OS = "ubuntu-latest"
CANONICAL_BUILD_VERSION = "1.5.1"
CANONICAL_SETUPTOOLS_VERSION = "83.0.0"
CANONICAL_WHEEL_VERSION = "0.47.0"
RELEASE_ASSET_NAMES = (
    "SHA256SUMS.txt",
    "analyzing-chemical-eia-processes-0.1.0.zip",
    "chemical_eia_core-0.1.0-py3-none-any.whl",
    "chemical_eia_core-0.1.0.tar.gz",
)

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_PYTHON_RE = re.compile(r"^3\.13\.\d+$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        "public_commit",
        "ci_run_id",
        "workflow",
        "artifact_name",
        "retention_days",
        "builder",
        "files",
        "created_at_utc",
    }
)
_BUILDER_KEYS = frozenset({"os", "python", "build", "setuptools", "wheel"})
_FILE_KEYS = frozenset({"name", "size", "sha256"})


class CandidateError(RuntimeError):
    """Raised when a release candidate identity or manifest is invalid."""


@dataclass(frozen=True)
class CandidateFile:
    name: str
    size: int
    sha256: str


@dataclass(frozen=True)
class BuilderIdentity:
    os: str
    python: str
    build: str
    setuptools: str
    wheel: str


@dataclass(frozen=True)
class ReleaseCandidateManifest:
    schema_version: int
    public_commit: str
    ci_run_id: int
    workflow: str
    artifact_name: str
    retention_days: int
    builder: BuilderIdentity
    files: tuple[CandidateFile, ...]
    created_at_utc: str


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_exact_keys(value: object, expected: frozenset[str], label: str) -> dict:
    if not isinstance(value, dict):
        raise CandidateError(f"{label} must be an object")
    actual = frozenset(value)
    if actual != expected:
        raise CandidateError(f"{label} has unexpected or missing fields")
    return value


def _reject_duplicate_object_pairs(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CandidateError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def candidate_artifact_name(public_commit: str, ci_run_id: int) -> str:
    if not isinstance(public_commit, str) or _COMMIT_RE.fullmatch(public_commit) is None:
        raise CandidateError("public_commit must be one lowercase 40-hex commit ID")
    if not _is_int(ci_run_id) or ci_run_id <= 0:
        raise CandidateError("ci_run_id must be a positive integer")
    return f"release-candidate-{public_commit}-{ci_run_id}"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_builder(builder: BuilderIdentity) -> None:
    for field_name in ("os", "python", "build", "setuptools", "wheel"):
        if not isinstance(getattr(builder, field_name), str):
            raise CandidateError(f"builder.{field_name} must be a string")
    if builder.os != CANONICAL_OS:
        raise CandidateError("builder.os does not identify the canonical builder")
    if _PYTHON_RE.fullmatch(builder.python) is None:
        raise CandidateError("builder.python must be one full Python 3.13 version")
    if builder.build != CANONICAL_BUILD_VERSION:
        raise CandidateError("builder.build version is not pinned")
    if builder.setuptools != CANONICAL_SETUPTOOLS_VERSION:
        raise CandidateError("builder.setuptools version is not pinned")
    if builder.wheel != CANONICAL_WHEEL_VERSION:
        raise CandidateError("builder.wheel version is not pinned")


def _validate_files(files: tuple[CandidateFile, ...]) -> None:
    if not isinstance(files, tuple):
        raise CandidateError("files must be an immutable tuple")
    if len(files) != len(RELEASE_ASSET_NAMES):
        raise CandidateError("files must contain exactly four release assets")

    names: list[str] = []
    for item in files:
        if not isinstance(item, CandidateFile):
            raise CandidateError("files must contain CandidateFile rows")
        if not isinstance(item.name, str):
            raise CandidateError("files[].name must be a string")
        if not _is_int(item.size) or item.size <= 0:
            raise CandidateError("files[].size must be a positive integer")
        if not isinstance(item.sha256, str) or _DIGEST_RE.fullmatch(item.sha256) is None:
            raise CandidateError("files[].sha256 must be lowercase 64-hex")
        names.append(item.name)

    if len(names) != len(set(names)):
        raise CandidateError("candidate file names must be unique")
    if len(names) != len({name.casefold() for name in names}):
        raise CandidateError("candidate file names must not collide by case")
    if set(names) != set(RELEASE_ASSET_NAMES):
        raise CandidateError("candidate file names do not match the release contract")


def _validate_created_at(value: str) -> None:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise CandidateError("created_at_utc must use second-precision UTC format")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise CandidateError("created_at_utc is not a valid timestamp") from exc


def _validate_manifest(manifest: ReleaseCandidateManifest) -> None:
    if not isinstance(manifest, ReleaseCandidateManifest):
        raise CandidateError("manifest must be a ReleaseCandidateManifest")
    if not _is_int(manifest.schema_version) or manifest.schema_version != SCHEMA_VERSION:
        raise CandidateError("unsupported candidate schema version")
    expected_name = candidate_artifact_name(manifest.public_commit, manifest.ci_run_id)
    if not isinstance(manifest.workflow, str) or manifest.workflow != WORKFLOW_NAME:
        raise CandidateError("workflow must be test.yml")
    if not isinstance(manifest.artifact_name, str) or manifest.artifact_name != expected_name:
        raise CandidateError("artifact_name does not match commit and run ID")
    if not _is_int(manifest.retention_days) or manifest.retention_days != RETENTION_DAYS:
        raise CandidateError("retention_days must be 30")
    _validate_builder(manifest.builder)
    _validate_files(manifest.files)
    _validate_created_at(manifest.created_at_utc)


def _manifest_from_document(document: object) -> ReleaseCandidateManifest:
    root = _require_exact_keys(document, _TOP_LEVEL_KEYS, "manifest")
    builder_data = _require_exact_keys(root["builder"], _BUILDER_KEYS, "builder")
    files_data = root["files"]
    if not isinstance(files_data, list):
        raise CandidateError("files must be an array")

    files: list[CandidateFile] = []
    for index, raw_file in enumerate(files_data):
        file_data = _require_exact_keys(raw_file, _FILE_KEYS, f"files[{index}]")
        files.append(
            CandidateFile(
                name=file_data["name"],
                size=file_data["size"],
                sha256=file_data["sha256"],
            )
        )

    manifest = ReleaseCandidateManifest(
        schema_version=root["schema_version"],
        public_commit=root["public_commit"],
        ci_run_id=root["ci_run_id"],
        workflow=root["workflow"],
        artifact_name=root["artifact_name"],
        retention_days=root["retention_days"],
        builder=BuilderIdentity(
            os=builder_data["os"],
            python=builder_data["python"],
            build=builder_data["build"],
            setuptools=builder_data["setuptools"],
            wheel=builder_data["wheel"],
        ),
        files=tuple(files),
        created_at_utc=root["created_at_utc"],
    )
    _validate_manifest(manifest)
    return manifest


def load_candidate_manifest(path: Path) -> ReleaseCandidateManifest:
    try:
        text = Path(path).read_text(encoding="utf-8")
        document = json.loads(text, object_pairs_hook=_reject_duplicate_object_pairs)
    except CandidateError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateError("candidate manifest cannot be read as strict UTF-8 JSON") from exc
    return _manifest_from_document(document)


def write_candidate_manifest(manifest: ReleaseCandidateManifest, path: Path) -> Path:
    _validate_manifest(manifest)
    destination = Path(path)
    payload = json.dumps(
        asdict(manifest),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"
    try:
        destination.write_text(payload, encoding="utf-8", newline="\n")
    except OSError as exc:
        raise CandidateError("candidate manifest cannot be written") from exc
    return destination.resolve()

def current_builder_identity() -> BuilderIdentity:
    """Read the real builder identity; callers cannot supply a forged identity."""

    system_name = platform.system()
    operating_system = CANONICAL_OS if system_name == "Linux" else system_name.lower()
    try:
        build_version = metadata.version("build")
        setuptools_version = metadata.version("setuptools")
        wheel_version = metadata.version("wheel")
    except metadata.PackageNotFoundError as exc:
        raise CandidateError(f"required builder package is not installed: {exc.name}") from exc
    return BuilderIdentity(
        os=operating_system,
        python=platform.python_version(),
        build=build_version,
        setuptools=setuptools_version,
        wheel=wheel_version,
    )


def _is_link_or_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction is not None and is_junction())


def _require_exact_regular_files(directory: Path, expected_names: Sequence[str]) -> None:
    root = Path(directory)
    if _is_link_or_junction(root) or not root.is_dir():
        raise CandidateError("candidate or release root must be one real directory")
    try:
        members = list(root.iterdir())
    except OSError as exc:
        raise CandidateError("candidate or release directory cannot be enumerated") from exc

    names = [member.name for member in members]
    if len(names) != len(set(names)) or len(names) != len(
        {name.casefold() for name in names}
    ):
        raise CandidateError("directory members must not collide by case")
    if set(names) != set(expected_names) or len(names) != len(expected_names):
        raise CandidateError("directory members do not match the exact release contract")

    for member in members:
        try:
            mode = member.stat(follow_symlinks=False).st_mode
        except OSError as exc:
            raise CandidateError("directory member cannot be inspected safely") from exc
        if _is_link_or_junction(member) or not stat.S_ISREG(mode):
            raise CandidateError("every release member must be one regular non-linked file")


def _verify_checksum_manifest(directory: Path) -> None:
    try:
        verify_sha256s(
            Path(directory) / "SHA256SUMS.txt",
            Path(directory),
            RELEASE_ASSET_NAMES[1:],
        )
    except (ChecksumError, OSError) as exc:
        raise CandidateError("SHA256SUMS.txt does not match the release assets") from exc


def create_candidate_manifest(
    candidate_dir: Path,
    public_commit: str,
    ci_run_id: int,
    artifact_name: str,
    created_at_utc: str | None = None,
) -> ReleaseCandidateManifest:
    root = Path(candidate_dir)
    _require_exact_regular_files(root, RELEASE_ASSET_NAMES)
    _verify_checksum_manifest(root)

    builder = current_builder_identity()
    _validate_builder(builder)
    files = tuple(
        CandidateFile(
            name=name,
            size=(root / name).stat().st_size,
            sha256=sha256_file(root / name),
        )
        for name in RELEASE_ASSET_NAMES
    )
    timestamp = created_at_utc or datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    manifest = ReleaseCandidateManifest(
        schema_version=SCHEMA_VERSION,
        public_commit=public_commit,
        ci_run_id=ci_run_id,
        workflow=WORKFLOW_NAME,
        artifact_name=artifact_name,
        retention_days=RETENTION_DAYS,
        builder=builder,
        files=files,
        created_at_utc=timestamp,
    )
    write_candidate_manifest(manifest, root / "release-candidate.json")
    return manifest


def _verify_manifest_files(directory: Path, manifest: ReleaseCandidateManifest) -> None:
    root = Path(directory)
    rows = {row.name: row for row in manifest.files}
    for name in RELEASE_ASSET_NAMES:
        path = root / name
        row = rows[name]
        try:
            actual_size = path.stat().st_size
            actual_digest = sha256_file(path)
        except OSError as exc:
            raise CandidateError("release asset cannot be read") from exc
        if actual_size != row.size:
            raise CandidateError(f"release asset size mismatch: {name}")
        if not hmac.compare_digest(actual_digest, row.sha256):
            raise CandidateError(f"release asset digest mismatch: {name}")
    _verify_checksum_manifest(root)


def verify_candidate_directory(
    candidate_dir: Path,
    expected_commit: str,
    expected_run_id: int,
    expected_artifact_name: str,
    expected_manifest_sha256: str,
) -> ReleaseCandidateManifest:
    expected_name = candidate_artifact_name(expected_commit, expected_run_id)
    if expected_artifact_name != expected_name:
        raise CandidateError("expected artifact name does not bind commit and run ID")
    if (
        not isinstance(expected_manifest_sha256, str)
        or _DIGEST_RE.fullmatch(expected_manifest_sha256) is None
    ):
        raise CandidateError("expected manifest digest must be lowercase 64-hex")

    root = Path(candidate_dir)
    _require_exact_regular_files(
        root, RELEASE_ASSET_NAMES + ("release-candidate.json",)
    )
    manifest_path = root / "release-candidate.json"
    actual_manifest_sha256 = sha256_file(manifest_path)
    if not hmac.compare_digest(actual_manifest_sha256, expected_manifest_sha256):
        raise CandidateError("candidate manifest digest mismatch")

    manifest = load_candidate_manifest(manifest_path)
    if manifest.public_commit != expected_commit:
        raise CandidateError("candidate public commit mismatch")
    if manifest.ci_run_id != expected_run_id:
        raise CandidateError("candidate CI run ID mismatch")
    if manifest.artifact_name != expected_artifact_name:
        raise CandidateError("candidate artifact name mismatch")
    _verify_manifest_files(root, manifest)
    return manifest


def verify_release_directory(
    release_dir: Path, manifest: ReleaseCandidateManifest
) -> None:
    _validate_manifest(manifest)
    root = Path(release_dir)
    _require_exact_regular_files(root, RELEASE_ASSET_NAMES)
    _verify_manifest_files(root, manifest)

def verify_published_release(
    candidate_dir: Path,
    release_dir: Path,
    expected_commit: str,
    expected_run_id: int,
    expected_artifact_name: str,
    expected_manifest_sha256: str,
) -> ReleaseCandidateManifest:
    manifest = verify_candidate_directory(
        candidate_dir,
        expected_commit,
        expected_run_id,
        expected_artifact_name,
        expected_manifest_sha256,
    )
    verify_release_directory(release_dir, manifest)
    return manifest

_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_ALLOWED_RUN_EVENTS = frozenset({"push", "workflow_dispatch"})
_WORKFLOW_PATH = ".github/workflows/test.yml"


def verify_workflow_run_document(
    document: dict[str, object],
    expected_repository: str,
    expected_run_id: int,
    expected_commit: str,
) -> None:
    if (
        not isinstance(expected_repository, str)
        or _REPOSITORY_RE.fullmatch(expected_repository) is None
    ):
        raise CandidateError("expected_repository must be one owner/repository name")
    candidate_artifact_name(expected_commit, expected_run_id)
    if not isinstance(document, dict):
        raise CandidateError("workflow run document must be an object")

    required_fields = ("id", "event", "status", "conclusion", "head_sha", "path")
    if any(field not in document for field in required_fields):
        raise CandidateError("workflow run document is missing required fields")
    if not _is_int(document["id"]):
        raise CandidateError("workflow run id must be an integer")
    for field in ("event", "status", "conclusion", "head_sha", "path"):
        if not isinstance(document[field], str):
            raise CandidateError(f"workflow run {field} must be a string")

    repository = document.get("repository")
    if not isinstance(repository, dict):
        raise CandidateError("workflow run repository must be an object")
    full_name = repository.get("full_name")
    if not isinstance(full_name, str):
        raise CandidateError("workflow run repository.full_name must be a string")

    if document["id"] != expected_run_id:
        raise CandidateError("workflow run ID mismatch")
    if document["event"] not in _ALLOWED_RUN_EVENTS:
        raise CandidateError("workflow run event is not allowed")
    if document["status"] != "completed":
        raise CandidateError("workflow run is not completed")
    if document["conclusion"] != "success":
        raise CandidateError("workflow run did not succeed")
    if document["head_sha"] != expected_commit:
        raise CandidateError("workflow run head SHA mismatch")
    if document["path"] != _WORKFLOW_PATH:
        raise CandidateError("workflow run path is not test.yml")
    if full_name != expected_repository:
        raise CandidateError("workflow run repository mismatch")


def _load_json_document(path: Path, label: str) -> object:
    try:
        text = Path(path).read_text(encoding="utf-8")
        return json.loads(text, object_pairs_hook=_reject_duplicate_object_pairs)
    except CandidateError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateError(f"{label} cannot be read as strict UTF-8 JSON") from exc

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--candidate-dir", type=Path, required=True)
    create.add_argument("--public-commit", required=True)
    create.add_argument("--ci-run-id", type=int, required=True)
    create.add_argument("--artifact-name", required=True)

    verify_candidate = subparsers.add_parser("verify-candidate")
    verify_candidate.add_argument("--candidate-dir", type=Path, required=True)
    verify_candidate.add_argument("--public-commit", required=True)
    verify_candidate.add_argument("--ci-run-id", type=int, required=True)
    verify_candidate.add_argument("--artifact-name", required=True)
    verify_candidate.add_argument("--manifest-sha256", required=True)

    verify_release = subparsers.add_parser("verify-release")
    verify_release.add_argument("--release-dir", type=Path, required=True)
    verify_release.add_argument("--manifest", type=Path, required=True)

    verify_run = subparsers.add_parser("verify-run")
    verify_run.add_argument("--run-json", type=Path, required=True)
    verify_run.add_argument("--repository", required=True)
    verify_run.add_argument("--ci-run-id", type=int, required=True)
    verify_run.add_argument("--public-commit", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            manifest = create_candidate_manifest(
                args.candidate_dir,
                args.public_commit,
                args.ci_run_id,
                args.artifact_name,
            )
            print(sha256_file(args.candidate_dir / "release-candidate.json"))
            print(manifest.artifact_name)
        elif args.command == "verify-candidate":
            manifest = verify_candidate_directory(
                args.candidate_dir,
                args.public_commit,
                args.ci_run_id,
                args.artifact_name,
                args.manifest_sha256,
            )
            print(manifest.artifact_name)
        elif args.command == "verify-release":
            manifest = load_candidate_manifest(args.manifest)
            verify_release_directory(args.release_dir, manifest)
            print(manifest.artifact_name)
        else:
            document = _load_json_document(args.run_json, "workflow run document")
            verify_workflow_run_document(
                document,
                args.repository,
                args.ci_run_id,
                args.public_commit,
            )
            print(args.ci_run_id)
    except CandidateError as exc:
        print(f"release candidate error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
