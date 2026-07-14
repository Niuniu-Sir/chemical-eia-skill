"""Coordinate fixed-commit private and public release verification."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Sequence

from tools.public_export import (
    CandidateResult,
    cleanup_failed_candidate,
    create_candidate,
    resolve_source_commit,
)
from tools.public_scan import (
    enumerate_git_objects,
    scan_git_history,
    scan_git_index,
    scan_source_tree,
)
from tools.release_artifacts import CandidateBuildError, ReleaseArtifacts, build_candidate_release


_STEP_STATUS = Literal["passed", "failed"]
_REPORT_STATUS = Literal["passed", "failed", "awaiting_manual_review"]
_MODULE_RE = re.compile(r"^tests(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

_EXPECTED_ASSETS = (
    "analyzing-chemical-eia-processes-0.1.0.zip",
    "chemical_eia_core-0.1.0-py3-none-any.whl",
    "chemical_eia_core-0.1.0.tar.gz",
)
_EXPECTED_CI_MATRIX = frozenset(
    (operating_system, python_version)
    for operating_system in ("windows-latest", "ubuntu-latest")
    for python_version in ("3.10", "3.11", "3.12", "3.13")
)
_RELEASE_ACTIONS = [
    "create-annotated-tag",
    "push-tag",
    "dispatch-release-workflow",
    "create-github-prerelease",
]


class GateError(RuntimeError):
    """Raised when release verification cannot be executed safely."""


@dataclass(frozen=True)
class GateConfig:
    source_repo: Path
    source_commit: str
    candidates_parent: Path
    evidence_root: Path
    private_test_modules: tuple[str, ...]
    private_identifier_policy: Path
    public_test_start_dir: str = "tests/public"


@dataclass(frozen=True)
class GateStepResult:
    name: str
    status: _STEP_STATUS
    source_commit: str
    command: tuple[str, ...]
    returncode: int
    evidence_file: Path | None
    duration_seconds: float


@dataclass(frozen=True)
class GateReport:
    status: _REPORT_STATUS
    source_commit: str
    steps: tuple[GateStepResult, ...]
    candidate_created: bool
    candidate_root: Path | None
    candidate_digest: str | None
    artifacts: tuple[str, ...]
    manual_review_status: str
    evidence_path: Path


def load_private_gate_config(path: Path) -> tuple[str, ...]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) != {
        "schema_version",
        "private_test_modules",
    }:
        raise ValueError("private gate config has unexpected keys")
    if data["schema_version"] != 1 or isinstance(data["schema_version"], bool):
        raise ValueError("unsupported private gate config schema")
    modules = data["private_test_modules"]
    if not isinstance(modules, list) or not modules:
        raise ValueError("private_test_modules must be a non-empty list")
    if any(not isinstance(item, str) or _MODULE_RE.fullmatch(item) is None for item in modules):
        raise ValueError("private test modules must be explicit unittest module names")
    if len(modules) != len(set(modules)):
        raise ValueError("private test modules must be unique")
    return tuple(modules)


def _validate_config(config: GateConfig) -> None:
    if _COMMIT_RE.fullmatch(config.source_commit) is None:
        raise ValueError("source_commit must be one lowercase 40-hex commit ID")
    if not config.private_test_modules:
        raise ValueError("private_test_modules must not be empty")
    for module in config.private_test_modules:
        if _MODULE_RE.fullmatch(module) is None:
            raise ValueError("private test module is not explicit")
    if config.public_test_start_dir != "tests/public":
        raise ValueError("public test start directory must be tests/public")
    private_policy = Path(config.private_identifier_policy)
    if not private_policy.is_file() or private_policy.is_symlink():
        raise ValueError("private identifier policy must be one regular file")


def _private_identifier_module():
    try:
        module = importlib.import_module("tools.private_sensitive_identifiers")
    except ImportError as exc:
        raise GateError("private identifier scanner is unavailable") from exc
    required = (
        "load_identifier_policy",
        "scan_candidate_tree",
        "scan_release_artifacts",
        "scan_public_git",
    )
    if any(not callable(getattr(module, name, None)) for name in required):
        raise GateError("private identifier scanner contract is incomplete")
    return module


def _set_git_safe_directories(
    environment: dict[str, str],
    paths: Sequence[Path],
) -> None:
    for key in tuple(environment):
        upper = key.upper()
        if (
            upper == "GIT_CONFIG_COUNT"
            or upper.startswith("GIT_CONFIG_KEY_")
            or upper.startswith("GIT_CONFIG_VALUE_")
        ):
            environment.pop(key, None)
    values = tuple(dict.fromkeys(str(Path(path).resolve()) for path in paths))
    environment["GIT_CONFIG_COUNT"] = str(len(values))
    for index, value in enumerate(values):
        environment[f"GIT_CONFIG_KEY_{index}"] = "safe.directory"
        environment[f"GIT_CONFIG_VALUE_{index}"] = value


def _clean_environment(source_repo: Path) -> dict[str, str]:
    internal = str(Path(source_repo).resolve()).casefold()
    environment: dict[str, str] = {}
    for key, value in os.environ.items():
        upper = key.upper()
        if upper in {"PYTHONPATH", "PYTHONHOME"}:
            continue
        if (
            upper == "GIT_CONFIG_COUNT"
            or upper.startswith("GIT_CONFIG_KEY_")
            or upper.startswith("GIT_CONFIG_VALUE_")
        ):
            continue
        if internal and internal in value.casefold():
            continue
        environment[key] = value
    environment["PYTHONUTF8"] = "1"
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_DEFAULT_HASH"] = "sha1"
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    _set_git_safe_directories(environment, (source_repo,))
    return environment


def _run(arguments: Sequence[str], *, cwd: Path, environment: dict[str, str]):
    return subprocess.run(
        [str(item) for item in arguments],
        cwd=str(Path(cwd).resolve()),
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )


def _step_evidence(
    config: GateConfig,
    source_commit: str,
    name: str,
    payload: dict[str, object],
) -> Path:
    destination = Path(config.evidence_root) / source_commit / f"{name}.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return destination


def _step(
    config: GateConfig,
    source_commit: str,
    *,
    name: str,
    status: _STEP_STATUS,
    command: Sequence[str],
    returncode: int,
    started: float,
    details: dict[str, object],
) -> GateStepResult:
    duration = max(0.0, time.monotonic() - started)
    evidence = _step_evidence(
        config,
        source_commit,
        name,
        {
            "schema_version": 1,
            "source_commit": source_commit,
            "step": name,
            "status": status,
            "returncode": returncode,
            "duration_seconds": round(duration, 6),
            **details,
        },
    )
    return GateStepResult(
        name=name,
        status=status,
        source_commit=source_commit,
        command=tuple(command),
        returncode=returncode,
        evidence_file=evidence,
        duration_seconds=duration,
    )


def _remove_private_checkout(repo: Path, checkout: Path, parent: Path) -> None:
    checkout = Path(checkout)
    parent = Path(parent).resolve()
    if checkout.parent.resolve() != parent:
        raise GateError("private checkout escaped its approved parent")
    subprocess.run(
        ["git", "-C", str(Path(repo).resolve()), "worktree", "remove", "--force", str(checkout)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    subprocess.run(
        ["git", "-C", str(Path(repo).resolve()), "worktree", "prune"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if checkout.exists():
        if checkout.is_symlink() or checkout.resolve().parent != parent:
            raise GateError("refusing unsafe private checkout cleanup")
        shutil.rmtree(checkout)


def run_private_gate(config: GateConfig) -> GateStepResult:
    _validate_config(config)
    source_commit = resolve_source_commit(config.source_repo, config.source_commit)
    started = time.monotonic()
    checkout_parent = Path(config.candidates_parent) / "private-checkouts"
    checkout_parent.mkdir(parents=True, exist_ok=True)
    checkout = checkout_parent / f"{source_commit[:12]}-{uuid.uuid4().hex[:12]}"
    environment = _clean_environment(config.source_repo)
    _set_git_safe_directories(environment, (config.source_repo, checkout))
    added = False
    module_returncode = 1
    full_returncode = 1
    try:
        added_cp = _run(
            ["git", "worktree", "add", "--detach", str(checkout), source_commit],
            cwd=config.source_repo,
            environment=environment,
        )
        if added_cp.returncode != 0:
            return _step(
                config,
                source_commit,
                name="private-tests",
                status="failed",
                command=("git", "worktree", "add", "--detach", "<checkout>", source_commit),
                returncode=added_cp.returncode,
                started=started,
                details={"module_count": len(config.private_test_modules)},
            )
        added = True
        module_cp = _run(
            [sys.executable, "-m", "unittest", *config.private_test_modules, "-v"],
            cwd=checkout,
            environment=environment,
        )
        module_returncode = module_cp.returncode
        if module_returncode == 0:
            full_cp = _run(
                [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
                cwd=checkout,
                environment=environment,
            )
            full_returncode = full_cp.returncode
        status: _STEP_STATUS = (
            "passed" if module_returncode == 0 and full_returncode == 0 else "failed"
        )
        return _step(
            config,
            source_commit,
            name="private-tests",
            status=status,
            command=(
                "python", "-m", "unittest", *config.private_test_modules, "-v",
                "then", "python", "-m", "unittest", "discover", "-s", "tests", "-v",
            ),
            returncode=0 if status == "passed" else 1,
            started=started,
            details={
                "modules": list(config.private_test_modules),
                "module_returncode": module_returncode,
                "full_returncode": full_returncode,
            },
        )
    finally:
        if added or checkout.exists():
            _remove_private_checkout(config.source_repo, checkout, checkout_parent)


def _tracked_files(policy_path: Path) -> tuple[str, ...]:
    data = json.loads(Path(policy_path).read_text(encoding="utf-8"))
    values = data.get("tracked_files")
    if not isinstance(values, list) or not values:
        raise GateError("public policy has no tracked files")
    if any(not isinstance(value, str) or not value for value in values):
        raise GateError("public policy tracked files are invalid")
    if len(values) != len(set(values)):
        raise GateError("public policy tracked files are duplicated")
    return tuple(values)


def _candidate_digest(candidate_root: Path, policy_path: Path) -> str:
    digest = hashlib.sha256()
    for relative in _tracked_files(policy_path):
        path = Path(candidate_root) / relative
        if not path.is_file() or path.is_symlink():
            raise GateError("candidate tracked file is missing or linked")
        encoded = relative.encode("utf-8")
        content = path.read_bytes()
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _cleanup_candidate(candidate_root: Path, candidates_parent: Path) -> None:
    if Path(candidate_root).exists():
        cleanup_failed_candidate(candidate_root, candidates_parent)


def run_public_gate(candidate_root: Path, config: GateConfig) -> list[GateStepResult]:
    _validate_config(config)
    source_commit = resolve_source_commit(config.source_repo, config.source_commit)
    candidate_root = Path(candidate_root)
    policy_path = candidate_root / "release" / "public-release-policy.json"
    steps: list[GateStepResult] = []
    stage_commands = {
        "source-scan": ("scan_source_tree",),
        "public-tests": (
            "python",
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests/public",
            "-t",
            ".",
            "-v",
        ),
        "release-artifacts": (
            "build_candidate_release",
            "inspect_artifact",
            "verify_sha256s",
        ),
        "offline-rebuild": (
            "verify_offline_rebuild",
            "clean-install-smoke",
        ),
    }

    Path(config.evidence_root).mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=config.evidence_root) as temporary:
        work = Path(temporary)
        started = time.monotonic()
        try:
            artifacts = build_candidate_release(
                candidate_root,
                work / "dist",
                policy_path,
                work / "offline",
            )
        except CandidateBuildError as exc:
            stage = exc.stage if exc.stage in stage_commands else "release-artifacts"
            for completed in ("source-scan", "public-tests", "release-artifacts", "offline-rebuild"):
                if completed == stage:
                    break
                if completed not in exc.stage_durations:
                    continue
                duration = exc.stage_durations[completed]
                steps.append(
                    _step(
                        config,
                        source_commit,
                        name=completed,
                        status="passed",
                        command=stage_commands[completed],
                        returncode=0,
                        started=time.monotonic() - duration,
                        details={"completed_before_failure": True},
                    )
                )
            steps.append(
                _step(
                    config,
                    source_commit,
                    name=stage,
                    status="failed",
                    command=stage_commands[stage],
                    returncode=1,
                    started=started,
                    details={"error_type": type(exc).__name__},
                )
            )
            _cleanup_candidate(candidate_root, config.candidates_parent)
            return steps

        for stage in ("source-scan", "public-tests", "release-artifacts", "offline-rebuild"):
            details: dict[str, object]
            if stage == "source-scan":
                details = {"finding_rule_ids": []}
            elif stage == "public-tests":
                details = {"test_output_recorded": False}
            elif stage == "release-artifacts":
                details = {"assets": list(artifacts.names)}
            else:
                details = {"rebuilt_wheel": artifacts.rebuilt_wheel.name}
            duration = artifacts.stage_durations.get(stage, 0.0)
            stage_started = time.monotonic() - duration
            steps.append(
                _step(
                    config,
                    source_commit,
                    name=stage,
                    status="passed",
                    command=stage_commands[stage],
                    returncode=0,
                    started=stage_started,
                    details=details,
                )
            )

        private_started = time.monotonic()
        try:
            scanner = _private_identifier_module()
            private_policy = scanner.load_identifier_policy(config.private_identifier_policy)
            findings = [
                *scanner.scan_candidate_tree(candidate_root, private_policy),
                *scanner.scan_release_artifacts(
                    (*artifacts.paths, artifacts.rebuilt_wheel),
                    private_policy,
                ),
            ]
            finding_rule_ids = sorted({item.rule_id for item in findings})
        except Exception:
            finding_rule_ids = ["PRIVATE_IDENTIFIER_GATE_FAILED"]
        private_status: _STEP_STATUS = "failed" if finding_rule_ids else "passed"
        steps.append(
            _step(
                config,
                source_commit,
                name="private-identifiers",
                status=private_status,
                command=("scan_candidate_tree", "scan_release_artifacts"),
                returncode=1 if finding_rule_ids else 0,
                started=private_started,
                details={"finding_rule_ids": finding_rule_ids},
            )
        )
        if private_status == "failed":
            _cleanup_candidate(candidate_root, config.candidates_parent)
            return steps
    return steps


def _materialize_commit_file(
    repo: Path,
    source_commit: str,
    relative_path: str,
    destination: Path,
) -> Path:
    cp = subprocess.run(
        ["git", "-C", str(Path(repo).resolve()), "show", f"{source_commit}:{relative_path}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if cp.returncode != 0:
        raise GateError("required gate input is absent from the fixed commit")
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(cp.stdout)
    return destination


def _create_candidate_from_commit(config: GateConfig, source_commit: str) -> CandidateResult:
    manifest = _materialize_commit_file(
        config.source_repo,
        source_commit,
        "release/public-export-manifest.json",
        Path(config.evidence_root) / source_commit / "public-export-manifest.json",
    )
    return create_candidate(
        config.source_repo,
        source_commit,
        config.candidates_parent,
        manifest,
        mode="bootstrap",
    )


def _manual_review_status(
    config: GateConfig,
    source_commit: str,
    candidate_digest: str,
    policy_path: Path,
) -> str:
    review_path = Path(config.evidence_root) / f"manual-review-{source_commit}.json"
    if not review_path.is_file():
        return "missing"
    try:
        data = json.loads(review_path.read_text(encoding="utf-8"))
        expected_keys = {
            "source_commit",
            "candidate_sha256",
            "reviewer",
            "reviewed_at_utc",
            "files",
        }
        if not isinstance(data, dict) or set(data) != expected_keys:
            return "invalid"
        if data["source_commit"] != source_commit:
            return "invalid"
        if data["candidate_sha256"] != candidate_digest or _DIGEST_RE.fullmatch(candidate_digest) is None:
            return "invalid"
        if not isinstance(data["reviewer"], str) or not data["reviewer"].strip():
            return "invalid"
        if not isinstance(data["reviewed_at_utc"], str) or _UTC_RE.fullmatch(data["reviewed_at_utc"]) is None:
            return "invalid"
        if data["files"] != list(_tracked_files(policy_path)):
            return "invalid"
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return "invalid"
    return "passed"


def _write_report(
    config: GateConfig,
    *,
    status: _REPORT_STATUS,
    source_commit: str,
    steps: Sequence[GateStepResult],
    candidate_created: bool,
    candidate_root: Path | None,
    candidate_digest: str | None,
    artifacts: Sequence[str],
    manual_review_status: str,
) -> GateReport:
    evidence_path = Path(config.evidence_root) / f"gate-report-{source_commit}.json"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "status": status,
        "source_commit": source_commit,
        "steps": [
            {
                "name": item.name,
                "status": item.status,
                "returncode": item.returncode,
                "duration_seconds": round(item.duration_seconds, 6),
                "evidence_file": item.evidence_file.name if item.evidence_file else None,
            }
            for item in steps
        ],
        "candidate_created": candidate_created,
        "candidate_name": Path(candidate_root).name if candidate_root is not None else None,
        "candidate_sha256": candidate_digest,
        "artifacts": list(artifacts),
        "manual_review_status": manual_review_status,
    }
    evidence_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return GateReport(
        status=status,
        source_commit=source_commit,
        steps=tuple(steps),
        candidate_created=candidate_created,
        candidate_root=Path(candidate_root) if candidate_root is not None else None,
        candidate_digest=candidate_digest,
        artifacts=tuple(artifacts),
        manual_review_status=manual_review_status,
        evidence_path=evidence_path,
    )


def run_public_release_gate(config: GateConfig) -> GateReport:
    _validate_config(config)
    source_commit = resolve_source_commit(config.source_repo, config.source_commit)
    private_step = run_private_gate(config)
    steps: list[GateStepResult] = [private_step]
    if private_step.status != "passed":
        return _write_report(
            config,
            status="failed",
            source_commit=source_commit,
            steps=steps,
            candidate_created=False,
            candidate_root=None,
            candidate_digest=None,
            artifacts=(),
            manual_review_status="not_started",
        )

    candidate_result = _create_candidate_from_commit(config, source_commit)
    candidate_root = candidate_result.path
    public_steps = run_public_gate(candidate_root, config)
    steps.extend(public_steps)
    if any(item.status != "passed" for item in public_steps):
        _cleanup_candidate(candidate_root, config.candidates_parent)
        return _write_report(
            config,
            status="failed",
            source_commit=source_commit,
            steps=steps,
            candidate_created=True,
            candidate_root=candidate_root,
            candidate_digest=None,
            artifacts=(),
            manual_review_status="not_started",
        )

    policy_path = candidate_root / "release" / "public-release-policy.json"
    candidate_digest = _candidate_digest(candidate_root, policy_path)
    review_status = _manual_review_status(
        config,
        source_commit,
        candidate_digest,
        policy_path,
    )
    report_status: _REPORT_STATUS = (
        "passed" if review_status == "passed" else "awaiting_manual_review"
    )
    return _write_report(
        config,
        status=report_status,
        source_commit=source_commit,
        steps=steps,
        candidate_created=True,
        candidate_root=candidate_root,
        candidate_digest=candidate_digest,
        artifacts=(*_EXPECTED_ASSETS, "SHA256SUMS.txt"),
        manual_review_status=review_status,
    )

_INITIAL_PUBLIC_MESSAGE = "chore: publish v0.1.0 preview source"
_GIT_ENVIRONMENT_KEYS = {
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_WORK_TREE",
}
_LFS_POINTER_PREFIX = b"version " + b"https://git-lfs.github.com/spec/v1"


class RepositoryInitError(RuntimeError):
    """Raised when a reviewed candidate cannot become an isolated repository."""


@dataclass(frozen=True)
class PublicRepositoryReceipt:
    repository_root: Path
    initial_commit: str
    source_commit: str
    tracked_files: tuple[str, ...]
    object_ids: tuple[str, ...]


@dataclass(frozen=True)
class CiRunReceipt:
    run_id: int
    workflow: str
    public_commit: str
    conclusion: str
    matrix_results: tuple[tuple[str, str, str], ...]
    url: str


class AuthorizationError(RuntimeError):
    """Raised when a public release action lacks exact user authorization."""


def _validate_authorization_artifacts(artifacts: ReleaseArtifacts) -> tuple[str, ...]:
    expected = set(_EXPECTED_ASSETS) | {"SHA256SUMS.txt"}
    names = tuple(artifacts.names)
    if set(names) != expected or len(names) != len(expected):
        raise AuthorizationError("release authorization assets are incomplete")
    if set(artifacts.sha256) != expected:
        raise AuthorizationError("release authorization digests are incomplete")
    for path in (*artifacts.paths, artifacts.rebuilt_wheel):
        if not Path(path).is_file() or Path(path).is_symlink():
            raise AuthorizationError("release authorization artifact is unavailable")
    for path in artifacts.paths:
        digest = artifacts.sha256.get(path.name)
        if not isinstance(digest, str) or _DIGEST_RE.fullmatch(digest) is None:
            raise AuthorizationError("release authorization digest is invalid")
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest:
            raise AuthorizationError("release authorization artifact digest changed")
    return tuple(sorted(expected))


def render_first_authorization_packet(
    receipt: PublicRepositoryReceipt,
    artifacts: ReleaseArtifacts,
    destination: Path,
) -> Path:
    if _COMMIT_RE.fullmatch(receipt.initial_commit) is None:
        raise AuthorizationError("public commit is invalid")
    repository_root = Path(receipt.repository_root).resolve()
    if not repository_root.is_dir() or not receipt.tracked_files:
        raise AuthorizationError("public repository receipt is incomplete")
    raw_destination = Path(destination)
    if _path_is_link_or_junction(raw_destination):
        raise AuthorizationError("authorization packet destination must not be linked")
    destination = raw_destination.resolve()
    if destination == repository_root or repository_root in destination.parents:
        raise AuthorizationError("authorization evidence must stay outside the public repository")
    asset_names = _validate_authorization_artifacts(artifacts)

    lines = [
        "# 首次公开上传授权包",
        "",
        "## 本次申请",
        "",
        "申请创建公开 GitHub 仓库 `chemical-eia-skill`、添加 `origin`，并首次推送 `main`。",
        "",
        f"- 公开提交：`{receipt.initial_commit}`",
        "- 仓库名称：`chemical-eia-skill`",
        "- 可见性：公开（PUBLIC）",
        f"- 跟踪文件数：{len(receipt.tracked_files)}",
        "",
        "## 已完成的本地验证",
        "",
        "- 内部私有测试：通过",
        "- 公开源码、索引和 Git 历史扫描：通过",
        "- 构建产物及 SHA-256 验证：通过",
        "- 独立公开仓库人工复核：通过",
        "- Windows 与 Ubuntu、Python 3.10—3.13 CI：配置已冻结，首次推送后等待远程实跑",
        "",
        "## 精确跟踪文件",
        "",
    ]
    lines.extend(f"- `{relative}`" for relative in receipt.tracked_files)
    lines.extend(["", "## 发布资产", "", "| 文件 | SHA-256 |", "|---|---|"])
    for name in asset_names:
        lines.append(f"| `{name}` | `{artifacts.sha256[name]}` |")
    lines.extend(
        [
            "",
            "## 权限边界",
            "",
            "本次授权仅包括：创建公开 GitHub 仓库、添加 `origin`、首次推送 `main`。",
            "",
            "**本次授权不包括创建 `v0.1.0` 标签。**",
            "",
            "**本次授权不包括创建 GitHub Release。**",
            "",
            "远程 main CI 全部通过后，标签和 Preview Release 必须再次单独取得明确授权。",
        ]
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return destination


def assert_first_remote_authorization(
    authorization_record: Path,
    public_commit: str,
) -> None:
    if _COMMIT_RE.fullmatch(public_commit) is None:
        raise AuthorizationError("public commit is invalid")
    path = Path(authorization_record)
    if not path.is_file() or path.is_symlink():
        raise AuthorizationError("first public push authorization is missing")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise AuthorizationError("first public push authorization is unreadable") from exc
    expected_keys = {
        "schema_version",
        "authorization",
        "public_commit",
        "repository",
        "visibility",
        "approved_actions",
        "approved_by",
        "approved_at_utc",
    }
    if not isinstance(document, dict) or set(document) != expected_keys:
        raise AuthorizationError("first public push authorization has unexpected fields")
    if document["schema_version"] != 1 or isinstance(document["schema_version"], bool):
        raise AuthorizationError("first public push authorization schema is unsupported")
    if document["authorization"] != "first-public-push":
        raise AuthorizationError("first public push was not explicitly authorized")
    if document["public_commit"] != public_commit:
        raise AuthorizationError("first public push authorization commit does not match")
    if document["repository"] != "chemical-eia-skill" or document["visibility"] != "public":
        raise AuthorizationError("first public push repository target is not approved")
    if document["approved_actions"] != [
        "create-public-github-repository",
        "add-origin",
        "push-main",
    ]:
        raise AuthorizationError("first public push actions are not explicitly approved")
    if not isinstance(document["approved_by"], str) or not document["approved_by"].strip():
        raise AuthorizationError("first public push approver is missing")
    approved_at = document["approved_at_utc"]
    if not isinstance(approved_at, str) or _UTC_RE.fullmatch(approved_at) is None:
        raise AuthorizationError("first public push authorization timestamp is invalid")



def _validate_ci_run(ci_run: CiRunReceipt, public_commit: str) -> None:
    if not isinstance(ci_run, CiRunReceipt):
        raise AuthorizationError("release authorization CI receipt is invalid")
    if isinstance(ci_run.run_id, bool) or not isinstance(ci_run.run_id, int) or ci_run.run_id <= 0:
        raise AuthorizationError("release authorization CI run id is invalid")
    if ci_run.workflow != "test.yml":
        raise AuthorizationError("release authorization CI workflow is invalid")
    if ci_run.public_commit != public_commit:
        raise AuthorizationError("release authorization CI commit does not match")
    if ci_run.conclusion != "success":
        raise AuthorizationError("release authorization CI did not succeed")
    if not isinstance(ci_run.url, str) or not ci_run.url.startswith("https://github.com/"):
        raise AuthorizationError("release authorization CI URL is invalid")
    if "/actions/runs/" not in ci_run.url:
        raise AuthorizationError("release authorization CI URL is not a run URL")
    results = ci_run.matrix_results
    if not isinstance(results, tuple) or len(results) != len(_EXPECTED_CI_MATRIX):
        raise AuthorizationError("release authorization CI matrix is incomplete")
    combinations: set[tuple[str, str]] = set()
    for result in results:
        if not isinstance(result, tuple) or len(result) != 3:
            raise AuthorizationError("release authorization CI matrix row is invalid")
        operating_system, python_version, conclusion = result
        if conclusion != "success":
            raise AuthorizationError("release authorization CI matrix contains a failure")
        combinations.add((operating_system, python_version))
    if combinations != _EXPECTED_CI_MATRIX or len(combinations) != len(results):
        raise AuthorizationError("release authorization CI matrix does not match policy")


def _assert_authorization_destination(
    receipt: PublicRepositoryReceipt,
    destination: Path,
) -> tuple[Path, Path]:
    if _COMMIT_RE.fullmatch(receipt.initial_commit) is None:
        raise AuthorizationError("public commit is invalid")
    repository_root = Path(receipt.repository_root).resolve()
    if not repository_root.is_dir() or not receipt.tracked_files:
        raise AuthorizationError("public repository receipt is incomplete")
    raw_destination = Path(destination)
    if _path_is_link_or_junction(raw_destination):
        raise AuthorizationError("authorization packet destination must not be linked")
    resolved_destination = raw_destination.resolve()
    if resolved_destination == repository_root or repository_root in resolved_destination.parents:
        raise AuthorizationError("authorization evidence must stay outside the public repository")
    return repository_root, resolved_destination


def render_release_authorization_packet(
    receipt: PublicRepositoryReceipt,
    ci_run: CiRunReceipt,
    artifacts: ReleaseArtifacts,
    destination: Path,
) -> Path:
    _, destination = _assert_authorization_destination(receipt, destination)
    _validate_ci_run(ci_run, receipt.initial_commit)
    asset_names = _validate_authorization_artifacts(artifacts)

    lines = [
        "# v0.1.0 Preview Release 第二次授权包",
        "",
        "## 本次申请",
        "",
        "申请创建 annotated tag `v0.1.0`、推送该标签、调度 `release.yml`，并创建 GitHub prerelease。",
        "",
        f"- 公开提交：`{receipt.initial_commit}`",
        "- 标签：`v0.1.0`（annotated tag）",
        "- 发布状态：GitHub prerelease",
        "- 仓库：`chemical-eia-skill`",
        "",
        "## 远程 main CI",
        "",
        f"- 工作流：`{ci_run.workflow}`",
        f"- CI run ID：`{ci_run.run_id}`",
        f"- CI run：{ci_run.url}",
        f"- 总结论：`{ci_run.conclusion}`",
        "",
        "| 系统 | Python | 结果 |",
        "|---|---|---|",
    ]
    for operating_system, python_version, conclusion in sorted(ci_run.matrix_results):
        lines.append(f"| `{operating_system}` | `{python_version}` | `{conclusion}` |")
    lines.extend(["", "## 四个发布资产", "", "| 文件 | SHA-256 |", "|---|---|"])
    for name in asset_names:
        lines.append(f"| `{name}` | `{artifacts.sha256[name]}` |")
    lines.extend(
        [
            "",
            "## 发布说明摘要",
            "",
            "v0.1.0 Preview 提供结构化工序建模、当前已支持的反应物料衡算、确定性校验、四类成果输出和技术员确认闭环；不宣称可从原始可研报告自动完成整套工程分析。",
            "",
            "## 权限边界",
            "",
            "本次授权仅包括：创建并推送 `v0.1.0` annotated tag、调度正式发布工作流、创建标记为 prerelease 的 GitHub Release。",
            "",
            "授权必须同时绑定本页公开提交、CI run、四个资产摘要和 prerelease 状态；任何一项变化都需要重新生成授权包并再次确认。",
            "",
            "## 回滚边界",
            "",
            "- 标签推送前扫描失败：只删除尚未推送的本地标签并停止。",
            "- 发布工作流失败：不得手工绕过检查创建 Release。",
            "- 已发布资产与摘要不一致：停止传播并重新从固定公开提交构建，不覆盖旧资产。",
        ]
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return destination


def _parse_utc(value: object, field: str) -> datetime:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise AuthorizationError(f"release authorization {field} is invalid")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise AuthorizationError(f"release authorization {field} is invalid") from exc


def assert_release_authorization(
    authorization_record: Path,
    public_commit: str,
    tag: str = "v0.1.0",
    *,
    artifacts: ReleaseArtifacts,
    ci_run: CiRunReceipt,
) -> None:
    if _COMMIT_RE.fullmatch(public_commit) is None:
        raise AuthorizationError("public commit is invalid")
    if tag != "v0.1.0":
        raise AuthorizationError("preview release tag is invalid")
    asset_names = _validate_authorization_artifacts(artifacts)
    _validate_ci_run(ci_run, public_commit)

    path = Path(authorization_record)
    if not path.is_file() or path.is_symlink():
        raise AuthorizationError("preview release authorization is missing")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise AuthorizationError("preview release authorization is unreadable") from exc
    expected_keys = {
        "schema_version",
        "authorization",
        "public_commit",
        "tag",
        "repository",
        "prerelease",
        "ci_workflow",
        "ci_run_id",
        "asset_sha256",
        "approved_actions",
        "approved_by",
        "approved_at_utc",
        "expires_at_utc",
    }
    if not isinstance(document, dict) or set(document) != expected_keys:
        raise AuthorizationError("preview release authorization has unexpected fields")
    if document["schema_version"] != 1 or isinstance(document["schema_version"], bool):
        raise AuthorizationError("preview release authorization schema is unsupported")
    if document["authorization"] != "preview-release":
        raise AuthorizationError("preview release was not explicitly authorized")
    if document["public_commit"] != public_commit or document["tag"] != tag:
        raise AuthorizationError("preview release commit or tag does not match")
    if document["repository"] != "chemical-eia-skill" or document["prerelease"] is not True:
        raise AuthorizationError("preview release target or status is not approved")
    if document["ci_workflow"] != ci_run.workflow or document["ci_run_id"] != ci_run.run_id:
        raise AuthorizationError("preview release CI run does not match")
    expected_digests = {name: artifacts.sha256[name] for name in asset_names}
    if document["asset_sha256"] != expected_digests:
        raise AuthorizationError("preview release asset digests do not match")
    if document["approved_actions"] != _RELEASE_ACTIONS:
        raise AuthorizationError("preview release actions are not explicitly approved")
    if not isinstance(document["approved_by"], str) or not document["approved_by"].strip():
        raise AuthorizationError("preview release approver is missing")
    approved_at = _parse_utc(document["approved_at_utc"], "approval timestamp")
    expires_at = _parse_utc(document["expires_at_utc"], "expiration timestamp")
    if expires_at <= approved_at:
        raise AuthorizationError("preview release authorization expiration is invalid")
    if datetime.now(timezone.utc) >= expires_at:
        raise AuthorizationError("preview release authorization has expired")


def _path_is_link_or_junction(path: Path) -> bool:
    path = Path(path)
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction is not None and is_junction())


def _repository_environment(identity: tuple[str, str] | None = None) -> dict[str, str]:
    environment = os.environ.copy()
    for key in list(environment):
        if key.upper() in _GIT_ENVIRONMENT_KEYS:
            environment.pop(key, None)
    environment["PYTHONUTF8"] = "1"
    environment["PYTHONIOENCODING"] = "utf-8"
    if identity is not None:
        name, email = identity
        environment.update(
            {
                "GIT_AUTHOR_NAME": name,
                "GIT_AUTHOR_EMAIL": email,
                "GIT_COMMITTER_NAME": name,
                "GIT_COMMITTER_EMAIL": email,
            }
        )
    return environment


def _repository_git(
    repo: Path,
    arguments: Sequence[str],
    *,
    identity: tuple[str, str] | None = None,
    allowed_returncodes: frozenset[int] = frozenset({0}),
) -> subprocess.CompletedProcess[str]:
    cp = subprocess.run(
        ["git", "-C", str(Path(repo).resolve()), *[str(item) for item in arguments]],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        env=_repository_environment(identity),
    )
    if cp.returncode not in allowed_returncodes:
        raise RepositoryInitError("public repository Git command failed")
    return cp


def _read_git_identity(context: Path) -> tuple[str, str] | None:
    environment = os.environ
    author_name = environment.get("GIT_AUTHOR_NAME", "").strip()
    author_email = environment.get("GIT_AUTHOR_EMAIL", "").strip()
    committer_name = environment.get("GIT_COMMITTER_NAME", "").strip()
    committer_email = environment.get("GIT_COMMITTER_EMAIL", "").strip()
    name = author_name or committer_name
    email = author_email or committer_email
    if name and email:
        return name, email

    values = []
    for key in ("user.name", "user.email"):
        cp = subprocess.run(
            ["git", "-C", str(Path(context).resolve()), "config", "--get", key],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            env=_repository_environment(),
        )
        if cp.returncode not in {0, 1}:
            raise RepositoryInitError("Git commit identity could not be read")
        values.append(cp.stdout.strip() if cp.returncode == 0 else "")
    if all(values):
        return values[0], values[1]
    return None


def _candidate_actual_files(candidate_root: Path) -> tuple[str, ...]:
    files: list[str] = []
    for path in Path(candidate_root).rglob("*"):
        if _path_is_link_or_junction(path):
            raise RepositoryInitError("public candidate contains a linked path")
        if path.is_file():
            files.append(path.relative_to(candidate_root).as_posix())
    return tuple(sorted(files))


def _validate_repository_destination(candidate_root: Path, destination: Path) -> bool:
    raw_destination = Path(destination)
    if _path_is_link_or_junction(raw_destination):
        raise RepositoryInitError("public repository destination must not be linked")
    destination = raw_destination.resolve()
    candidate_root = Path(candidate_root).resolve()
    if destination == candidate_root or candidate_root in destination.parents or destination in candidate_root.parents:
        raise RepositoryInitError("public repository destination must be independent")
    if any(part.casefold() in {".git", ".worktrees"} for part in destination.parts):
        raise RepositoryInitError("public repository destination is inside internal Git metadata")
    if os.path.lexists(str(destination)):
        if _path_is_link_or_junction(destination) or not destination.is_dir():
            raise RepositoryInitError("public repository destination must be a real directory")
        if any(destination.iterdir()):
            raise RepositoryInitError("public repository destination must be empty")
        return True
    return False


def _retry_remove_readonly(function, path: str, exc_info) -> None:
    try:
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        function(path)
    except OSError:
        raise exc_info[1]


def _remove_repository_destination(destination: Path) -> None:
    destination = Path(destination).absolute()
    if destination.parent == destination or destination == Path(destination.anchor):
        raise RepositoryInitError("refusing to remove an unsafe repository destination")
    if os.path.lexists(str(destination)):
        if _path_is_link_or_junction(destination) or not destination.is_dir():
            raise RepositoryInitError("refusing to remove a linked repository destination")
        shutil.rmtree(destination, onerror=_retry_remove_readonly)


def _copy_reviewed_candidate(
    candidate_root: Path,
    destination: Path,
    tracked_files: Sequence[str],
) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for relative in tracked_files:
        source = Path(candidate_root) / relative
        target = Path(destination) / relative
        if not source.is_file() or _path_is_link_or_junction(source):
            raise RepositoryInitError("reviewed candidate file is unavailable")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def _parse_count_objects(output: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in output.splitlines():
        if ": " not in line:
            raise RepositoryInitError("git count-objects output is malformed")
        key, value = line.split(": ", 1)
        values[key] = value
    return values


def verify_initial_public_repository(
    repo: Path,
    policy_path: Path,
    internal_commit: str,
    private_identifier_policy: Path | None = None,
) -> PublicRepositoryReceipt:
    raw_repo = Path(repo)
    raw_policy = Path(policy_path)
    if _path_is_link_or_junction(raw_repo) or _path_is_link_or_junction(raw_policy):
        raise RepositoryInitError("public repository verification paths must not be linked")
    repo = raw_repo.resolve()
    policy_path = raw_policy.resolve()
    if not repo.is_dir() or not (repo / ".git").is_dir():
        raise RepositoryInitError("public repository is not initialized")
    expected_policy = (repo / "release/public-release-policy.json").resolve()
    if policy_path != expected_policy or not policy_path.is_file():
        raise RepositoryInitError("public repository policy path is invalid")
    if _COMMIT_RE.fullmatch(internal_commit) is None:
        raise RepositoryInitError("internal commit must be a lowercase full object ID")

    tracked_files = _tracked_files(policy_path)
    if _repository_git(repo, ("symbolic-ref", "--short", "HEAD")).stdout.strip() != "main":
        raise RepositoryInitError("public repository branch must be main")
    if _repository_git(repo, ("rev-parse", "--show-object-format")).stdout.strip() != "sha1":
        raise RepositoryInitError("public repository must use the audited SHA-1 object format")
    if _repository_git(repo, ("rev-list", "--all", "--count")).stdout.strip() != "1":
        raise RepositoryInitError("public repository must contain exactly one commit")
    if _repository_git(repo, ("status", "--short")).stdout.strip():
        raise RepositoryInitError("public repository worktree must be clean")
    if _repository_git(repo, ("remote",)).stdout.strip():
        raise RepositoryInitError("public repository must not contain remotes")
    if _repository_git(repo, ("tag", "--list")).stdout.strip():
        raise RepositoryInitError("public repository must not contain tags")
    refs = tuple(
        line
        for line in _repository_git(
            repo,
            ("for-each-ref", "--format=%(refname)"),
        ).stdout.splitlines()
        if line
    )
    if refs != ("refs/heads/main",):
        raise RepositoryInitError("public repository contains unexpected refs")
    message = _repository_git(repo, ("log", "-1", "--format=%s")).stdout.strip()
    if message != _INITIAL_PUBLIC_MESSAGE:
        raise RepositoryInitError("public repository initial message is not frozen")

    index_files = tuple(
        sorted(
            name
            for name in _repository_git(repo, ("ls-files", "-z")).stdout.split("\0")
            if name
        )
    )
    tree_files = tuple(
        sorted(
            name
            for name in _repository_git(
                repo,
                ("ls-tree", "-r", "--name-only", "HEAD", "-z"),
            ).stdout.split("\0")
            if name
        )
    )
    if index_files != tuple(sorted(tracked_files)) or tree_files != tuple(sorted(tracked_files)):
        raise RepositoryInitError("public repository tree does not match tracked_files")
    if ".gitmodules" in tree_files:
        raise RepositoryInitError("public repository must not contain submodules")
    for relative in tree_files:
        content = (repo / relative).read_bytes()
        if content.startswith(_LFS_POINTER_PREFIX):
            raise RepositoryInitError("public repository must not contain Git LFS pointers")

    forbidden_git_metadata = (
        repo / ".git" / "objects" / "info" / "alternates",
        repo / ".git" / "info" / "grafts",
        repo / ".git" / "shallow",
    )
    if any(os.path.lexists(str(path)) for path in forbidden_git_metadata):
        raise RepositoryInitError("public repository must not use shared or rewritten history metadata")
    forbidden = _repository_git(
        repo,
        ("cat-file", "-e", internal_commit + "^{commit}"),
        allowed_returncodes=frozenset({0, 1, 128}),
    )
    if forbidden.returncode == 0:
        raise RepositoryInitError("internal commit is present in the public object database")

    index_findings = scan_git_index(repo, policy_path)
    history_findings = scan_git_history(repo, policy_path, forbidden_object_ids=(internal_commit,))
    if index_findings or history_findings:
        raise RepositoryInitError("public repository Git scan found blocked content")

    if private_identifier_policy is not None:
        raw_private_policy = Path(private_identifier_policy)
        if _path_is_link_or_junction(raw_private_policy):
            raise RepositoryInitError("private identifier policy must not be linked")
        private_policy_path = raw_private_policy.resolve()
        if not private_policy_path.is_file():
            raise RepositoryInitError("private identifier policy is unavailable")
        try:
            scanner = _private_identifier_module()
            private_policy = scanner.load_identifier_policy(private_policy_path)
            private_findings = scanner.scan_public_git(repo, private_policy)
        except Exception as exc:
            raise RepositoryInitError("public repository private identifier scan failed") from exc
        if private_findings:
            raise RepositoryInitError("public repository contains a private identifier")

    objects = enumerate_git_objects(repo)
    object_ids = tuple(sorted(item.object_id for item in objects))
    reachable = tuple(
        sorted(
            line.split(" ", 1)[0]
            for line in _repository_git(repo, ("rev-list", "--objects", "--all")).stdout.splitlines()
            if line
        )
    )
    if object_ids != reachable:
        raise RepositoryInitError("public repository contains unreachable or foreign objects")
    count_values = _parse_count_objects(
        _repository_git(repo, ("count-objects", "-v")).stdout
    )
    try:
        counted_objects = int(count_values["count"]) + int(count_values["in-pack"])
    except (KeyError, ValueError) as exc:
        raise RepositoryInitError("git count-objects output is incomplete") from exc
    if counted_objects != len(object_ids):
        raise RepositoryInitError("public repository object counts are inconsistent")

    initial_commit = _repository_git(repo, ("rev-parse", "HEAD")).stdout.strip()
    if initial_commit == internal_commit or _COMMIT_RE.fullmatch(initial_commit) is None:
        raise RepositoryInitError("public repository initial commit is not independent")
    return PublicRepositoryReceipt(
        repository_root=repo,
        initial_commit=initial_commit,
        source_commit=internal_commit,
        tracked_files=tuple(tracked_files),
        object_ids=object_ids,
    )


def initialize_public_repository(
    candidate_root: Path,
    destination: Path,
    gate_report: GateReport,
    initial_message: str,
    private_identifier_policy: Path | None = None,
) -> PublicRepositoryReceipt:
    raw_candidate = Path(candidate_root)
    raw_destination = Path(destination)
    if _path_is_link_or_junction(raw_candidate):
        raise RepositoryInitError("public candidate must not be linked")
    if _path_is_link_or_junction(raw_destination):
        raise RepositoryInitError("public repository destination must not be linked")
    candidate_root = raw_candidate.resolve()
    destination = raw_destination.resolve()
    if not candidate_root.is_dir() or os.path.lexists(str(candidate_root / ".git")):
        raise RepositoryInitError("public candidate must be a non-Git directory")
    if initial_message != _INITIAL_PUBLIC_MESSAGE:
        raise RepositoryInitError("public repository initial message is not approved")
    if (
        gate_report.status != "passed"
        or gate_report.manual_review_status != "passed"
        or not gate_report.candidate_created
        or gate_report.candidate_root is None
        or Path(gate_report.candidate_root).resolve() != candidate_root
        or _COMMIT_RE.fullmatch(gate_report.source_commit) is None
    ):
        raise RepositoryInitError("public candidate has no matching passed gate report")
    expected_assets = set(_EXPECTED_ASSETS) | {"SHA256SUMS.txt"}
    if set(gate_report.artifacts) != expected_assets:
        raise RepositoryInitError("public gate report release assets are incomplete")

    policy_path = candidate_root / "release/public-release-policy.json"
    tracked_files = _tracked_files(policy_path)
    findings = scan_source_tree(candidate_root, policy_path)
    if findings or _candidate_actual_files(candidate_root) != tuple(sorted(tracked_files)):
        raise RepositoryInitError("public candidate tree is not the reviewed allowlist")
    try:
        digest = _candidate_digest(candidate_root, policy_path)
    except GateError as exc:
        raise RepositoryInitError("public candidate digest could not be recomputed") from exc
    if digest != gate_report.candidate_digest:
        raise RepositoryInitError("public candidate changed after gate review")

    destination_preexisted = _validate_repository_destination(candidate_root, raw_destination)
    identity = _read_git_identity(candidate_root)
    if identity is None:
        raise RepositoryInitError("public Git commit identity is not configured")

    try:
        _copy_reviewed_candidate(candidate_root, destination, tracked_files)
        _repository_git(
            destination,
            ("init", "-b", "main", "--template="),
            identity=identity,
        )
        _repository_git(destination, ("add", "--", *tracked_files), identity=identity)
        staged = tuple(
            sorted(
                name
                for name in _repository_git(
                    destination,
                    ("diff", "--cached", "--name-only", "-z"),
                    identity=identity,
                ).stdout.split("\0")
                if name
            )
        )
        if staged != tuple(sorted(tracked_files)):
            raise RepositoryInitError("public repository staged files do not match tracked_files")
        _repository_git(
            destination,
            ("-c", "commit.gpgSign=false", "commit", "-m", initial_message),
            identity=identity,
        )
        return verify_initial_public_repository(
            destination,
            destination / "release/public-release-policy.json",
            gate_report.source_commit,
            private_identifier_policy=private_identifier_policy,
        )
    except (OSError, RuntimeError, ValueError, TypeError, RepositoryInitError):
        if destination.exists() or destination_preexisted:
            _remove_repository_destination(destination)
        raise
