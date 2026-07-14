"""Build and inspect the public Gate 2 release artifacts."""

from __future__ import annotations

import base64
import csv
import hashlib
import importlib.metadata
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import venv
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath


REQUIRED_SKILL_MEMBERS = ("SKILL.md",)
OPTIONAL_SKILL_MEMBERS = ("agents/openai.yaml",)

_DENY_NAME_PATTERNS = (
    re.compile(r"(?:^|/)(?:tests/fixtures|tests/evals|doc|\.git|\.worktrees|\.cache|\.superpowers|__pycache__)(?:/|$)", re.I),
    re.compile(r"(?:^|/)(?:handoffs?)(?:/|$)", re.I),
    re.compile(r"(?:^|/)(?:agent-report|test-output)(?:\.[^/]*)?$", re.I),
    re.compile(r"(?:^|/)[^/]+\.(?:pyc|pyo|tmp|bak|swp)$", re.I),
)
_DENY_CONTENT_PATTERNS = (
    ("machine path", re.compile(rb"(?<![A-Za-z0-9])[A-Za-z]:[\\/]")),
    ("user home path", re.compile(rb"/(?:home|Users)/", re.I)),
    (
        "case oracle",
        re.compile(rb"case[-_]001|expected[-_]values|expert[-_]decisions", re.I),
    ),
    ("test oracle path", re.compile(rb"tests[\\/]fixtures|tests[\\/]evals", re.I)),
    (
        "secret prefix",
        re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\b(?:sk|ghp)_[A-Za-z0-9_-]{12,}", re.I),
    ),
)
_SECRET_ASSIGNMENT = re.compile(
    rb"[\"']?[A-Za-z0-9_]*(?:token|session|credential|secret|password)[A-Za-z0-9_]*[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_./+=:-]{8,})",
    re.I,
)
_WINDOWS_ABSOLUTE_MEMBER = re.compile(r"^(?:[A-Za-z]:/|//)")


def _clean_environment():
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() not in {
            "PYTHONPATH",
            "PYTHONHOME",
            "PYTHONIOENCODING",
            "PYTHONUTF8",
        }
    }
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["PYTHONUTF8"] = "1"
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def _run(args, *, cwd: Path):
    return subprocess.run(
        [str(arg) for arg in args],
        cwd=str(Path(cwd).resolve()),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=_clean_environment(),
    )


def build_artifacts(repo: Path, dist_dir: Path) -> tuple[Path, Path]:
    repo = Path(repo).resolve()
    dist_dir = Path(dist_dir).resolve()
    dist_dir.mkdir(parents=True, exist_ok=True)
    cp = _run(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--wheel",
            "--sdist",
            "--outdir",
            dist_dir,
            repo,
        ],
        cwd=dist_dir.parent,
    )
    if cp.returncode != 0:
        raise RuntimeError("artifact build failed:\n{}".format(cp.stderr))
    wheels = sorted(dist_dir.glob("chemical_eia_core-*.whl"))
    sdists = sorted(dist_dir.glob("chemical_eia_core-*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise RuntimeError(
            "expected one wheel and one sdist, found wheels={!r}, sdists={!r}".format(
                wheels,
                sdists,
            )
        )
    return wheels[0], sdists[0]


def build_skill_archive(skill_dir: Path, archive_path: Path) -> Path:
    skill_dir = Path(skill_dir).resolve()
    archive_path = Path(archive_path).resolve()
    if archive_path == skill_dir or skill_dir in archive_path.parents:
        raise ValueError("Skill archive must be written outside the Skill source directory")

    members = []
    for relative in REQUIRED_SKILL_MEMBERS:
        source = skill_dir / relative
        if not source.is_file():
            raise FileNotFoundError("required Skill member is missing: {}".format(source))
        members.append((relative, source))
    for relative in OPTIONAL_SKILL_MEMBERS:
        source = skill_dir / relative
        if source.is_file():
            members.append((relative, source))

    archive_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = archive_path.with_name(archive_path.name + ".tmp")
    root_name = skill_dir.name
    try:
        with zipfile.ZipFile(temp_path, "w", zipfile.ZIP_DEFLATED) as archive:
            for relative, source in members:
                archive.write(source, "{}/{}".format(root_name, relative))
        temp_path.replace(archive_path)
    finally:
        if temp_path.exists():
            temp_path.unlink()
    return archive_path


def rebuild_wheel_from_sdist(sdist: Path, output_dir: Path) -> Path:
    sdist = Path(sdist).resolve()
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    cp = _run(
        [
            sys.executable,
            "-m",
            "pip",
            "--isolated",
            "wheel",
            "--no-cache-dir",
            "--no-index",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            output_dir,
            sdist,
        ],
        cwd=output_dir,
    )
    if cp.returncode != 0:
        raise RuntimeError("offline sdist rebuild failed:\n{}".format(cp.stderr))
    wheels = sorted(output_dir.glob("chemical_eia_core-*.whl"))
    if len(wheels) != 1:
        raise RuntimeError("expected one rebuilt wheel, found {!r}".format(wheels))
    return wheels[0]


def _scan_member(name: str, content: bytes | None, findings: list[str], deny_patterns):
    normalized = name.replace("\\", "/").rstrip("/")
    pure = PurePosixPath(normalized)
    if (
        not normalized
        or pure.is_absolute()
        or _WINDOWS_ABSOLUTE_MEMBER.match(normalized)
        or ".." in pure.parts
        or "\x00" in normalized
    ):
        findings.append("unsafe member path: {}".format(normalized))
    if "\\" in name:
        findings.append("non-POSIX member path: {}".format(name))
    for pattern in _DENY_NAME_PATTERNS:
        if pattern.search(normalized):
            findings.append("denied member name: {}".format(normalized))
            break
    if content is None:
        return
    for label, pattern in _DENY_CONTENT_PATTERNS:
        if pattern.search(content):
            findings.append("{} in {}".format(label, normalized))
            break
    secret_match = _SECRET_ASSIGNMENT.search(content)
    if secret_match:
        value = secret_match.group(1).lower()
        if value not in {b"placeholder", b"changeme", b"example-value"}:
            findings.append("secret assignment in {}".format(normalized))
    for index, pattern in enumerate(deny_patterns):
        matched = False
        if isinstance(pattern, bytes):
            matched = pattern in content
        elif hasattr(pattern, "search"):
            target = content if isinstance(pattern.pattern, bytes) else normalized
            matched = pattern.search(target) is not None
        else:
            raise TypeError("deny patterns must be bytes or compiled regex")
        if matched:
            findings.append("custom deny pattern {} in {}".format(index, normalized))


def _expected_member_sets(allowlist):
    normalized = [str(name).replace("\\", "/").rstrip("/") for name in allowlist]
    if any(not name for name in normalized):
        raise ValueError("artifact allowlist contains an empty member")
    if len(normalized) != len(set(normalized)):
        raise ValueError("artifact allowlist contains duplicate members")
    if len(normalized) != len({name.casefold() for name in normalized}):
        raise ValueError("artifact allowlist contains case collisions")
    allowed = set(normalized)
    directories = {
        name
        for name in allowed
        if any(other.startswith(name + "/") for other in allowed)
    }
    return allowed - directories, directories


def _compare_members(actual_files, actual_directories, expected_files, expected_directories, findings):
    for name in sorted(actual_files - expected_files):
        findings.append("unexpected member: {}".format(name))
    for name in sorted(expected_files - actual_files):
        findings.append("missing required member: {}".format(name))
    for name in sorted(actual_directories - expected_directories):
        findings.append("unexpected directory: {}".format(name))
    for name in sorted(expected_directories - actual_directories):
        findings.append("missing required directory: {}".format(name))


def inspect_artifact(path: Path, allowlist, deny_patterns=()) -> list[str]:
    path = Path(path).resolve()
    expected_files, expected_directories = _expected_member_sets(allowlist)
    findings = []
    actual_files = []
    actual_directories = []
    all_names = []
    try:
        if path.suffix in {".whl", ".zip"}:
            with zipfile.ZipFile(path) as archive:
                if archive.comment:
                    findings.append("zip comment is not allowed")
                infos = archive.infolist()
                for info in infos:
                    original_name = getattr(info, "orig_filename", info.filename)
                    normalized = info.filename.replace("\\", "/").rstrip("/")
                    all_names.append(normalized)
                    if info.is_dir():
                        actual_directories.append(normalized)
                        content = None
                    else:
                        actual_files.append(normalized)
                        content = None if info.flag_bits & 0x1 else archive.read(info)
                    mode = (info.external_attr >> 16) & 0xFFFF
                    member_type = stat.S_IFMT(mode)
                    if member_type == stat.S_IFLNK:
                        findings.append("unsupported zip symlink: {}".format(normalized))
                    elif (
                        member_type not in {0, stat.S_IFREG}
                        and not info.is_dir()
                    ):
                        findings.append("unsupported zip member type: {}".format(normalized))
                    if info.flag_bits & 0x1:
                        findings.append("encrypted zip member: {}".format(normalized))
                    _scan_member(original_name, content, findings, deny_patterns)
        elif path.suffixes[-2:] == [".tar", ".gz"]:
            with tarfile.open(path, "r:gz") as archive:
                members = archive.getmembers()
                for member in members:
                    normalized = member.name.replace("\\", "/").rstrip("/")
                    all_names.append(normalized)
                    content = None
                    if member.isdir():
                        actual_directories.append(normalized)
                    else:
                        actual_files.append(normalized)
                        if member.isfile():
                            stream = archive.extractfile(member)
                            content = None if stream is None else stream.read()
                        else:
                            findings.append(
                                "unsupported tar member type: {}".format(normalized)
                            )
                            if member.issym() or member.islnk():
                                link = member.linkname.replace("\\", "/")
                                if (
                                    PurePosixPath(link).is_absolute()
                                    or ".." in PurePosixPath(link).parts
                                ):
                                    findings.append(
                                        "unsafe tar link target: {}".format(normalized)
                                    )
                    _scan_member(member.name, content, findings, deny_patterns)
        else:
            raise ValueError("unsupported release artifact: {}".format(path))
    except (OSError, RuntimeError, tarfile.TarError, zipfile.BadZipFile):
        return ["artifact could not be inspected"]

    if len(all_names) != len(set(all_names)):
        findings.append("duplicate archive member")
    if len(all_names) != len({name.casefold() for name in all_names}):
        findings.append("case-colliding archive member")
    _compare_members(
        set(actual_files),
        set(actual_directories),
        expected_files,
        expected_directories,
        findings,
    )
    return sorted(set(findings))

_FINAL_ASSET_NAMES = (
    "SHA256SUMS.txt",
    "analyzing-chemical-eia-processes-0.1.0.zip",
    "chemical_eia_core-0.1.0-py3-none-any.whl",
    "chemical_eia_core-0.1.0.tar.gz",
)
_OUTPUT_NAMES = {
    "project-model.yaml",
    "process-flow.mmd",
    "diagnostic-balance.yaml",
    "review-report.md",
}
_BUILD_GENERATED_PATHS = (
    "build",
    "src/chemical_eia_core.egg-info",
)
_PROXY_VARIABLES = {
    "ALL_PROXY",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "PIP_EXTRA_INDEX_URL",
    "PIP_INDEX_URL",
    "PIP_TRUSTED_HOST",
}


class CandidateBuildError(RuntimeError):
    """Raised when an isolated public candidate cannot be verified safely."""

    def __init__(self, message: str, *, stage: str = "release-artifacts"):
        super().__init__(message)
        self.stage = stage
        self.stage_durations: dict[str, float] = {}


@dataclass(frozen=True)
class ReleaseArtifacts:
    wheel: Path
    sdist: Path
    skill_zip: Path
    checksums: Path
    rebuilt_wheel: Path
    sha256: dict[str, str]
    stage_durations: dict[str, float] = field(default_factory=dict)

    @property
    def paths(self) -> tuple[Path, ...]:
        return (self.checksums, self.skill_zip, self.wheel, self.sdist)

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(path.name for path in self.paths)


def _is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _is_link_or_junction(path: Path) -> bool:
    path = Path(path)
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction is not None and is_junction())


def _assert_unrelated_paths(*paths: Path) -> None:
    for index, left in enumerate(paths):
        for right in paths[index + 1 :]:
            if _is_within(left, right) or _is_within(right, left):
                raise CandidateBuildError("candidate, dist, and offline paths must be independent")


def _prepare_empty_directory(path: Path) -> Path:
    raw_path = Path(path)
    if _is_link_or_junction(raw_path):
        raise CandidateBuildError("release work directory must not be linked")
    path = raw_path.resolve()
    if os.path.lexists(str(path)):
        if _is_link_or_junction(path) or not path.is_dir():
            raise CandidateBuildError("release work directory must be a real directory")
        if any(path.iterdir()):
            raise CandidateBuildError("release work directory must be empty")
    else:
        path.mkdir(parents=True)
    return path


def _remove_owned_directory(path: Path) -> None:
    path = Path(path).absolute()
    anchor = Path(path.anchor)
    if path == anchor or path.parent == path:
        raise CandidateBuildError("refusing to remove an unsafe release directory")
    if os.path.lexists(str(path)):
        if _is_link_or_junction(path) or not path.is_dir():
            raise CandidateBuildError("refusing to remove a linked release directory")
        shutil.rmtree(path)


def _cleanup_build_generated_paths(candidate_root: Path) -> None:
    candidate_root = Path(candidate_root).resolve()
    for relative in _BUILD_GENERATED_PATHS:
        target = (candidate_root / relative).resolve()
        if not _is_within(target, candidate_root) or target == candidate_root:
            raise CandidateBuildError("unsafe generated build path")
        if not os.path.lexists(str(target)):
            continue
        if target.is_symlink() or target.is_file():
            target.unlink()
        else:
            shutil.rmtree(target)


def _load_release_policy(policy_path: Path) -> dict:
    try:
        policy = json.loads(Path(policy_path).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise CandidateBuildError("public release policy could not be loaded") from exc
    required = {
        "version",
        "wheel_exact_files",
        "sdist_exact_files",
        "sdist_exact_directories",
        "skill_zip_exact_files",
    }
    if not isinstance(policy, dict) or not required.issubset(policy):
        raise CandidateBuildError("public release policy is incomplete")
    if policy["version"] != "0.1.0":
        raise CandidateBuildError("unsupported public release version")
    return policy


def _assert_clean_source_tree(candidate_root: Path, policy_path: Path) -> None:
    from tools.public_scan import scan_source_tree

    findings = scan_source_tree(candidate_root, policy_path)
    if findings:
        rule_ids = sorted({finding.rule_id for finding in findings})
        raise CandidateBuildError(
            "public source scan failed: {}".format(", ".join(rule_ids)),
            stage="source-scan",
        )


def _run_public_tests(candidate_root: Path) -> None:
    cp = _run(
        [
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests/public",
            "-t",
            ".",
            "-v",
        ],
        cwd=candidate_root,
    )
    if cp.returncode != 0:
        raise CandidateBuildError("public candidate tests failed", stage="public-tests")


def _assert_artifact_contract(path: Path, allowlist) -> None:
    findings = inspect_artifact(path, allowlist)
    if findings:
        raise CandidateBuildError("release artifact contract failed")


def _venv_python(environment_root: Path) -> Path:
    scripts = "Scripts" if os.name == "nt" else "bin"
    executable = "python.exe" if os.name == "nt" else "python"
    return Path(environment_root) / scripts / executable


def _venv_site_packages(environment_root: Path) -> Path:
    python = _venv_python(environment_root)
    cp = subprocess.run(
        [str(python), "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
        cwd=str(Path(environment_root).resolve()),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=_clean_environment(),
    )
    if cp.returncode != 0 or not cp.stdout.strip():
        raise CandidateBuildError("isolated environment site-packages could not be located")
    return Path(cp.stdout.strip()).resolve()


def _copy_distribution_to_site_packages(name: str, site_packages: Path) -> None:
    try:
        distribution = importlib.metadata.distribution(name)
    except importlib.metadata.PackageNotFoundError as exc:
        raise CandidateBuildError("approved offline build backend is unavailable") from exc
    copied = 0
    for item in distribution.files or ():
        relative = str(item).replace("\\", "/")
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts:
            continue
        source = Path(distribution.locate_file(item)).resolve()
        if not source.is_file():
            continue
        destination = (site_packages / Path(*pure.parts)).resolve()
        if not _is_within(destination, site_packages):
            raise CandidateBuildError("offline backend file escaped site-packages")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        copied += 1
    metadata_source = Path(distribution._path).resolve()
    metadata_destination = (site_packages / metadata_source.name).resolve()
    if not _is_within(metadata_destination, site_packages):
        raise CandidateBuildError("offline backend metadata escaped site-packages")
    if metadata_source.is_dir():
        shutil.copytree(metadata_source, metadata_destination, dirs_exist_ok=True)
        copied += 1
    elif metadata_source.is_file():
        shutil.copyfile(metadata_source, metadata_destination)
        copied += 1
    if copied == 0:
        raise CandidateBuildError("approved offline build backend had no copyable files")


def _offline_environment() -> dict[str, str]:
    environment = _clean_environment()
    for key in list(environment):
        if key.upper() in _PROXY_VARIABLES:
            environment.pop(key, None)
    environment["PIP_NO_INDEX"] = "1"
    environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    environment["PIP_NO_CACHE_DIR"] = "1"
    return environment


def _install_network_blocker(site_packages: Path, log_path: Path) -> None:
    payload = "\n".join(
        [
            "import socket",
            "from pathlib import Path",
            "_network_log = Path({!r})".format(str(Path(log_path).resolve())),
            "def _blocked(*args, **kwargs):",
            "    _network_log.parent.mkdir(parents=True, exist_ok=True)",
            "    with _network_log.open('a', encoding='utf-8') as stream:",
            "        stream.write('network connection attempted\\n')",
            "    raise OSError('network access is disabled for offline release verification')",
            "class _BlockedSocket(socket.socket):",
            "    def connect(self, *args, **kwargs):",
            "        return _blocked(*args, **kwargs)",
            "socket.socket = _BlockedSocket",
            "socket.create_connection = _blocked",
            "",
        ]
    )
    (Path(site_packages) / "sitecustomize.py").write_text(
        payload,
        encoding="utf-8",
        newline="\n",
    )


def _verify_wheel_record(wheel: Path) -> dict[str, bytes]:
    try:
        with zipfile.ZipFile(wheel) as archive:
            members = {
                info.filename: archive.read(info)
                for info in archive.infolist()
                if not info.is_dir()
            }
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise CandidateBuildError("wheel RECORD could not be verified") from exc
    record_names = [name for name in members if name.endswith(".dist-info/RECORD")]
    if len(record_names) != 1:
        raise CandidateBuildError("wheel must contain exactly one RECORD")
    record_name = record_names[0]
    try:
        rows = list(csv.reader(io.StringIO(members[record_name].decode("utf-8"))))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise CandidateBuildError("wheel RECORD is malformed") from exc
    records: dict[str, tuple[str, str]] = {}
    for row in rows:
        if len(row) != 3 or row[0] in records:
            raise CandidateBuildError("wheel RECORD is malformed")
        records[row[0]] = (row[1], row[2])
    if set(records) != set(members):
        raise CandidateBuildError("wheel RECORD paths do not match wheel members")
    for name, content in members.items():
        digest, size = records[name]
        if name == record_name:
            if digest or size:
                raise CandidateBuildError("wheel RECORD self-entry must be unhashed")
            continue
        expected_digest = "sha256=" + base64.urlsafe_b64encode(
            hashlib.sha256(content).digest()
        ).rstrip(b"=").decode("ascii")
        if digest != expected_digest or size != str(len(content)):
            raise CandidateBuildError("wheel RECORD digest or size mismatch")
    return members


def _assert_semantically_equal_wheels(
    reference_wheel: Path,
    rebuilt_wheel: Path,
    policy: dict,
) -> None:
    reference = _verify_wheel_record(reference_wheel)
    rebuilt = _verify_wheel_record(rebuilt_wheel)
    suffixes = (
        "/METADATA",
        "/WHEEL",
        "/entry_points.txt",
        "/top_level.txt",
    )
    compared = [
        name
        for name in policy["wheel_exact_files"]
        if name.startswith("chemical_eia/") or name.endswith(suffixes)
    ]
    for name in compared:
        if reference.get(name) != rebuilt.get(name):
            raise CandidateBuildError("offline rebuilt wheel is not semantically equal")


def verify_offline_rebuild(
    sdist: Path,
    reference_wheel: Path,
    offline_dir: Path,
    policy_path: Path,
) -> Path:
    raw_sdist = Path(sdist)
    raw_reference_wheel = Path(reference_wheel)
    raw_policy_path = Path(policy_path)
    raw_offline_dir = Path(offline_dir)
    if any(
        _is_link_or_junction(path)
        for path in (raw_sdist, raw_reference_wheel, raw_policy_path, raw_offline_dir)
    ):
        raise CandidateBuildError("offline rebuild inputs must not be linked", stage="offline-rebuild")
    sdist = raw_sdist.resolve()
    reference_wheel = raw_reference_wheel.resolve()
    policy_path = raw_policy_path.resolve()
    if not sdist.is_file() or not reference_wheel.is_file() or not policy_path.is_file():
        raise CandidateBuildError("offline rebuild inputs must be regular files", stage="offline-rebuild")
    policy = _load_release_policy(policy_path)
    offline_dir = _prepare_empty_directory(raw_offline_dir)
    network_log = offline_dir / "network-attempts.log"
    try:
        input_dir = offline_dir / "input"
        output_dir = offline_dir / "output"
        environment_root = offline_dir / "build-venv"
        input_dir.mkdir()
        output_dir.mkdir()
        copied_sdist = input_dir / sdist.name
        shutil.copyfile(sdist, copied_sdist)

        venv.EnvBuilder(with_pip=True, clear=False).create(environment_root)
        site_packages = _venv_site_packages(environment_root)
        for distribution_name in ("setuptools", "wheel", "packaging"):
            _copy_distribution_to_site_packages(distribution_name, site_packages)
        _install_network_blocker(site_packages, network_log)

        cp = subprocess.run(
            [
                str(_venv_python(environment_root)),
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--no-index",
                "--no-build-isolation",
                "--wheel-dir",
                str(output_dir),
                str(copied_sdist),
            ],
            cwd=str(offline_dir),
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=_offline_environment(),
        )
        if cp.returncode != 0:
            raise CandidateBuildError("offline sdist rebuild failed", stage="offline-rebuild")
        if network_log.exists() and network_log.read_text(encoding="utf-8").strip():
            raise CandidateBuildError("offline rebuild attempted network access", stage="offline-rebuild")
        wheels = sorted(output_dir.glob("chemical_eia_core-*.whl"))
        if len(wheels) != 1:
            raise CandidateBuildError("offline rebuild produced an unexpected wheel set", stage="offline-rebuild")
        rebuilt = wheels[0].resolve()
        _assert_artifact_contract(rebuilt, policy["wheel_exact_files"])
        _assert_semantically_equal_wheels(reference_wheel, rebuilt, policy)
        return rebuilt
    except CandidateBuildError as exc:
        exc.stage = "offline-rebuild"
        raise
    except (OSError, RuntimeError, ValueError, TypeError) as exc:
        raise CandidateBuildError("offline rebuild verification failed", stage="offline-rebuild") from exc


def _smoke_install_and_run(candidate_root: Path, rebuilt_wheel: Path, offline_dir: Path) -> None:
    smoke_venv = Path(offline_dir) / "smoke-venv"
    venv.EnvBuilder(with_pip=True, clear=False).create(smoke_venv)
    smoke_site_packages = _venv_site_packages(smoke_venv)
    network_log = Path(offline_dir) / "network-attempts.log"
    _install_network_blocker(smoke_site_packages, network_log)
    python = _venv_python(smoke_venv)
    install = subprocess.run(
        [str(python), "-m", "pip", "install", "--no-deps", "--no-index", str(rebuilt_wheel)],
        cwd=str(Path(offline_dir).resolve()),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=_offline_environment(),
    )
    if install.returncode != 0:
        raise CandidateBuildError("rebuilt wheel could not be installed", stage="offline-rebuild")
    scripts = python.parent
    cli = scripts / ("chemical-eia.exe" if os.name == "nt" else "chemical-eia")
    help_cp = subprocess.run(
        [str(cli), "--help"],
        cwd=str(Path(offline_dir).resolve()),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=_offline_environment(),
    )
    if help_cp.returncode != 0:
        raise CandidateBuildError("installed chemical-eia command failed", stage="offline-rebuild")

    smoke_input = Path(offline_dir) / "smoke-input"
    smoke_input.mkdir()
    model = smoke_input / "model.json"
    decisions = smoke_input / "decisions.json"
    shutil.copyfile(Path(candidate_root) / "examples/minimal/model.json", model)
    shutil.copyfile(Path(candidate_root) / "examples/minimal/decisions.json", decisions)
    output_root = Path(offline_dir) / "smoke-output"
    cases = (("preliminary", None), ("formal", decisions))
    for expected_status, decision_path in cases:
        output = output_root / expected_status
        command = [str(cli), str(model), "--output-dir", str(output)]
        if decision_path is not None:
            command.extend(("--decisions", str(decision_path)))
        cp = subprocess.run(
            command,
            cwd=str(Path(offline_dir).resolve()),
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=_offline_environment(),
        )
        if cp.returncode != 0 or not output.is_dir():
            raise CandidateBuildError("installed minimal example failed", stage="offline-rebuild")
        if {path.name for path in output.iterdir()} != _OUTPUT_NAMES:
            raise CandidateBuildError("installed minimal example produced unexpected files", stage="offline-rebuild")
        try:
            model_data = json.loads((output / "project-model.yaml").read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise CandidateBuildError("installed minimal example output is invalid", stage="offline-rebuild") from exc
        if model_data.get("analysis_status") != expected_status:
            raise CandidateBuildError("installed minimal example status is incorrect", stage="offline-rebuild")
    if network_log.exists() and network_log.read_text(encoding="utf-8").strip():
        raise CandidateBuildError("offline smoke verification attempted network access", stage="offline-rebuild")


def _assert_final_dist(dist_dir: Path) -> None:
    actual = tuple(sorted(path.name for path in Path(dist_dir).iterdir()))
    if actual != _FINAL_ASSET_NAMES or any(not path.is_file() for path in Path(dist_dir).iterdir()):
        raise CandidateBuildError("final dist directory does not match the release contract")


def build_candidate_release(
    candidate_root: Path,
    dist_dir: Path,
    policy_path: Path,
    offline_dir: Path,
) -> ReleaseArtifacts:
    from tools.public_checksums import sha256_file, verify_sha256s, write_sha256s
    from tools.public_scan import scan_file_bytes

    raw_candidate_root = Path(candidate_root)
    raw_dist_dir = Path(dist_dir)
    raw_offline_dir = Path(offline_dir)
    raw_policy_path = Path(policy_path)
    if _is_link_or_junction(raw_candidate_root):
        raise CandidateBuildError("public candidate must be a real directory", stage="source-scan")
    if _is_link_or_junction(raw_policy_path):
        raise CandidateBuildError("public release policy must not be linked", stage="source-scan")
    if _is_link_or_junction(raw_dist_dir) or _is_link_or_junction(raw_offline_dir):
        raise CandidateBuildError("release work directories must not be linked")
    candidate_root = raw_candidate_root.resolve()
    dist_dir = raw_dist_dir.resolve()
    offline_dir = raw_offline_dir.resolve()
    policy_path = raw_policy_path.resolve()
    if not candidate_root.is_dir():
        raise CandidateBuildError("public candidate must be a real directory", stage="source-scan")
    if os.path.lexists(str(candidate_root / ".git")):
        raise CandidateBuildError("public candidate must not contain Git metadata", stage="source-scan")
    expected_policy = (candidate_root / "release/public-release-policy.json").resolve()
    if policy_path != expected_policy or not policy_path.is_file():
        raise CandidateBuildError("policy must be the candidate public release policy", stage="source-scan")
    _assert_unrelated_paths(candidate_root, dist_dir, offline_dir)
    policy = _load_release_policy(policy_path)
    _prepare_empty_directory(dist_dir)
    stage_durations: dict[str, float] = {}
    current_stage = "source-scan"
    try:
        started = time.monotonic()
        _assert_clean_source_tree(candidate_root, policy_path)
        stage_durations["source-scan"] = time.monotonic() - started

        current_stage = "public-tests"
        started = time.monotonic()
        _run_public_tests(candidate_root)
        _assert_clean_source_tree(candidate_root, policy_path)
        stage_durations["public-tests"] = time.monotonic() - started

        current_stage = "release-artifacts"
        started = time.monotonic()
        try:
            wheel, sdist = build_artifacts(candidate_root, dist_dir)
        finally:
            _cleanup_build_generated_paths(candidate_root)
        skill_zip = build_skill_archive(
            candidate_root / "skills/analyzing-chemical-eia-processes",
            dist_dir / _FINAL_ASSET_NAMES[1],
        )
        _assert_artifact_contract(wheel, policy["wheel_exact_files"])
        _assert_artifact_contract(
            sdist,
            policy["sdist_exact_files"] + policy["sdist_exact_directories"],
        )
        _assert_artifact_contract(skill_zip, policy["skill_zip_exact_files"])
        _assert_clean_source_tree(candidate_root, policy_path)
        stage_durations["release-artifacts"] = time.monotonic() - started

        current_stage = "offline-rebuild"
        started = time.monotonic()
        rebuilt_wheel = verify_offline_rebuild(sdist, wheel, offline_dir, policy_path)
        _smoke_install_and_run(candidate_root, rebuilt_wheel, offline_dir)
        stage_durations["offline-rebuild"] = time.monotonic() - started

        checksums = write_sha256s(
            [skill_zip, wheel, sdist],
            dist_dir / _FINAL_ASSET_NAMES[0],
        )
        verify_sha256s(checksums, dist_dir, _FINAL_ASSET_NAMES[1:])
        if scan_file_bytes(checksums.name, checksums.read_bytes()):
            raise CandidateBuildError("checksum manifest failed the sensitive-content scan")
        _assert_artifact_contract(wheel, policy["wheel_exact_files"])
        _assert_artifact_contract(
            sdist,
            policy["sdist_exact_files"] + policy["sdist_exact_directories"],
        )
        _assert_artifact_contract(skill_zip, policy["skill_zip_exact_files"])
        _assert_final_dist(dist_dir)
        sha256 = {path.name: sha256_file(path) for path in (checksums, skill_zip, wheel, sdist)}
        return ReleaseArtifacts(
            wheel=wheel.resolve(),
            sdist=sdist.resolve(),
            skill_zip=skill_zip.resolve(),
            checksums=checksums.resolve(),
            rebuilt_wheel=rebuilt_wheel.resolve(),
            sha256=sha256,
            stage_durations=stage_durations,
        )
    except CandidateBuildError as exc:
        if exc.stage not in {"source-scan", "public-tests"}:
            exc.stage = current_stage
        exc.stage_durations.update(stage_durations)
        _remove_owned_directory(dist_dir)
        raise
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
        _remove_owned_directory(dist_dir)
        error = CandidateBuildError("isolated candidate release build failed", stage=current_stage)
        error.stage_durations.update(stage_durations)
        raise error from exc
