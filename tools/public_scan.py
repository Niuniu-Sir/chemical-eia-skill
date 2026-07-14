"""Fail-closed source-tree scanning for the isolated public repository."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Sequence


_ALLOWED_GIT_BLOB_MODES = frozenset({"100644", "100755"})


_DEFAULT_PATTERN_ENCODINGS = (
    (
        "CONTENT_MACHINE_PATH",
        "KD9pKSg/OlxiW0EtWl06W1xcL10oPzpbXlxzIic8PnxdK1tcXC9dPykrfC8oPzpVc2Vyc3xob21lKS9bQS1aYS16MC05Ll8tXSsoPzovW15ccyInPD58XSspKik=",
    ),
    (
        "CONTENT_SECRET_ASSIGNMENT",
        "KD9pKVxiKD86YXBpW18tXT90b2tlbnxhY2Nlc3NbXy1dP3Rva2VufHNlY3JldHxwYXNzd29yZHxwYXNzd2R8Y2xpZW50W18tXT9zZWNyZXQpXHMqWzo9XVxzKlsiJ10/W0EtWmEtejAtOV8uLys9LV17MTIsfQ==",
    ),
    (
        "CONTENT_CREDENTIAL_PREFIX",
        "KD9pKVxiKD86c2stW0EtWmEtejAtOV17MjAsfXxnaFtwb3Vzcl1fW0EtWmEtejAtOV17MjAsfSlcYg==",
    ),
    (
        "CONTENT_PRIVATE_KEY",
        "LS0tLS1CRUdJTiAoPzpSU0EgfEVDIHxPUEVOU1NIICk/UFJJVkFURSBLRVktLS0tLQ==",
    ),
)


@dataclass(frozen=True)
class Finding:
    layer: str
    rule_id: str
    subject: str
    detail: str


class ScanError(RuntimeError):
    """Raised when one or more release-safety findings remain."""


def _finding(rule_id: str, subject: str, detail: str) -> Finding:
    return Finding(
        layer="source-tree",
        rule_id=rule_id,
        subject=subject,
        detail=detail,
    )


def _decode_pattern(rule_id: str, encoded: str) -> re.Pattern[str]:
    try:
        raw = base64.b64decode(encoded, validate=True)
        pattern = raw.decode("utf-8", "strict")
        return re.compile(pattern)
    except (ValueError, UnicodeDecodeError, re.error) as exc:
        raise ValueError(f"invalid encoded scan pattern for {rule_id}") from exc


def _default_patterns() -> tuple[tuple[str, re.Pattern[str]], ...]:
    return tuple(
        (rule_id, _decode_pattern(rule_id, encoded))
        for rule_id, encoded in _DEFAULT_PATTERN_ENCODINGS
    )


def _is_absolute_or_unsafe_path(relative_path: str) -> bool:
    if not isinstance(relative_path, str) or not relative_path:
        return True
    if "\\" in relative_path:
        if (
            len(relative_path) >= 3
            and relative_path[0].isalpha()
            and relative_path[1] == ":"
            and relative_path[2] in "\\/"
        ):
            return True
    pure = PurePosixPath(relative_path)
    return pure.is_absolute() or ".." in pure.parts


def _is_link_or_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction is not None and is_junction())


def _content_findings(
    relative_path: str,
    content: bytes,
    *,
    allow_binary: bool,
    patterns: Sequence[tuple[str, re.Pattern[str]]],
    forbidden_keyword_hashes: frozenset[str],
) -> list[Finding]:
    findings: list[Finding] = []
    if bytes((0,)) in content:
        if not allow_binary:
            findings.append(
                _finding(
                    "BINARY_NOT_ALLOWED",
                    relative_path,
                    "file contains NUL bytes and is not exactly allowlisted",
                )
            )
        return findings

    try:
        text = content.decode("utf-8", "strict")
    except UnicodeDecodeError:
        if not allow_binary:
            findings.append(
                _finding(
                    "BINARY_NOT_ALLOWED",
                    relative_path,
                    "file is not strict UTF-8 and is not exactly allowlisted",
                )
            )
        return findings

    for rule_id, pattern in patterns:
        if pattern.search(text) is not None:
            findings.append(
                _finding(
                    rule_id,
                    relative_path,
                    "generic encoded content rule matched",
                )
            )

    if forbidden_keyword_hashes:
        tokens = set(re.findall(r"[\w.-]+", text.casefold(), flags=re.UNICODE))
        token_hashes = {
            hashlib.sha256(token.encode("utf-8")).hexdigest()
            for token in tokens
        }
        if token_hashes.intersection(forbidden_keyword_hashes):
            findings.append(
                _finding(
                    "CONTENT_FORBIDDEN_KEYWORD",
                    relative_path,
                    "content token matched an approved SHA-256 denylist entry",
                )
            )
    return findings


def scan_file_bytes(relative_path: str, content: bytes) -> list[Finding]:
    """Scan one public path and byte payload using generic encoded rules."""
    findings: list[Finding] = []
    if _is_absolute_or_unsafe_path(relative_path):
        findings.append(
            _finding(
                "PATH_ABSOLUTE",
                str(relative_path),
                "path must be one relative non-traversing public path",
            )
        )
    findings.extend(
        _content_findings(
            str(relative_path),
            content,
            allow_binary=False,
            patterns=_default_patterns(),
            forbidden_keyword_hashes=frozenset(),
        )
    )
    return _sorted_findings(findings)


def _literal_policy_paths(values: object, *, label: str) -> tuple[str, ...]:
    if not isinstance(values, list):
        raise ValueError(f"{label} must be a list")
    result: list[str] = []
    for index, value in enumerate(values):
        if not isinstance(value, str) or _is_absolute_or_unsafe_path(value):
            raise ValueError(f"{label}[{index}] must be one relative path")
        pure = PurePosixPath(value)
        if value != pure.as_posix() or "\\" in value or value == ".":
            raise ValueError(f"{label}[{index}] must be normalized POSIX")
        result.append(value)
    if len(result) != len(set(result)):
        raise ValueError(f"{label} contains duplicate paths")
    if len(result) != len({value.casefold() for value in result}):
        raise ValueError(f"{label} contains case-conflicting paths")
    return tuple(result)


def _load_policy(policy_path: Path) -> tuple[
    tuple[str, ...],
    frozenset[str],
    frozenset[str],
    tuple[str, ...],
    tuple[tuple[str, re.Pattern[str]], ...],
    frozenset[str],
]:
    data = json.loads(policy_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("unsupported public release policy")
    tracked = _literal_policy_paths(data.get("tracked_files"), label="tracked_files")
    rules = data.get("scan_rules")
    if not isinstance(rules, dict):
        raise ValueError("scan_rules must be an object")
    expected_rule_keys = {
        "allowed_binary_files",
        "forbidden_content_patterns",
        "forbidden_keyword_hashes",
        "forbidden_path_segments",
        "forbidden_path_suffixes",
    }
    if set(rules) != expected_rule_keys:
        raise ValueError("unexpected scan_rules keys")

    allowed_binary = frozenset(
        _literal_policy_paths(
            rules["allowed_binary_files"],
            label="allowed_binary_files",
        )
    )
    if not allowed_binary.issubset(set(tracked)):
        raise ValueError("allowed binary files must be tracked files")

    segments_raw = rules["forbidden_path_segments"]
    suffixes_raw = rules["forbidden_path_suffixes"]
    if not isinstance(segments_raw, list) or not all(
        isinstance(value, str) and value for value in segments_raw
    ):
        raise ValueError("forbidden_path_segments must contain strings")
    if not isinstance(suffixes_raw, list) or not all(
        isinstance(value, str) and value for value in suffixes_raw
    ):
        raise ValueError("forbidden_path_suffixes must contain strings")
    forbidden_segments = frozenset(value.casefold() for value in segments_raw)
    forbidden_suffixes = tuple(value.casefold() for value in suffixes_raw)

    pattern_items = list(_default_patterns())
    seen_pattern_ids = {rule_id for rule_id, _ in pattern_items}
    raw_patterns = rules["forbidden_content_patterns"]
    if not isinstance(raw_patterns, list):
        raise ValueError("forbidden_content_patterns must be a list")
    for index, item in enumerate(raw_patterns):
        if not isinstance(item, dict) or set(item) != {
            "rule_id",
            "pattern_base64",
        }:
            raise ValueError(f"forbidden_content_patterns[{index}] is invalid")
        rule_id = item["rule_id"]
        encoded = item["pattern_base64"]
        if not isinstance(rule_id, str) or not rule_id:
            raise ValueError("content pattern rule_id must be a string")
        if not isinstance(encoded, str) or not encoded:
            raise ValueError("content pattern encoding must be a string")
        if rule_id in seen_pattern_ids:
            continue
        pattern_items.append((rule_id, _decode_pattern(rule_id, encoded)))
        seen_pattern_ids.add(rule_id)

    raw_hashes = rules["forbidden_keyword_hashes"]
    if not isinstance(raw_hashes, list):
        raise ValueError("forbidden_keyword_hashes must be a list")
    hashes: set[str] = set()
    for value in raw_hashes:
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError("keyword hashes must be lowercase SHA-256 hex")
        hashes.add(value)
    return (
        tracked,
        allowed_binary,
        forbidden_segments,
        forbidden_suffixes,
        tuple(pattern_items),
        frozenset(hashes),
    )


def _tree_paths(root: Path) -> tuple[list[str], list[Finding], dict[str, Path]]:
    findings: list[Finding] = []
    actual: list[str] = []
    paths: dict[str, Path] = {}
    root_resolved = root.resolve()
    if _is_link_or_junction(root):
        findings.append(
            _finding(
                "PATH_LINK_OR_JUNCTION",
                ".",
                "source root must not be a link or junction",
            )
        )
        return actual, findings, paths

    for current_root, directory_names, file_names in os.walk(
        root,
        topdown=True,
        followlinks=False,
    ):
        current = Path(current_root)
        safe_directories: list[str] = []
        for name in directory_names:
            directory = current / name
            relative = directory.relative_to(root).as_posix()
            if _is_link_or_junction(directory):
                findings.append(
                    _finding(
                        "PATH_LINK_OR_JUNCTION",
                        relative,
                        "directory link or junction is forbidden",
                    )
                )
            else:
                safe_directories.append(name)
        directory_names[:] = safe_directories

        for name in file_names:
            path = current / name
            relative = path.relative_to(root).as_posix()
            actual.append(relative)
            paths[relative] = path
            if _is_link_or_junction(path):
                findings.append(
                    _finding(
                        "PATH_LINK_OR_JUNCTION",
                        relative,
                        "file link or junction is forbidden",
                    )
                )
                continue
            if not path.is_file():
                findings.append(
                    _finding(
                        "PATH_NOT_REGULAR_FILE",
                        relative,
                        "tracked source entry must be a regular file",
                    )
                )
                continue
            try:
                path.resolve().relative_to(root_resolved)
            except ValueError:
                findings.append(
                    _finding(
                        "PATH_ESCAPE",
                        relative,
                        "resolved file escapes the source root",
                    )
                )
    return actual, findings, paths


def _allowlist_findings(
    expected: Sequence[str],
    actual: Sequence[str],
) -> list[Finding]:
    findings: list[Finding] = []
    expected_by_fold: dict[str, list[str]] = {}
    actual_by_fold: dict[str, list[str]] = {}
    for path in expected:
        expected_by_fold.setdefault(path.casefold(), []).append(path)
    for path in actual:
        actual_by_fold.setdefault(path.casefold(), []).append(path)

    for folded in sorted(set(expected_by_fold) | set(actual_by_fold)):
        expected_paths = expected_by_fold.get(folded, [])
        actual_paths = actual_by_fold.get(folded, [])
        if len(expected_paths) > 1 or len(actual_paths) > 1:
            subject = sorted(expected_paths + actual_paths)[0]
            findings.append(
                _finding(
                    "PATH_CASE_COLLISION",
                    subject,
                    "case-insensitive path collision detected",
                )
            )
            continue
        if expected_paths and actual_paths:
            if expected_paths[0] != actual_paths[0]:
                findings.append(
                    _finding(
                        "PATH_CASE_COLLISION",
                        actual_paths[0],
                        "tracked path casing differs from policy",
                    )
                )
            continue
        if expected_paths:
            findings.append(
                _finding(
                    "FILE_MISSING",
                    expected_paths[0],
                    "tracked policy file is missing",
                )
            )
        else:
            findings.append(
                _finding(
                    "FILE_NOT_ALLOWED",
                    actual_paths[0],
                    "source tree contains an unapproved file",
                )
            )
    return findings


def _path_rule_findings(
    relative_path: str,
    forbidden_segments: frozenset[str],
    forbidden_suffixes: Sequence[str],
) -> list[Finding]:
    findings: list[Finding] = []
    parts = PurePosixPath(relative_path).parts
    if any(part.casefold() in forbidden_segments for part in parts):
        findings.append(
            _finding(
                "PATH_SEGMENT_FORBIDDEN",
                relative_path,
                "path contains a forbidden internal segment",
            )
        )
    folded = relative_path.casefold()
    if any(folded.endswith(suffix) for suffix in forbidden_suffixes):
        findings.append(
            _finding(
                "PATH_SUFFIX_FORBIDDEN",
                relative_path,
                "path has a forbidden backup, cache, or credential suffix",
            )
        )
    return findings


def _sorted_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda item: (
            item.subject.casefold(),
            item.subject,
            item.rule_id,
            item.detail,
        ),
    )


def scan_source_tree(root: Path, policy_path: Path) -> list[Finding]:
    """Compare a no-.git public source tree to policy and scan every file."""
    (
        tracked,
        allowed_binary,
        forbidden_segments,
        forbidden_suffixes,
        patterns,
        forbidden_keyword_hashes,
    ) = _load_policy(policy_path)
    root = Path(root)
    actual, findings, path_map = _tree_paths(root)
    findings.extend(_allowlist_findings(tracked, actual))

    for relative_path in sorted(actual, key=lambda value: (value.casefold(), value)):
        findings.extend(
            _path_rule_findings(
                relative_path,
                forbidden_segments,
                forbidden_suffixes,
            )
        )
        path = path_map[relative_path]
        if _is_link_or_junction(path) or not path.is_file():
            continue
        findings.extend(
            _content_findings(
                relative_path,
                path.read_bytes(),
                allow_binary=relative_path in allowed_binary,
                patterns=patterns,
                forbidden_keyword_hashes=forbidden_keyword_hashes,
            )
        )
    return _sorted_findings(findings)


def assert_no_findings(findings: Sequence[Finding]) -> None:
    if not findings:
        return
    rule_ids = sorted({finding.rule_id for finding in findings})
    raise ScanError(
        "release safety scan found {} issue(s): {}".format(
            len(findings),
            ", ".join(rule_ids),
        )
    )
@dataclass(frozen=True)
class GitObject:
    object_id: str
    object_type: str
    size: int


@dataclass(frozen=True)
class _GitRef:
    name: str
    object_id: str
    object_type: str


def _git_process(
    repo: Path,
    arguments: Sequence[str],
    *,
    allowed_returncodes: frozenset[int] = frozenset({0}),
) -> subprocess.CompletedProcess[bytes]:
    cp = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if cp.returncode not in allowed_returncodes:
        raise ScanError("Git safety command failed closed")
    return cp


def _git_failure(subject: str, detail: str) -> Finding:
    return Finding(
        layer="git",
        rule_id="GIT_COMMAND_FAILED",
        subject=subject,
        detail=detail,
    )


def _git_layer_findings(
    findings: Sequence[Finding],
    *,
    layer: str,
    subject: str | None = None,
) -> list[Finding]:
    return [
        Finding(
            layer=layer,
            rule_id=finding.rule_id,
            subject=subject if subject is not None else finding.subject,
            detail=finding.detail,
        )
        for finding in findings
    ]


def _index_entries(repo: Path) -> tuple[list[tuple[str, str, int, str]], list[Finding]]:
    try:
        output = _git_process(repo, ["ls-files", "-s", "-z"]).stdout
    except ScanError:
        return [], [_git_failure("index", "git ls-files failed")]
    entries: list[tuple[str, str, int, str]] = []
    findings: list[Finding] = []
    for record in output.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            raw_mode, raw_object_id, raw_stage = metadata.split(b" ")
            mode = raw_mode.decode("ascii", "strict")
            object_id = raw_object_id.decode("ascii", "strict")
            stage = int(raw_stage.decode("ascii", "strict"))
            path = raw_path.decode("utf-8", "strict")
        except (UnicodeDecodeError, ValueError) as exc:
            findings.append(
                Finding(
                    layer="git-index",
                    rule_id="INDEX_PARSE_ERROR",
                    subject="index",
                    detail="Git index entry could not be parsed",
                )
            )
            continue
        entries.append((mode, object_id, stage, path))
    return entries, findings


def _index_allowlist_findings(
    expected: Sequence[str],
    actual: Sequence[str],
) -> list[Finding]:
    generic = _allowlist_findings(expected, actual)
    rule_map = {
        "FILE_MISSING": "INDEX_FILE_MISSING",
        "FILE_NOT_ALLOWED": "INDEX_FILE_NOT_ALLOWED",
        "PATH_CASE_COLLISION": "INDEX_PATH_CASE_COLLISION",
    }
    return [
        Finding(
            layer="git-index",
            rule_id=rule_map[finding.rule_id],
            subject=finding.subject,
            detail=finding.detail,
        )
        for finding in generic
    ]


def scan_git_index(repo: Path, policy_path: Path) -> list[Finding]:
    """Scan exact stage-zero index blobs without reading the worktree."""
    try:
        tracked, _, _, _, _, _ = _load_policy(policy_path)
    except (OSError, ValueError, json.JSONDecodeError):
        return [_git_failure("index-policy", "public release policy is invalid")]
    entries, findings = _index_entries(repo)
    paths = [path for _, _, _, path in entries]
    findings.extend(_index_allowlist_findings(tracked, paths))

    seen_paths: set[str] = set()
    for mode, object_id, stage, path in entries:
        if path in seen_paths:
            findings.append(
                Finding(
                    layer="git-index",
                    rule_id="INDEX_DUPLICATE_PATH",
                    subject=path,
                    detail="index contains duplicate path stages",
                )
            )
        seen_paths.add(path)
        if stage != 0:
            findings.append(
                Finding(
                    layer="git-index",
                    rule_id="INDEX_STAGE_NOT_ZERO",
                    subject=path,
                    detail="only fully merged stage-zero entries are allowed",
                )
            )
            continue
        if mode not in _ALLOWED_GIT_BLOB_MODES:
            findings.append(
                Finding(
                    layer="git-index",
                    rule_id="INDEX_MODE_NOT_ALLOWED",
                    subject=path,
                    detail="index entry must be an ordinary file blob",
                )
            )
            continue
        try:
            content = _git_process(
                repo,
                ["cat-file", "blob", object_id],
            ).stdout
        except ScanError:
            findings.append(_git_failure(path, "index blob could not be read"))
            continue
        findings.extend(
            _git_layer_findings(
                scan_file_bytes(path, content),
                layer="git-index",
                subject=path,
            )
        )
    return _sorted_findings(findings)


def enumerate_git_objects(repo: Path) -> list[GitObject]:
    """Enumerate reachable and unreachable loose/packed objects."""
    cp = _git_process(
        repo,
        [
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname)%00%(objecttype)%00%(objectsize)",
        ],
    )
    objects: dict[str, GitObject] = {}
    for record in cp.stdout.splitlines():
        if not record:
            continue
        parts = record.split(b"%00")
        if len(parts) != 3:
            raise ScanError("Git object enumeration record is malformed")
        try:
            object_id = parts[0].decode("ascii", "strict")
            object_type = parts[1].decode("ascii", "strict")
            size = int(parts[2].decode("ascii", "strict"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ScanError("Git object enumeration record is malformed") from exc
        if re.fullmatch(r"[0-9a-f]{40}", object_id) is None:
            raise ScanError("Git object ID is not lowercase SHA-1")
        if object_type not in {"blob", "tree", "commit", "tag"} or size < 0:
            raise ScanError("Git object type or size is invalid")
        item = GitObject(object_id, object_type, size)
        previous = objects.get(object_id)
        if previous is not None and previous != item:
            raise ScanError("Git object enumeration is inconsistent")
        objects[object_id] = item
    return sorted(objects.values(), key=lambda item: item.object_id)


def _enumerate_refs(repo: Path) -> list[_GitRef]:
    cp = _git_process(
        repo,
        [
            "for-each-ref",
            "--format=%(refname)%00%(objectname)%00%(objecttype)",
        ],
    )
    refs: list[_GitRef] = []
    for record in cp.stdout.splitlines():
        if not record:
            continue
        parts = record.split(b"\0")
        if len(parts) != 3:
            raise ScanError("Git ref enumeration record is malformed")
        try:
            name, object_id, object_type = (
                part.decode("utf-8", "strict") for part in parts
            )
        except UnicodeDecodeError as exc:
            raise ScanError("Git ref enumeration record is not UTF-8") from exc
        if not name.startswith("refs/"):
            raise ScanError("Git ref name is outside refs namespace")
        if re.fullmatch(r"[0-9a-f]{40}", object_id) is None:
            raise ScanError("Git ref target is invalid")
        refs.append(_GitRef(name, object_id, object_type))
    if len({item.name for item in refs}) != len(refs):
        raise ScanError("Git ref enumeration contains duplicates")
    return refs


def _scan_git_text(subject: str, content: bytes) -> list[Finding]:
    return _git_layer_findings(
        scan_file_bytes("git-metadata", content),
        layer="git-history",
        subject=subject,
    )


def scan_commit_message(object_id: str, message: bytes) -> list[Finding]:
    return _scan_git_text(object_id, message)


def scan_tag_message(object_id: str, message: bytes) -> list[Finding]:
    return _scan_git_text(object_id, message)


def _parse_tree_object(
    object_id: str,
    content: bytes,
    object_ids: frozenset[str],
) -> list[Finding]:
    findings: list[Finding] = []
    offset = 0
    names: list[str] = []
    while offset < len(content):
        space = content.find(b" ", offset)
        nul = content.find(b"\0", space + 1 if space >= 0 else offset)
        if space < 0 or nul < 0 or nul + 21 > len(content):
            findings.append(
                Finding(
                    layer="git-history",
                    rule_id="TREE_PARSE_ERROR",
                    subject=object_id,
                    detail="tree object record is malformed",
                )
            )
            return findings
        raw_mode = content[offset:space]
        raw_name = content[space + 1 : nul]
        child_id = content[nul + 1 : nul + 21].hex()
        offset = nul + 21
        try:
            mode = raw_mode.decode("ascii", "strict")
            name = raw_name.decode("utf-8", "strict")
        except UnicodeDecodeError:
            findings.append(
                Finding(
                    layer="git-history",
                    rule_id="TREE_PATH_INVALID_UTF8",
                    subject=object_id,
                    detail="tree path is not strict UTF-8",
                )
            )
            continue
        names.append(name)
        if (
            not name
            or PurePosixPath(name).is_absolute()
            or ".." in PurePosixPath(name).parts
            or "/" in name
            or "\\" in name
        ):
            findings.append(
                Finding(
                    layer="git-history",
                    rule_id="TREE_PATH_UNSAFE",
                    subject=object_id,
                    detail="tree entry path is unsafe",
                )
            )
        if mode not in {"40000", "100644", "100755"}:
            findings.append(
                Finding(
                    layer="git-history",
                    rule_id="TREE_MODE_NOT_ALLOWED",
                    subject=object_id,
                    detail="tree contains symlink, submodule, or unknown mode",
                )
            )
        if child_id not in object_ids:
            findings.append(
                Finding(
                    layer="git-history",
                    rule_id="OBJECT_REFERENCE_MISSING",
                    subject=object_id,
                    detail="tree references an object absent from enumeration",
                )
            )
        findings.extend(_scan_git_text(object_id, raw_name))
    if len(names) != len({name.casefold() for name in names}):
        findings.append(
            Finding(
                layer="git-history",
                rule_id="TREE_PATH_CASE_COLLISION",
                subject=object_id,
                detail="tree contains case-insensitive path collision",
            )
        )
    return findings


def _split_object_headers(content: bytes) -> tuple[list[bytes], bytes] | None:
    separator = content.find(b"\n\n")
    if separator < 0:
        return None
    raw_headers = content[:separator].splitlines()
    headers: list[bytes] = []
    for line in raw_headers:
        if line.startswith(b" ") and headers:
            headers[-1] += b"\n" + line
        else:
            headers.append(line)
    return headers, content[separator + 2 :]


def _scan_commit_object(
    object_id: str,
    content: bytes,
    object_ids: frozenset[str],
) -> list[Finding]:
    parsed = _split_object_headers(content)
    if parsed is None:
        return [
            Finding(
                layer="git-history",
                rule_id="COMMIT_PARSE_ERROR",
                subject=object_id,
                detail="commit object has no header/message separator",
            )
        ]
    headers, message = parsed
    findings: list[Finding] = []
    seen_tree = False
    seen_author = False
    seen_committer = False
    for header in headers:
        key, separator, value = header.partition(b" ")
        if not separator:
            findings.append(
                Finding(
                    layer="git-history",
                    rule_id="COMMIT_PARSE_ERROR",
                    subject=object_id,
                    detail="commit header is malformed",
                )
            )
            continue
        if key == b"tree":
            seen_tree = True
            target = value.decode("ascii", "ignore")
            if target not in object_ids:
                findings.append(
                    Finding(
                        layer="git-history",
                        rule_id="OBJECT_REFERENCE_MISSING",
                        subject=object_id,
                        detail="commit tree is absent from enumeration",
                    )
                )
        elif key == b"parent":
            target = value.decode("ascii", "ignore")
            if target not in object_ids:
                findings.append(
                    Finding(
                        layer="git-history",
                        rule_id="OBJECT_REFERENCE_MISSING",
                        subject=object_id,
                        detail="commit parent is absent from enumeration",
                    )
                )
        elif key == b"author":
            seen_author = True
            findings.extend(_scan_git_text(object_id, value))
        elif key == b"committer":
            seen_committer = True
            findings.extend(_scan_git_text(object_id, value))
    if not (seen_tree and seen_author and seen_committer):
        findings.append(
            Finding(
                layer="git-history",
                rule_id="COMMIT_REQUIRED_HEADER_MISSING",
                subject=object_id,
                detail="commit is missing tree, author, or committer",
            )
        )
    findings.extend(scan_commit_message(object_id, message))
    return findings


def _scan_tag_object(
    object_id: str,
    content: bytes,
    object_ids: frozenset[str],
) -> list[Finding]:
    parsed = _split_object_headers(content)
    if parsed is None:
        return [
            Finding(
                layer="git-history",
                rule_id="TAG_PARSE_ERROR",
                subject=object_id,
                detail="tag object has no header/message separator",
            )
        ]
    headers, message = parsed
    findings: list[Finding] = []
    seen = set()
    for header in headers:
        key, separator, value = header.partition(b" ")
        if not separator:
            findings.append(
                Finding(
                    layer="git-history",
                    rule_id="TAG_PARSE_ERROR",
                    subject=object_id,
                    detail="tag header is malformed",
                )
            )
            continue
        seen.add(key)
        if key == b"object":
            target = value.decode("ascii", "ignore")
            if target not in object_ids:
                findings.append(
                    Finding(
                        layer="git-history",
                        rule_id="OBJECT_REFERENCE_MISSING",
                        subject=object_id,
                        detail="tag target is absent from enumeration",
                    )
                )
        elif key in {b"tag", b"tagger"}:
            findings.extend(_scan_git_text(object_id, value))
    if not {b"object", b"type", b"tag", b"tagger"}.issubset(seen):
        findings.append(
            Finding(
                layer="git-history",
                rule_id="TAG_REQUIRED_HEADER_MISSING",
                subject=object_id,
                detail="annotated tag is missing required headers",
            )
        )
    findings.extend(scan_tag_message(object_id, message))
    return findings


def _fsck_findings(
    repo: Path,
    object_ids: frozenset[str],
) -> list[Finding]:
    try:
        cp = _git_process(
            repo,
            ["fsck", "--full", "--no-reflogs", "--unreachable"],
        )
    except ScanError:
        return [_git_failure("object-database", "git fsck failed")]
    findings: list[Finding] = []
    output = cp.stdout + b"\n" + cp.stderr
    for match in re.finditer(
        rb"(?:unreachable|dangling) (?:blob|tree|commit|tag) ([0-9a-f]{40})",
        output,
    ):
        object_id = match.group(1).decode("ascii")
        if object_id not in object_ids:
            findings.append(
                Finding(
                    layer="git-history",
                    rule_id="OBJECT_ENUMERATION_INCOMPLETE",
                    subject=object_id,
                    detail="fsck found an object absent from batch enumeration",
                )
            )
    return findings


def scan_git_history(
    repo: Path,
    policy_path: Path,
    forbidden_object_ids: Sequence[str] = (),
) -> list[Finding]:
    """Scan every ref and every reachable or unreachable Git object."""
    try:
        _load_policy(policy_path)
    except (OSError, ValueError, json.JSONDecodeError):
        return [_git_failure("history-policy", "public release policy is invalid")]
    forbidden = frozenset(forbidden_object_ids)
    if any(re.fullmatch(r"[0-9a-f]{40}", value) is None for value in forbidden):
        raise ValueError("forbidden object IDs must be lowercase 40-hex strings")

    try:
        objects = enumerate_git_objects(repo)
        refs = _enumerate_refs(repo)
    except ScanError:
        return [_git_failure("object-database", "Git enumeration failed")]
    object_map = {item.object_id: item for item in objects}
    object_ids = frozenset(object_map)
    findings: list[Finding] = []

    try:
        symbolic = _git_process(
            repo,
            ["symbolic-ref", "-q", "HEAD"],
            allowed_returncodes=frozenset({0, 1}),
        )
        head = _git_process(repo, ["rev-parse", "--verify", "HEAD"])
    except ScanError:
        findings.append(_git_failure("HEAD", "HEAD enumeration failed"))
    else:
        head_id = head.stdout.decode("ascii", "ignore").strip()
        if head_id not in object_ids:
            findings.append(
                Finding(
                    layer="git-history",
                    rule_id="REF_ENUMERATION_INCOMPLETE",
                    subject="HEAD",
                    detail="HEAD target is absent from object enumeration",
                )
            )
        if symbolic.returncode == 0:
            symbolic_name = symbolic.stdout.decode("utf-8", "strict").strip()
            if symbolic_name not in {item.name for item in refs}:
                findings.append(
                    Finding(
                        layer="git-history",
                        rule_id="REF_ENUMERATION_INCOMPLETE",
                        subject=symbolic_name,
                        detail="symbolic HEAD ref is absent from ref enumeration",
                    )
                )

    for ref in refs:
        findings.extend(_scan_git_text(ref.name, ref.name.encode("utf-8")))
        if ref.object_id not in object_ids:
            findings.append(
                Finding(
                    layer="git-history",
                    rule_id="REF_ENUMERATION_INCOMPLETE",
                    subject=ref.name,
                    detail="ref target is absent from object enumeration",
                )
            )
        if ref.object_id in forbidden:
            findings.append(
                Finding(
                    layer="git-history",
                    rule_id="INTERNAL_OBJECT_PRESENT",
                    subject=ref.name,
                    detail="ref targets a forbidden internal object ID",
                )
            )

    findings.extend(_fsck_findings(repo, object_ids))
    for item in objects:
        try:
            content = _git_process(
                repo,
                ["cat-file", item.object_type, item.object_id],
            ).stdout
        except ScanError:
            findings.append(
                _git_failure(item.object_id, "Git object content could not be read")
            )
            continue
        if len(content) != item.size:
            findings.append(
                Finding(
                    layer="git-history",
                    rule_id="OBJECT_SIZE_MISMATCH",
                    subject=item.object_id,
                    detail="object content size differs from enumeration",
                )
            )
        if item.object_id in forbidden:
            findings.append(
                Finding(
                    layer="git-history",
                    rule_id="INTERNAL_OBJECT_PRESENT",
                    subject=item.object_id,
                    detail="forbidden internal object exists in public database",
                )
            )
        for forbidden_id in forbidden:
            if forbidden_id.encode("ascii") in content:
                findings.append(
                    Finding(
                        layer="git-history",
                        rule_id="INTERNAL_OBJECT_PRESENT",
                        subject=item.object_id,
                        detail="object content references a forbidden internal object ID",
                    )
                )
                break

        if item.object_type == "blob":
            findings.extend(
                _git_layer_findings(
                    scan_file_bytes(f"git-object/{item.object_id}", content),
                    layer="git-history",
                    subject=item.object_id,
                )
            )
        elif item.object_type == "tree":
            findings.extend(_parse_tree_object(item.object_id, content, object_ids))
        elif item.object_type == "commit":
            findings.extend(_scan_commit_object(item.object_id, content, object_ids))
        elif item.object_type == "tag":
            findings.extend(_scan_tag_object(item.object_id, content, object_ids))
    return _sorted_findings(findings)