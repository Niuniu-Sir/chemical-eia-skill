from __future__ import annotations

import json
import shutil
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from tools.public_checksums import verify_sha256s, write_sha256s
from tools.release_artifacts import (
    build_artifacts,
    build_skill_archive,
    inspect_artifact,
)


ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "release" / "public-release-policy.json"
SKILL = ROOT / "skills" / "analyzing-chemical-eia-processes"
BUILD_SOURCE_FILES = (
    "LICENSE",
    "MANIFEST.in",
    "README.md",
    "pyproject.toml",
    "src/chemical_eia/__init__.py",
    "src/chemical_eia/balance.py",
    "src/chemical_eia/cli.py",
    "src/chemical_eia/model_io.py",
    "src/chemical_eia/pipeline.py",
    "src/chemical_eia/rendering.py",
    "src/chemical_eia/validation.py",
)


EXPECTED_ASSETS = (
    "analyzing-chemical-eia-processes-0.1.0.zip",
    "chemical_eia_core-0.1.0-py3-none-any.whl",
    "chemical_eia_core-0.1.0.tar.gz",
)


class PublicArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        temporary_root = Path(cls.temporary.name)
        cls.dist = temporary_root / "dist"
        build_source = temporary_root / "source"
        for relative in BUILD_SOURCE_FILES:
            destination = build_source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        cls.policy = json.loads(POLICY.read_text(encoding="utf-8"))
        cls.wheel, cls.sdist = build_artifacts(build_source, cls.dist)
        cls.skill_zip = build_skill_archive(
            SKILL,
            cls.dist / EXPECTED_ASSETS[0],
        )

    def test_asset_names_and_exact_members_are_frozen(self):
        self.assertEqual(
            {self.skill_zip.name, self.wheel.name, self.sdist.name},
            set(EXPECTED_ASSETS),
        )
        self.assertEqual(
            inspect_artifact(self.wheel, self.policy["wheel_exact_files"]),
            [],
        )
        self.assertEqual(
            inspect_artifact(
                self.sdist,
                self.policy["sdist_exact_files"]
                + self.policy["sdist_exact_directories"],
            ),
            [],
        )
        self.assertEqual(
            inspect_artifact(self.skill_zip, self.policy["skill_zip_exact_files"]),
            [],
        )

    def test_checksum_manifest_is_generated_and_verified(self):
        manifest = self.dist / "SHA256SUMS.txt"
        write_sha256s(
            [self.skill_zip, self.wheel, self.sdist],
            manifest,
        )
        verify_sha256s(manifest, self.dist, EXPECTED_ASSETS)
        self.assertEqual(
            {path.name for path in self.dist.iterdir()},
            set(EXPECTED_ASSETS) | {"SHA256SUMS.txt"},
        )

    def test_archives_exclude_public_tests_examples_adapter_and_release_docs(self):
        names = set()
        with zipfile.ZipFile(self.wheel) as archive:
            names.update(archive.namelist())
        with zipfile.ZipFile(self.skill_zip) as archive:
            names.update(archive.namelist())
        with tarfile.open(self.sdist, "r:gz") as archive:
            names.update(member.name for member in archive.getmembers())

        forbidden_segments = (
            "tests/",
            "examples/",
            "adapters/",
            "docs/",
            "release/",
        )
        for name in names:
            normalized = name.replace("\\", "/")
            self.assertFalse(
                any(
                    normalized.startswith(segment)
                    or ("/" + segment) in normalized
                    for segment in forbidden_segments
                ),
                normalized,
            )


if __name__ == "__main__":
    unittest.main()
