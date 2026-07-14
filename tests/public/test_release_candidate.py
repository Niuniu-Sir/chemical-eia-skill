from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from tools.public_checksums import write_sha256s
from tools.release_candidate import (
    BuilderIdentity,
    CandidateError,
    CandidateFile,
    ReleaseCandidateManifest,
    candidate_artifact_name,
    load_candidate_manifest,
    sha256_file,
    verify_candidate_directory,
    verify_release_directory,
    write_candidate_manifest,
)


COMMIT = "d46881bf640fd97f4d8e88072fac9467adbfcf94"
RUN_ID = 29349045381
ARTIFACT_NAME = candidate_artifact_name(COMMIT, RUN_ID)
ASSET_NAMES = (
    "SHA256SUMS.txt",
    "analyzing-chemical-eia-processes-0.1.0.zip",
    "chemical_eia_core-0.1.0-py3-none-any.whl",
    "chemical_eia_core-0.1.0.tar.gz",
)


class PublicReleaseCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.candidate = self.root / "candidate"
        self.candidate.mkdir()
        archives = []
        for index, name in enumerate(ASSET_NAMES[1:], start=1):
            path = self.candidate / name
            path.write_bytes((f"public fictional asset {index}\n".encode("ascii")) * index)
            archives.append(path)
        write_sha256s(archives, self.candidate / "SHA256SUMS.txt")
        self.manifest = ReleaseCandidateManifest(
            schema_version=1,
            public_commit=COMMIT,
            ci_run_id=RUN_ID,
            workflow="test.yml",
            artifact_name=ARTIFACT_NAME,
            retention_days=30,
            builder=BuilderIdentity(
                os="ubuntu-latest",
                python="3.13.12",
                build="1.5.1",
                setuptools="83.0.0",
                wheel="0.47.0",
            ),
            files=tuple(
                CandidateFile(
                    name=name,
                    size=(self.candidate / name).stat().st_size,
                    sha256=sha256_file(self.candidate / name),
                )
                for name in ASSET_NAMES
            ),
            created_at_utc="2026-07-15T00:00:00Z",
        )
        self.manifest_path = self.candidate / "release-candidate.json"
        write_candidate_manifest(self.manifest, self.manifest_path)
        self.manifest_digest = sha256_file(self.manifest_path)

    def test_manifest_round_trip_and_exact_candidate_verification(self):
        self.assertEqual(load_candidate_manifest(self.manifest_path), self.manifest)
        self.assertEqual(
            verify_candidate_directory(
                self.candidate,
                COMMIT,
                RUN_ID,
                ARTIFACT_NAME,
                self.manifest_digest,
            ),
            self.manifest,
        )

    def test_modified_candidate_asset_is_rejected(self):
        with (self.candidate / ASSET_NAMES[1]).open("ab") as handle:
            handle.write(b"modified")
        with self.assertRaises(CandidateError):
            verify_candidate_directory(
                self.candidate,
                COMMIT,
                RUN_ID,
                ARTIFACT_NAME,
                self.manifest_digest,
            )

    def test_exact_release_is_accepted_and_modified_release_is_rejected(self):
        release = self.root / "release"
        release.mkdir()
        for name in ASSET_NAMES:
            shutil.copyfile(self.candidate / name, release / name)
        verify_release_directory(release, self.manifest)
        with (release / ASSET_NAMES[2]).open("ab") as handle:
            handle.write(b"modified")
        with self.assertRaises(CandidateError):
            verify_release_directory(release, self.manifest)


if __name__ == "__main__":
    unittest.main()