from __future__ import annotations

import re
import unittest
from pathlib import Path, PurePosixPath

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


ROOT = Path(__file__).resolve().parents[2]

DOCUMENTS = (
    "README.md",
    "LICENSE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "SUPPORT.md",
    "CHANGELOG.md",
    "docs/release-notes/v0.1.0.md",
)

MANIFEST_LINES = (
    "include LICENSE",
    "include MANIFEST.in",
    "include README.md",
    "include pyproject.toml",
    "include src/chemical_eia/__init__.py",
    "include src/chemical_eia/balance.py",
    "include src/chemical_eia/cli.py",
    "include src/chemical_eia/model_io.py",
    "include src/chemical_eia/pipeline.py",
    "include src/chemical_eia/rendering.py",
    "include src/chemical_eia/validation.py",
)

README_HEADINGS = (
    "# Chemical EIA Process Analysis",
    "## Preview status",
    "## Install the Python package",
    "## Install the Canonical Skill in Codex",
    "## Install the Claude Code adapter",
    "## Five-minute minimal example",
    "## Four outputs",
    "## From preliminary to formal",
    "## Architecture boundary",
    "## Support matrix",
    "## Security, contributing, and license",
)


class DistributionContractTests(unittest.TestCase):
    def test_required_public_documents_exist_and_are_nonempty(self):
        for relative in DOCUMENTS:
            with self.subTest(path=relative):
                path = ROOT / relative
                self.assertTrue(path.is_file())
                self.assertGreater(len(path.read_bytes()), 100)

    def test_pyproject_freezes_public_package_metadata(self):
        data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        project = data["project"]
        self.assertEqual(project["name"], "chemical-eia-core")
        self.assertEqual(project["version"], "0.1.0")
        self.assertEqual(project["requires-python"], ">=3.10")
        self.assertEqual(project["dependencies"], [])
        self.assertEqual(project["readme"], "README.md")
        self.assertEqual(project["license"], {"file": "LICENSE"})
        self.assertEqual(
            project["scripts"]["chemical-eia"],
            "chemical_eia.cli:main",
        )
        self.assertNotIn("urls", project)
        classifiers = set(project["classifiers"])
        for minor in range(10, 14):
            self.assertIn(
                f"Programming Language :: Python :: 3.{minor}",
                classifiers,
            )
        self.assertIn(
            "License :: OSI Approved :: Apache Software License",
            classifiers,
        )

    def test_manifest_is_literal_and_exact(self):
        raw = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
        self.assertNotIn("\r", raw)
        self.assertEqual(tuple(raw.splitlines()), MANIFEST_LINES)
        lowered = raw.lower()
        self.assertNotIn("recursive" + "-include", lowered)
        self.assertNotIn("gr" + "aft", lowered)
        self.assertNotRegex(raw, r"[*?\[\]]")
        for line in MANIFEST_LINES:
            path = line.removeprefix("include ")
            pure = PurePosixPath(path)
            self.assertFalse(pure.is_absolute())
            self.assertNotIn("..", pure.parts)

    def test_readme_has_fixed_five_minute_path_and_responsibility_boundary(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        positions = [readme.index(heading) for heading in README_HEADINGS]
        self.assertEqual(positions, sorted(positions))
        for marker in (
            "process-equipment-waste correspondence",
            "material balance",
            "three-waste source strength",
            "water balance",
            "preliminary",
            "formal",
            "technician",
            "Preview",
            "not a regulatory conclusion",
            "examples/minimal",
            "python -m pip",
        ):
            self.assertIn(marker, readme)
        self.assertNotIn("http://", readme)
        self.assertNotIn("https://", readme)

    def test_governance_documents_cover_release_boundaries(self):
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        support = (ROOT / "SUPPORT.md").read_text(encoding="utf-8")
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        notes = (ROOT / "docs/release-notes/v0.1.0.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("privately", security)
        self.assertIn("credentials", security)
        self.assertIn("fictional", contributing)
        self.assertIn("Apache-2.0", contributing)
        self.assertIn("## Release candidates", contributing)
        self.assertIn("never rebuilds", contributing)
        self.assertIn("must not hand-edit", contributing)
        self.assertIn("not provide regulatory conclusions", support)
        self.assertIn("[Unreleased]", changelog)
        self.assertIn("[0.1.0] - 2026-07-13", changelog)
        for artifact in ("wheel", "sdist", "Skill ZIP", "SHA256SUMS.txt"):
            self.assertIn(artifact, notes)
        self.assertIn("technician", notes)

    def test_license_is_complete_apache_2_text(self):
        license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertGreater(len(license_text), 10000)
        self.assertIn("Apache License", license_text)
        self.assertIn("Version 2.0, January 2004", license_text)
        self.assertIn("TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION", license_text)
        self.assertIn("END OF TERMS AND CONDITIONS", license_text)

    def test_public_documents_do_not_reference_private_sources(self):
        forbidden_fragments = (
            "Project" + "_Skill",
            "tests/" + "fixtures",
            "tests/" + "evals",
            "private" + " gate",
            "internal" + " commit",
            "work" + "tree",
        )
        drive_path = re.compile(r"(?i)(?<![a-z0-9])[a-z]:[\\/]")
        commit_id = re.compile(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])", re.I)
        for relative in DOCUMENTS:
            text = (ROOT / relative).read_text(encoding="utf-8")
            with self.subTest(path=relative):
                self.assertFalse(drive_path.search(text))
                self.assertFalse(commit_id.search(text))
                for fragment in forbidden_fragments:
                    self.assertNotIn(fragment, text)

    def test_gitignore_is_narrow_and_explicit(self):
        lines = tuple((ROOT / ".gitignore").read_text(encoding="utf-8").splitlines())
        self.assertEqual(
            lines,
            (
                ".venv/",
                "build/",
                "dist/",
                "*.egg-info/",
                "__pycache__/",
                "*.py[cod]",
                ".coverage",
                "htmlcov/",
                "*.tmp",
                "*.swp",
                "*~",
            ),
        )


    def test_ci_workflow_has_exact_supported_matrix_and_triggers(self):
        workflow = (ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8")
        self.assertIn("pull_request:", workflow)
        self.assertRegex(workflow, r"(?m)^  push:\n    branches: \[main\]$")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotRegex(workflow, r"(?m)^\s+tags:")
        self.assertRegex(
            workflow,
            r'os: \[windows-latest, ubuntu-latest\]',
        )
        self.assertRegex(
            workflow,
            r'python-version: \["3\.10", "3\.11", "3\.12", "3\.13"\]',
        )
        matrix_block = workflow.split("matrix:", 1)[1].split("steps:", 1)[0]
        self.assertEqual(matrix_block.count("windows-latest"), 1)
        self.assertEqual(matrix_block.count("ubuntu-latest"), 1)
        for command in (
            "python -m unittest discover -s tests/public -t . -v",
            'python -m pip install --upgrade pip build "setuptools>=68" wheel',
            "chemical_eia_core-0.1.0-py3-none-any.whl",
            "examples/minimal/model.json",
            "SHA256SUMS.txt",
        ):
            self.assertIn(command, workflow)

    def test_ci_workflow_builds_one_canonical_candidate(self):
        workflow = (ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8")
        self.assertEqual(workflow.count("  release-candidate:\n"), 1)
        self.assertIn("needs: public-tests", workflow)
        self.assertIn("runs-on: ubuntu-latest", workflow)
        self.assertIn('python-version: "3.13"', workflow)
        self.assertIn("build==1.5.1", workflow)
        self.assertIn("setuptools==83.0.0", workflow)
        self.assertIn("wheel==0.47.0", workflow)
        self.assertIn(
            "release-candidate-${{ github.sha }}-${{ github.run_id }}",
            workflow,
        )
        self.assertIn("actions/upload-artifact@v4", workflow)
        self.assertIn("retention-days: 30", workflow)
        self.assertIn("if-no-files-found: error", workflow)
        self.assertIn("candidate/release-candidate.json", workflow)
        self.assertIn("github.event_name == 'push'", workflow)
        self.assertIn("github.event_name == 'workflow_dispatch'", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("build_candidate_release", workflow)
        self.assertIn("git archive --format=tar HEAD", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("actions: write", workflow)
        matrix_block = workflow.split("matrix:", 1)[1].split("steps:", 1)[0]
        self.assertIn("os: [windows-latest, ubuntu-latest]", matrix_block)
        self.assertIn(
            'python-version: ["3.10", "3.11", "3.12", "3.13"]',
            matrix_block,
        )
    def test_ci_matrix_installs_declared_build_backend(self):
        workflow = (ROOT / ".github/workflows/test.yml").read_text(encoding="utf-8")
        self.assertIn(
            'run: python -m pip install --upgrade pip build "setuptools>=68" wheel',
            workflow,
        )

    def test_release_workflow_is_manual_v010_prerelease_with_exact_assets(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )
        trigger_block = workflow.split("permissions:", 1)[0]
        self.assertIn("workflow_dispatch:", trigger_block)
        self.assertNotIn("pull_request:", trigger_block)
        self.assertNotRegex(trigger_block, r"(?m)^\s*push:")
        self.assertNotIn("release:", trigger_block)
        self.assertNotRegex(workflow, r"(?m)^\s+tags:")
        self.assertRegex(
            workflow,
            r"(?m)^permissions:\n  contents: write\n  actions: read$",
        )
        self.assertIn("prerelease: true", workflow)
        self.assertIn("body_path: docs/release-notes/v0.1.0.md", workflow)
        expected_assets = {
            "candidate/chemical_eia_core-0.1.0-py3-none-any.whl",
            "candidate/chemical_eia_core-0.1.0.tar.gz",
            "candidate/analyzing-chemical-eia-processes-0.1.0.zip",
            "candidate/SHA256SUMS.txt",
        }
        files_block = workflow.split("files: |", 1)[1]
        actual_assets = {
            line.strip()
            for line in files_block.splitlines()
            if line.strip()
        }
        self.assertEqual(actual_assets, expected_assets)
        self.assertNotIn("candidate/release-candidate.json", actual_assets)

    def test_release_workflow_reuses_authorized_candidate_bytes(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )
        for forbidden in (
            "python -m build",
            "build_artifacts",
            "build_skill_archive",
            "rebuild_wheel_from_sdist",
        ):
            self.assertNotIn(forbidden, workflow)
        for required in (
            "public_commit:",
            "source_run_id:",
            "candidate_artifact_name:",
            "candidate_manifest_sha256:",
            "actions: read",
            "actions/download-artifact@v4",
            "github-token: ${{ secrets.GITHUB_TOKEN }}",
            "run-id: ${{ inputs.source_run_id }}",
            "name: ${{ inputs.candidate_artifact_name }}",
            "tools/release_candidate.py verify-run",
            "tools/release_candidate.py verify-candidate",
            "fetch-depth: 0",
            "ref: ${{ inputs.tag }}",
        ):
            self.assertIn(required, workflow)
        self.assertEqual(workflow.count("required: true"), 5)
        self.assertIn("git cat-file -t", workflow)
        self.assertIn("git rev-parse", workflow)
        self.assertIn("gh api", workflow)
        self.assertIn("gh release view", workflow)
        self.assertIn(
            "          fi\n      - name: Create the approved GitHub prerelease",
            workflow,
        )
        self.assertNotIn("fi      - name:", workflow)
        self.assertIn("--no-index --no-deps", workflow)
        self.assertIn("examples/minimal/output-preliminary", workflow)
        self.assertIn("examples/minimal/output-formal", workflow)
        download_position = workflow.index("actions/download-artifact@v4")
        verify_position = workflow.index("tools/release_candidate.py verify-candidate")
        release_position = workflow.index("softprops/action-gh-release")
        self.assertLess(download_position, verify_position)
        self.assertLess(verify_position, release_position)

if __name__ == "__main__":
    unittest.main()
