from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SKILL_NAME = "analyzing-chemical-eia-processes"
SKILL = ROOT / "skills" / SKILL_NAME
ADAPTER = ROOT / "adapters" / "claude-code" / "adapter.json"


class SkillAndAdapterTests(unittest.TestCase):
    def test_canonical_skill_frontmatter_and_agent_metadata_are_stable(self):
        self.assertEqual(SKILL.name, SKILL_NAME)
        text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("---\n"))
        frontmatter = text.split("---\n", 2)[1]
        fields = {}
        for line in frontmatter.splitlines():
            key, separator, value = line.partition(":")
            if separator:
                fields[key.strip()] = value.strip()
        self.assertEqual(fields["name"], SKILL_NAME)
        self.assertTrue(fields["description"].startswith("Use when "))

        agent = (SKILL / "agents" / "openai.yaml").read_text(encoding="utf-8")
        display_name = "\u5316\u5de5\u73af\u8bc4\u521d\u6b65\u5de5\u827a\u5efa\u6a21"
        self.assertIn(f'display_name: "{display_name}"', agent)
        self.assertIn("short_description:", agent)
        self.assertIn("$" + SKILL_NAME, agent)

    def test_adapter_maps_to_canonical_skill_and_documented_install_targets(self):
        adapter = json.loads(ADAPTER.read_text(encoding="utf-8"))
        self.assertEqual(adapter["name"], SKILL_NAME)
        self.assertEqual(
            adapter["canonical_skill"],
            "../../skills/analyzing-chemical-eia-processes/SKILL.md",
        )
        self.assertEqual(
            adapter["install_target"],
            ".claude/skills/analyzing-chemical-eia-processes/SKILL.md",
        )
        resolved = (ADAPTER.parent / adapter["canonical_skill"]).resolve()
        self.assertEqual(resolved, (SKILL / "SKILL.md").resolve())

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(".codex/skills/" + SKILL_NAME, readme)
        self.assertIn(".claude/skills/" + SKILL_NAME, readme)

    def test_removing_adapter_does_not_break_core_cli_or_canonical_skill(self):
        with tempfile.TemporaryDirectory() as temporary:
            isolated = Path(temporary)
            shutil.copytree(ROOT / "src", isolated / "src")
            shutil.copytree(ROOT / "skills", isolated / "skills")
            shutil.copytree(ROOT / "adapters", isolated / "adapters")
            moved = isolated / "removed-adapter"
            shutil.move(str(isolated / "adapters" / "claude-code"), moved)

            self.assertFalse((isolated / "adapters" / "claude-code").exists())
            self.assertTrue(
                (isolated / "skills" / SKILL_NAME / "SKILL.md").is_file()
            )
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(isolated / "src")
            environment["PYTHONUTF8"] = "1"
            environment["PYTHONIOENCODING"] = "utf-8"
            imported = subprocess.run(
                [sys.executable, "-c", "import chemical_eia"],
                cwd=isolated,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            self.assertEqual(imported.returncode, 0, imported.stderr)
            help_result = subprocess.run(
                [sys.executable, "-m", "chemical_eia.cli", "--help"],
                cwd=isolated,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            self.assertEqual(help_result.returncode, 0, help_result.stderr)
            self.assertIn("chemical-eia", help_result.stdout)


if __name__ == "__main__":
    unittest.main()
