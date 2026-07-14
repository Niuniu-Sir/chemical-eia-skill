from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.public_scan import scan_file_bytes, scan_source_tree


ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "release" / "public-release-policy.json"
SCANNER = ROOT / "tools" / "public_scan.py"
THIS_TEST = Path(__file__).resolve()


class PublicReleaseSafetyTests(unittest.TestCase):
    def test_complete_public_tree_scans_clean(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            copy_tracked_tree(root)
            self.assertEqual(scan_source_tree(root, POLICY), [])

    def test_scanner_and_safety_test_do_not_trigger_their_own_rules(self):
        self.assertEqual(
            scan_file_bytes("tools/public_scan.py", SCANNER.read_bytes()),
            [],
        )
        self.assertEqual(
            scan_file_bytes(
                "tests/public/test_release_safety.py",
                THIS_TEST.read_bytes(),
            ),
            [],
        )

    def test_runtime_assembled_negative_examples_are_detected(self):
        separator = bytes((92,))
        machine_path = b"E" + b":" + separator + b"Users" + separator + b"sample"
        assignment = b"api_" + b"token" + b" = " + b"abcdefghijklmnop"
        credential = b"g" + b"hp_" + b"abcdefghijklmnopqrstuv"

        findings = scan_file_bytes(
            "safe/runtime-negative.txt",
            b"\n".join((machine_path, assignment, credential)),
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertIn("CONTENT_MACHINE_PATH", rule_ids)
        self.assertIn("CONTENT_SECRET_ASSIGNMENT", rule_ids)
        self.assertIn("CONTENT_CREDENTIAL_PREFIX", rule_ids)

    def test_unexpected_file_fails_closed_without_excluding_tests(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            copy_tracked_tree(root)
            unexpected = root / "unexpected-public-file.txt"
            unexpected.write_text("fictional public text\n", encoding="utf-8")
            findings = scan_source_tree(root, POLICY)
            self.assertTrue(
                any(finding.rule_id == "FILE_NOT_ALLOWED" for finding in findings)
            )


def copy_tracked_tree(destination_root: Path):
    for relative in json_tracked_files():
        source = ROOT / relative
        destination = destination_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())


def json_tracked_files():
    import json

    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    return tuple(policy["tracked_files"])


if __name__ == "__main__":
    unittest.main()
