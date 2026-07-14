from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.public.helpers import OUTPUT_NAMES, ROOT, load_json, run_cli


EXAMPLE = ROOT / "examples" / "minimal"
NODE_IDS = {
    "N-DOSING",
    "N-FICTIONAL-REACTION",
    "N-GAS-LIQUID-SEPARATION",
}
STREAM_IDS = {
    "S-FEED",
    "S-PREMIX",
    "S-REACTED",
    "S-PRODUCT",
    "S-PURGE",
}
MATERIAL_IDS = {
    "FEED-A",
    "REAGENT-B",
    "INTERMEDIATE-C",
    "PRODUCT-D",
    "PURGE-E",
}


class MinimalExampleTests(unittest.TestCase):
    def test_topology_materials_and_fictional_boundary_are_exact(self):
        model = load_json(EXAMPLE / "model.json")
        self.assertEqual(model["schema_version"], "1.0")
        self.assertEqual({node["node_id"] for node in model["nodes"]}, NODE_IDS)
        self.assertEqual(
            {stream["stream_id"] for stream in model["streams"]},
            STREAM_IDS,
        )
        component_ids = {
            component["material_id"]
            for stream in model["streams"]
            for component in stream["components"]
        }
        species_ids = set(model["reaction_calculations"][0]["species"])
        initial_ids = set(model["reaction_calculations"][0]["initial_masses"])
        self.assertEqual(component_ids | species_ids | initial_ids, MATERIAL_IDS)

        streams = {stream["stream_id"]: stream for stream in model["streams"]}
        separation = next(
            node
            for node in model["nodes"]
            if node["node_id"] == "N-GAS-LIQUID-SEPARATION"
        )
        self.assertEqual(separation["input_stream_ids"], ["S-REACTED"])
        self.assertEqual(
            separation["output_stream_ids"],
            ["S-PRODUCT", "S-PURGE"],
        )
        self.assertEqual(streams["S-REACTED"]["to_node"], separation["node_id"])
        self.assertEqual(
            {streams[name]["from_node"] for name in separation["output_stream_ids"]},
            {separation["node_id"]},
        )
        self.assertEqual(
            {name: streams[name]["total_mass"] for name in STREAM_IDS},
            {
                "S-FEED": 100,
                "S-PREMIX": 100,
                "S-REACTED": 100,
                "S-PRODUCT": 75,
                "S-PURGE": 25,
            },
        )

        conversion = model["parameters"]["conversion"]
        self.assertEqual(conversion["active_version"], 1)
        self.assertEqual(
            conversion["candidates"],
            [
                {
                    "value": 0.8,
                    "unit": "fraction",
                    "value_basis": "ai_suggested",
                    "adoption_status": "pending",
                    "review_status": "provisional",
                    "source_ids": ["SRC-PUBLIC-FICTION"],
                    "suggestion_basis": "Fictional demonstration value selected from scratch.",
                    "selection_logic": "Use one round number solely to exercise deterministic formulas.",
                    "affected_result_ids": ["CAL-RXN-PUBLIC"],
                    "impact_level": "high",
                    "version": 1,
                }
            ],
        )

        documents = (
            EXAMPLE / "README.md",
            EXAMPLE / "expected-structure.md",
        )
        for path in documents:
            text = path.read_text(encoding="utf-8").casefold()
            self.assertIn("fictional", text)
            self.assertIn("from scratch", text)
        notice = model["sources"][0]["description"].casefold()
        self.assertIn("fictional", notice)
        self.assertIn("from scratch", notice)
        forbidden = (
            "tests/" + "fixtures",
            "tests/" + "evals",
            "case" + "-001",
            "Project" + "_Skill",
        )
        combined = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (
                EXAMPLE / "README.md",
                EXAMPLE / "model.json",
                EXAMPLE / "decisions.json",
                EXAMPLE / "expected-structure.md",
            )
        )
        for marker in forbidden:
            self.assertNotIn(marker, combined)

    def test_decision_file_is_the_only_approved_adoption(self):
        decisions = load_json(EXAMPLE / "decisions.json")
        self.assertEqual(
            decisions,
            [
                {
                    "path": "parameters.conversion",
                    "action": "adopt",
                    "candidate_version": 1,
                    "version": 2,
                }
            ],
        )
        readme = (EXAMPLE / "README.md").read_text(encoding="utf-8")
        self.assertIn("technician", readme)
        self.assertIn("cannot adopt itself", readme)
        self.assertIn("downgraded", readme)

    def test_cli_transitions_preliminary_to_formal_and_writes_only_four_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            preliminary = root / "preliminary"
            formal = root / "formal"

            first = run_cli(preliminary)
            self.assertEqual(first.returncode, 0, first.stderr)
            second = run_cli(formal, decisions=Path("examples/minimal/decisions.json"))
            self.assertEqual(second.returncode, 0, second.stderr)

            self.assertEqual({path.name for path in preliminary.iterdir()}, OUTPUT_NAMES)
            self.assertEqual({path.name for path in formal.iterdir()}, OUTPUT_NAMES)

            preliminary_model = load_json(preliminary / "project-model.yaml")
            formal_model = load_json(formal / "project-model.yaml")
            self.assertEqual(preliminary_model["analysis_status"], "preliminary")
            self.assertEqual(formal_model["analysis_status"], "formal")
            self.assertFalse(
                any(issue["severity"] == "blocking" for issue in formal_model["issues"])
            )
            self.assertEqual(
                formal_model["parameters"]["conversion"]["active_version"],
                2,
            )
            adopted = formal_model["parameters"]["conversion"]["candidates"][-1]
            self.assertEqual(adopted["adoption_status"], "adopted")
            self.assertEqual(adopted["review_status"], "confirmed")

            for output in (preliminary, formal):
                self.assertIsInstance(load_json(output / "diagnostic-balance.yaml"), dict)
                self.assertTrue((output / "process-flow.mmd").read_text(encoding="utf-8"))
                self.assertTrue((output / "review-report.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
