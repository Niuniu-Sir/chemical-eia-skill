# Chemical EIA Process Analysis

Chemical EIA Process Analysis is a portable skill pack and deterministic Python core for structuring chemical-process engineering analysis. It turns technician-reviewed process models into traceable tables and diagnostic calculations while keeping professional judgment with the technician.

## Preview status

This v0.1.0 release is a Preview. It is intended for controlled evaluation, reproducible workflow testing, and technician-assisted drafting. It is not a regulatory conclusion, does not replace enterprise verification, and must not be used as an unattended compliance decision system.

## Install the Python package

From the repository root, create an isolated environment and install the local package:

```text
python -m venv .venv
python -m pip install .
chemical-eia --help
```

The runtime has no third-party Python dependencies. Building a wheel or sdist requires the build tools declared in `pyproject.toml`.

## Install the Canonical Skill in Codex

The canonical Skill is stored at `skills/analyzing-chemical-eia-processes/`. Copy that directory into the `skills/` directory of the Codex home you are using. Keep the directory name unchanged so `$analyzing-chemical-eia-processes` remains the invocation name.

For a repository-local evaluation layout, use relative paths:

```text
python -c "from pathlib import Path; import shutil; shutil.copytree(Path('skills/analyzing-chemical-eia-processes'), Path('.codex/skills/analyzing-chemical-eia-processes'), dirs_exist_ok=True)"
```

Restart or reload the Codex session after installation.

## Install the Claude Code adapter

The adapter manifest at `adapters/claude-code/adapter.json` points to the canonical Skill and its relative installation target. Install the same Skill content rather than maintaining a second prompt:

```text
python -c "from pathlib import Path; import shutil; target=Path('.claude/skills/analyzing-chemical-eia-processes/SKILL.md'); target.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(Path('skills/analyzing-chemical-eia-processes/SKILL.md'), target)"
```

## Five-minute minimal example

The `examples/minimal` dataset is completely fictional. Run it first without technician decisions:

```text
chemical-eia examples/minimal/model.json --output-dir examples/minimal/output-preliminary
```

Then rerun with the reviewed decision record:

```text
chemical-eia examples/minimal/model.json --decisions examples/minimal/decisions.json --output-dir examples/minimal/output-formal
```

Compare the review reports and model outputs. The first run demonstrates a `preliminary` state; the second demonstrates the transition that is permitted only after a technician decision is supplied.

## Four outputs

The CLI writes four traceable artifacts:

1. `project-model.yaml` preserves the structured process model used for process-equipment-waste correspondence.
2. `process-flow.mmd` renders the node-and-stream view used to review routing and material balance context.
3. `diagnostic-balance.yaml` contains deterministic diagnostic calculations that support material balance, three-waste source strength, and water balance review.
4. `review-report.md` lists unresolved assumptions, conflicts, adoption status, and blocking items for technician action.

These artifacts are engineering-analysis inputs. Their presence does not mean that source data are complete or that a result has been accepted.

## From preliminary to formal

AI-proposed values remain `preliminary` and carry provenance, basis, version, and review status. The deterministic program may calculate with an explicitly permitted provisional candidate, but it cannot adopt that candidate.

A result becomes `formal` only when a technician records an explicit decision in a separate decisions file, the pipeline applies that decision without erasing history, and all blocking validation findings are resolved. Enterprise confirmation may still be required. Software never substitutes for that confirmation authority.

## Architecture boundary

The Skill translates submitted material into a structured node-and-stream model. The Python core performs routing, validation, arithmetic, balance diagnostics, and rendering. It does not infer undisclosed reaction definitions, silently repair missing flows, or convert an AI suggestion into a technician decision.

Project data stay outside the Skill. Use fictional or properly authorized inputs, preserve source anchors, and keep review decisions separate from the raw model.

## Support matrix

| Component | Supported in v0.1.0 |
|---|---|
| Operating systems | Windows and Ubuntu |
| Python | 3.10, 3.11, 3.12, 3.13 |
| Python package | wheel and sdist |
| Agent entry | Canonical Codex Skill |
| Adapter | Claude Code manifest |
| Data format | JSON or YAML process model and decisions |

## Security, contributing, and license

Read `SECURITY.md` before reporting a vulnerability and never attach confidential project material or credentials. Development and fictional-test-data requirements are in `CONTRIBUTING.md`; usage boundaries are in `SUPPORT.md`; release changes are in `CHANGELOG.md` and `docs/release-notes/v0.1.0.md`.

The project is licensed under Apache-2.0. See `LICENSE` for the complete terms.
