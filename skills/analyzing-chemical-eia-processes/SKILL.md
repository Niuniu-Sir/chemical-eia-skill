---
name: analyzing-chemical-eia-processes
description: Use when analyzing chemical process materials for environmental impact engineering, including process topology, material balances, wastewater, waste gas, solid waste, or iterative technician review.
---

# Analyzing Chemical EIA Processes

## Step 1: Read technician-submitted materials

Read only the materials the technician provides as this run's input.  Do not
track whether the materials came from an enterprise document, a communication
thread, or the technician directly.  The technician is the only confirmation
authority.

## Step 2: Extract explicit facts and source anchors

- Assign a stable `source_id` to every fact extracted from the input.
- Every fact must carry `source_ids` referencing its origin.
- Do not present inference as explicit material.
- Preserve conflicting sources and historical versions as separate candidates.

## Step 3: Build the process model with nodes and streams

- Model the process as `nodes` connected by `streams` using stable internal
  identifiers (`node_id`, `stream_id`).
- External display labels may be renumbered consecutively, but internal
  identifiers must never change.
- Preserve series, split, merge, recycle, and alternative route topologies.
- Create a `reaction_calculations` entry only when the submitted materials
  explicitly provide a complete reaction definition and all calculation inputs
  required by the model. Its `node_id` must exactly match the stable `node_id`
  of the corresponding reaction node. If any required reaction definition or
  calculation input is missing, leave the `reaction_calculations` entry absent;
  do not infer or invent stoichiometric data. The deterministic CLI will report
  the resulting blocking issue.
- Do not duplicate reaction calculation formulas in this Skill.

## Step 4: Preserve gaps and conflicts

- Do not silently delete conflicting information.
- Do not rewrite an unknown value as a confirmed one.
- When critical structural gaps exist (reaction equations, material routing),
  leave them missing rather than inventing placeholders.
- Estimable parameters such as temperature, pressure, and conversion may enter
  the AI proposal workflow.

## Step 5: Create AI provisional candidates

Every AI proposal must carry the complete metadata:

```yaml
origin: ai_proposed
value_basis: ai_suggested
review_status: provisional
adoption_status: pending
source_ids: [...]
version: 1
suggestion_basis: ...
selection_logic: ...
affected_result_ids: [...]
impact_level: ...
```

Parameter fields use `candidates` with `active_version`.  AI proposals may
participate in preliminary computation but must never self-label as adopted by
the technician.  Do not mark an AI proposal as adopted.

## Step 6: Record technician decisions

- The technician is the only confirmation authority.
- All adoptions, replacements, and rejections are recorded in a standalone
  `decisions.json` file.
- Never overwrite historical candidates; append new versions and advance
  `active_version` only when a technician decision exists.
- Do not assign issue severity.

## Step 7: Invoke the installed deterministic program

The raw `project-model.yaml` must always carry:

```yaml
calculations: []
issues: []
```

Run the installed CLI without decisions:

```text
chemical-eia project-model.yaml --output-dir results
```

When a technician `decisions.json` is available, run:

```text
chemical-eia project-model.yaml --output-dir results --decisions decisions.json
```

Deterministic computation, validation, formal result status, and issue
severity are produced exclusively by the installed `chemical-eia` program.
The AI prepares the `project-model.yaml` input; it does **not** perform the
calculations or assign severity levels.

## Step 8: Inspect results and iterate

- Examine the four output artifacts under `results/`.
- Present every `blocking` and `review` item to the technician.
- Update the standalone `decisions.json` and re-run the same deterministic
  core.
- While any `blocking` issue remains open the run is not formally complete.
- When critical AI proposals remain unadopted the output is preliminary;
  formal results are produced by the deterministic program only after the
  technician has adopted the relevant values.
