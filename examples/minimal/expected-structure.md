# Expected structure

This completely fictional example was designed from scratch. Verify semantic fields rather than comparing a full text snapshot.

## `project-model.yaml`

JSON-compatible structured output containing the three nodes, five streams, generated reaction calculation, validation issues, provenance, and `analysis_status`. The run without decisions is `preliminary`; the run with the technician decision is `formal`.

## `process-flow.mmd`

Mermaid topology for the dosing, fictional reaction, and gas-liquid separation nodes. `S-REACTED` enters the separation node, then `S-PRODUCT` and `S-PURGE` leave it as a simple split.

## `diagnostic-balance.yaml`

JSON-compatible diagnostic projection containing only calculations produced and trusted in the current run. The conversion dependency is provisional before adoption and determined after adoption.

## `review-report.md`

Human-readable status and issue summary. The preliminary report identifies the pending AI suggestion for technician confirmation. The formal report contains no blocking issue after the independent decision is applied.

The generated directory must contain exactly these four files. UUID-like run identifiers and presentation details may vary, so they are intentionally not frozen here.
