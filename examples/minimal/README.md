# Minimal fictional example

This example is completely fictional and designed from scratch. Its names, masses, topology, molecular weights, and coefficients do not describe a real compound, facility, report, or process mechanism.

Run the first pass without a decision:

```text
chemical-eia examples/minimal/model.json --output-dir examples/minimal/output/preliminary
```

The active conversion candidate is an AI-origin suggestion, so this run remains `preliminary`.

Run the reviewed pass with the separate decision record:

```text
chemical-eia examples/minimal/model.json --decisions examples/minimal/decisions.json --output-dir examples/minimal/output/formal
```

`decisions.json` simulates an explicit technician adoption. The AI candidate cannot adopt itself. Even if an input AI candidate claims it is already adopted, the pipeline treats that claim as untrusted and it is downgraded before decisions are applied.

The example contains three nodes and five streams. The reacted stream enters the fictional gas-liquid separation node and splits into a 75 kg product branch and a 25 kg purge branch. The numbers exist only to demonstrate deterministic mass formulas and review-state transitions.
