import copy
import json
import uuid
from pathlib import Path

from chemical_eia import __version__
from chemical_eia.balance import apply_reaction, reaction_extent_from_conversion
from chemical_eia.model_io import (
    apply_decisions,
    dump_model,
    load_model,
    normalize_value_metadata,
    validate_model_authority,
)
from chemical_eia.rendering import (
    collect_pending_ai_suggestions,
    is_current_run_calculation,
    render_balance_view,
    render_mermaid,
    render_review_report,
)
from chemical_eia.validation import SEVERITY_ORDER, issue, validate_model

_OUTPUT_NAMES = {
    "project_model": "project-model.yaml",
    "process_flow": "process-flow.mmd",
    "diagnostic_balance": "diagnostic-balance.yaml",
    "review_report": "review-report.md",
}


def _resolve_active_value(model, path):
    """Resolve a dot-separated path to the active candidate in a versioned field.

    Returns the candidate dict whose ``version`` matches ``active_version``.
    """
    current = model
    for segment in path.split("."):
        if segment not in current or not isinstance(current[segment], dict):
            raise ValueError(f"decision path not found: {path}")
        current = current[segment]
    if "candidates" not in current or "active_version" not in current:
        raise ValueError(f"decision target is not a versioned field: {path}")
    active_version = current["active_version"]
    for candidate in current["candidates"]:
        if candidate.get("version") == active_version:
            return candidate
    raise ValueError(
        f"active version {active_version} not found among candidates at {path}"
    )


def derive_result_status(dependency_candidates):
    """Derive a calculation status from only its direct parameter dependencies."""
    for candidate in dependency_candidates:
        value = normalize_value_metadata(candidate)
        if (
            value.get("value_basis") == "ai_suggested"
            and value.get("adoption_status") != "adopted"
        ):
            return "provisional"
    return "determined"


def _has_active_pending_ai_suggestion(model):
    """Return True when *model* contains at least one versioned field whose
    active candidate is an un-adopted AI suggestion.

    Delegates to ``collect_pending_ai_suggestions`` so the traversal rules
    (active-candidate-only, recurse-into-active, exclude-derived-keys) are
    shared with ``render_review_report``.
    """
    if model is None:
        return False
    return bool(collect_pending_ai_suggestions(model))


def derive_analysis_status(calculations, issues, model=None):
    """Derive the whole-analysis status from current results and issues.

    Status priority (highest first):

    1. **blocked** — any ``blocking`` severity issue.
    2. **preliminary** — any provisional current-run calculation, *or* any
       active ``ai_suggested`` / ``pending`` candidate in a versioned field.
    3. **formal** — otherwise.

    When *model* is supplied (recommended), versioned fields are inspected
    for pending AI suggestions.  Callers that only pass two arguments
    continue to work — the model scan is skipped.
    """
    if any(item.get("severity") == "blocking" for item in issues):
        return "blocked"
    if any(
        calculation.get("result_status") == "provisional"
        for calculation in calculations
    ):
        return "preliminary"
    if _has_active_pending_ai_suggestion(model):
        return "preliminary"
    return "formal"


def mark_untrusted_outputs(model):
    """Deep-copy a model and quarantine results supplied as input."""
    updated = copy.deepcopy(model)
    for calculation in updated.get("calculations", []):
        calculation["authority_status"] = "untrusted_input"
        calculation["trusted_in_current_run"] = False
    updated.pop("issues", None)
    return updated


def _downgrade_input_adoptions(item):
    if isinstance(item, dict):
        normalized_basis = item.get("value_basis")
        if normalized_basis is None and item.get("origin") == "ai_proposed":
            normalized_basis = "ai_suggested"
        if (
            normalized_basis == "ai_suggested"
            and item.get("adoption_status") == "adopted"
        ):
            item["adoption_status"] = "pending"
        for value in item.values():
            _downgrade_input_adoptions(value)
    elif isinstance(item, list):
        for value in item:
            _downgrade_input_adoptions(value)


def sanitize_input_authority(model):
    """Quarantine input outputs and revoke self-claimed AI adoption."""
    updated = mark_untrusted_outputs(model)
    _downgrade_input_adoptions(updated)
    return updated


def _execute_reactions(model, current_run_id):
    """Execute declared reaction calculations.

    Returns a list of pipeline issues for unusable conversions.
    """
    pipeline_issues = []
    declarations = model.get("reaction_calculations", [])

    existing = model.get("calculations", [])
    replacement_ids = {
        "CAL-{}".format(declaration["reaction_id"])
        for declaration in declarations
    }
    preserved = [
        calculation
        for calculation in existing
        if calculation.get("calculation_id") not in replacement_ids
    ]
    generated = []

    for decl in declarations:
        reaction_id = decl["reaction_id"]
        conv_path = decl["conversion_path"]
        node_id = decl["node_id"]

        try:
            candidate = _resolve_active_value(model, conv_path)
        except (ValueError, KeyError, TypeError):
            pipeline_issues.append(
                issue(
                    "actual_conversion_missing",
                    "blocking",
                    "missing conversion at {}".format(conv_path),
                    [node_id, conv_path],
                    "technician",
                )
            )
            continue

        conv_value = candidate.get("value")
        if (
            isinstance(conv_value, bool)
            or not isinstance(conv_value, (int, float))
        ):
            pipeline_issues.append(
                issue(
                    "actual_conversion_missing",
                    "blocking",
                    "usable conversion not found at {}".format(conv_path),
                    [node_id, conv_path],
                    "technician",
                )
            )
            continue

        extent = reaction_extent_from_conversion(
            decl["limiting_mass"],
            decl["limiting_mw"],
            decl["limiting_coefficient"],
            conv_value,
        )
        outputs = apply_reaction(
            dict(decl["initial_masses"]),
            decl["species"],
            extent,
        )

        decl_sources = decl.get("source_ids", [])
        cand_sources = candidate.get("source_ids", [])
        seen = set()
        source_ids = []
        for sid in decl_sources + cand_sources:
            if sid not in seen:
                seen.add(sid)
                source_ids.append(sid)

        calc = {
            "calculation_id": "CAL-{}".format(reaction_id),
            "node_id": node_id,
            "name": "reaction_material_balance",
            "inputs": {
                "limiting_mass": decl["limiting_mass"],
                "limiting_mw": decl["limiting_mw"],
                "limiting_coefficient": decl["limiting_coefficient"],
                "conversion": copy.deepcopy(candidate),
                "initial_masses": copy.deepcopy(decl["initial_masses"]),
                "species": copy.deepcopy(decl["species"]),
            },
            "formula": (
                "extent = limiting_mass / limiting_mw * conversion / abs(limiting_coefficient); "
                "outputs = initial_masses + extent * coefficient * mw"
            ),
            "outputs": outputs,
            "origin": "calculated",
            "result_status": derive_result_status([candidate]),
            "dependency_paths": [conv_path],
            "producer": "chemical_eia",
            "producer_version": __version__,
            "run_id": current_run_id,
            "trusted_in_current_run": True,
            "source_ids": source_ids,
            "version": candidate.get("version"),
        }
        calc["review_status"] = (
            "provisional"
            if calc["result_status"] == "provisional"
            else "confirmed"
        )
        generated.append(calc)

    model["calculations"] = preserved + generated
    return pipeline_issues


def _sort_key(iss):
    return (SEVERITY_ORDER.get(iss["severity"], 99), iss["code"], iss["affected_ids"])


def _staged_write(output_dir, artifacts):
    """Write artifacts to *output_dir* using staged temporary files.

    Each artifact is first written to a ``.tmp`` sibling.  Only after all
    temporary writes succeed are the final files replaced with
    ``Path.replace``.  On failure temporary files are removed and existing
    final files are left unchanged.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    temp_pairs = []
    try:
        for filename, artifact in artifacts.items():
            final_path = out / filename
            temp_path = out / (filename + ".tmp")
            temp_pairs.append((temp_path, final_path))
            if callable(artifact):
                artifact(temp_path)
            else:
                temp_path.write_text(artifact, encoding="utf-8")
    except Exception:
        for temp_path, _ in temp_pairs:
            if temp_path.exists():
                temp_path.unlink()
        raise

    for temp_path, final_path in temp_pairs:
        temp_path.replace(final_path)


def run_pipeline(model_path, output_dir, decisions_path=None):
    """Execute the diagnostic process modeling pipeline.

    Parameters
    ----------
    model_path : str or Path
        Path to the JSON-compatible YAML project model.
    output_dir : str or Path
        Directory for the four output artifacts.
    decisions_path : str or Path, optional
        Path to a JSON list of expert decisions.

    Returns
    -------
    dict[str, Path]
        Mapping from output key to absolute ``Path``.
    """
    output_dir = Path(output_dir)

    model = sanitize_input_authority(load_model(model_path))
    authority_errors = validate_model_authority(model)
    if authority_errors:
        raise ValueError(
            "model authority validation failed: " + "; ".join(authority_errors)
        )

    if decisions_path is not None:
        decisions = json.loads(Path(decisions_path).read_text(encoding="utf-8"))
        if not isinstance(decisions, list):
            raise ValueError("decisions file must contain a JSON list at the root")
        model = apply_decisions(model, decisions)
        authority_errors = validate_model_authority(
            model, allow_adopted_suggestions=True
        )
        if authority_errors:
            raise ValueError(
                "model authority validation failed: "
                + "; ".join(authority_errors)
            )

    current_run_id = uuid.uuid4().hex
    pipeline_issues = _execute_reactions(model, current_run_id)

    validation_issues = validate_model(model)
    all_issues = validation_issues + pipeline_issues
    all_issues.sort(key=_sort_key)
    current_calculations = [
        calculation
        for calculation in model.get("calculations", [])
        if is_current_run_calculation(calculation, current_run_id)
    ]
    model["analysis_status"] = derive_analysis_status(
        current_calculations, all_issues, model=model
    )
    model["issues"] = all_issues

    process_flow_mmd = render_mermaid(model)
    balance_view = render_balance_view(model, current_run_id)
    diagnostic_balance_yaml = json.dumps(balance_view, ensure_ascii=False, indent=2) + "\n"
    review_report_md = render_review_report(model, all_issues)

    artifacts = {
        _OUTPUT_NAMES["project_model"]: lambda path: dump_model(model, path),
        _OUTPUT_NAMES["process_flow"]: process_flow_mmd,
        _OUTPUT_NAMES["diagnostic_balance"]: diagnostic_balance_yaml,
        _OUTPUT_NAMES["review_report"]: review_report_md,
    }

    _staged_write(output_dir, artifacts)

    return {
        key: (output_dir / filename).resolve()
        for key, filename in _OUTPUT_NAMES.items()
    }
