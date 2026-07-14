import copy
import json
from pathlib import Path

VALUE_BASES = frozenset({"submitted", "ai_suggested", "calculated"})
ADOPTION_STATUSES = frozenset({"not_applicable", "pending", "adopted"})
IMPACT_LEVELS = frozenset({"low", "medium", "high", "unknown"})


def load_model(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("model root must be an object")
    return data


def dump_model(model: dict, path: str | Path) -> None:
    if not isinstance(model, dict):
        raise ValueError("model root must be an object")
    Path(path).write_text(
        json.dumps(model, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def normalize_value_metadata(value: dict) -> dict:
    normalized = copy.deepcopy(value)
    if "value_basis" not in normalized:
        normalized["value_basis"] = {
            "ai_proposed": "ai_suggested",
            "expert_set": "submitted",
            "calculated": "calculated",
        }.get(normalized.get("origin"), normalized.get("origin"))
    if "adoption_status" not in normalized:
        if normalized.get("origin") == "ai_proposed":
            normalized["adoption_status"] = "pending"
        else:
            normalized["adoption_status"] = "not_applicable"
    return normalized


def validate_value_object(
    value: dict, *, allow_adopted_suggestion: bool = False
) -> list[str]:
    normalized = normalize_value_metadata(value)
    errors = []
    basis = normalized.get("value_basis")
    adoption = normalized.get("adoption_status")
    if basis not in VALUE_BASES:
        errors.append(f"unsupported value_basis: {basis!r}")
    if adoption not in ADOPTION_STATUSES:
        errors.append(f"unsupported adoption_status: {adoption!r}")
    if "version" not in normalized:
        errors.append("version is required")
    elif (
        isinstance(normalized["version"], bool)
        or not isinstance(normalized["version"], int)
        or normalized["version"] <= 0
    ):
        errors.append("version must be a positive integer")
    if basis == "submitted" and adoption != "not_applicable":
        errors.append("submitted values require adoption_status=not_applicable")
    if basis == "ai_suggested":
        source_ids = normalized.get("source_ids")
        if (
            not isinstance(source_ids, list)
            or not source_ids
            or any(
                not isinstance(source_id, str) or not source_id.strip()
                for source_id in source_ids
            )
        ):
            errors.append(
                "ai_suggested values require non-empty string source_ids"
            )
        suggestion_basis = normalized.get("suggestion_basis")
        if not isinstance(suggestion_basis, str) or not suggestion_basis.strip():
            errors.append("ai_suggested values require non-empty suggestion_basis")
        selection_logic = normalized.get("selection_logic")
        if not isinstance(selection_logic, str) or not selection_logic.strip():
            errors.append("ai_suggested values require non-empty selection_logic")
        affected_result_ids = normalized.get("affected_result_ids")
        if (
            not isinstance(affected_result_ids, list)
            or not affected_result_ids
            or any(
                not isinstance(result_id, str) or not result_id.strip()
                for result_id in affected_result_ids
            )
        ):
            errors.append("ai_suggested values require non-empty affected_result_ids")
        if normalized.get("impact_level") not in IMPACT_LEVELS:
            errors.append(
                "ai_suggested values require impact_level=low|medium|high|unknown"
            )
        if adoption == "adopted" and not allow_adopted_suggestion:
            errors.append("ai_suggested values cannot self-claim adopted")
        if adoption not in {"pending", "adopted"}:
            errors.append("ai_suggested values require pending or adopted status")
    if basis == "calculated":
        errors.append("calculated values cannot be input parameter candidates")
    return errors


def validate_model_authority(
    model: dict, *, allow_adopted_suggestions: bool = False
) -> list[str]:
    errors = []

    def walk(item, path):
        if isinstance(item, dict):
            if "value" in item and ("value_basis" in item or "origin" in item):
                for error in validate_value_object(
                    item,
                    allow_adopted_suggestion=allow_adopted_suggestions,
                ):
                    errors.append(f"{path}: {error}")
            for key, child in item.items():
                walk(child, f"{path}.{key}")
        elif isinstance(item, list):
            for index, child in enumerate(item):
                walk(child, f"{path}[{index}]")

    walk(model, "$")
    return errors


def _field_at_path(model: dict, path: str) -> dict:
    current = model
    for segment in path.split("."):
        if segment not in current or not isinstance(current[segment], dict):
            raise ValueError(f"decision path not found: {path}")
        current = current[segment]
    if "candidates" not in current or "active_version" not in current:
        raise ValueError(f"decision target is not a versioned field: {path}")
    return current


def _require_positive_version(version, *, label: str = "version") -> None:
    if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
        raise ValueError(f"{label} must be a positive integer")


def _existing_versions(field: dict) -> set[int]:
    return {candidate["version"] for candidate in field["candidates"]}


def _apply_adopt_decision(field: dict, decision: dict) -> dict:
    candidate_version = decision.get("candidate_version")
    _require_positive_version(candidate_version, label="candidate_version")
    new_version = decision.get("version")
    _require_positive_version(new_version)

    versions = _existing_versions(field)
    if new_version in versions:
        raise ValueError(f"duplicate version {new_version} at {decision['path']}")

    source = next(
        (
            candidate
            for candidate in field["candidates"]
            if candidate.get("version") == candidate_version
        ),
        None,
    )
    if source is None:
        raise ValueError(
            f"candidate version {candidate_version} not found at {decision['path']}"
        )

    normalized = normalize_value_metadata(source)
    if normalized.get("value_basis") != "ai_suggested":
        raise ValueError("only ai_suggested candidates can be adopted")
    adoption_status = normalized.get("adoption_status")
    if adoption_status == "adopted":
        raise ValueError(f"candidate version {candidate_version} is already adopted")
    if adoption_status != "pending":
        raise ValueError(
            f"candidate version {candidate_version} must have "
            "adoption_status=pending"
        )
    source_errors = validate_value_object(normalized)
    if source_errors:
        raise ValueError(
            f"candidate version {candidate_version} is invalid: "
            + "; ".join(source_errors)
        )

    adopted = copy.deepcopy(normalized)
    adopted["adoption_status"] = "adopted"
    adopted.pop("origin", None)
    adopted["review_status"] = "confirmed"
    adopted["version"] = new_version
    errors = validate_value_object(adopted, allow_adopted_suggestion=True)
    if errors:
        raise ValueError("; ".join(errors))
    return adopted


def apply_decisions(model: dict, decisions: list[dict]) -> dict:
    updated = copy.deepcopy(model)
    for decision in decisions:
        field = _field_at_path(updated, decision["path"])
        if decision.get("action") == "adopt":
            value = _apply_adopt_decision(field, decision)
        elif "action" in decision:
            raise ValueError(f"unsupported decision action: {decision['action']!r}")
        else:
            value = normalize_value_metadata(copy.deepcopy(decision["value"]))
            errors = validate_value_object(value)
            if errors:
                raise ValueError("; ".join(errors))
            if value["version"] in _existing_versions(field):
                raise ValueError(
                    f"duplicate version {value['version']} at {decision['path']}"
                )
        field["candidates"].append(value)
        field["active_version"] = value["version"]
    return updated
