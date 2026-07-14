SEVERITY_ORDER = {"error": 0, "blocking": 1, "review": 2, "notice": 3}

_VALID_SOURCE_SCOPES = frozenset(
    {"process_direct", "treatment_secondary", "utility_shared", "plant_wide"}
)


def issue(code, severity, message, affected_ids, required_actor):
    if not affected_ids:
        affected_ids = ["PROJECT"]
    issue_id = "ISS-{}-{}".format(code, "-".join(affected_ids))
    return {
        "issue_id": issue_id,
        "severity": severity,
        "code": code,
        "message": message,
        "affected_ids": affected_ids,
        "required_actor": "technician",
    }


def validate_capacity(capacity):
    hours_per_batch = capacity.get("hours_per_batch", 0)
    if hours_per_batch <= 0:
        raise ValueError("hours_per_batch must be positive")
    annual_hours = capacity.get("annual_hours", 0)
    declared_max = capacity.get("declared_max_batches", 0)
    equipment_id = capacity.get("equipment_id", "PROJECT")

    calculated = annual_hours / hours_per_batch
    if abs(calculated - declared_max) > 0.01:
        return [
            issue(
                "capacity_batch_conflict",
                "error",
                "calculated batches {} conflict with declared max {}".format(
                    round(calculated, 4), declared_max
                ),
                [equipment_id],
                "technician",
            )
        ]
    return []


def validate_calendar(calendar):
    production = calendar.get("production_months", 0)
    idle_months = calendar.get("idle_months", 0)
    total = production + idle_months
    if total not in (0, 12):
        return [
            issue(
                "calendar_conflict",
                "review",
                "production {} + idle {} = {} months, expected 0 or 12".format(
                    production, idle_months, total
                ),
                [],
                "technician",
            )
        ]
    return []


def _build_stream_index(model):
    return {s["stream_id"]: s for s in model.get("streams", []) if "stream_id" in s}


def _streams_have_numeric_total_mass(streams):
    for s in streams:
        if s is None:
            return False
        mass = s.get("total_mass")
        if mass is None or not isinstance(mass, (int, float)):
            return False
    return True


def _streams_have_complete_components(streams):
    for s in streams:
        if s is None:
            return False
        components = s.get("components")
        if not components or not isinstance(components, list):
            return False
        for c in components:
            if not isinstance(c, dict):
                return False
            if "material_id" not in c:
                return False
            mass = c.get("mass")
            if mass is None or not isinstance(mass, (int, float)):
                return False
    return True


def _aggregate_component_masses(streams):
    totals = {}
    for s in streams:
        for c in s.get("components", []):
            mid = c.get("material_id")
            mass = c.get("mass", 0)
            if mid is not None and isinstance(mass, (int, float)):
                totals[mid] = totals.get(mid, 0) + mass
    return totals


def validate_node_balances(model, tolerance=0.01):
    if tolerance < 0:
        raise ValueError("tolerance cannot be negative")

    stream_index = _build_stream_index(model)
    issues = []

    for node in model.get("nodes", []):
        node_id = node.get("node_id")
        if not node_id:
            continue

        input_ids = node.get("input_stream_ids", [])
        output_ids = node.get("output_stream_ids", [])

        input_streams = [stream_index.get(sid) for sid in input_ids]
        output_streams = [stream_index.get(sid) for sid in output_ids]

        all_streams = input_streams + output_streams

        # Total mass closure: only when every referenced stream exists and has numeric total_mass
        if _streams_have_numeric_total_mass(all_streams):
            total_in = sum(s["total_mass"] for s in input_streams)
            total_out = sum(s["total_mass"] for s in output_streams)
            if abs(total_in - total_out) > tolerance:
                issues.append(
                    issue(
                        "mass_not_closed",
                        "error",
                        "node {} input mass {} kg does not equal output mass {} kg".format(
                            node_id, total_in, total_out
                        ),
                        [node_id],
                        "technician",
                    )
                )

        # Component closure: only when flag is exactly True and all streams have complete components
        if node.get("component_balance_required") is True and _streams_have_complete_components(
            all_streams
        ):
            in_components = _aggregate_component_masses(input_streams)
            out_components = _aggregate_component_masses(output_streams)

            all_material_ids = set(in_components.keys()) | set(out_components.keys())
            for mid in sorted(all_material_ids):
                in_mass = in_components.get(mid, 0)
                out_mass = out_components.get(mid, 0)
                if abs(in_mass - out_mass) > tolerance:
                    issues.append(
                        issue(
                            "component_not_closed",
                            "error",
                            "node {} material {} input {} kg output {} kg".format(
                                node_id, mid, in_mass, out_mass
                            ),
                            [node_id, mid],
                            "technician",
                        )
                    )

    return issues


def validate_versioned_fields(model):
    issues = []

    def _walk(obj, path):
        if isinstance(obj, dict):
            if "candidates" in obj and "active_version" in obj:
                confirmed = [
                    c
                    for c in obj["candidates"]
                    if isinstance(c, dict)
                    and c.get("review_status") == "confirmed"
                ]
                if len(confirmed) >= 2:
                    values = [c.get("value") for c in confirmed]
                    if any(value != values[0] for value in values[1:]):
                        issues.append(
                            issue(
                                "active_value_conflict",
                                "review",
                                "versioned field {} has conflicting confirmed values".format(
                                    ".".join(path)
                                ),
                                [".".join(path)],
                                "technician",
                            )
                        )
                return
            for key, value in obj.items():
                _walk(value, path + [key])
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                _walk(item, path + [str(idx)])

    _walk(model, [])
    return issues


def validate_source_scopes(model):
    issues = []
    for node in model.get("nodes", []):
        node_id = node.get("node_id")
        if not node_id:
            continue
        scope = node.get("source_scope")
        if scope not in _VALID_SOURCE_SCOPES:
            issues.append(
                issue(
                    "source_scope_missing",
                    "review",
                    "node {} has missing or invalid source_scope".format(node_id),
                    [node_id],
                    "technician",
                )
            )
    return issues


def validate_declared_properties(model):
    issues = []
    for stream in model.get("streams", []):
        stream_id = stream.get("stream_id")
        if not stream_id:
            continue
        declared = stream.get("declared_property")
        if not declared:
            continue
        components = stream.get("components")
        if not components or not isinstance(components, list) or len(components) == 0:
            issues.append(
                issue(
                    "declared_property_unverified",
                    "review",
                    "stream {} declared property '{}' lacks component evidence".format(
                        stream_id, declared
                    ),
                    [stream_id],
                    "technician",
                )
            )
    return issues


def validate_process_skeleton(model):
    issues = []
    if not model.get("nodes"):
        issues.append(
            issue(
                "process_nodes_missing",
                "blocking",
                "process model must contain at least one process node",
                [],
                "technician",
            )
        )
    if not model.get("streams"):
        issues.append(
            issue(
                "process_streams_missing",
                "blocking",
                "process model must contain at least one material stream",
                [],
                "technician",
            )
        )
    return issues


def validate_reaction_definitions(model):
    declared_node_ids = {
        declaration.get("node_id")
        for declaration in model.get("reaction_calculations", [])
        if isinstance(declaration, dict)
    }
    issues = []
    for node in model.get("nodes", []):
        if not isinstance(node, dict) or node.get("operation_type") != "reaction":
            continue
        node_id = node.get("node_id")
        if node_id not in declared_node_ids:
            issues.append(
                issue(
                    "reaction_definition_missing",
                    "blocking",
                    "reaction node {} requires a matching reaction definition".format(
                        node_id
                    ),
                    [node_id] if node_id else [],
                    "technician",
                )
            )
    return issues


def _sort_key(iss):
    return (SEVERITY_ORDER.get(iss["severity"], 99), iss["code"], iss["affected_ids"])


def validate_model(model, tolerance=0.01):
    issues = validate_process_skeleton(model)

    issues.extend(validate_reaction_definitions(model))

    for capacity in model.get("capacity_checks", []):
        issues.extend(validate_capacity(capacity))

    calendar = model.get("calendar")
    if isinstance(calendar, dict):
        issues.extend(validate_calendar(calendar))

    issues.extend(validate_node_balances(model, tolerance=tolerance))
    issues.extend(validate_versioned_fields(model))
    issues.extend(validate_source_scopes(model))
    issues.extend(validate_declared_properties(model))

    issues.sort(key=_sort_key)
    return issues
