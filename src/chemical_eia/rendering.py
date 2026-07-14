import copy

from chemical_eia.model_io import normalize_value_metadata

_SEVERITY_ORDER = ["error", "blocking", "review", "notice"]

_CALCULATION_KEYS = [
    "calculation_id",
    "node_id",
    "name",
    "inputs",
    "formula",
    "outputs",
    "origin",
    "review_status",
    "source_ids",
    "version",
    "result_status",
    "dependency_paths",
    "producer",
    "producer_version",
    "run_id",
    "trusted_in_current_run",
]


def _normalize_node_key(node_id):
    """Transform a node_id into a stable Mermaid-safe key."""
    chars = []
    for ch in node_id:
        if ch.isascii() and (ch.isalnum() or ch == "_"):
            chars.append(ch)
        else:
            chars.append("_")
    key = "".join(chars)
    if not key or not (key[0].isascii() and (key[0].isalpha() or key[0] == "_")):
        key = "NODE_" + key
    return key


def _escape_label(text):
    """Escape a label for Mermaid double-quoted text."""
    text = text.replace('"', "&quot;")
    text = text.replace("\r", " ")
    text = text.replace("\n", " ")
    text = text.replace("|", "/")
    return text


def render_mermaid(model):
    """Render a Mermaid flowchart from the project model.

    Returns a string starting with ``flowchart LR`` and ending with one newline.
    """
    nodes = model.get("nodes", [])
    streams = model.get("streams", [])

    # Build deterministic node-key map; detect duplicates.
    node_keys = {}
    seen_keys = set()
    for node in nodes:
        nid = node["node_id"]
        key = _normalize_node_key(nid)
        if key in seen_keys:
            raise ValueError(f"duplicate Mermaid node key: {key}")
        seen_keys.add(key)
        node_keys[nid] = key

    known_nodes = {n["node_id"] for n in nodes}

    lines = ["flowchart LR"]

    # Nodes in model order.
    for node in nodes:
        key = node_keys[node["node_id"]]
        name = node.get("node_name") or node["node_id"]
        lines.append(f'    {key}["{_escape_label(name)}"]')

    # Streams in model order; skip unknown endpoints.
    for stream in streams:
        from_nid = stream.get("from_node")
        to_nid = stream.get("to_node")
        if from_nid not in known_nodes or to_nid not in known_nodes:
            continue

        from_key = node_keys[from_nid]
        to_key = node_keys[to_nid]
        label = _escape_label(stream.get("declared_name") or stream["stream_id"])

        if stream.get("stream_role") == "recycle":
            label = f"回用: {label}"
            lines.append(f'    {from_key} -.->|"{label}"| {to_key}')
        else:
            lines.append(f'    {from_key} -->|"{label}"| {to_key}')

    return "\n".join(lines) + "\n"


def is_current_run_calculation(calculation, current_run_id):
    """Return whether a calculation has complete trusted current-run provenance."""
    return (
        calculation.get("producer") == "chemical_eia"
        and bool(calculation.get("producer_version"))
        and calculation.get("run_id") == current_run_id
        and calculation.get("trusted_in_current_run") is True
        and calculation.get("result_status") in {"determined", "provisional"}
    )


def render_balance_view(model, current_run_id):
    """Return a projection of the model that exposes only calculation fields
    authorized for human review.

    Uses ``copy.deepcopy`` so mutations to the returned view cannot affect the
    source model.
    """
    view = {
        "schema_version": model.get("schema_version", "1.0"),
        "calculations": [],
    }
    for calc in model.get("calculations", []):
        if not is_current_run_calculation(calc, current_run_id):
            continue
        projected = {}
        for key in _CALCULATION_KEYS:
            if key in calc:
                projected[key] = copy.deepcopy(calc[key])
        view["calculations"].append(projected)
    return view


def collect_pending_ai_suggestions(model):
    """Return ``(path, normalized_active_candidate)`` for every versioned
    field in *model* whose active candidate is an un-adopted AI suggestion.

    Only the candidate matching ``active_version`` is checked — historical
    non-active candidates are never recursed into.  The active candidate
    itself is further recursed so that nested versioned fields inside a
    submitted/not_applicable wrapper are still discovered.

    Top-level keys ``calculations``, ``issues`` and ``analysis_status`` are
    excluded from traversal because they hold derived or untrusted output
    that must not influence the pending-AI scan.
    """
    EXCLUDED_TOP_KEYS = {"calculations", "issues", "analysis_status"}
    suggestions = []

    def walk(item, path):
        if isinstance(item, dict):
            candidates = item.get("candidates")
            if isinstance(candidates, list) and "active_version" in item:
                active_version = item["active_version"]
                active = next(
                    (
                        candidate
                        for candidate in candidates
                        if isinstance(candidate, dict)
                        and candidate.get("version") == active_version
                    ),
                    None,
                )
                if isinstance(active, dict):
                    normalized_active = normalize_value_metadata(active)
                    if (
                        normalized_active.get("value_basis") == "ai_suggested"
                        and normalized_active.get("adoption_status") == "pending"
                    ):
                        suggestions.append((".".join(path), normalized_active))
                    # Recurse into active candidate's internals so nested
                    # versioned fields (e.g. value.parameters.*) are found.
                    for key, child in active.items():
                        walk(child, path + [key])
                return
            for key, child in item.items():
                if not path and key in EXCLUDED_TOP_KEYS:
                    continue
                walk(child, path + [key])
        elif isinstance(item, list):
            for index, child in enumerate(item):
                walk(child, path + [str(index)])

    walk(model, [])
    return suggestions


# Keep the old name as an alias so existing internal callers don't break
# while pipeline can import the public name.
_pending_ai_suggestions = collect_pending_ai_suggestions


def _analysis_status_label(status):
    labels = {
        "formal": "正式工程分析",
        "preliminary": "初步工程分析",
        "blocked": "阻塞性工程分析",
    }
    return labels.get(status, labels["formal"])


def render_review_report(model, issues):
    """Render a diagnostic review report from a list of structured issues.

    Sections are rendered in fixed severity order.  Unknown severities raise
    ``ValueError``.  The returned string ends with exactly one newline.
    """
    # Validate severities early.
    for issue in issues:
        sev = issue.get("severity", "")
        if sev not in _SEVERITY_ORDER:
            raise ValueError(f"unknown severity: {sev}")

    # Group issues by severity, preserving input order inside each group.
    groups = {sev: [] for sev in _SEVERITY_ORDER}
    for issue in issues:
        groups[issue["severity"]].append(issue)

    status = model.get("analysis_status", "formal")
    status_label = _analysis_status_label(status)
    lines = [f"# {status_label}", f"成果状态：{status_label}"]

    if status == "preliminary":
        lines.append("## 待技术员确认的 AI 建议")
        suggestions = _pending_ai_suggestions(model)
        if not suggestions:
            lines.append("_无可展示的待确认建议。_")
        else:
            for path, candidate in suggestions:
                value = candidate.get("value")
                unit = candidate.get("unit") or "未注明"
                basis = candidate.get("suggestion_basis") or "未说明"
                lines.append(
                    f"- `{path}`：{value} {unit}；依据：{basis}；请技术员确认。"
                )

    for severity in _SEVERITY_ORDER:
        lines.append(f"## {severity.capitalize()}")
        group = groups[severity]
        if not group:
            lines.append("_None._")
        else:
            for issue in group:
                issue_id = issue["issue_id"]
                code = issue["code"]
                message = issue["message"]
                affected = issue.get("affected_ids", [])
                affected_str = ", ".join(affected) if affected else "PROJECT"
                lines.append(f"- **{issue_id}** `[{code}]` {message}")
                lines.append(f"  - Affected: {affected_str}")
                lines.append("  - 技术员处理/确认")

    return "\n".join(lines) + "\n"
