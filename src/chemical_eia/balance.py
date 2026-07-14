def mix(streams: list[dict[str, float]]) -> dict[str, float]:
    result: dict[str, float] = {}
    for stream in streams:
        for component, mass in stream.items():
            if mass < 0:
                raise ValueError("mass cannot be negative")
            result[component] = result.get(component, 0.0) + mass
    return result


def reaction_extent_from_conversion(
    limiting_mass, limiting_mw, limiting_coefficient, conversion
):
    if not 0 <= conversion <= 1:
        raise ValueError("conversion must be between 0 and 1")
    if limiting_mass < 0 or limiting_mw <= 0 or limiting_coefficient >= 0:
        raise ValueError("invalid limiting reactant")
    return limiting_mass / limiting_mw * conversion / abs(limiting_coefficient)


def apply_reaction(initial_masses, species, extent_kmol):
    if extent_kmol < 0:
        raise ValueError("extent cannot be negative")
    for component, mass in initial_masses.items():
        if mass < 0:
            raise ValueError(f"initial mass cannot be negative: {component}")
    result = dict(initial_masses)
    for name, item in species.items():
        coefficient = item["coefficient"]
        mw = item["mw"]
        if mw <= 0 or coefficient == 0:
            raise ValueError("invalid reaction species")
        delta = extent_kmol * coefficient * mw
        final_mass = result.get(name, 0.0) + delta
        if final_mass < -1e-9:
            raise ValueError(f"reaction consumes unavailable mass: {name}")
        result[name] = max(0.0, final_mass)
    return result


def split_components(components, allocations):
    for component, mass in components.items():
        if mass < 0:
            raise ValueError(f"component mass cannot be negative: {component}")
    for output_name, allocated in allocations.items():
        for component, value in allocated.items():
            if value < 0:
                raise ValueError(f"allocation cannot be negative: {output_name}.{component}")
            if component not in components:
                raise ValueError(f"allocation component not in input: {component}")
    outputs = {name: dict(values) for name, values in allocations.items()}
    for component, available in components.items():
        allocated = sum(stream.get(component, 0.0) for stream in outputs.values())
        if allocated > available + 1e-9:
            raise ValueError(f"allocation exceeds input: {component}")
    return outputs


def treat(load, efficiency):
    if load < 0 or not 0 <= efficiency <= 1:
        raise ValueError("invalid treatment input")
    return {"removed": load * efficiency, "emitted": load * (1 - efficiency)}


def scale(kg_per_batch, batches_per_year):
    if kg_per_batch < 0 or batches_per_year < 0:
        raise ValueError("scale inputs cannot be negative")
    return kg_per_batch * batches_per_year / 1000.0


def difference(total, known_components):
    if total < 0:
        raise ValueError("total cannot be negative")
    for component, mass in known_components.items():
        if mass < 0:
            raise ValueError(f"known component cannot be negative: {component}")
    residual = total - sum(known_components.values())
    if residual < -1e-9:
        raise ValueError("known components exceed total")
    return max(0.0, residual)
