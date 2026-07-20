from bgp_validator import PathAnalysis, analyze_path, collapse_prepending


def test_module_imports() -> None:
    import bgp_validator

    assert hasattr(bgp_validator, "app")


def test_collapse_prepending_removes_consecutive_dupes() -> None:
    assert collapse_prepending(["64497", "64496", "64496"]) == ["64497", "64496"]
    assert collapse_prepending(["64497", "64497", "64498"]) == ["64497", "64498"]
    assert collapse_prepending(["64496"]) == ["64496"]
    assert collapse_prepending([]) == []


def test_analyze_path_extracts_origin_and_upstream() -> None:
    a: PathAnalysis = analyze_path(
        "RRC01", "London", "192.0.2.1", "64510 64505 64497 64496"
    )
    assert a.origin == 64496
    assert a.upstream == 64497
    assert a.has_as_set is False


def test_analyze_path_collapses_prepending() -> None:
    a = analyze_path("RRC01", "London", "192.0.2.1", "64497 64496 64496")
    assert a.origin == 64496
    assert a.upstream == 64497


def test_analyze_path_single_hop_has_no_upstream() -> None:
    a = analyze_path("RRC01", "London", "192.0.2.1", "64496")
    assert a.origin == 64496
    assert a.upstream is None


def test_analyze_path_flags_as_set() -> None:
    a = analyze_path("RRC01", "London", "192.0.2.1", "64497 {64496,64501}")
    assert a.has_as_set is True
    assert a.origin is None
