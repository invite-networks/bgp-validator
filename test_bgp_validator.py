from pathlib import Path

import pytest

from bgp_validator import (
    Config,
    PathAnalysis,
    PrefixExpectation,
    analyze_path,
    collapse_prepending,
    load_config,
    resolve_expectation,
    validate_cidr,
)


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


def test_validate_cidr_accepts_and_normalizes() -> None:
    assert validate_cidr("203.0.113.0/24") == "203.0.113.0/24"


def test_validate_cidr_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        validate_cidr("not-a-subnet")


def test_load_config_roundtrip(tmp_path: Path) -> None:
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "prefixes:\n"
        "  - prefix: 203.0.113.0/24\n"
        "    origin_asn: 64496\n"
        "    expected_upstreams:\n"
        "      - { asn: 64497, name: Provider A }\n"
    )
    loaded = load_config(cfg)
    assert loaded.prefixes[0].origin_asn == 64496
    assert loaded.prefixes[0].expected_upstreams[0].asn == 64497


def test_resolve_from_config() -> None:
    config = Config(
        prefixes=[
            PrefixExpectation(
                prefix="203.0.113.0/24",
                origin_asn=64496,
                expected_upstreams=[{"asn": 64497, "name": "Provider A"}],
            )
        ]
    )
    exp = resolve_expectation("203.0.113.0/24", config, None, [])
    assert exp.origin_asn == 64496
    assert exp.expected_upstreams[0].asn == 64497


def test_resolve_cli_only() -> None:
    exp = resolve_expectation("192.0.2.0/24", None, 64496, [64497, 64498])
    assert exp.origin_asn == 64496
    assert {u.asn for u in exp.expected_upstreams} == {64497, 64498}


def test_resolve_cli_overrides_config() -> None:
    config = Config(
        prefixes=[
            PrefixExpectation(
                prefix="203.0.113.0/24",
                origin_asn=64496,
                expected_upstreams=[{"asn": 64497, "name": "Provider A"}],
            )
        ]
    )
    exp = resolve_expectation("203.0.113.0/24", config, None, [64499])
    assert {u.asn for u in exp.expected_upstreams} == {64499}


def test_resolve_no_data_raises() -> None:
    with pytest.raises(ValueError):
        resolve_expectation("192.0.2.0/24", None, None, [])
