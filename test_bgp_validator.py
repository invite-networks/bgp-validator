import json
from pathlib import Path

import httpx
import pytest
from rich.console import Console
from typer.testing import CliRunner

from bgp_validator import (
    RIPE_URL,
    Config,
    ExpectedUpstream,
    PathAnalysis,
    PrefixExpectation,
    RipeError,
    analyze_path,
    app,
    collapse_prepending,
    fetch_looking_glass,
    load_config,
    parse_paths,
    render_report,
    resolve_expectation,
    validate,
    validate_cidr,
)

FIXTURE = Path(__file__).parent / "tests" / "fixtures" / "looking_glass.json"


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


def test_ripe_url_is_https() -> None:
    assert RIPE_URL.startswith("https://")


def test_parse_paths_walks_all_collectors() -> None:
    data = json.loads(FIXTURE.read_text())["data"]
    paths = parse_paths(data)
    assert len(paths) == 3
    assert {p.rrc for p in paths} == {"RRC01", "RRC03"}
    assert all(p.origin == 64496 for p in paths)


def test_fetch_looking_glass_ok() -> None:
    payload = json.loads(FIXTURE.read_text())

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["resource"] == "203.0.113.0/24"
        return httpx.Response(200, json=payload)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    data = fetch_looking_glass("203.0.113.0/24", client)
    assert len(data["rrcs"]) == 2


def test_fetch_looking_glass_bad_status_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "error", "data": {}})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(RipeError):
        fetch_looking_glass("203.0.113.0/24", client)


def _exp() -> PrefixExpectation:
    return PrefixExpectation(
        prefix="203.0.113.0/24",
        origin_asn=64496,
        expected_upstreams=[
            ExpectedUpstream(asn=64497, name="Provider A"),
            ExpectedUpstream(asn=64498, name="Provider B"),
        ],
    )


def test_validate_all_present_is_ok() -> None:
    paths = [
        analyze_path("RRC01", "L", "192.0.2.1", "64510 64497 64496"),
        analyze_path("RRC03", "A", "192.0.2.2", "64502 64498 64496"),
    ]
    result = validate(_exp(), paths)
    assert result.ok is True
    assert result.missing == []
    assert result.unexpected == set()


def test_validate_missing_upstream_fails() -> None:
    paths = [analyze_path("RRC01", "L", "192.0.2.1", "64510 64497 64496")]
    result = validate(_exp(), paths)
    assert result.ok is False
    assert [u.asn for u in result.missing] == [64498]


def test_validate_unexpected_upstream_fails() -> None:
    paths = [
        analyze_path("RRC01", "L", "192.0.2.1", "64510 64497 64496"),
        analyze_path("RRC03", "A", "192.0.2.2", "64502 64498 64496"),
        analyze_path("RRC03", "A", "192.0.2.3", "64502 64507 64496"),
    ]
    result = validate(_exp(), paths)
    assert result.ok is False
    assert result.unexpected == {64507}


def test_validate_bad_origin_fails() -> None:
    paths = [
        analyze_path("RRC01", "L", "192.0.2.1", "64510 64497 64496"),
        analyze_path("RRC03", "A", "192.0.2.2", "64502 64498 64511"),
    ]
    result = validate(_exp(), paths)
    assert result.ok is False
    assert len(result.bad_origin_paths) == 1


def test_render_report_runs() -> None:
    paths = [analyze_path("RRC01", "London", "192.0.2.1", "64510 64497 64496")]
    result = validate(_exp(), paths)  # missing 64498 -> not ok
    console = Console(record=True, width=100)
    render_report(console, result)
    text = console.export_text()
    assert "203.0.113.0/24" in text
    assert "RRC01" in text


def test_cli_invalid_subnet_exits_nonzero_without_traceback() -> None:
    result = CliRunner().invoke(
        app, ["not-a-cidr", "--origin", "64496", "--expect", "64497"]
    )
    assert result.exit_code != 0
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_resolve_cli_both_override_config() -> None:
    config = Config(
        prefixes=[
            PrefixExpectation(
                prefix="203.0.113.0/24",
                origin_asn=64496,
                expected_upstreams=[{"asn": 64497, "name": "Provider A"}],
            )
        ]
    )
    exp = resolve_expectation("203.0.113.0/24", config, 64511, [64499])
    assert exp.origin_asn == 64511
    assert {u.asn for u in exp.expected_upstreams} == {64499}


def test_validate_direct_and_as_set_paths() -> None:
    paths = [
        analyze_path("RRC01", "L", "192.0.2.1", "64496"),
        analyze_path("RRC02", "M", "192.0.2.2", "64497 {64496,64501}"),
        analyze_path("RRC03", "A", "192.0.2.3", "64510 64497 64496"),
    ]
    result = validate(_exp(), paths)
    assert len(result.direct_paths) == 1
    assert len(result.as_set_paths) == 1


def test_render_report_shows_missing_and_unexpected() -> None:
    paths = [
        analyze_path("RRC01", "London", "192.0.2.1", "64510 64497 64496"),
        analyze_path("RRC02", "Paris", "192.0.2.2", "64502 64507 64496"),
    ]
    result = validate(_exp(), paths)
    console = Console(record=True, width=120)
    render_report(console, result)
    text = console.export_text()
    assert "MISSING" in text
    assert "64507" in text
    assert "64498" in text


def test_render_report_pass() -> None:
    paths = [
        analyze_path("RRC01", "London", "192.0.2.1", "64510 64497 64496"),
        analyze_path("RRC02", "Paris", "192.0.2.2", "64502 64498 64496"),
    ]
    result = validate(_exp(), paths)
    assert result.ok
    console = Console(record=True, width=120)
    render_report(console, result)
    assert "PASS" in console.export_text()


def test_fetch_invalid_json_raises_ripe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>not json</html>")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(RipeError):
        fetch_looking_glass("203.0.113.0/24", client)


def test_fetch_missing_data_raises_ripe_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "ok"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(RipeError):
        fetch_looking_glass("203.0.113.0/24", client)


def test_render_report_summary_only_omits_per_collector_table() -> None:
    paths = [
        analyze_path("RRC01", "London", "192.0.2.1", "64510 64497 64496"),
        analyze_path("RRC02", "Paris", "192.0.2.2", "64502 64498 64496"),
    ]
    result = validate(_exp(), paths)
    console = Console(record=True, width=120)
    render_report(console, result, show_details=False)
    text = console.export_text()
    # Summary panel still present...
    assert "BGP Path Validation" in text
    assert "203.0.113.0/24" in text
    # ...but the per-collector detail table is suppressed.
    assert "Per-collector observations" not in text
    assert "RRC01" not in text


def test_cli_no_args_defaults_to_config_all(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # With no arguments and no providers.yaml in the working directory, the CLI
    # must default to loading providers.yaml (equivalent to
    # `--config providers.yaml --all`) and fail cleanly on the missing file,
    # rather than asking for a subnet.
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, [])
    assert result.exit_code == 2
    assert "providers.yaml" in result.output
