# /// script
# requires-python = ">=3.13"
# dependencies = ["httpx", "typer", "pydantic", "rich", "pyyaml"]
# ///
"""Validate observed BGP paths for a subnet against expected origin + upstreams."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path

import httpx
import typer
import yaml
from pydantic import BaseModel, ValidationError
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

app = typer.Typer(add_completion=False, help=__doc__)

RIPE_URL = "https://stat.ripe.net/data/looking-glass/data.json"

# When invoked with no arguments at all, behave as `--config providers.yaml --all`.
DEFAULT_CONFIG = Path("providers.yaml")


def collapse_prepending(tokens: list[str]) -> list[str]:
    """Collapse consecutive duplicate ASNs (neutralizes AS-path prepending)."""
    out: list[str] = []
    for token in tokens:
        if not out or out[-1] != token:
            out.append(token)
    return out


def _asn(token: str) -> int | None:
    """Return the ASN as int, or None for AS-set / malformed tokens."""
    return int(token) if token.isdigit() else None


@dataclass(frozen=True)
class PathAnalysis:
    rrc: str
    location: str
    peer: str
    raw_path: list[str]
    origin: int | None
    upstream: int | None
    has_as_set: bool


def analyze_path(rrc: str, location: str, peer: str, as_path: str) -> PathAnalysis:
    """Parse one AS path into origin (last hop) and upstream (2nd-to-last hop)."""
    raw = as_path.split()
    tokens = collapse_prepending(raw)
    last_two = tokens[-2:]
    has_as_set = any("{" in t for t in last_two)
    origin = _asn(tokens[-1]) if tokens else None
    upstream = _asn(tokens[-2]) if len(tokens) >= 2 else None
    return PathAnalysis(
        rrc=rrc,
        location=location,
        peer=peer,
        raw_path=raw,
        origin=origin,
        upstream=upstream,
        has_as_set=has_as_set,
    )


class ExpectedUpstream(BaseModel):
    asn: int
    name: str


class PrefixExpectation(BaseModel):
    prefix: str
    origin_asn: int
    expected_upstreams: list[ExpectedUpstream]


class Config(BaseModel):
    prefixes: list[PrefixExpectation]


def load_config(path: Path) -> Config:
    """Load and validate the YAML config file."""
    data = yaml.safe_load(path.read_text())
    return Config.model_validate(data)


def validate_cidr(subnet: str) -> str:
    """Return the normalized CIDR string, or raise ValueError."""
    return str(ipaddress.ip_network(subnet, strict=False))


def resolve_expectation(
    subnet: str,
    config: Config | None,
    cli_origin: int | None,
    cli_expect: list[int],
) -> PrefixExpectation:
    """Combine config + CLI overrides into one expectation. CLI wins."""
    entry = None
    if config is not None:
        entry = next((p for p in config.prefixes if p.prefix == subnet), None)

    origin = (
        cli_origin if cli_origin is not None else (entry.origin_asn if entry else None)
    )

    if cli_expect:
        upstreams = [ExpectedUpstream(asn=a, name=f"AS{a}") for a in cli_expect]
    elif entry is not None:
        upstreams = list(entry.expected_upstreams)
    else:
        upstreams = []

    if origin is None or not upstreams:
        raise ValueError(
            f"No expectation for {subnet}: provide it in the config or via --origin and --expect."
        )

    return PrefixExpectation(
        prefix=subnet, origin_asn=origin, expected_upstreams=upstreams
    )


class RipeError(Exception):
    """RIPE looking-glass returned an error or unexpected payload."""


def fetch_looking_glass(subnet: str, client: httpx.Client) -> dict:
    """Fetch looking-glass data for a subnet; return the `data` object."""
    resp = client.get(RIPE_URL, params={"resource": subnet}, timeout=30.0)
    resp.raise_for_status()
    try:
        payload = resp.json()
    except ValueError as exc:
        raise RipeError(f"RIPE returned invalid JSON for {subnet}") from exc
    if payload.get("status") != "ok":
        raise RipeError(f"RIPE status={payload.get('status')!r} for {subnet}")
    data = payload.get("data")
    if data is None:
        raise RipeError(f"RIPE returned no data for {subnet}")
    return data


def parse_paths(data: dict) -> list[PathAnalysis]:
    """Flatten RIPE rrcs->peers into analyzed paths."""
    paths: list[PathAnalysis] = []
    for rrc in data.get("rrcs", []):
        rrc_id = rrc.get("rrc", "?")
        location = rrc.get("location", "")
        for peer in rrc.get("peers", []):
            paths.append(
                analyze_path(
                    rrc_id, location, peer.get("peer", ""), peer.get("as_path", "")
                )
            )
    return paths


@dataclass(frozen=True)
class ValidationResult:
    prefix: str
    expected_origin: int
    expected_upstreams: list[ExpectedUpstream]
    seen_upstreams: set[int]
    missing: list[ExpectedUpstream]
    unexpected: set[int]
    bad_origin_paths: list[PathAnalysis]
    direct_paths: list[PathAnalysis]
    as_set_paths: list[PathAnalysis]
    paths: list[PathAnalysis]

    @property
    def ok(self) -> bool:
        return not self.missing and not self.unexpected and not self.bad_origin_paths


def validate(
    expectation: PrefixExpectation, paths: list[PathAnalysis]
) -> ValidationResult:
    """Aggregate analyzed paths into a pass/fail result for one prefix."""
    expected_asns = {u.asn for u in expectation.expected_upstreams}
    seen = {p.upstream for p in paths if p.upstream is not None}
    missing = [u for u in expectation.expected_upstreams if u.asn not in seen]
    unexpected = seen - expected_asns
    bad_origin = [p for p in paths if p.origin != expectation.origin_asn]
    direct = [p for p in paths if p.upstream is None and not p.has_as_set]
    as_sets = [p for p in paths if p.has_as_set]
    return ValidationResult(
        prefix=expectation.prefix,
        expected_origin=expectation.origin_asn,
        expected_upstreams=expectation.expected_upstreams,
        seen_upstreams=seen,
        missing=missing,
        unexpected=unexpected,
        bad_origin_paths=bad_origin,
        direct_paths=direct,
        as_set_paths=as_sets,
        paths=paths,
    )


def render_report(
    console: Console, result: ValidationResult, show_details: bool = True
) -> None:
    """Print the summary panel, and the per-collector breakdown unless summary-only."""
    status = "[green]PASS[/green]" if result.ok else "[red]FAIL[/red]"
    lines = [
        f"Prefix: [bold]{result.prefix}[/bold]    Result: {status}",
        f"Expected origin AS{result.expected_origin}: "
        + (
            "[green]OK[/green]"
            if not result.bad_origin_paths
            else "[red]VIOLATED[/red]"
        ),
        "",
        "Expected upstreams:",
    ]
    for u in result.expected_upstreams:
        seen = u.asn in result.seen_upstreams
        mark = "[green]seen[/green]" if seen else "[red]MISSING[/red]"
        lines.append(f"  AS{u.asn} ({u.name}): {mark}")
    if result.unexpected:
        joined = ", ".join(f"AS{a}" for a in sorted(result.unexpected))
        lines.append(f"[yellow]Unexpected upstreams seen:[/yellow] {joined}")
    if result.as_set_paths:
        lines.append(
            f"[yellow]Paths with AS-sets in last two hops:[/yellow] {len(result.as_set_paths)}"
        )
    console.print(Panel("\n".join(lines), title="BGP Path Validation"))

    if not show_details:
        return

    table = Table(title="Per-collector observations", show_lines=False)
    table.add_column("Collector")
    table.add_column("Location")
    table.add_column("Peer")
    table.add_column("Upstream")
    table.add_column("Origin")
    for p in result.paths:
        origin_ok = p.origin == result.expected_origin
        origin_txt = f"AS{p.origin}" if p.origin is not None else "AS-set"
        origin_cell = origin_txt if origin_ok else f"[red]{origin_txt}[/red]"
        if p.upstream is None:
            up_cell = (
                "[dim]direct[/dim]" if not p.has_as_set else "[yellow]AS-set[/yellow]"
            )
        elif p.upstream in result.unexpected:
            up_cell = f"[yellow]AS{p.upstream}[/yellow]"
        else:
            up_cell = f"AS{p.upstream}"
        table.add_row(p.rrc, p.location, p.peer, up_cell, origin_cell)
    console.print(table)


@app.command()
def main(
    subnet: str | None = typer.Argument(
        None, help="Subnet to validate, e.g. 203.0.113.0/24"
    ),
    config: Path | None = typer.Option(None, "--config", help="Path to providers YAML"),
    origin: int | None = typer.Option(
        None, "--origin", help="Expected origin ASN (ad-hoc)"
    ),
    expect: list[int] = typer.Option(
        [], "--expect", help="Expected upstream ASN (repeatable)"
    ),
    all_prefixes: bool = typer.Option(
        False, "--all", help="Validate every prefix in the config"
    ),
    summary: bool = typer.Option(
        False, "--summary", help="Print only the summary, not the per-collector detail"
    ),
) -> None:
    """Validate observed BGP paths for a subnet against expected origin + upstreams."""
    if (
        subnet is None
        and config is None
        and origin is None
        and not expect
        and not all_prefixes
    ):
        # No arguments: default to validating every prefix in providers.yaml.
        config = DEFAULT_CONFIG
        all_prefixes = True

    console = Console()
    cfg: Config | None = None
    if config:
        try:
            cfg = load_config(config)
        except (OSError, yaml.YAMLError, ValidationError) as exc:
            console.print(f"[red]Failed to load config {config}: {exc}[/red]")
            raise typer.Exit(code=2)

    if all_prefixes:
        if cfg is None:
            console.print("[red]--all requires --config[/red]")
            raise typer.Exit(code=2)
        subnets = [p.prefix for p in cfg.prefixes]
        if not subnets:
            console.print("[red]Config has no prefixes to validate[/red]")
            raise typer.Exit(code=2)
    else:
        if not subnet:
            console.print("[red]Provide a subnet or use --all with --config[/red]")
            raise typer.Exit(code=2)
        try:
            subnets = [validate_cidr(subnet)]
        except ValueError as exc:
            console.print(f"[red]Invalid subnet {subnet!r}: {exc}[/red]")
            raise typer.Exit(code=2)

    overall_ok = True
    with httpx.Client() as client:
        for target in subnets:
            try:
                expectation = resolve_expectation(target, cfg, origin, expect)
            except ValueError as exc:
                console.print(f"[red]{exc}[/red]")
                overall_ok = False
                continue
            try:
                data = fetch_looking_glass(target, client)
            except (httpx.HTTPError, RipeError) as exc:
                console.print(f"[red]Fetch failed for {target}: {exc}[/red]")
                overall_ok = False
                continue
            paths = parse_paths(data)
            if not paths:
                console.print(f"[red]{target}: not seen by any collector[/red]")
                overall_ok = False
                continue
            result = validate(expectation, paths)
            render_report(console, result, show_details=not summary)
            overall_ok = overall_ok and result.ok

    if not overall_ok:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
