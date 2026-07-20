# /// script
# requires-python = ">=3.13"
# dependencies = ["httpx", "typer", "pydantic", "rich", "pyyaml"]
# ///
"""Validate observed BGP paths for a subnet against expected origin + upstreams."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path

import typer
import yaml
from pydantic import BaseModel

app = typer.Typer(add_completion=False, help=__doc__)


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


@app.command()
def main() -> None:
    """Placeholder; wired up in a later task."""
    raise NotImplementedError


if __name__ == "__main__":
    app()
