# /// script
# requires-python = ">=3.13"
# dependencies = ["httpx", "typer", "pydantic", "rich", "pyyaml"]
# ///
"""Validate observed BGP paths for a subnet against expected origin + upstreams."""

from __future__ import annotations

from dataclasses import dataclass

import typer

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


@app.command()
def main() -> None:
    """Placeholder; wired up in a later task."""
    raise NotImplementedError


if __name__ == "__main__":
    app()
