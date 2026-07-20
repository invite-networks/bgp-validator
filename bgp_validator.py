# /// script
# requires-python = ">=3.13"
# dependencies = ["httpx", "typer", "pydantic", "rich", "pyyaml"]
# ///
"""Validate observed BGP paths for a subnet against expected origin + upstreams."""

from __future__ import annotations

import typer

app = typer.Typer(add_completion=False, help=__doc__)


@app.command()
def main() -> None:
    """Placeholder; wired up in a later task."""
    raise NotImplementedError


if __name__ == "__main__":
    app()
