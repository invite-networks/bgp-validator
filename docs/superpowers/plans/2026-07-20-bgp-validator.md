# BGP Path Validator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a single-file `uv` script that validates a subnet's observed BGP paths (from RIPE's looking-glass) against an expected origin AS and expected set of upstream transit providers.

**Architecture:** One file, `bgp_validator.py`, with a PEP 723 header so `uv` resolves deps at runtime. Pure functions (path parsing, validation) are module-level and importable so `test_bgp_validator.py` can test them without network. I/O (fetch, config load, rich rendering, CLI) sits in thin wrappers. A YAML config is the source of truth; CLI flags override it for ad-hoc runs.

**Tech Stack:** Python 3.13, `uv`, `httpx`, `typer`, `pydantic` v2, `rich`, `pyyaml`, `pytest`.

## Global Constraints

- Python `>=3.13`; single-file uv script with a PEP 723 header. Runtime deps exactly: `httpx`, `typer`, `pydantic`, `rich`, `pyyaml`.
- Full type hints on every function. Format with system `ruff` (`ruff format bgp_validator.py test_bgp_validator.py`).
- **No customer data anywhere.** Examples/tests use only RFC 5737 prefixes (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and RFC 5398 ASNs (`64496`-`64511`).
- Commit author is `aasay@users.noreply.github.com` (already set on the repo).
- **Canonical test command** (installs test deps without a project):
  `uv run --with pytest --with httpx --with typer --with pydantic --with rich --with pyyaml pytest -q`
- Every AS path reads left-to-right observer->origin: origin = last hop, upstream = 2nd-to-last hop.

---

### Task 1: Repo scaffold, license, example config, script skeleton

**Files:**
- Create: `LICENSE` (MIT), `.gitignore`, `README.md`, `providers.example.yaml`
- Create: `bgp_validator.py` (PEP 723 header + typer skeleton)
- Create: `test_bgp_validator.py` (empty import-smoke test)

**Interfaces:**
- Produces: an importable `bgp_validator` module and a runnable `uv run bgp_validator.py --help`.

- [ ] **Step 1: Create `LICENSE`** (MIT). Use this exact text, filling the year `2026` and holder `INVITE Networks`:

```
MIT License

Copyright (c) 2026 INVITE Networks

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 2: Create `.gitignore`**:

```
__pycache__/
*.pyc
.pytest_cache/
.ruff_cache/
.venv/
```

- [ ] **Step 3: Create `providers.example.yaml`** (documentation data only):

```yaml
# Expected BGP origin + upstream providers per prefix.
# Values below use RFC 5737 / RFC 5398 documentation ranges only.
prefixes:
  - prefix: 203.0.113.0/24
    origin_asn: 64496
    expected_upstreams:
      - { asn: 64497, name: "Provider A" }
      - { asn: 64498, name: "Provider B" }
      - { asn: 64499, name: "Provider C" }
  - prefix: 198.51.100.0/24
    origin_asn: 64496
    expected_upstreams:
      - { asn: 64497, name: "Provider A" }
      - { asn: 64500, name: "Provider D" }
```

- [ ] **Step 4: Create `bgp_validator.py`** skeleton:

```python
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
```

- [ ] **Step 5: Create `test_bgp_validator.py`** smoke test:

```python
def test_module_imports() -> None:
    import bgp_validator

    assert hasattr(bgp_validator, "app")
```

- [ ] **Step 6: Create `README.md`** (minimal; expanded in Task 6):

```markdown
# bgp-validator

Validate that a subnet's BGP paths, as observed by RIPE's looking-glass, come
from the origin AS and upstream transit providers you expect.

## Usage

```
uv run bgp_validator.py 203.0.113.0/24 --config providers.yaml
```

Requires [uv](https://docs.astral.sh/uv/). Dependencies resolve at runtime.
```

- [ ] **Step 7: Verify help and tests run**

Run: `uv run bgp_validator.py --help`
Expected: usage text prints, exit 0.

Run: `uv run --with pytest --with httpx --with typer --with pydantic --with rich --with pyyaml pytest -q`
Expected: 1 passed.

- [ ] **Step 8: Format and commit**

```bash
ruff format bgp_validator.py test_bgp_validator.py
git add LICENSE .gitignore README.md providers.example.yaml bgp_validator.py test_bgp_validator.py
git commit -m "Scaffold bgp-validator script, license, example config"
```

---

### Task 2: AS-path parsing (`collapse_prepending`, `analyze_path`)

**Files:**
- Modify: `bgp_validator.py`
- Test: `test_bgp_validator.py`

**Interfaces:**
- Produces:
  - `collapse_prepending(tokens: list[str]) -> list[str]`
  - `@dataclass(frozen=True) PathAnalysis` with fields `rrc: str`, `location: str`, `peer: str`, `raw_path: list[str]`, `origin: int | None`, `upstream: int | None`, `has_as_set: bool`
  - `analyze_path(rrc: str, location: str, peer: str, as_path: str) -> PathAnalysis`

- [ ] **Step 1: Write failing tests** (add to `test_bgp_validator.py`):

```python
from bgp_validator import PathAnalysis, analyze_path, collapse_prepending


def test_collapse_prepending_removes_consecutive_dupes() -> None:
    assert collapse_prepending(["64497", "64496", "64496"]) == ["64497", "64496"]
    assert collapse_prepending(["64497", "64497", "64498"]) == ["64497", "64498"]
    assert collapse_prepending(["64496"]) == ["64496"]
    assert collapse_prepending([]) == []


def test_analyze_path_extracts_origin_and_upstream() -> None:
    a = analyze_path("RRC01", "London", "192.0.2.1", "64510 64505 64497 64496")
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run --with pytest --with httpx --with typer --with pydantic --with rich --with pyyaml pytest -q`
Expected: FAIL (ImportError: cannot import name 'collapse_prepending').

- [ ] **Step 3: Implement** (add to `bgp_validator.py`, after imports; add `from dataclasses import dataclass`):

```python
from dataclasses import dataclass


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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run --with pytest --with httpx --with typer --with pydantic --with rich --with pyyaml pytest -q`
Expected: all passing.

- [ ] **Step 5: Format and commit**

```bash
ruff format bgp_validator.py test_bgp_validator.py
git add bgp_validator.py test_bgp_validator.py
git commit -m "Add AS-path parsing and analysis"
```

---

### Task 3: Config models, CIDR validation, and input resolution

**Files:**
- Modify: `bgp_validator.py`
- Test: `test_bgp_validator.py`

**Interfaces:**
- Produces:
  - pydantic models `ExpectedUpstream` (`asn: int`, `name: str`), `PrefixExpectation` (`prefix: str`, `origin_asn: int`, `expected_upstreams: list[ExpectedUpstream]`), `Config` (`prefixes: list[PrefixExpectation]`)
  - `load_config(path: Path) -> Config`
  - `validate_cidr(subnet: str) -> str` (returns normalized CIDR; raises `ValueError` on bad input)
  - `resolve_expectation(subnet: str, config: Config | None, cli_origin: int | None, cli_expect: list[int]) -> PrefixExpectation`
- Consumes: nothing from prior tasks.

**Resolution rules:** CLI flags override config for the given subnet. If `cli_origin` and `cli_expect` are both provided, build the expectation purely from CLI (upstream names default to `"AS<asn>"`). Otherwise look the subnet up in config; if found, apply any provided CLI overrides. If neither yields an origin + at least one upstream, raise `ValueError`.

- [ ] **Step 1: Write failing tests**:

```python
from pathlib import Path

import pytest

from bgp_validator import (
    Config,
    PrefixExpectation,
    load_config,
    resolve_expectation,
    validate_cidr,
)


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run --with pytest --with httpx --with typer --with pydantic --with rich --with pyyaml pytest -q`
Expected: FAIL (ImportError).

- [ ] **Step 3: Implement** (add to `bgp_validator.py`; add imports `import ipaddress`, `from pathlib import Path`, `import yaml`, `from pydantic import BaseModel`):

```python
import ipaddress
from pathlib import Path

import yaml
from pydantic import BaseModel


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

    origin = cli_origin if cli_origin is not None else (entry.origin_asn if entry else None)

    if cli_expect:
        upstreams = [ExpectedUpstream(asn=a, name=f"AS{a}") for a in cli_expect]
    elif entry is not None:
        upstreams = list(entry.expected_upstreams)
    else:
        upstreams = []

    if origin is None or not upstreams:
        raise ValueError(
            f"No expectation for {subnet}: provide it in the config or via "
            f"--origin and --expect."
        )

    return PrefixExpectation(
        prefix=subnet, origin_asn=origin, expected_upstreams=upstreams
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run --with pytest --with httpx --with typer --with pydantic --with rich --with pyyaml pytest -q`
Expected: all passing.

- [ ] **Step 5: Format and commit**

```bash
ruff format bgp_validator.py test_bgp_validator.py
git add bgp_validator.py test_bgp_validator.py
git commit -m "Add config models, CIDR validation, input resolution"
```

---

### Task 4: RIPE fetch + response parsing

**Files:**
- Modify: `bgp_validator.py`
- Test: `test_bgp_validator.py`
- Create: `tests/fixtures/looking_glass.json` (generic, documentation data only)

**Interfaces:**
- Produces:
  - `RIPE_URL: str`
  - `class RipeError(Exception)`
  - `fetch_looking_glass(subnet: str, client: httpx.Client) -> dict` (returns the `data` object; raises `RipeError` on non-ok status)
  - `parse_paths(data: dict) -> list[PathAnalysis]`
- Consumes: `analyze_path`, `PathAnalysis` from Task 2.

- [ ] **Step 1: Create `tests/fixtures/looking_glass.json`** (mirrors RIPE shape; two collectors, generic data):

```json
{
  "status": "ok",
  "data": {
    "rrcs": [
      {
        "rrc": "RRC01",
        "location": "London, United Kingdom",
        "peers": [
          {"as_path": "64510 64505 64497 64496", "peer": "192.0.2.10", "prefix": "203.0.113.0/24"},
          {"as_path": "64502 64498 64496", "peer": "192.0.2.11", "prefix": "203.0.113.0/24"}
        ]
      },
      {
        "rrc": "RRC03",
        "location": "Amsterdam, Netherlands",
        "peers": [
          {"as_path": "64503 64497 64496 64496", "peer": "198.51.100.5", "prefix": "203.0.113.0/24"}
        ]
      }
    ]
  }
}
```

- [ ] **Step 2: Write failing tests**:

```python
import json

import httpx

from bgp_validator import RIPE_URL, RipeError, fetch_looking_glass, parse_paths

FIXTURE = Path(__file__).parent / "tests" / "fixtures" / "looking_glass.json"


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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run --with pytest --with httpx --with typer --with pydantic --with rich --with pyyaml pytest -q`
Expected: FAIL (ImportError).

- [ ] **Step 4: Implement** (add to `bgp_validator.py`; add `import httpx`):

```python
import httpx

RIPE_URL = "https://stat.ripe.net/data/looking-glass/data.json"


class RipeError(Exception):
    """RIPE looking-glass returned an error or unexpected payload."""


def fetch_looking_glass(subnet: str, client: httpx.Client) -> dict:
    """Fetch looking-glass data for a subnet; return the `data` object."""
    resp = client.get(RIPE_URL, params={"resource": subnet}, timeout=30.0)
    resp.raise_for_status()
    payload = resp.json()
    if payload.get("status") != "ok":
        raise RipeError(f"RIPE status={payload.get('status')!r} for {subnet}")
    return payload["data"]


def parse_paths(data: dict) -> list[PathAnalysis]:
    """Flatten RIPE rrcs->peers into analyzed paths."""
    paths: list[PathAnalysis] = []
    for rrc in data.get("rrcs", []):
        rrc_id = rrc.get("rrc", "?")
        location = rrc.get("location", "")
        for peer in rrc.get("peers", []):
            paths.append(
                analyze_path(rrc_id, location, peer.get("peer", ""), peer.get("as_path", ""))
            )
    return paths
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run --with pytest --with httpx --with typer --with pydantic --with rich --with pyyaml pytest -q`
Expected: all passing.

- [ ] **Step 6: Format and commit**

```bash
ruff format bgp_validator.py test_bgp_validator.py
git add bgp_validator.py test_bgp_validator.py tests/fixtures/looking_glass.json
git commit -m "Add RIPE fetch and response parsing"
```

---

### Task 5: Validation aggregation

**Files:**
- Modify: `bgp_validator.py`
- Test: `test_bgp_validator.py`

**Interfaces:**
- Produces:
  - `@dataclass ValidationResult` with fields: `prefix: str`, `expected_origin: int`, `expected_upstreams: list[ExpectedUpstream]`, `seen_upstreams: set[int]`, `missing: list[ExpectedUpstream]`, `unexpected: set[int]`, `bad_origin_paths: list[PathAnalysis]`, `direct_paths: list[PathAnalysis]`, `as_set_paths: list[PathAnalysis]`, `paths: list[PathAnalysis]`; and a property `ok: bool`.
  - `validate(expectation: PrefixExpectation, paths: list[PathAnalysis]) -> ValidationResult`
- Consumes: `PrefixExpectation`, `ExpectedUpstream` (Task 3), `PathAnalysis` (Task 2).

**Rules:** `seen_upstreams` = every non-None `upstream`. `missing` = expected upstreams whose asn is not seen. `unexpected` = seen upstreams not in the expected asn set. `bad_origin_paths` = paths whose `origin != expected_origin` (this also catches `origin is None` from AS-set origins). `direct_paths` = paths with `upstream is None` and not an AS-set. `as_set_paths` = paths with `has_as_set`. `ok` = no missing, no unexpected, no bad origin.

- [ ] **Step 1: Write failing tests**:

```python
from bgp_validator import ExpectedUpstream, PrefixExpectation, analyze_path, validate


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run --with pytest --with httpx --with typer --with pydantic --with rich --with pyyaml pytest -q`
Expected: FAIL (ImportError: validate).

- [ ] **Step 3: Implement** (add to `bgp_validator.py`):

```python
@dataclass
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run --with pytest --with httpx --with typer --with pydantic --with rich --with pyyaml pytest -q`
Expected: all passing.

- [ ] **Step 5: Format and commit**

```bash
ruff format bgp_validator.py test_bgp_validator.py
git add bgp_validator.py test_bgp_validator.py
git commit -m "Add validation aggregation"
```

---

### Task 6: Rich reporting + CLI wiring + README

**Files:**
- Modify: `bgp_validator.py`, `README.md`
- Test: `test_bgp_validator.py`

**Interfaces:**
- Produces:
  - `render_report(console: Console, result: ValidationResult) -> None`
  - `main(...)` typer command wired to fetch/parse/validate/render across one or all prefixes; exits non-zero on any failure.
- Consumes: everything above.

**Behavior:** `main` accepts `subnet` (optional positional), `--config` (Path), `--origin` (int), `--expect` (repeatable int), `--all` (bool). Determine the target subnets: if `--all`, every prefix in config; else the single `subnet` (required, CIDR-validated). For each, resolve the expectation, fetch, parse, validate, render. Track overall pass; `raise typer.Exit(code=1)` if any failed.

- [ ] **Step 1: Write a failing test for rendering** (renders without error and marks failure):

```python
from rich.console import Console

from bgp_validator import render_report, validate


def test_render_report_runs() -> None:
    paths = [analyze_path("RRC01", "London", "192.0.2.1", "64510 64497 64496")]
    result = validate(_exp(), paths)  # missing 64498 -> not ok
    console = Console(record=True, width=100)
    render_report(console, result)
    text = console.export_text()
    assert "203.0.113.0/24" in text
    assert "RRC01" in text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run --with pytest --with httpx --with typer --with pydantic --with rich --with pyyaml pytest -q`
Expected: FAIL (ImportError: render_report).

- [ ] **Step 3: Implement rendering + CLI** (add to `bgp_validator.py`; add `from typing import Optional`, `from rich.console import Console`, `from rich.table import Table`, `from rich.panel import Panel`):

```python
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


def render_report(console: Console, result: ValidationResult) -> None:
    """Print the summary panel and the per-collector breakdown."""
    status = "[green]PASS[/green]" if result.ok else "[red]FAIL[/red]"
    lines = [
        f"Prefix: [bold]{result.prefix}[/bold]    Result: {status}",
        f"Expected origin AS{result.expected_origin}: "
        + ("[green]OK[/green]" if not result.bad_origin_paths else "[red]VIOLATED[/red]"),
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
        lines.append(f"[yellow]Paths with AS-sets in last two hops:[/yellow] {len(result.as_set_paths)}")
    console.print(Panel("\n".join(lines), title="BGP Path Validation"))

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
            up_cell = "[dim]direct[/dim]" if not p.has_as_set else "[yellow]AS-set[/yellow]"
        elif p.upstream in result.unexpected:
            up_cell = f"[yellow]AS{p.upstream}[/yellow]"
        else:
            up_cell = f"AS{p.upstream}"
        table.add_row(p.rrc, p.location, p.peer, up_cell, origin_cell)
    console.print(table)


@app.command()
def main(
    subnet: Optional[str] = typer.Argument(None, help="Subnet to validate, e.g. 203.0.113.0/24"),
    config: Optional[Path] = typer.Option(None, "--config", help="Path to providers YAML"),
    origin: Optional[int] = typer.Option(None, "--origin", help="Expected origin ASN (ad-hoc)"),
    expect: list[int] = typer.Option([], "--expect", help="Expected upstream ASN (repeatable)"),
    all_prefixes: bool = typer.Option(False, "--all", help="Validate every prefix in the config"),
) -> None:
    """Validate observed BGP paths for a subnet against expected origin + upstreams."""
    cfg = load_config(config) if config else None
    console = Console()

    if all_prefixes:
        if cfg is None:
            console.print("[red]--all requires --config[/red]")
            raise typer.Exit(code=2)
        subnets = [p.prefix for p in cfg.prefixes]
    else:
        if not subnet:
            console.print("[red]Provide a subnet or use --all with --config[/red]")
            raise typer.Exit(code=2)
        subnets = [validate_cidr(subnet)]

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
            render_report(console, result)
            overall_ok = overall_ok and result.ok

    if not overall_ok:
        raise typer.Exit(code=1)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run --with pytest --with httpx --with typer --with pydantic --with rich --with pyyaml pytest -q`
Expected: all passing.

- [ ] **Step 5: Expand `README.md`** with full usage:

```markdown
# bgp-validator

Validate that a subnet's BGP paths, as observed by RIPE's public looking-glass,
originate from the AS you expect and traverse the upstream transit providers you
expect. It walks every path from every RIPE route collector, checks the last two
AS hops (upstream + origin), and reports anything missing, unexpected, or wrong.

## Requirements

[uv](https://docs.astral.sh/uv/). Dependencies resolve at runtime from the
script's inline metadata; there is no install step.

## Usage

Validate one prefix defined in a config file:

```
uv run bgp_validator.py 203.0.113.0/24 --config providers.yaml
```

Ad-hoc, without a config file:

```
uv run bgp_validator.py 203.0.113.0/24 --origin 64496 --expect 64497 --expect 64498
```

Validate every prefix in the config:

```
uv run bgp_validator.py --config providers.yaml --all
```

CLI flags (`--origin`, `--expect`) override the config for that run. The process
exits non-zero if any prefix fails validation.

## Config

See `providers.example.yaml`. Each prefix lists its expected origin AS and the
upstream providers that should appear just before the origin in observed paths.

## Development

```
uv run --with pytest --with httpx --with typer --with pydantic --with rich --with pyyaml pytest -q
```

## License

MIT. See `LICENSE`.
```

- [ ] **Step 6: Smoke-test the CLI end to end** (live network; confirms it runs, exit code varies):

Run: `uv run bgp_validator.py 203.0.113.0/24 --origin 64496 --expect 64497 || echo "exit $?"`
Expected: renders a panel + per-collector table (this documentation prefix is not globally routed, so expect a FAIL/empty-collector message and a non-zero exit; the point is it runs without a traceback).

- [ ] **Step 7: Format and commit**

```bash
ruff format bgp_validator.py test_bgp_validator.py
git add bgp_validator.py test_bgp_validator.py README.md
git commit -m "Add rich reporting, CLI wiring, and full README"
```

---

### Task 7: Create and push the public GitHub repo

**Files:** none (repo operations only).

- [ ] **Step 1: Create the repo and push**

```bash
gh repo create invite-networks/bgp-validator --public --source=. --remote=origin --push
```

- [ ] **Step 2: Verify**

Run: `gh repo view invite-networks/bgp-validator --json url,visibility -q '.url + " " + .visibility'`
Expected: prints the URL and `PUBLIC`.

---

## Self-Review Notes

- **Spec coverage:** input capture (Tasks 1, 3), fetch (Task 4), validation incl. prepending/origin/upstream/AS-set/direct (Tasks 2, 5), per-collector output (Task 6), MIT license (Task 1), single-file uv script (Task 1), public repo (Task 7), no-customer-data constraint (fixtures/examples throughout). Covered.
- **Type consistency:** `PathAnalysis`, `ExpectedUpstream`, `PrefixExpectation`, `Config`, `ValidationResult`, and function signatures are used identically across tasks.
- **Placeholders:** none; all steps carry concrete code/commands.
