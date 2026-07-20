# BGP Path Validator - Design

**Date:** 2026-07-20
**Status:** Approved (pending spec review)

> Note on examples: every prefix, ASN, and provider name in this document uses
> the RFC-reserved documentation ranges (prefixes from RFC 5737, ASNs 64496-64511
> from RFC 5398). No customer or production data appears anywhere in this repo.

## Context

We need to confirm that a network's IP prefixes are being announced to the
global routing table the way we expect. For a prefix we control, the BGP paths
observed around the internet should always terminate in our own origin AS, and
just before that origin we should see the specific set of transit providers we
buy from. If an expected provider is missing, a path is not propagating; if an
unexpected upstream or a foreign origin appears, that can signal a route leak or
hijack.

RIPE's looking-glass exposes this data publicly. For any prefix it returns the
current best paths seen by ~23 route collectors (RRCs) worldwide. This tool
takes a subnet, fetches those paths, and validates the **last two AS hops** of
each path against an expected origin and an expected set of upstream providers.

## Goal

A single-file `uv` script that, given a subnet, reports whether every expected
transit provider is visible as the upstream hop across all collectors, whether
the origin AS is correct on every path, and flags anything missing or
unexpected. Output is human-readable terminal output with a per-collector
breakdown. Exit code is non-zero on any validation failure.

## Data model (RIPE looking-glass)

Endpoint: `https://stat.ripe.net/data/looking-glass/data.json?resource=<subnet>`

Relevant response shape:

```
data.rrcs[]              # one entry per route collector
  .rrc                   # collector id, e.g. "RRC01"
  .location              # e.g. "London, United Kingdom"
  .peers[]               # one entry per peer that sees the prefix
    .as_path             # space-separated ASNs, e.g. "64510 64505 64497 64496"
    .asn_origin          # origin AS as reported by RIPE
    .peer                # peer IP
```

The AS path reads left-to-right from the observing peer toward the origin. The
**origin** is the last (rightmost) ASN. The **upstream** is the second-to-last
ASN: the transit provider directly connected to the origin.

## Input capture

**Primary source: a multi-prefix YAML config** (the maintained source of truth):

```yaml
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

**Ad-hoc / override via CLI flags**, for one-off checks without editing the file:

```
# Validate one prefix defined in the config:
uv run bgp_validator.py 203.0.113.0/24 --config providers.yaml

# Fully ad-hoc, no config file needed:
uv run bgp_validator.py 203.0.113.0/24 --origin 64496 --expect 64497 --expect 64498

# Validate every prefix in the config:
uv run bgp_validator.py --config providers.yaml --all
```

**Precedence:** if a prefix appears in the config and CLI flags are also given,
the CLI flags (`--origin`, `--expect`) override the config entry for that run.
CLI-only mode requires `--origin` and at least one `--expect`. The subnet
argument is validated as a real CIDR before any network call.

## Validation logic (pure, testable)

For each path in every collector's peer list:

1. Split `as_path` into tokens.
2. **Collapse consecutive duplicate ASNs** to neutralize AS-path prepending
   (`64497 64496 64496` -> `64497 64496`).
3. **Origin** = last hop. Must equal the expected origin. A mismatch is a hard
   failure (possible hijack).
4. **Upstream** = second-to-last hop. If the collapsed path has only one hop
   (a collector peering directly with the origin), record it as
   "direct / no upstream" rather than erroring.
5. Flag any AS-set token (`{...}`) that lands in the last two positions.

Aggregate across all collectors:

- Set of upstreams observed, and per-collector which upstreams appeared.
- **Missing:** expected upstreams never seen anywhere -> failure.
- **Unexpected:** observed upstreams not in the expected set -> failure.
- **Bad origin:** any path whose origin != expected -> failure.

The validation functions take parsed data structures and return a result
object. They perform no I/O, so they can be unit-tested against recorded
fixtures without network access.

## Output

`rich` terminal rendering, always including the per-collector breakdown:

- **Summary panel:** the prefix, expected origin (pass/fail), and each expected
  upstream with a seen/missing indicator, plus a line listing any unexpected
  upstreams and any bad-origin paths.
- **Per-collector table:** collector id + location by which origins/upstreams it
  observed, with offending rows highlighted.

The process exits non-zero if any prefix fails validation, so the script drops
naturally into a shell or cron context.

## Tech stack and structure

INVITE standards: Python 3.13+, `uv`, full type hints, `ruff` formatting.

Single-file `uv` script with PEP 723 inline metadata so dependencies resolve at
runtime with no install step:

```python
# /// script
# requires-python = ">=3.13"
# dependencies = ["httpx", "typer", "pydantic", "rich", "pyyaml"]
# ///
```

- `typer` - CLI
- `httpx` - fetch (synchronous; one request per prefix)
- `pydantic` - config schema + RIPE response validation
- `rich` - terminal output
- `pyyaml` - config parsing

Repository layout:

```
bgp_validator.py            # the single-file uv script (all logic + CLI)
test_bgp_validator.py       # pytest, imports pure functions from the script
providers.example.yaml      # generic example config (documentation data only)
tests/fixtures/*.json       # recorded RIPE responses (scrubbed / generic)
README.md
LICENSE                     # MIT
docs/superpowers/specs/     # this design doc
```

Pure logic (path parsing, dedup, validation) lives in importable module-level
functions so `test_bgp_validator.py` can exercise them without hitting the
network. Tests run via `uv run --with pytest pytest`.

## Testing

- Unit tests for path collapsing (prepending), origin extraction, upstream
  extraction, single-hop/direct handling, and AS-set detection.
- Validation-result tests for the missing / unexpected / bad-origin cases.
- Fetch layer tested against recorded fixtures (no live network in CI).
- All fixtures use documentation prefixes and ASNs only.

## Deliverables

- `bgp_validator.py` single-file uv script
- `test_bgp_validator.py` with fixtures
- `providers.example.yaml`
- `README.md` with usage
- `LICENSE` (MIT)
- Local git repo, committed as `aasay@users.noreply.github.com`
- Public GitHub repo `invite-networks/bgp-validator`

## Out of scope (YAGNI)

- Web UI / API service
- Persisting results to a database
- Historical trend tracking or alerting integrations
- Data sources other than the RIPE looking-glass
