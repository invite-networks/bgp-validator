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
