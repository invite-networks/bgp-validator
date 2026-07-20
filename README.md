# bgp-validator

Validate that a subnet's BGP paths, as observed by RIPE's looking-glass, come
from the origin AS and upstream transit providers you expect.

## Usage

```
uv run bgp_validator.py 203.0.113.0/24 --config providers.yaml
```

Requires [uv](https://docs.astral.sh/uv/). Dependencies resolve at runtime.
