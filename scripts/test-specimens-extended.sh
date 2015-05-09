#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

# Keep uv usable in sandboxes where $HOME may be read-only. Callers can override.
export UV_CACHE_DIR="${UV_CACHE_DIR:-${TMPDIR:-/tmp}/containre-uv-cache}"

make -C specimens
exec uv run pytest -m "specimen and not docker" "$@"
