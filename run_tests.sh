#!/usr/bin/env bash
# Run the ContainRE test suite.
#
# By default it runs the fast, offline **unit** tests only. The slower
# **integration** group (specimen binaries compiled and run under the ptrace
# harness — needs a C compiler and ptrace privileges; the `docker` subset also
# needs a working Docker daemon) is off unless you ask for it. Any arguments
# after the group flags are forwarded straight to pytest.
#
#   ./run_tests.sh                     # unit tests only (default)
#   ./run_tests.sh --integration       # unit + integration
#   ./run_tests.sh --only-integration  # integration only
#   ./run_tests.sh --all               # both groups (alias for --integration)
#   ./run_tests.sh --integration --no-docker   # skip the Docker-daemon subset
#   ./run_tests.sh -v -k policy        # unit tests, extra pytest args passed through
#   ./run_tests.sh --integration -x    # both groups, stop on first failure
#   ./run_tests.sh --only-integration --no-build   # don't rebuild specimens first
set -euo pipefail
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

unit=1          # offline unit group       (default: on)
integration=0   # specimen/ptrace group    (default: off)
docker=1        # include the docker subset of integration (default: on when integration runs)
build=1         # rebuild specimen binaries before the integration group
pytest_args=()

usage() {
  # Print the leading comment block (after the shebang) as help text.
  awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --unit)              unit=1 ;;
    --no-unit)           unit=0 ;;
    --integration|-i)    integration=1 ;;
    --no-integration)    integration=0 ;;
    --only-integration)  unit=0; integration=1 ;;
    --all|-a)            unit=1; integration=1 ;;
    --docker)            docker=1 ;;
    --no-docker)         docker=0 ;;
    --no-build)          build=0 ;;
    -h|--help)           usage 0 ;;
    --)                  shift; pytest_args+=("$@"); break ;;
    *)                   pytest_args+=("$1") ;;
  esac
  shift
done

# Translate the selected groups into a pytest -m marker expression. Unit tests
# are everything that does NOT run a specimen ("not specimen and not docker");
# the integration group is the specimen tests, plus the docker subset unless
# --no-docker is given. The docker tests are also marked `specimen`, so
# excluding them needs an explicit "and not docker". Passing -m on the command
# line overrides these; pytest has no default marker filter, so a bare `pytest`
# would otherwise run the lot.
if [ "$docker" -eq 1 ]; then
  integ_expr="specimen or docker"
else
  integ_expr="specimen and not docker"
fi

if [ "$unit" -eq 1 ] && [ "$integration" -eq 1 ]; then
  # Both groups: run everything, minus the docker subset if it was excluded.
  if [ "$docker" -eq 1 ]; then marker=""; else marker="not docker"; fi
elif [ "$unit" -eq 1 ]; then
  marker="not specimen and not docker"   # unit only (default)
elif [ "$integration" -eq 1 ]; then
  marker="$integ_expr"                    # integration only
else
  echo "run_tests.sh: no test group selected (both --no-unit and --no-integration)" >&2
  exit 2
fi

# Keep uv usable in sandboxes where $HOME may be read-only. Callers can override.
export UV_CACHE_DIR="${UV_CACHE_DIR:-${TMPDIR:-/tmp}/containre-uv-cache}"

# The specimen tests import compiled binaries from specimens/bin; build them
# first (the individual tests also self-skip when a compiler is unavailable).
if [ "$integration" -eq 1 ] && [ "$build" -eq 1 ]; then
  make -C specimens
fi

# Prefer uv (installs pytest from the dev group); fall back to a plain pytest.
# Always invoke pytest via `python -m pytest` rather than the `pytest` console
# script: `-m` puts the repo root on sys.path so the `containre` package imports,
# and it sidesteps stale console-script shebangs if the .venv was moved.
if command -v uv >/dev/null 2>&1; then
  runner=(uv run python -m pytest)
else
  runner=(python3 -m pytest)
fi

marker_args=()
[ -n "$marker" ] && marker_args=(-m "$marker")

set -x
exec "${runner[@]}" ${marker_args[@]+"${marker_args[@]}"} ${pytest_args[@]+"${pytest_args[@]}"}
