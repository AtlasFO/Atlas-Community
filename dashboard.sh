#!/usr/bin/env bash
# dashboard.sh — start the persistent multi-case Atlas trace dashboard.
#
# Thin wrapper around bin/atlas-dashboard so you can launch from the repo
# root without needing the symlink in /usr/local/bin to be installed:
#
#   ./dashboard.sh                       # production ~/cases on :8765
#   ./dashboard.sh --demo                # Atlas/demo-cases
#   ./dashboard.sh --benchmarks          # Atlas/benchmarks
#   ./dashboard.sh --port 9090
#   ./dashboard.sh --cases-root /data/cases
#
# Environment:
#   ATLAS_CASES_ROOT      default cases root (fallback: ~/cases)
#   ATLAS_DASHBOARD_PORT  default port       (fallback: 8765)
#   ATLAS_DASHBOARD_BIND  listen address     (fallback: 127.0.0.1; 0.0.0.0 = LAN/HTTPS)

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$HERE/bin/atlas-dashboard" "$@"
