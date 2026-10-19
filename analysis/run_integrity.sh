#!/usr/bin/env bash
# ==============================================================================
# Project Zephyr - Automated NIDSAlert Dataset Integrity Pipeline
#
# Audits synthetic Contract A alerts and ground-truth sidecar labels.
# Installs dependencies, runs all 12 integrity checks, outputs reports and
# charts, prints the final verdict line, and exits non-zero if any FAIL occurs.
# ==============================================================================

set -uo pipefail

echo "=============================================================================="
echo " Project Zephyr: Installing Pipeline Dependencies (pandas, matplotlib, pydantic) "
echo "=============================================================================="
pip install --disable-pip-version-check --quiet pandas matplotlib pydantic

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${WORKSPACE_ROOT}"

# Run integrity checks suite; capture exit code
python "${SCRIPT_DIR}/integrity_checks.py" "$@"
EXIT_CODE=$?

exit ${EXIT_CODE}
