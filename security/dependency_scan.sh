#!/usr/bin/env bash
# =============================================================================
# Task 5 — Dependency Security Scanning
# Tools: pip-audit, safety
# Run from project root: bash security/dependency_scan.sh
# =============================================================================

set -o errexit

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_DIR="$PROJECT_ROOT/security/reports"
mkdir -p "$REPORT_DIR"

echo "============================================================"
echo " Dependency Security Scan — $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo " Project: $PROJECT_ROOT"
echo "============================================================"

# ---------------------------------------------------------------------------
# 1. pip-audit — scans installed packages against PyPI Advisory DB & OSV
# ---------------------------------------------------------------------------
echo ""
echo "[1/2] Running pip-audit..."

pip-audit \
    --requirement "$PROJECT_ROOT/requirements.txt" \
    --format json \
    --output "$REPORT_DIR/pip_audit_report.json" \
    || true

pip-audit \
    --requirement "$PROJECT_ROOT/requirements.txt" \
    --format columns \
    --output "$REPORT_DIR/pip_audit_report.txt" \
    || true

echo "  pip-audit reports saved to $REPORT_DIR/pip_audit_report.{json,txt}"

# ---------------------------------------------------------------------------
# 2. Safety — checks against Safety DB (known CVEs)
# ---------------------------------------------------------------------------
echo ""
echo "[2/2] Running Safety..."

if command -v safety &>/dev/null; then
    safety check \
        --file "$PROJECT_ROOT/requirements.txt" \
        --json \
        --output "$REPORT_DIR/safety_report.json" \
        || true

    safety check \
        --file "$PROJECT_ROOT/requirements.txt" \
        --output "$REPORT_DIR/safety_report.txt" \
        || true

    echo "  Safety reports saved to $REPORT_DIR/safety_report.{json,txt}"
else
    echo "  WARNING: safety not found. Install with: pip install safety"
fi

echo ""
echo "============================================================"
echo " Dependency Scan Complete"
echo " Reports: $REPORT_DIR"
echo "============================================================"
