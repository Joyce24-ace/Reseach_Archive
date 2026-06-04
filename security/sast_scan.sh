#!/usr/bin/env bash
# =============================================================================
# Task 4 — Static Application Security Testing (SAST)
# Tools: bandit, semgrep
# Run from project root: bash security/sast_scan.sh
# =============================================================================

set -o errexit

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_DIR="$PROJECT_ROOT/security/reports"
mkdir -p "$REPORT_DIR"

echo "============================================================"
echo " SAST Scan — $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo " Project: $PROJECT_ROOT"
echo "============================================================"

# ---------------------------------------------------------------------------
# 1. Bandit — Python AST-based security linter
# ---------------------------------------------------------------------------
echo ""
echo "[1/2] Running Bandit..."

bandit \
    -r "$PROJECT_ROOT" \
    --exclude "$PROJECT_ROOT/.venv,$PROJECT_ROOT/staticfiles,$PROJECT_ROOT/security/reports" \
    -f json \
    -o "$REPORT_DIR/bandit_report.json" \
    --severity-level low \
    --confidence-level low \
    || true   # don't exit on findings — we want the full report

bandit \
    -r "$PROJECT_ROOT" \
    --exclude "$PROJECT_ROOT/.venv,$PROJECT_ROOT/staticfiles,$PROJECT_ROOT/security/reports" \
    -f txt \
    -o "$REPORT_DIR/bandit_report.txt" \
    --severity-level low \
    --confidence-level low \
    || true

echo "  Bandit reports saved to $REPORT_DIR/bandit_report.{json,txt}"

# ---------------------------------------------------------------------------
# 2. Semgrep — pattern-based multi-language SAST
# ---------------------------------------------------------------------------
echo ""
echo "[2/2] Running Semgrep..."

if command -v semgrep &>/dev/null; then
    semgrep \
        --config "p/django" \
        --config "p/python" \
        --config "p/owasp-top-ten" \
        --config "p/secrets" \
        --json \
        --output "$REPORT_DIR/semgrep_report.json" \
        "$PROJECT_ROOT" \
        --exclude ".venv" \
        --exclude "staticfiles" \
        --exclude "security/reports" \
        || true

    semgrep \
        --config "p/django" \
        --config "p/python" \
        --config "p/owasp-top-ten" \
        --config "p/secrets" \
        --output "$REPORT_DIR/semgrep_report.txt" \
        "$PROJECT_ROOT" \
        --exclude ".venv" \
        --exclude "staticfiles" \
        --exclude "security/reports" \
        || true

    echo "  Semgrep reports saved to $REPORT_DIR/semgrep_report.{json,txt}"
else
    echo "  WARNING: semgrep not found. Install with: pip install semgrep"
    echo "  Skipping semgrep scan."
fi

echo ""
echo "============================================================"
echo " SAST Scan Complete"
echo " Reports: $REPORT_DIR"
echo "============================================================"
