#!/usr/bin/env bash
# =============================================================================
# integration_test.sh — End-to-end integration test for the ransomware
# defense simulator + monitor pipeline.
#
# Pass criteria:
#   1. Monitor produces zero alerts after 5 s idle (no false positives)
#   2. After running simulator, ≥1 alert appears in logs/alerts.csv within 10 s
#   3. No simulator-written file exists outside ./test_env/
#
# Usage:
#   bash tests/integration_test.sh
#   Exit 0 = all checks passed
#   Exit 1 = a check failed (details printed to stderr)
# =============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BIN_MONITOR="./bin/monitor"
BIN_SIMULATOR="./bin/simulator"
ALERTS_CSV="logs/alerts.csv"
MONITOR_PID=""

fail() { echo "[FAIL] $*" >&2; exit 1; }
pass() { echo "[PASS] $*"; }

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------
[[ -x "$BIN_MONITOR"   ]] || fail "bin/monitor not found — run 'make' first"
[[ -x "$BIN_SIMULATOR" ]] || fail "bin/simulator not found — run 'make' first"

# Clean state
make clean-sandbox >/dev/null 2>&1

# ---------------------------------------------------------------------------
# Step 1: Start monitor in background
# ---------------------------------------------------------------------------
"$BIN_MONITOR" >/dev/null 2>&1 &
MONITOR_PID=$!
echo "[INFO] Monitor started (PID $MONITOR_PID)"

cleanup() {
    if [[ -n "$MONITOR_PID" ]]; then
        kill "$MONITOR_PID" 2>/dev/null || true
        wait "$MONITOR_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Step 2: Idle check — no false positives after 5 s
# ---------------------------------------------------------------------------
echo "[INFO] Waiting 5 s for idle baseline..."
sleep 5

if [[ -f "$ALERTS_CSV" ]] && [[ $(wc -l < "$ALERTS_CSV") -gt 1 ]]; then
    fail "False positive: alerts.csv has entries on idle system"
fi
pass "Idle baseline: no false positives"

# ---------------------------------------------------------------------------
# Step 3: Run simulator
# ---------------------------------------------------------------------------
echo "[INFO] Starting simulator..."
"$BIN_SIMULATOR" --files=200 --children=8 --mem-mb=200 --i-am-in-a-vm \
    >/dev/null 2>&1 &
SIM_PID=$!

# ---------------------------------------------------------------------------
# Step 4: Wait up to 10 s for at least 1 alert
# ---------------------------------------------------------------------------
echo "[INFO] Waiting up to 10 s for detection..."
DETECTED=false
for i in $(seq 1 10); do
    sleep 1
    if [[ -f "$ALERTS_CSV" ]] && [[ $(wc -l < "$ALERTS_CSV") -gt 1 ]]; then
        DETECTED=true
        break
    fi
done

wait "$SIM_PID" 2>/dev/null || true

if [[ "$DETECTED" != "true" ]]; then
    fail "No alert detected within 10 s of simulator run"
fi
pass "Detection: ≥1 alert in logs/alerts.csv"

# ---------------------------------------------------------------------------
# Step 5: Verify no file written outside ./test_env/
# ---------------------------------------------------------------------------
LEAKED=$(find . -name "dummy_*.dat*" -not -path "./test_env/*" 2>/dev/null || true)
if [[ -n "$LEAKED" ]]; then
    fail "Simulator wrote files outside sandbox: $LEAKED"
fi
pass "Sandbox confinement: no files leaked outside test_env/"

# ---------------------------------------------------------------------------
# All checks passed
# ---------------------------------------------------------------------------
echo ""
echo "========================================="
echo "  All integration checks PASSED"
echo "========================================="
exit 0
