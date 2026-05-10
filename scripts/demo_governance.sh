#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[1/5] Building digest..."
go build -ldflags "-s -w" -o digest ./cmd/digest

echo "[2/5] Installing demo policy (./digest.policy.yaml)..."
cp examples/digest.policy.yaml ./digest.policy.yaml

echo "[3/5] Running allowed read-only command (should auto-allow, no TUI)..."
./digest echo "demo: read-only command allowed"

echo "[4/5] Running blocked command (safe dry-run style; command must not execute)..."
set +e
./digest git push --force --dry-run >/tmp/digest_demo_blocked.out 2>/tmp/digest_demo_blocked.err
blocked_code=$?
set -e

if [[ $blocked_code -eq 0 ]]; then
  echo "ERROR: expected blocked command to fail, but it succeeded"
  exit 1
fi

echo "Blocked command exit code: $blocked_code"
echo "stderr (expected policy block message):"
cat /tmp/digest_demo_blocked.err

echo "[5/5] Audit log tail (./digest.audit.log):"
if [[ -f ./digest.audit.log ]]; then
  tail -n 5 ./digest.audit.log
else
  echo "No audit log found (unexpected)."
  exit 1
fi

echo
echo "Demo complete."
