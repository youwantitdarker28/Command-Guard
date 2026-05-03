#!/usr/bin/env bash
# smoke_test.sh — end-to-end validation of the digest binary.
#
# Runs a series of black-box tests against the compiled binary.
# Set DIGEST_BIN to override the binary path (default: ./digest).
#
# Exit codes:
#   0 — all tests passed
#   1 — one or more tests failed

set -euo pipefail

DIGEST_BIN="${DIGEST_BIN:-./digest}"
PASS=0
FAIL=0

# ── Helpers ───────────────────────────────────────────────────────────────────

green()  { printf '\033[32m%s\033[0m\n' "$*"; }
red()    { printf '\033[31m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n'  "$*"; }
header() { printf '\n'; bold "── $* ──"; }

pass() {
  PASS=$((PASS + 1))
  green  "  ✓  $1"
}

fail() {
  FAIL=$((FAIL + 1))
  red    "  ✗  $1"
  if [[ -n "${2-}" ]]; then
    printf '     %s\n' "$2"
  fi
}

# assert_exit <expected_code> <description> -- <command...>
assert_exit() {
  local expected="$1"; shift
  local desc="$1";     shift
  # consume the "--" separator
  shift

  local actual
  actual=0
  "$@" 2>/dev/null || actual=$?

  if [[ "$actual" -eq "$expected" ]]; then
    pass "$desc (exit $actual)"
  else
    fail "$desc" "expected exit $expected, got $actual"
  fi
}

# ── Pre-flight ────────────────────────────────────────────────────────────────

header "Pre-flight"

if [[ ! -x "$DIGEST_BIN" ]]; then
  fail "Binary not found or not executable: $DIGEST_BIN"
  echo ""
  red "Run 'make build' first, then re-run this script."
  exit 1
fi
pass "Binary found: $DIGEST_BIN"

# ── Test 1: no-args prints usage and exits 1 ─────────────────────────────────

header "Test 1 — no-args usage"
assert_exit 1 "no-args exits 1" -- "$DIGEST_BIN"

usage_output=$("$DIGEST_BIN" 2>&1 || true)
if echo "$usage_output" | grep -q "Usage:"; then
  pass "usage message contains 'Usage:'"
else
  fail "usage message missing 'Usage:'" "got: $usage_output"
fi

# ── Test 2: DIGEST_AUTO_APPROVE=1 executes and streams stdout ────────────────

header "Test 2 — auto-approve: echo success"
output=$(DIGEST_AUTO_APPROVE=1 "$DIGEST_BIN" echo success 2>/dev/null)
if [[ "$output" == "success" ]]; then
  pass "stdout contains 'success'"
else
  fail "stdout did not contain 'success'" "got: '$output'"
fi

# ── Test 3: exit code is propagated from child process ───────────────────────

header "Test 3 — exit code propagation"
assert_exit 42 "child exit 42 propagated" -- \
  bash -c "DIGEST_AUTO_APPROVE=1 $DIGEST_BIN bash -c 'exit 42'"

assert_exit 0 "child exit 0 propagated" -- \
  bash -c "DIGEST_AUTO_APPROVE=1 $DIGEST_BIN bash -c 'exit 0'"

# ── Test 4: multi-arg command passes all args correctly ──────────────────────

header "Test 4 — argument forwarding"
output=$(DIGEST_AUTO_APPROVE=1 "$DIGEST_BIN" printf '%s %s %s' hello world foo 2>/dev/null)
if [[ "$output" == "hello world foo" ]]; then
  pass "all arguments forwarded correctly"
else
  fail "argument forwarding" "expected 'hello world foo', got '$output'"
fi

# ── Test 5: risk classification smoke-check (unit tests act as oracle) ────────

header "Test 5 — unit test suite"
if (cd "$(dirname "$0")/.." && go test -race -count=1 ./... 2>&1 | tail -5); then
  pass "go test ./... passed"
else
  fail "go test ./... failed"
fi

# ── Test 6: stderr is used for TUI / status messages, stdout for output ───────

header "Test 6 — stdout / stderr separation"
stdout_out=$(DIGEST_AUTO_APPROVE=1 "$DIGEST_BIN" echo clean 2>/dev/null)
stderr_out=$(DIGEST_AUTO_APPROVE=1 "$DIGEST_BIN" echo clean 2>&1 >/dev/null)

if [[ "$stdout_out" == "clean" ]]; then
  pass "stdout carries only command output"
else
  fail "unexpected stdout content" "got: '$stdout_out'"
fi

if echo "$stderr_out" | grep -qi "executing"; then
  pass "stderr carries digest status messages"
else
  fail "digest status messages not found on stderr" "got: '$stderr_out'"
fi

# ── Summary ───────────────────────────────────────────────────────────────────

printf '\n'
bold "Results: $PASS passed, $FAIL failed"

if [[ "$FAIL" -gt 0 ]]; then
  red "Smoke test FAILED."
  exit 1
fi

green "All smoke tests passed."
exit 0
