#!/usr/bin/env bash
#
# unit/mayhem/test.sh — RUN the nxt_checker Known-Answer-Test (KAT) built by mayhem/build.sh, plus a
# light existence smoke-check of the fuzz binaries, then emit a CTRF summary.
#
# BEHAVIORAL ORACLE (§6.3, anti-reward-hacking): nxt_checker is a standalone (non-libFuzzer) program
# that calls the SAME library entry points the fuzz targets exercise — nxt_base64_decode (fuzz_basic),
# nxt_conf_json_parse_str (fuzz_json), nxt_http_parse_request (fuzz_http_h1p / fuzz_http_controller /
# fuzz_http_h1p_peer all call this same request-line parser) — on FIXED, hard-coded input, and prints
# the COMPUTED result as "key=value" lines. This script greps stdout for the exact expected values.
#
# This is NOT "did the fuzzer run without crashing" (that would be reward-hackable: a PATCH that
# no-ops the parsing code would still "not crash"). It is NOT a libFuzzer coverage/stats proxy either
# (the previous version of this file grepped for "Executed"/"cov:" and even had an "exited 0 or ran
# without crash" fallback that made EVERY outcome pass). Instead: if nxt_base64_decode /
# nxt_conf_json_parse_str / nxt_http_parse_request were neutered (patched to a no-op, or the whole
# process is intercepted and _exit(0)'d before main() runs — the sabotage probe), nxt_checker prints
# NONE of the expected lines, so every grep below fails and the oracle correctly reports FAILURE.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

PASSED=0
FAILED=0

echo "=== unit KAT (nxt_checker): behavioral known-answer test ==="

CHECKER="/mayhem/nxt_checker"

if [ ! -x "$CHECKER" ]; then
  echo "FAIL: $CHECKER not found — did mayhem/build.sh build it?"
  FAILED=$((FAILED + 1))
else
  # Run once, capture stdout. A neutered/patched parser (or the sabotage LD_PRELOAD shim, which
  # _exit(0)s the process before main() runs at all) produces EMPTY output here.
  checker_out="$(timeout 10 "$CHECKER" 2>&1)"
  checker_rc=$?
  echo "$checker_out"

  # Each exact "key=value" line the checker must print when the real parsing code ran.
  declare -A EXPECTED=(
    [base64_decoded_len]="5"
    [base64_decoded]="hello"
    [json_member_count]="2"
    [json_count]="42"
    [json_name]="unit"
    [http_method]="GET"
    [http_path]="/hello"
  )

  for key in "${!EXPECTED[@]}"; do
    want="${EXPECTED[$key]}"
    got="$(printf '%s\n' "$checker_out" | grep -m1 "^${key}=" | cut -d= -f2-)"
    if [ "$got" = "$want" ]; then
      echo "  PASS  $key=$want"
      PASSED=$((PASSED + 1))
    else
      echo "  FAIL  $key: got='$got' want='$want'"
      FAILED=$((FAILED + 1))
    fi
  done

  # Overall exit code as one more test (catches sanitizer deaths / crashes in the checker itself).
  if [ "$checker_rc" -eq 0 ]; then
    PASSED=$((PASSED + 1))
  else
    echo "  FAIL  nxt_checker exited $checker_rc"
    FAILED=$((FAILED + 1))
  fi
fi

# ── Existence smoke-check for the remaining fuzz binaries ───────────────────────────────────────
# fuzz_basic / fuzz_http_controller / fuzz_http_h1p / fuzz_http_h1p_peer / fuzz_json are libFuzzer
# targets with no assertable return value of their own (nxt_checker above already exercises their
# UNDERLYING parse functions with real known-answer assertions: nxt_base64_decode for fuzz_basic,
# nxt_conf_json_parse_str for fuzz_json, nxt_http_parse_request for the three HTTP targets). This is
# just confirming build.sh actually produced each binary — it is NOT the primary oracle, and it is
# not gameable by neutering the parsing code at runtime (a missing/zero-byte file is a build failure,
# not a runtime behavior question).
echo "=== fuzz-target build smoke-check ==="
for fuzzer in fuzz_basic fuzz_http_controller fuzz_http_h1p fuzz_http_h1p_peer fuzz_json; do
  if [ -x "/mayhem/$fuzzer" ]; then
    echo "  PASS  /mayhem/$fuzzer present"
    PASSED=$((PASSED + 1))
  else
    echo "  FAIL  /mayhem/$fuzzer missing"
    FAILED=$((FAILED + 1))
  fi
done

echo "=== Test results ==="
echo "Passed: $PASSED"
echo "Failed: $FAILED"

emit_ctrf "unit-kat" "$PASSED" "$FAILED"
