#!/usr/bin/env bash
# Protocol Ward — Definition of Done v0.2 acceptance harness.
#
# Runs the v0.2 acceptance bullets enumerated in
# docs/engineering/definition-of-done.md. Exits 0 only when every required
# bullet passes; any FAIL or TODO bullet exits non-zero. The DOD doc + this
# script are rewritten together at each version boundary (v0.2 → v0.3 → …).
#
# Statuses:
#   PASS  — bullet ran and the assertion held.
#   FAIL  — bullet ran and the assertion did NOT hold. Exits non-zero.
#   TODO  — feature not implemented yet (the bullet names its blocking
#           sub-project). Exits non-zero so "make dod green" cannot mean
#           "shipped" until every TODO is replaced with PASS.
#   SKIP  — bullet intentionally skipped (e.g. closeout-only bullets when
#           --closeout is not passed). Does NOT cause a non-zero exit.
#
# Flags:
#   --closeout   include bullet 16 (git log origin/main..HEAD must be empty).
#                Run this at slice-closeout time, NOT during development.

set -uo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

closeout=0
for arg in "$@"; do
  case "$arg" in
    --closeout) closeout=1 ;;
    -h|--help)
      sed -n '2,22p' "$0"
      exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

if [[ -t 1 ]]; then
  C_PASS=$'\e[32m'; C_FAIL=$'\e[31m'; C_TODO=$'\e[33m'; C_SKIP=$'\e[90m'; C_RST=$'\e[0m'
else
  C_PASS=""; C_FAIL=""; C_TODO=""; C_SKIP=""; C_RST=""
fi

tmpdir="$(mktemp -d -t ward-dod.XXXXXX)"
ward_pid=""

cleanup() {
  if [[ -n "$ward_pid" ]] && kill -0 "$ward_pid" 2>/dev/null; then
    kill "$ward_pid" 2>/dev/null || true
    wait "$ward_pid" 2>/dev/null || true
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT

results=()

record() {
  local status="$1" num="$2" desc="$3" detail="${4:-}"
  results+=("$status|$num|$desc")
  local color=""
  case "$status" in
    PASS) color="$C_PASS" ;;
    FAIL) color="$C_FAIL" ;;
    TODO) color="$C_TODO" ;;
    SKIP) color="$C_SKIP" ;;
  esac
  if [[ -n "$detail" ]]; then
    printf "  %s[%s]%s bullet %2s — %s\n        %s\n" \
      "$color" "$status" "$C_RST" "$num" "$desc" "$detail"
  else
    printf "  %s[%s]%s bullet %2s — %s\n" \
      "$color" "$status" "$C_RST" "$num" "$desc"
  fi
}

# ---------------------------------------------------------------------------
# Bullets. Each function records exactly one bullet via `record`. Bullets
# 1–11 encode shipped v0.1 behavior (unchanged at the v0.2 bump). Bullets
# 12–15 are the v0.2 model-stack assertions. Bullet 16 is the SHIP gate,
# opt-in via --closeout.
# ---------------------------------------------------------------------------

bullet_1_make_ci() {
  local log="$tmpdir/make-ci.log"
  if make ci >"$log" 2>&1; then
    record PASS 1 "make ci passes"
  else
    record FAIL 1 "make ci passes" "see $log (tail: $(tail -1 "$log"))"
  fi
}

bullet_2_make_audit() {
  local log="$tmpdir/make-audit.log"
  if make audit >"$log" 2>&1; then
    record PASS 2 "make audit passes"
  else
    record FAIL 2 "make audit passes" "see $log (tail: $(tail -1 "$log"))"
  fi
}

WARD_LOG=""

# bullet_3_ward_boots brings ward up and LEAVES it running for bullets 4–6.
# The EXIT trap (cleanup) is responsible for teardown.
bullet_3_ward_boots() {
  WARD_LOG="$tmpdir/ward.log"
  if ! make build >"$tmpdir/build.log" 2>&1; then
    record FAIL 3 "ward serve binds 127.0.0.1:5354 within 5s" "make build failed; see $tmpdir/build.log"
    return
  fi
  bin/ward serve --config testdata/dod/ward.yaml >"$WARD_LOG" 2>&1 &
  ward_pid=$!
  local waited=0
  while (( waited < 50 )); do
    # DOD fixture always has both blocklists and allowlists, so the
    # banner must be the "engine ready" branch. Accepting "not configured"
    # would mask a fixture misconfiguration (Ralph N1).
    if grep -q "policy: engine ready" "$WARD_LOG" 2>/dev/null; then
      record PASS 3 "ward serve binds 127.0.0.1:5354 within 5s"
      return
    fi
    if ! kill -0 "$ward_pid" 2>/dev/null; then
      record FAIL 3 "ward serve binds 127.0.0.1:5354 within 5s" "process exited early; see $WARD_LOG"
      ward_pid=""
      return
    fi
    sleep 0.1
    waited=$((waited+1))
  done
  record FAIL 3 "ward serve binds 127.0.0.1:5354 within 5s" "ready banner not seen in 5s; see $WARD_LOG"
}

# ward_ready returns 0 iff bullet 3 left ward running.
ward_ready() { [[ -n "$ward_pid" ]] && kill -0 "$ward_pid" 2>/dev/null; }

# dig_at runs a single DNS query against the local ward instance. Echoes
# the +short response on stdout; non-zero exit on dig error.
dig_at() {
  dig +time=2 +tries=1 +short @127.0.0.1 -p 5354 "$@" 2>/dev/null
}
bullet_4_block_response() {
  if ! ward_ready; then
    record FAIL 4 "DNS: blocked hostname → block response + attribution" "ward not running (bullet 3 failed)"
    return
  fi
  local out
  out="$(dig_at known-blocked.dod.test A)"
  # 0.0.0.0 is the block_response.a DEFAULT used when testdata/dod/ward.yaml
  # omits the block_response: section. If that section is added to the
  # fixture, update this assertion in the same commit (Ralph N2).
  if [[ "$out" != "0.0.0.0" ]]; then
    record FAIL 4 "DNS: blocked hostname → block response + attribution" "dig returned '$out' (expected '0.0.0.0' per ward.yaml default)"
    return
  fi
  # Attribution: the policy:blocked log line must name the qname.
  if ! grep -q '"msg":"policy: blocked".*"qname":"known-blocked.dod.test"' "$WARD_LOG"; then
    record FAIL 4 "DNS: blocked hostname → block response + attribution" "no policy:blocked log line for known-blocked.dod.test in $WARD_LOG"
    return
  fi
  record PASS 4 "DNS: blocked hostname → block response + attribution"
}

bullet_5_allow_upstream() {
  # Bullet 5 needs the upstream forward path to complete end-to-end. The
  # checked-in testdata/dod/ward.yaml points at 127.0.0.1:5853 with
  # server_name=127.0.0.1, which is intentionally a dead address (so bullets
  # 3/4/6 stay green without an upstream). For bullet 5 we:
  #   1. build cmd/wardtestdot, the in-process fake DoT server (helper writes
  #      its self-signed CA PEM to a path we choose);
  #   2. write a per-run fixture override that adds ca_bundle: AND patches
  #      server_name to wardtestdot.test (matches the helper's cert DNS SAN);
  #   3. restart ward against the override (the original ward from bullet 3
  #      stays running for nobody — we tear it down first so the listen port
  #      is free);
  #   4. dig allowed.dod.test → expect 93.184.216.34 (helper's fixed answer).
  local helper_bin="$tmpdir/wardtestdot"
  local ca_pem="$tmpdir/wardtestdot-ca.pem"
  local override_yaml="$tmpdir/ward-bullet5.yaml"
  local helper_log="$tmpdir/wardtestdot.log"
  local ward5_log="$tmpdir/ward-bullet5.log"

  if ! go build -o "$helper_bin" ./cmd/wardtestdot >"$tmpdir/build-helper.log" 2>&1; then
    record FAIL 5 "DNS: forwarded hostname → upstream answer" "go build wardtestdot failed; see $tmpdir/build-helper.log"
    return
  fi

  # Tear down the bullet 3 ward so we can rebind 127.0.0.1:5354 against the override.
  if [[ -n "$ward_pid" ]] && kill -0 "$ward_pid" 2>/dev/null; then
    kill "$ward_pid" 2>/dev/null || true
    wait "$ward_pid" 2>/dev/null || true
    ward_pid=""
  fi

  # Start the helper. It writes the CA PEM to ca_pem before it begins listening
  # ('wardtestdot ready' on stdout signals readiness).
  "$helper_bin" -listen 127.0.0.1:5853 -ca-out "$ca_pem" >"$helper_log" 2>&1 &
  local helper_pid=$!
  local waited=0
  while (( waited < 50 )); do
    if grep -q "^wardtestdot ready" "$helper_log" 2>/dev/null; then
      break
    fi
    if ! kill -0 "$helper_pid" 2>/dev/null; then
      record FAIL 5 "DNS: forwarded hostname → upstream answer" "wardtestdot exited early; see $helper_log"
      return
    fi
    sleep 0.1
    waited=$((waited+1))
  done
  if (( waited >= 50 )); then
    kill "$helper_pid" 2>/dev/null || true
    record FAIL 5 "DNS: forwarded hostname → upstream answer" "wardtestdot did not become ready in 5s; see $helper_log"
    return
  fi

  # Write the per-run override. Starts from the checked-in fixture; rewrites
  # the upstreams stanza to include ca_bundle + the matching server_name.
  cat > "$override_yaml" <<EOF
listen: "127.0.0.1:5354"
log_level: "info"

upstreams:
  - address: "127.0.0.1:5853"
    server_name: "wardtestdot.test"
    ca_bundle: "$ca_pem"

timeouts:
  dial: "2s"
  query: "2s"
  shutdown: "2s"

blocklists:
  - id: "dod-blocked"
    path: "./testdata/dod/blocklists/blocked.txt"

allowlists:
  - id: "dod-allowed"
    path: "./testdata/dod/allowlists/allowed.txt"
EOF

  bin/ward serve --config "$override_yaml" >"$ward5_log" 2>&1 &
  local ward5_pid=$!
  waited=0
  while (( waited < 50 )); do
    if grep -q "policy: engine ready" "$ward5_log" 2>/dev/null; then
      break
    fi
    if ! kill -0 "$ward5_pid" 2>/dev/null; then
      kill "$helper_pid" 2>/dev/null || true
      record FAIL 5 "DNS: forwarded hostname → upstream answer" "ward (bullet 5 override) exited early; see $ward5_log"
      return
    fi
    sleep 0.1
    waited=$((waited+1))
  done
  if (( waited >= 50 )); then
    kill "$ward5_pid" 2>/dev/null || true
    kill "$helper_pid" 2>/dev/null || true
    record FAIL 5 "DNS: forwarded hostname → upstream answer" "ward (bullet 5 override) ready banner not seen in 5s; see $ward5_log"
    return
  fi

  local out
  out="$(dig +time=2 +tries=1 +short @127.0.0.1 -p 5354 allowed.dod.test A 2>/dev/null)"

  # Tear down ward + helper regardless of result.
  kill "$ward5_pid" 2>/dev/null || true
  wait "$ward5_pid" 2>/dev/null || true
  kill "$helper_pid" 2>/dev/null || true
  wait "$helper_pid" 2>/dev/null || true

  if [[ "$out" != "93.184.216.34" ]]; then
    record FAIL 5 "DNS: forwarded hostname → upstream answer" "dig returned '$out' (expected '93.184.216.34' from wardtestdot); ward log: $ward5_log"
    return
  fi
  record PASS 5 "DNS: forwarded hostname → upstream answer"
}

bullet_6_allow_beats_blk() {
  if ! ward_ready; then
    record FAIL 6 "POLICY: allow-beats-block precedence E2E" "ward not running (bullet 3 failed)"
    return
  fi
  # bothlisted.dod.test is in BOTH blocklist and allowlist. The policy
  # engine must log "policy: allowed", not "policy: blocked". The actual
  # upstream forward will SERVFAIL today (no usable fake upstream — see
  # bullet 5 blocker), but the policy decision log fires BEFORE forwarding,
  # so the precedence assertion is independently observable.
  dig_at bothlisted.dod.test A >/dev/null
  # Wait up to 5s for the policy:allowed log line — matches bullet 3's
  # headroom. Earlier window of 1s was tighter than the 2s query timeout
  # and could spuriously FAIL on a loaded rig (Ralph B2).
  local waited=0
  while (( waited < 50 )); do
    if grep -q '"msg":"policy: allowed".*"qname":"bothlisted.dod.test"' "$WARD_LOG"; then
      if grep -q '"msg":"policy: blocked".*"qname":"bothlisted.dod.test"' "$WARD_LOG"; then
        record FAIL 6 "POLICY: allow-beats-block precedence E2E" "both 'policy: allowed' AND 'policy: blocked' fired for bothlisted.dod.test — precedence inverted"
        return
      fi
      record PASS 6 "POLICY: allow-beats-block precedence E2E"
      return
    fi
    sleep 0.1
    waited=$((waited+1))
  done
  record FAIL 6 "POLICY: allow-beats-block precedence E2E" "no 'policy: allowed' log line for bothlisted.dod.test in $WARD_LOG"
}
bullet_7_decoy_alert() {
  if ! ward_ready; then
    record FAIL 7 "DECOY: tripwire hostname fires policy alert" "ward not running (bullet 3 failed)"
    return
  fi
  # tripwire.dod.test is in testdata/dod/decoys/tripwires.txt. The decoy
  # short-circuit fires BEFORE Engine.Decide and emits a slog.Warn line at
  # "policy: alert" with kind=decoy, qname=tripwire.dod.test, plus the
  # configured BlockResponse on the wire (0.0.0.0 for the dod fixture).
  dig_at tripwire.dod.test A >/dev/null
  local waited=0
  while (( waited < 50 )); do
    # Match all three load-bearing fields: msg + kind=decoy + qname. A future
    # non-decoy "policy: alert" emitter (behavioral classifier in v0.2+) must
    # not be able to pass this bullet without an actual decoy hit (Ralph N3).
    if grep -q '"msg":"policy: alert".*"kind":"decoy".*"qname":"tripwire.dod.test"' "$WARD_LOG"; then
      record PASS 7 "DECOY: tripwire hostname fires policy alert"
      return
    fi
    sleep 0.1
    waited=$((waited+1))
  done
  record FAIL 7 "DECOY: tripwire hostname fires policy alert" "no 'policy: alert' log line for tripwire.dod.test in $WARD_LOG"
}
bullet_8_dashboard() {
  if ! ward_ready; then
    record FAIL 8 "DASHBOARD: GET /healthz → 200 + last decision" "ward not running (bullet 3 failed)"
    return
  fi
  # Fire a fresh, non-decoy, non-blocked qname so it lands as the last
  # decision recorded by the dataplane. Capturing the qname locally and
  # asserting against the captured value (not a hardcoded constant)
  # defends against future fixture renames.
  local probe_qname="dashboard-probe.dod.test"
  dig_at "$probe_qname" A >/dev/null
  # Give the dataplane a moment to call Record on its goroutine path.
  sleep 0.1

  local body_file="$tmpdir/healthz.json"
  if ! curl -sS -o "$body_file" -w "%{http_code}" "http://127.0.0.1:18987/healthz" > "$tmpdir/healthz.code" 2>"$tmpdir/healthz.err"; then
    record FAIL 8 "DASHBOARD: GET /healthz → 200 + last decision" "curl failed; see $tmpdir/healthz.err"
    return
  fi
  local http_code
  http_code="$(cat "$tmpdir/healthz.code")"
  if [[ "$http_code" != "200" ]]; then
    record FAIL 8 "DASHBOARD: GET /healthz → 200 + last decision" "HTTP $http_code; body: $(cat "$body_file")"
    return
  fi
  if ! grep -q '"status":"ok"' "$body_file"; then
    record FAIL 8 "DASHBOARD: GET /healthz → 200 + last decision" "no \"status\":\"ok\" in body: $(cat "$body_file")"
    return
  fi
  if ! grep -q "\"qname\":\"$probe_qname\"" "$body_file"; then
    record FAIL 8 "DASHBOARD: GET /healthz → 200 + last decision" "last_decision.qname does not match $probe_qname; body: $(cat "$body_file")"
    return
  fi
  record PASS 8 "DASHBOARD: GET /healthz → 200 + last decision"
}
bullet_9_export_noleak() {
  # ward config export reads testdata/dod/ward.yaml and writes the validated
  # config to stdout. The DOD fixture has decoys configured (decoy-tripwire
  # slice). Invariant 6: the decoy hostname AND the decoys: key must be
  # absent from the output. Asserted at the byte level.
  if [[ ! -x bin/ward ]]; then
    record FAIL 9 "EXPORT: config export does NOT leak decoy hosts" "bin/ward missing — make build should have produced it"
    return
  fi
  local out_file="$tmpdir/export.yaml"
  if ! bin/ward config export --config testdata/dod/ward.yaml >"$out_file" 2>"$tmpdir/export.err"; then
    record FAIL 9 "EXPORT: config export does NOT leak decoy hosts" "ward config export failed; see $tmpdir/export.err"
    return
  fi
  if grep -q 'tripwire.dod.test' "$out_file"; then
    record FAIL 9 "EXPORT: config export does NOT leak decoy hosts" "decoy hostname leaked into export; see $out_file"
    return
  fi
  # Unanchored grep — matches `decoys:` at any indentation level, mirroring
  # the byte-level bytes.Contains check in internal/decoy/export_test.go
  # (Ralph N2: anchored ^decoys: was structurally weaker than the unit test).
  if grep -q 'decoys:' "$out_file"; then
    record FAIL 9 "EXPORT: config export does NOT leak decoy hosts" "decoys: key present in export; see $out_file"
    return
  fi
  record PASS 9 "EXPORT: config export does NOT leak decoy hosts"
}
bullet_10_update_verify() {
  if [[ ! -x bin/ward ]]; then
    record FAIL 10 "UPDATE: ward update verify validates cosign+TUF" "bin/ward missing"
    return
  fi
  local out="$tmpdir/update-verify.out"
  if ! bin/ward update verify testdata/update/v0.1-good >"$out" 2>&1; then
    record FAIL 10 "UPDATE: ward update verify validates cosign+TUF" "exit non-zero; see $out (tail: $(tail -1 "$out"))"
    return
  fi
  # Anchored 'OK — verified' so a future log line starting with 'OK '
  # cannot falsely pass (T0 spec-review N1).
  if ! grep -q '^OK — verified' "$out"; then
    record FAIL 10 "UPDATE: ward update verify validates cosign+TUF" "no OK line in output; see $out"
    return
  fi
  record PASS 10 "UPDATE: ward update verify validates cosign+TUF"
}
bullet_11_ward_doctor() {
  # ward doctor runs two probes against the configured ward.yaml:
  #   - bind probe on cfg.Listen (UDP+TCP, brief)
  #   - per-upstream TCP reachability probe
  # We need an upstream port to accept TCP connections, so we spawn the
  # wardtestdot helper (same one bullet 5 uses) and point a per-run override
  # at it. The doctor probe does NOT need ca_bundle (TCP-only), but we keep
  # it in the override for symmetry with the bullet-5 fixture pattern.
  #
  # Required: bullet 5's bin/ward already exists from earlier in the run.
  local helper_bin="$tmpdir/wardtestdot"
  local ca_pem="$tmpdir/wardtestdot-doctor-ca.pem"
  local override_yaml="$tmpdir/ward-bullet11.yaml"
  local helper_log="$tmpdir/wardtestdot-doctor.log"
  local doctor_out="$tmpdir/ward-doctor.out"

  if [[ ! -x bin/ward ]]; then
    record FAIL 11 "CLI: ward doctor reports bind + upstream probe" "bin/ward missing"
    return
  fi
  if [[ ! -x "$helper_bin" ]]; then
    if ! go build -o "$helper_bin" ./cmd/wardtestdot >"$tmpdir/build-helper-bullet11.log" 2>&1; then
      record FAIL 11 "CLI: ward doctor reports bind + upstream probe" "go build wardtestdot failed; see $tmpdir/build-helper-bullet11.log"
      return
    fi
  fi

  # Tear down the shared ward (bullet 3) so the bind probe sees a free port.
  if [[ -n "$ward_pid" ]] && kill -0 "$ward_pid" 2>/dev/null; then
    kill "$ward_pid" 2>/dev/null || true
    wait "$ward_pid" 2>/dev/null || true
    ward_pid=""
  fi

  # Pick an unused upstream port so we don't clash with bullet 5's 5853 if it
  # already ran (and reciprocally, so a future re-run doesn't see a dangling
  # listener). Hard-code a different port: 5854.
  "$helper_bin" -listen 127.0.0.1:5854 -ca-out "$ca_pem" >"$helper_log" 2>&1 &
  local helper_pid=$!
  local waited=0
  while (( waited < 50 )); do
    if grep -q "^wardtestdot ready" "$helper_log" 2>/dev/null; then
      break
    fi
    if ! kill -0 "$helper_pid" 2>/dev/null; then
      record FAIL 11 "CLI: ward doctor reports bind + upstream probe" "wardtestdot exited early; see $helper_log"
      return
    fi
    sleep 0.1
    waited=$((waited+1))
  done
  if (( waited >= 50 )); then
    kill "$helper_pid" 2>/dev/null || true
    record FAIL 11 "CLI: ward doctor reports bind + upstream probe" "wardtestdot did not become ready in 5s"
    return
  fi

  cat > "$override_yaml" <<EOF
listen: "127.0.0.1:5354"
log_level: "info"

upstreams:
  - address: "127.0.0.1:5854"
    server_name: "wardtestdot.test"
    ca_bundle: "$ca_pem"

timeouts:
  dial: "2s"
  query: "2s"
  shutdown: "2s"
EOF

  bin/ward doctor --config "$override_yaml" >"$doctor_out" 2>&1
  local rc=$?

  kill "$helper_pid" 2>/dev/null || true
  wait "$helper_pid" 2>/dev/null || true

  if (( rc != 0 )); then
    record FAIL 11 "CLI: ward doctor reports bind + upstream probe" "ward doctor exit=$rc; see $doctor_out"
    return
  fi
  if ! grep -q 'bind' "$doctor_out"; then
    record FAIL 11 "CLI: ward doctor reports bind + upstream probe" "output missing 'bind' line; see $doctor_out"
    return
  fi
  if ! grep -q 'upstream' "$doctor_out"; then
    record FAIL 11 "CLI: ward doctor reports bind + upstream probe" "output missing 'upstream' line; see $doctor_out"
    return
  fi
  if ! grep -q '\[OK\]' "$doctor_out"; then
    record FAIL 11 "CLI: ward doctor reports bind + upstream probe" "output missing '[OK]' status indicator; see $doctor_out"
    return
  fi
  record PASS 11 "CLI: ward doctor reports bind + upstream probe"
}

# --- v0.2 model-stack bullets (12–15) --------------------------------------
# They touch no shared state (ward_pid, tmpdir, WARD_LOG), so they cannot
# interfere with bullets 1–11's pass/fail chaining.

bullet_12_model_abstraction() {
  # Two-clause assertion per definition-of-done.md bullet 12:
  #   Part A — no model→connstate path: pkg/model imports must not include
  #            internal/dataplane or internal/policy (invariant 1).
  #   Part B — Classifier→Verdict→Engine→Action: the
  #            TestDecideWithVerdict_* family in internal/policy proves the
  #            mapping from schema.Verdict to policy.Action via Engine.
  #            DecideWithVerdict (the Classifier is consumed by the
  #            dataplane fork landing in SP10c; the wiring is asserted
  #            here against the engine method that consumes the Verdict).
  local log="$tmpdir/dod12.log"

  # Part A — static import check on pkg/model.
  local forbidden
  forbidden="$(grep -rE '"[^"]*/(internal/dataplane|internal/policy)"' pkg/model/ 2>/dev/null || true)"
  if [[ -n "$forbidden" ]]; then
    record FAIL 12 "MODEL: Classifier→Verdict→Engine→Action; no model→connstate path (inv 1)" \
      "pkg/model imports a deciding package (invariant 1): $forbidden"
    return
  fi

  # Part B — Verdict→Action mapping assertion.
  if ! go test -run 'TestDecideWithVerdict' ./internal/policy/... >"$log" 2>&1; then
    record FAIL 12 "MODEL: Classifier→Verdict→Engine→Action; no model→connstate path (inv 1)" \
      "go test TestDecideWithVerdict failed; see $log (tail: $(tail -1 "$log"))"
    return
  fi

  record PASS 12 "MODEL: Classifier→Verdict→Engine→Action; no model→connstate path (inv 1)"
}

# S2 regression note (2026-10-05, public beta): ward.example.yaml now ships
# `model: {builtin: lexical}`, which runs pkg/detect in-process and never
# spawns a sibling. Bullets 13-15 deliberately keep `model.command` +
# cmd/wardtestmodel so the sibling-process path (invariant 3 isolation, the
# ErrUnavailable atomic latch, the unchanged `policy: classified` line) stays
# covered. Do NOT switch these fixtures to builtin. The builtin path is
# covered by internal/dataplane/flags_test.go and
# cmd/ward TestServe_Model_Builtin_FlagsOnDashboard_StillForwarded.
# bullet_13_setup_model_ward builds wardtestmodel, writes a per-run override
# ward.yaml with model: stanza pointing at the helper, and starts ward.
# On success: exports ward13_pid, helper13_pid, ward13_log, override13_yaml.
# On failure: records the FAIL via the caller-supplied bullet num + desc and
# returns non-zero. Shared by bullets 13 and 14 (both need the same setup).
bullet_13_setup_model_ward() {
  local bullet_num="$1" bullet_desc="$2"
  local helper_bin="$tmpdir/wardtestmodel"
  override13_yaml="$tmpdir/ward-bullet13.yaml"
  ward13_log="$tmpdir/ward-bullet13.log"
  local helper_log="$tmpdir/wardtestmodel-bullet13.log"

  if ! go build -o "$helper_bin" ./cmd/wardtestmodel >"$tmpdir/build-wardtestmodel.log" 2>&1; then
    record FAIL "$bullet_num" "$bullet_desc" "go build wardtestmodel failed; see $tmpdir/build-wardtestmodel.log"
    return 1
  fi

  if [[ ! -x bin/ward ]]; then
    record FAIL "$bullet_num" "$bullet_desc" "bin/ward missing — bullet 3 should have produced it"
    return 1
  fi

  # Ensure the bullet 3 ward isn't still bound to 5354.
  if [[ -n "$ward_pid" ]] && kill -0 "$ward_pid" 2>/dev/null; then
    kill "$ward_pid" 2>/dev/null || true
    wait "$ward_pid" 2>/dev/null || true
    ward_pid=""
  fi

  # Per-run override: bullet-3 baseline + model: stanza pointing at the helper.
  # The bullet-3 fixture's blocklists/allowlists are inherited so the policy:
  # engine ready banner emits (matcher-guarded). Upstream is the same dead
  # 127.0.0.1:5853 as bullet 3 — forwards SERVFAIL on the wire, but the slow-
  # path classifyAsync fork fires in the dataplane regardless (it's parallel
  # to forwardUpstream, not gated on its success).
  cat > "$override13_yaml" <<EOF
listen: "127.0.0.1:5354"
log_level: "info"

upstreams:
  - address: "127.0.0.1:5853"
    server_name: "127.0.0.1"

timeouts:
  dial: "2s"
  query: "2s"
  shutdown: "2s"

blocklists:
  - id: "dod-blocked"
    path: "./testdata/dod/blocklists/blocked.txt"

allowlists:
  - id: "dod-allowed"
    path: "./testdata/dod/allowlists/allowed.txt"

model:
  command: ["$helper_bin", "-malicious-substring", "evil"]
EOF

  bin/ward serve --config "$override13_yaml" >"$ward13_log" 2>&1 &
  ward13_pid=$!
  local waited=0
  while (( waited < 50 )); do
    if grep -q "policy: engine ready" "$ward13_log" 2>/dev/null; then
      break
    fi
    if ! kill -0 "$ward13_pid" 2>/dev/null; then
      record FAIL "$bullet_num" "$bullet_desc" "ward exited early; see $ward13_log"
      return 1
    fi
    sleep 0.1
    waited=$((waited+1))
  done
  if (( waited >= 50 )); then
    kill "$ward13_pid" 2>/dev/null || true
    record FAIL "$bullet_num" "$bullet_desc" "ward ready banner not seen in 5s; see $ward13_log"
    return 1
  fi

  # Confirm the adapter loaded — `policy: model loaded` is emitted by
  # cmd/ward/serve.go on the happy adapter path. Without this assertion a
  # silent adapter init failure would still pass bullet 13 trivially (no
  # classified line because no slow path).
  if ! grep -q '"msg":"policy: model loaded"' "$ward13_log"; then
    kill "$ward13_pid" 2>/dev/null || true
    record FAIL "$bullet_num" "$bullet_desc" "no 'policy: model loaded' log; adapter never wired. ward log: $ward13_log"
    return 1
  fi

  # pgrep -P finds the direct child the dataplane spawned. We track it so
  # bullet 14 can SIGKILL it later. Use pgrep -f to disambiguate from any
  # other process named wardtestmodel (unlikely but safe).
  helper13_pid="$(pgrep -P "$ward13_pid" -f wardtestmodel | head -n 1)"
  if [[ -z "$helper13_pid" ]]; then
    kill "$ward13_pid" 2>/dev/null || true
    record FAIL "$bullet_num" "$bullet_desc" "wardtestmodel child pid not found via pgrep -P $ward13_pid"
    return 1
  fi
  return 0
}

# bullet_13_teardown cleans up the ward + helper started by setup. Always
# safe to call; idempotent. Does NOT record any result.
bullet_13_teardown() {
  if [[ -n "${ward13_pid:-}" ]]; then
    kill "$ward13_pid" 2>/dev/null || true
    wait "$ward13_pid" 2>/dev/null || true
    ward13_pid=""
  fi
  if [[ -n "${helper13_pid:-}" ]] && kill -0 "$helper13_pid" 2>/dev/null; then
    kill "$helper13_pid" 2>/dev/null || true
    wait "$helper13_pid" 2>/dev/null || true
  fi
  helper13_pid=""
}

bullet_13_slow_path() {
  local desc="SLOW-PATH: ward serve loads reference sibling adapter; probe qname triggers async classify"
  if ! bullet_13_setup_model_ward 13 "$desc"; then
    return
  fi

  # Probe with a hostname containing "evil" → wardtestmodel returns
  # VerdictMalicious → classifyAsync emits `policy: classified` at WARN.
  dig +time=2 +tries=1 +short @127.0.0.1 -p 5354 evilprobe.dod.test A >/dev/null 2>&1

  local waited=0
  while (( waited < 50 )); do
    # Three fields gate: msg + verdict=malicious + qname. A non-classify log
    # line cannot pass this — verdict and qname are slow-path-exclusive.
    # slog attribute order in the emitted JSON: msg → qname → verdict
    # → kind → matched (see internal/dataplane.classifyAsync). Greps
    # match that order; reordering log fields requires updating this.
    if grep -q '"msg":"policy: classified".*"qname":"evilprobe.dod.test".*"verdict":"malicious"' "$ward13_log"; then
      bullet_13_teardown
      record PASS 13 "$desc"
      return
    fi
    sleep 0.1
    waited=$((waited+1))
  done

  bullet_13_teardown
  record FAIL 13 "$desc" "no 'policy: classified' verdict=malicious log line in $ward13_log"
}

bullet_14_model_isolation() {
  local desc="MODEL ISOLATION: sibling-process model; ward survives SIGKILL of sibling (inv 3); model-unavailable log line required (inv 7)"
  if ! bullet_13_setup_model_ward 14 "$desc"; then
    return
  fi

  # First probe so we know the slow path is alive end-to-end before we kill
  # the child. Without this, a setup race where ward writes "policy: model
  # loaded" but the child has not yet read its first request could mask a
  # latent bug — the SIGKILL then trips the latch on a never-used adapter.
  # Use a qname containing "evil" so wardtestmodel returns Malicious — the
  # log line lands at WARN (default log level captures it). Benign verdicts
  # are emitted at DEBUG and would be invisible against the default INFO
  # filter, masking adapter liveness.
  dig +time=2 +tries=1 +short @127.0.0.1 -p 5354 evil-alive.dod.test A >/dev/null 2>&1
  local waited=0
  while (( waited < 50 )); do
    if grep -q '"msg":"policy: classified".*"qname":"evil-alive.dod.test"' "$ward13_log"; then
      break
    fi
    sleep 0.1
    waited=$((waited+1))
  done
  if (( waited >= 50 )); then
    bullet_13_teardown
    record FAIL 14 "$desc" "slow-path did not respond before SIGKILL; ward log: $ward13_log"
    return
  fi

  # SIGKILL the sibling. ward must NOT crash; subsequent forwards must
  # surface `policy: model unavailable` exactly once.
  kill -9 "$helper13_pid" 2>/dev/null || true
  wait "$helper13_pid" 2>/dev/null || true
  helper13_pid=""

  # Second probe — slow path will detect EOF on stdout, return ErrUnavailable,
  # latch classifierDead, emit `policy: model unavailable`.
  dig +time=2 +tries=1 +short @127.0.0.1 -p 5354 post-sigkill.dod.test A >/dev/null 2>&1

  waited=0
  while (( waited < 50 )); do
    if grep -q '"msg":"policy: model unavailable"' "$ward13_log"; then
      break
    fi
    sleep 0.1
    waited=$((waited+1))
  done
  if (( waited >= 50 )); then
    bullet_13_teardown
    record FAIL 14 "$desc" "no 'policy: model unavailable' log line after SIGKILL; ward log: $ward13_log"
    return
  fi

  # Ward must still answer DNS post-SIGKILL — confirm by sending a third
  # probe and observing ward's process is still alive.
  if ! kill -0 "$ward13_pid" 2>/dev/null; then
    bullet_13_teardown
    record FAIL 14 "$desc" "ward died after SIGKILL of sibling — invariant 3 violation; see $ward13_log"
    return
  fi
  dig +time=2 +tries=1 +short @127.0.0.1 -p 5354 post-sigkill-2.dod.test A >/dev/null 2>&1
  # The third probe is also an atomic-latch witness (Ralph N1): give the
  # async fork a moment to consult `classifierDead.Load()` and return early
  # WITHOUT emitting a second `policy: model unavailable` line. Without this
  # assertion a regression from `CompareAndSwap` to `Store` would pass
  # bullet 14 silently. Unit test
  # TestSlowPath_ErrUnavailable_LatchOnce_Concurrent covers the same
  # invariant in process; this is the E2E mirror.
  sleep 0.2
  local unavailable_count
  unavailable_count="$(grep -c '"msg":"policy: model unavailable"' "$ward13_log" 2>/dev/null || echo 0)"
  if [[ "$unavailable_count" -ne 1 ]]; then
    bullet_13_teardown
    record FAIL 14 "$desc" "atomic-latch violated: $unavailable_count 'policy: model unavailable' lines (want exactly 1); see $ward13_log"
    return
  fi

  bullet_13_teardown
  record PASS 14 "$desc"
}

bullet_15_eval() {
  local desc="EVAL: ward eval --suite scores classifier vs fixture; threshold-gated"
  local helper_bin="$tmpdir/wardtestmodel"
  local override_yaml="$tmpdir/ward-bullet15.yaml"
  local eval_log="$tmpdir/ward-bullet15.log"

  if [[ ! -x bin/ward ]]; then
    record FAIL 15 "$desc" "bin/ward missing — bullet 3 should have produced it"
    return
  fi
  if [[ ! -x "$helper_bin" ]]; then
    # bullet 13 builds wardtestmodel; this rebuilds it standalone so
    # bullet 15 still passes even if bullet 13 was skipped.
    if ! go build -o "$helper_bin" ./cmd/wardtestmodel >"$tmpdir/build-wardtestmodel-15.log" 2>&1; then
      record FAIL 15 "$desc" "go build wardtestmodel failed; see $tmpdir/build-wardtestmodel-15.log"
      return
    fi
  fi

  # Per-run override: minimal valid config with just the model: stanza.
  # ward eval --config loads + validates this; the only thing it needs is
  # cfg.Model. Listen / blocklists / upstreams are validated by
  # config.Load but never used by the eval path.
  cat > "$override_yaml" <<EOF
listen: "127.0.0.1:5354"
log_level: "info"

upstreams:
  - address: "127.0.0.1:5853"
    server_name: "127.0.0.1"

timeouts:
  dial: "2s"
  query: "2s"
  shutdown: "2s"

blocklists:
  - id: "dod-blocked"
    path: "./testdata/dod/blocklists/blocked.txt"

allowlists:
  - id: "dod-allowed"
    path: "./testdata/dod/allowlists/allowed.txt"

model:
  command: ["$helper_bin", "-malicious-substring", "evil", "-telemetry-substring", "telemetry"]
EOF

  # Run the harness. Self-consistent fixture + wardtestmodel mapping →
  # 100% accuracy. Threshold 0.85 trivially clears. Exit 0 + stdout
  # contains "PASS" is the structural assertion.
  if ! bin/ward eval --suite testdata/eval/v0.2.jsonl --threshold 0.85 \
      --config "$override_yaml" >"$eval_log" 2>&1; then
    record FAIL 15 "$desc" "ward eval exited non-zero; see $eval_log (tail: $(tail -1 "$eval_log"))"
    return
  fi
  if ! grep -q ' — PASS$' "$eval_log"; then
    record FAIL 15 "$desc" "ward eval output missing 'PASS' marker; see $eval_log"
    return
  fi
  # Belt-and-braces: assert 100% accuracy on the self-consistent fixture.
  # An accuracy regression on wardtestmodel + the v0.2 fixture means the
  # SP10b adapter wire-format broke or the fixture drifted from the
  # substring mapping — either way, that's a regression bullet 15 catches
  # even though the threshold gate at 0.85 would not.
  #
  # The ≥50-record floor is enforced separately by
  # TestEvalFixtureSelfConsistency under `make ci` (bullet 1).
  if ! grep -qE 'ward eval: [0-9]+/[0-9]+ correct \(1\.00 ≥ 0\.85\) — PASS' "$eval_log"; then
    record FAIL 15 "$desc" "ward eval did not score 100% on self-consistent fixture; see $eval_log"
    return
  fi
  record PASS 15 "$desc"
}

bullet_16_shipped() {
  if (( closeout == 0 )); then
    record SKIP 16 "SHIP: git log origin/main..HEAD empty"              "pass --closeout to run"
    return
  fi
  local ahead
  ahead="$(git log origin/main..HEAD --oneline 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "$ahead" == "0" ]]; then
    record PASS 16 "SHIP: git log origin/main..HEAD empty"
  else
    record FAIL 16 "SHIP: git log origin/main..HEAD empty"             "$ahead unpushed commit(s)"
  fi
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

printf "ward DOD v0.2 acceptance — %s\n\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

bullet_1_make_ci
bullet_2_make_audit
bullet_3_ward_boots
bullet_4_block_response
# Bullet 6 runs BEFORE bullet 5: 6 exercises the shared ward from bullet 3
# (policy:allowed log assertion fires before forwarding, so it does not need
# an upstream). Bullet 5 tears that ward down to rebind 127.0.0.1:5354 against
# a per-run override that points at the wardtestdot helper — see
# bullet_5_allow_upstream for the rationale. Reversing 5/6 would leave bullet 6
# with no ward to query.
bullet_6_allow_beats_blk
# Bullet 7 (decoy alert) uses the shared ward from bullet 3 — its assertion
# fires on the log channel, not on a real forward. Must run BEFORE bullet 5
# tears the shared ward down (same rationale as bullet 6).
bullet_7_decoy_alert
# Bullet 8 (dashboard /healthz) also uses the shared ward (the dashboard is
# started in-process by ward serve). Must run BEFORE bullet 5 AND bullet 11,
# both of which kill ward_pid.
bullet_8_dashboard
bullet_5_allow_upstream
bullet_9_export_noleak
bullet_10_update_verify
bullet_11_ward_doctor
# Bullets 12–15 are the v0.2 model-stack assertions (model abstraction,
# slow-path classify, model-runtime isolation, eval suite). All four ship as
# real PASS/FAIL assertions; they touch no shared state, so they can run
# in any order relative to bullets 1–11 and to each other.
bullet_12_model_abstraction
bullet_13_slow_path
bullet_14_model_isolation
bullet_15_eval
bullet_16_shipped

pass=0; fail=0; todo=0; skip=0
for r in "${results[@]}"; do
  case "${r%%|*}" in
    PASS) pass=$((pass+1)) ;;
    FAIL) fail=$((fail+1)) ;;
    TODO) todo=$((todo+1)) ;;
    SKIP) skip=$((skip+1)) ;;
  esac
done

total=${#results[@]}
printf "\nSummary: %d/%d passing  (FAIL=%d  TODO=%d  SKIP=%d)\n" \
  "$pass" "$total" "$fail" "$todo" "$skip"

if (( fail > 0 || todo > 0 )); then
  echo "v0.2 NOT shipped."
  exit 1
fi
echo "v0.2 acceptance: GREEN."
exit 0
