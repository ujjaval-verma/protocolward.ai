#!/usr/bin/env bash
# Self-test for check-tool-deps.sh: three known regressions of the lint rule must turn the check red, the unmodified Makefile must stay green.
# The check always runs under "$BASH" (the interpreter running this file), never via its shebang,
# so a bash 3.2 run really exercises the check under bash 3.2.
set -euo pipefail
export LC_ALL=C
here="$(cd "$(dirname "$0")" && pwd)"
mk="$here/../Makefile"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
fail() { echo "check-tool-deps selftest: $*" >&2; exit 1; }
run() { "$BASH" "$here/check-tool-deps.sh" "$1"; }
tab=$'\t'

# Anchor guard: exactly one lint: rule line, and it must not continue onto the next line.
cp "$mk" "$T/base"
n="$(awk '/^lint:/{c++} END{print c+0}' "$T/base")"
if [ "$n" -ne 1 ]; then
  fail "anchor not found: want exactly one 'lint:' rule line in Makefile, got $n; update the mutations in this selftest"
fi
if grep '^lint:' "$T/base" | grep -q '\\$'; then
  fail "anchor not found: the 'lint:' rule line ends in a backslash; update the mutations in this selftest"
fi

# Baseline: without a green unmodified copy, a red mutation proves nothing.
rc=0
out="$(run "$T/base" 2>&1)" || rc=$?
if [ "$rc" -ne 0 ] || ! grep -qx 'check-tool-deps: OK' <<<"$out"; then
  fail "the unmodified Makefile copy fails the check (fix the Makefile, not this selftest); check output follows:"$'\n'"$out"
fi

# Mutations, all applied to the lint rule.
# M1 lint-tools: lint depends on the catch-all tools target again.
awk '/^lint:/{s=$0; i=index(s," ##"); r=i?substr(s,i):""; print "lint: tools" r; next} {print}' "$T/base" > "$T/lint-tools"
# M2 bare-install: a recipe line that starts a bare go install at column 0 once make -n drops the @.
l2="${tab}"'$(Q)$(GO) install golang.org/x/tools/cmd/stringer@v0.1.0'
awk -v l="$l2" '{print} /^lint:/{print l}' "$T/base" > "$T/bare-install"
# M3 second-pin: golangci-lint installed a second time at another pin.
l3="${tab}"'$(Q)GOBIN=$(CURDIR)/$(TOOLS_DIR) $(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@v0.0.1'
awk -v l="$l3" '{print} /^lint:/{print l}' "$T/base" > "$T/second-pin"

for m in lint-tools bare-install second-pin; do
  if cmp -s "$T/base" "$T/$m"; then fail "mutation $m did not apply"; fi
done
if ! grep -qE '^lint: tools( |$)' "$T/lint-tools"; then fail "mutation lint-tools did not apply"; fi
if ! grep -qxF "$l2" "$T/bare-install"; then fail "mutation bare-install did not apply"; fi
if ! grep -qxF "$l3" "$T/second-pin"; then fail "mutation second-pin did not apply"; fi

# expect_red NAME: the check must exit 1, not print OK, and print its remediation hint.
# Leaves the captured output in $out for the per-mutation row assertions.
expect_red() {
  m="$1"
  rc=0
  out="$(run "$T/$m" 2>&1)" || rc=$?
  if [ "$rc" -ne 1 ]; then fail "$m: expected exit 1, got $rc: $out"; fi
  if grep -qx 'check-tool-deps: OK' <<<"$out"; then fail "$m: printed OK: $out"; fi
  if ! grep -q '^check-tool-deps: hint: ' <<<"$out"; then fail "$m: no hint line: $out"; fi
}

# Order matters: M3 before M2, so a check that lost pin parity fails at M3 and one blind to column-0 installs fails at M2.
expect_red lint-tools
if ! grep -qE '^check-tool-deps: make lint would install: .*goreleaser.*; want: golangci-lint$' <<<"$out"; then
  fail "lint-tools: no tool-set row for lint: $out"
fi

expect_red second-pin
if ! grep -qE '^check-tool-deps: make lint runs an install line that differs from make tools: GOBIN=.+/\.tools go install github\.com/golangci/golangci-lint/cmd/golangci-lint@v0\.0\.1$' <<<"$out"; then
  fail "second-pin: no pin-parity row for lint: $out"
fi
if grep -q '^check-tool-deps: make lint would install: ' <<<"$out"; then
  fail "second-pin: caught by the tool-set row, not pin parity: $out"
fi

expect_red bare-install
if ! grep -qxF 'check-tool-deps: make lint would install: golangci-lint stringer; want: golangci-lint' <<<"$out"; then
  fail "bare-install: no tool-set row for lint: $out"
fi
if ! grep -qxF 'check-tool-deps: make lint runs an install line that differs from make tools: go install golang.org/x/tools/cmd/stringer@v0.1.0' <<<"$out"; then
  fail "bare-install: no pin-parity row for lint: $out"
fi

echo "check-tool-deps selftest: OK (bash ${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]})"
