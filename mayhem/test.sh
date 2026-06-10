#!/usr/bin/env bash
#
# net-snmp/mayhem/test.sh — RUN the golden BER/PDU-parse oracle built by mayhem/build.sh
# (/mayhem/net-snmp-test-oracle) and surface its CTRF summary. exit 0 iff every assertion passed.
#
# Why an oracle and not net-snmp's own suite: net-snmp's functional tests start a live snmpd daemon
# and exercise it over a network transport — not self-contained at image-build time. The oracle
# instead drives snmp_pdu_parse() (the exact fuzzed entry point) over a known-good SNMPv1 GET and a
# pair of malformed PDUs, asserting decoded FIELD VALUES (command, request-id, varbind count) and
# rejection of bad input. Those byte/field-exact checks make it a real PATCH oracle: a no-op or
# stubbed parser cannot pass. This script only RUNS the pre-built binary; it never compiles.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

ORACLE=/mayhem/net-snmp-test-oracle

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}"
  local tests=$(( passed + failed + skipped ))
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":0,"skipped":%d,"other":0}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$skipped"
}

if [ ! -x "$ORACLE" ]; then
  echo "missing $ORACLE — run mayhem/build.sh first" >&2
  emit_ctrf "net-snmp-ber-oracle" 0 1 0
  exit 2
fi

echo "=== running net-snmp BER/PDU-parse oracle ==="
# The oracle prints its own per-assertion lines to stderr and a CTRF line to stdout.
out="$("$ORACLE" 2>&1)"; rc=$?
echo "$out"

# Prefer the oracle's own CTRF line; if (for any reason) it didn't emit one, synthesize from rc.
if printf '%s\n' "$out" | grep -q '^CTRF '; then
  exit "$rc"
fi
[ "$rc" -eq 0 ] && emit_ctrf "net-snmp-ber-oracle" 1 0 0 || emit_ctrf "net-snmp-ber-oracle" 0 1 0
exit "$rc"
