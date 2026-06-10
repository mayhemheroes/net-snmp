#!/usr/bin/env bash
#
# net-snmp/mayhem/build.sh — build a representative subset of net-snmp's OSS-Fuzz harnesses as
# sanitized libFuzzer targets (+ standalone reproducers), AND a small golden BER/PDU-parse oracle
# for mayhem/test.sh.
#
# Fuzzed surface = net-snmp's ASN.1/BER SNMP packet & MIB parsers (the agent/library code, not the
# harness). We build the project EXACTLY like OSS-Fuzz does (./configure + make → the same static
# .libs the upstream testing/fuzzing/build-fuzz-tests.sh links), with $SANITIZER_FLAGS applied via
# --with-cflags so the parsers themselves are instrumented, then link each chosen harness.
#
# Chosen harnesses (the BER/PDU + MIB + OID surface — net-snmp ships 18; we take this 6 as a
# representative subset of the attacker-controlled parse paths):
#   snmp_pdu_parse        — snmp_pdu_parse(): raw SNMPv1/v2 PDU body BER decode → netsnmp_pdu.
#   snmp_parse            — snmp_parse() + snmpv3_parse(): full message (version+community+PDU).
#   snmp_scoped_pdu_parse — snmpv3_scopedPDU_parse(): the SNMPv3 scoped-PDU BER decode.
#   agentx_parse          — agentx_parse() + agentx_realloc_build(): the AgentX (RFC 2741) PDU codec.
#   snmp_mib              — read_mib(): the SMI/ASN.1 MIB-text parser.
#   snmp_parse_oid        — read_objid(): the textual OBJECT IDENTIFIER parser.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"

HARNESSES="snmp_pdu_parse snmp_parse snmp_scoped_pdu_parse agentx_parse snmp_mib snmp_parse_oid"

# Build flags handed to ./configure and the harness compile: sanitizers + coverage instrumentation
# (-fsanitize=fuzzer-no-link lets libFuzzer's coverage hooks land in the project code, not just the
# harness). -Wno-error=declaration-after-statement matches OSS-Fuzz's net-snmp build.sh.
FUZZ_CFLAGS="-fsanitize=fuzzer-no-link $SANITIZER_FLAGS $DEBUG_FLAGS -Wno-error=declaration-after-statement"
export CFLAGS="$FUZZ_CFLAGS"
export CXXFLAGS="$FUZZ_CFLAGS"

# ── 1) Configure + build net-snmp exactly like OSS-Fuzz (developer mode, defaults, system openssl,
#       no perl/python/embedded-perl). This produces the same static libs build-fuzz-tests.sh links. ──
echo "=== configure ==="
./configure \
  --enable-developer \
  --with-defaults \
  --with-openssl=/usr \
  --disable-embedded-perl \
  --without-perl-modules \
  --without-python-modules \
  --with-cflags="$FUZZ_CFLAGS"

echo "=== make (static libs) ==="
make -s -j"$MAYHEM_JOBS"

# The extra link libs net-snmp-config records (e.g. -lssl -lcrypto), same extraction as upstream.
LIBS=$(sed -n 's/^NSC_LNETSNMPLIBS="\(.*\)"$/\1/p' ./net-snmp-config;
       sed -n "s/^PERLLDOPTS_FOR_LIBS='\(.*\)'/\1/p" ./config.log)
LIBS_A="apps/.libs/libnetsnmptrapd.a agent/.libs/libnetsnmpmibs.a agent/.libs/libnetsnmpagent.a agent/helpers/.libs/libnetsnmphelpers.a snmplib/.libs/libnetsnmp.a"
BASE_CFLAGS="$(./net-snmp-config --base-cflags)"
LDFLAGS_NS="$(./net-snmp-config --ldflags)"

# Standalone driver from the base image (a run-once main calling LLVMFuzzerTestOneInput). Compile
# once as C so the LLVMFuzzerTestOneInput reference keeps C linkage.
SA_OBJ="$SRC/mayhem-build/standalone_main.o"
mkdir -p "$SRC/mayhem-build"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "${STANDALONE_FUZZ_MAIN:-/opt/mayhem/StandaloneFuzzTargetMain.c}" -o "$SA_OBJ"

# ── 2) Build each harness twice: libFuzzer (-> /mayhem/<name>_fuzzer) + standalone reproducer. ──
for h in $HARNESSES; do
  obj="$SRC/mayhem-build/${h}_fuzzer.o"
  $CC $BASE_CFLAGS $FUZZ_CFLAGS -c -Iinclude -Iagent/mibgroup/agentx \
      -Wno-unused-command-line-argument \
      "testing/fuzzing/${h}_fuzzer.c" -o "$obj"

  # libFuzzer target
  $CXX $CXXFLAGS "$obj" -Wno-unused-command-line-argument \
      $LDFLAGS_NS $LIB_FUZZING_ENGINE $LIBS_A $LIBS \
      -o "/mayhem/${h}_fuzzer"

  # standalone reproducer (no libFuzzer runtime)
  $CXX $CXXFLAGS "$SA_OBJ" "$obj" -Wno-unused-command-line-argument \
      $LDFLAGS_NS $LIBS_A $LIBS \
      -o "/mayhem/${h}_fuzzer-standalone"

  echo "built ${h}_fuzzer (+ standalone)"
done

# ── 3) Build the golden BER/PDU-parse oracle for mayhem/test.sh (NORMAL flags, no fuzzer runtime).
#       It links the same instrumented net-snmp libs and asserts the parser decodes a known-good
#       SNMPv1 GET and rejects truncated/garbage input. See mayhem/test_oracle.c. ──
echo "=== building test oracle ==="
$CC $BASE_CFLAGS $SANITIZER_FLAGS $DEBUG_FLAGS -Iinclude \
    "$SRC/mayhem/test_oracle.c" \
    $LDFLAGS_NS $LIBS_A $LIBS \
    -o /mayhem/net-snmp-test-oracle

echo "build.sh complete:"
ls -la /mayhem/*_fuzzer /mayhem/*_fuzzer-standalone /mayhem/net-snmp-test-oracle 2>&1 || true
