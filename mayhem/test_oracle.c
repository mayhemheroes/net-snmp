/*
 * net-snmp/mayhem/test_oracle.c — a small GOLDEN oracle over the fuzzed BER/PDU-parse path.
 *
 * net-snmp's full test suite needs a running snmpd agent (it spins up a daemon and talks to it over
 * a transport), which is not self-contained at image-build time. Instead this oracle drives the
 * exact library entry point the snmp_pdu_parse_fuzzer fuzzes — snmp_pdu_parse() — over hand-built
 * BER and asserts SEMANTIC correctness of the decode:
 *
 *   1. A known-good SNMPv1 GetRequest PDU decodes, returns success, and yields command==GET_REQ_MSG
 *      with the request-id we encoded (0x01020304).  (positive / golden)
 *   2. A PDU whose advertised length runs past the buffer is REJECTED (non-zero return).  (negative)
 *   3. A PDU with a corrupt request-type tag is REJECTED.                                  (negative)
 *
 * Because the asserts check decoded FIELD VALUES (not just "didn't crash"), a no-op / stubbed parser
 * cannot pass. Emits a CTRF summary line; exits non-zero on any failed assertion.
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int passed = 0, failed = 0;

static void check(const char *name, int ok)
{
    if (ok) {
        passed++;
        fprintf(stderr, "  ok   - %s\n", name);
    } else {
        failed++;
        fprintf(stderr, "  FAIL - %s\n", name);
    }
}

/*
 * A canonical SNMPv1 GetRequest PDU body (the bytes snmp_pdu_parse consumes — i.e. the part starting
 * at the request-type context tag 0xA0). request-id = 0x01020304, error-status = 0, error-index = 0,
 * one varbind for OID 1.3.6.1.2.1.1.1.0 (sysDescr.0) with a NULL value.
 */
static const uint8_t good_pdu[] = {
    0xA0, 0x1C,                                     /* GetRequest-PDU, len 28     */
      0x02, 0x04, 0x01, 0x02, 0x03, 0x04,           /*   request-id 0x01020304    */
      0x02, 0x01, 0x00,                             /*   error-status 0           */
      0x02, 0x01, 0x00,                             /*   error-index 0            */
      0x30, 0x0E,                                   /*   varbind-list SEQUENCE    */
        0x30, 0x0C,                                 /*     varbind SEQUENCE       */
          0x06, 0x08, 0x2B, 0x06, 0x01, 0x02,       /*       OID 1.3.6.1.2.1...   */
                      0x01, 0x01, 0x01, 0x00,       /*       ...1.1.0 (sysDescr.0)*/
          0x05, 0x00                                /*       value NULL           */
};

int main(void)
{
    netsnmp_pdu *pdu;
    int rc;

    /* 1) golden: a valid GET decodes with the expected command + request-id. */
    pdu = SNMP_MALLOC_TYPEDEF(netsnmp_pdu);
    {
        u_char buf[sizeof(good_pdu)];
        size_t len = sizeof(good_pdu);
        memcpy(buf, good_pdu, sizeof(good_pdu));
        rc = snmp_pdu_parse(pdu, buf, &len);
        check("valid SNMPv1 GET decodes (rc==0)", rc == 0);
        check("decoded command == GET_REQ_MSG", pdu->command == SNMP_MSG_GET);
        check("decoded request-id == 0x01020304", pdu->reqid == 0x01020304L);
        check("decoded one varbind", pdu->variables != NULL &&
                                     pdu->variables->next_variable == NULL);
    }
    snmp_free_pdu(pdu);

    /* 2) negative: advertised PDU length overruns the buffer -> reject. */
    pdu = SNMP_MALLOC_TYPEDEF(netsnmp_pdu);
    {
        u_char buf[] = { 0xA0, 0x7F, 0x02, 0x01, 0x00 };  /* claims 127 bytes, has 3 */
        size_t len = sizeof(buf);
        rc = snmp_pdu_parse(pdu, buf, &len);
        check("truncated/over-long PDU rejected (rc!=0)", rc != 0);
    }
    snmp_free_pdu(pdu);

    /* 3) negative: corrupt request-type tag (0xFF is not a PDU type) -> reject. */
    pdu = SNMP_MALLOC_TYPEDEF(netsnmp_pdu);
    {
        u_char buf[sizeof(good_pdu)];
        size_t len = sizeof(good_pdu);
        memcpy(buf, good_pdu, sizeof(good_pdu));
        buf[0] = 0xFF;
        rc = snmp_pdu_parse(pdu, buf, &len);
        check("corrupt request-type tag rejected (rc!=0)", rc != 0);
    }
    snmp_free_pdu(pdu);

    {
        int tests = passed + failed;
        printf("CTRF {\"results\":{\"tool\":{\"name\":\"net-snmp-ber-oracle\"},"
               "\"summary\":{\"tests\":%d,\"passed\":%d,\"failed\":%d,"
               "\"pending\":0,\"skipped\":0,\"other\":0}}}\n",
               tests, passed, failed);
    }
    return failed == 0 ? 0 : 1;
}
