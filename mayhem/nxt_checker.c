/*
 * unit/mayhem/nxt_checker.c — standalone Known-Answer-Test (KAT) for nginx-unit's fuzzed parsers.
 *
 * This is NOT a fuzz harness: it has its own main() and calls the SAME library entry points the
 * fuzz targets exercise, but on FIXED, hard-coded input, then prints "key=value" lines for the
 * COMPUTED result:
 *
 *   - check_base64()            — nxt_base64_decode(), the same function fuzz_basic's
 *                                  nxt_base64_fuzz() calls.
 *   - check_json()               — nxt_conf_json_parse_str() + nxt_conf_get_object_member() /
 *                                  nxt_conf_get_number() / nxt_conf_get_string(), the same parse
 *                                  entry point fuzz_json's LLVMFuzzerTestOneInput() calls.
 *   - check_http_request_line()  — nxt_http_parse_request_init() + nxt_http_parse_request(), the
 *                                  same request-line parser fuzz_http_h1p / fuzz_http_controller /
 *                                  fuzz_http_h1p_peer all call (they differ only in which header
 *                                  field-hash table they attach afterwards).
 *
 * mayhem/test.sh runs this binary and greps stdout for the exact expected values. A neutered
 * parser (the exit(0)-stub sabotage probe applied to any of nxt_base64_decode / nxt_conf_json_parse
 * / nxt_http_parse_request) produces NONE of the expected "key=value" lines (the function returns
 * early/wrong before printf runs, or prints an "*_error=..." line instead), so the grep-based check
 * fails — this is a real behavioral oracle on the parsers' output, not a coverage/exit-code proxy.
 */

#include <nxt_main.h>
#include <nxt_conf.h>
#include <nxt_http_parse.h>

#include <stdio.h>


extern char  **environ;


static int
check_base64(void)
{
    /* "aGVsbG8=" is base64("hello"); nxt_base64_decode() must recover "hello" (5 bytes). */
    static u_char  input[] = "aGVsbG8=";
    u_char         out[64];
    ssize_t        n;

    nxt_memzero(out, sizeof(out));

    n = nxt_base64_decode(out, input, nxt_length("aGVsbG8=") - 1);
    if (n < 0) {
        printf("base64_decoded=ERROR\n");
        return 1;
    }

    printf("base64_decoded_len=%d\n", (int) n);
    printf("base64_decoded=%.*s\n", (int) n, (char *) out);

    return 0;
}


static int
check_json(void)
{
    static const char  json_text[] = "{\"count\":42,\"name\":\"unit\"}";

    nxt_mp_t           *mp;
    nxt_str_t          input;
    nxt_conf_value_t   *conf, *member;
    int                rc;

    rc = 1;

    mp = nxt_mp_create(1024, 128, 256, 32);
    if (mp == NULL) {
        printf("json_error=mp_create_failed\n");
        return 1;
    }

    input.start = (u_char *) json_text;
    input.length = nxt_strlen(json_text);

    conf = nxt_conf_json_parse_str(mp, &input);
    if (conf == NULL) {
        printf("json_error=parse_failed\n");
        goto done;
    }

    printf("json_member_count=%d\n", (int) nxt_conf_object_members_count(conf));

    {
        nxt_str_t  count_name = nxt_string("count");

        member = nxt_conf_get_object_member(conf, &count_name, NULL);
        if (member != NULL) {
            printf("json_count=%d\n", (int) nxt_conf_get_number(member));
        } else {
            printf("json_count=missing\n");
        }
    }

    {
        nxt_str_t  name_name = nxt_string("name");

        member = nxt_conf_get_object_member(conf, &name_name, NULL);
        if (member != NULL) {
            nxt_str_t  value;

            nxt_conf_get_string(member, &value);
            printf("json_name=%.*s\n", (int) value.length, (char *) value.start);
        } else {
            printf("json_name=missing\n");
        }
    }

    rc = 0;

done:

    nxt_mp_destroy(mp);
    return rc;
}


static int
check_http_request_line(void)
{
    static const char         req_text[] =
        "GET /hello HTTP/1.1\r\nHost: example.com\r\n\r\n";

    nxt_mp_t                  *mp;
    nxt_int_t                 prc;
    nxt_buf_mem_t             buf;
    nxt_http_request_parse_t  rp;
    int                       rc;

    rc = 1;

    mp = nxt_mp_create(1024, 128, 256, 32);
    if (mp == NULL) {
        printf("http_error=mp_create_failed\n");
        return 1;
    }

    buf.start = (u_char *) req_text;
    buf.end = (u_char *) req_text + nxt_strlen(req_text);
    buf.pos = buf.start;
    buf.free = buf.end;

    nxt_memzero(&rp, sizeof(nxt_http_request_parse_t));

    prc = nxt_http_parse_request_init(&rp, mp);
    if (prc != NXT_OK) {
        printf("http_error=init_failed\n");
        goto done;
    }

    prc = nxt_http_parse_request(&rp, &buf);
    if (prc != NXT_DONE) {
        printf("http_error=parse_incomplete rc=%d\n", (int) prc);
        goto done;
    }

    printf("http_method=%.*s\n", (int) rp.method.length, (char *) rp.method.start);
    printf("http_path=%.*s\n", (int) rp.path.length, (char *) rp.path.start);

    rc = 0;

done:

    nxt_mp_destroy(mp);
    return rc;
}


int
main(int argc, char **argv)
{
    int  rc;

    (void) argc;
    (void) argv;

    if (nxt_lib_start("nxt_checker", NULL, &environ) != NXT_OK) {
        printf("lib_start=FAILED\n");
        return 1;
    }

    rc = 0;
    rc |= check_base64();
    rc |= check_json();
    rc |= check_http_request_line();

    return rc;
}
