/* Model of how Pingora's HTTP/1 server frames a request body
 * (CVE-2026-2835, GHSA-hj7x-879w-vrp7), pingora-core/src/protocols/http/v1:
 *   pre  9ac75d0 (parent of 7f7166d, = 0.7.0 behaviour)
 *        server.rs 253-263 (CL dropped when TE is present), 270 respect_keepalive,
 *        313-320 validate_request, 661-678 respect_keepalive, 802-811, 813-842
 *        init_body_reader (838-839: HTTP/1.0 without CL reads until close);
 *        common.rs 144-149 is_header_value_chunked_encoding (first TE value,
 *        exact "chunked"), 182-209 buf_to_content_length (Option), 252-270
 *   post 87e2e2f (after 7f7166d, 40c3c1e, 87e2e2f; = 0.8.0 behaviour)
 *        server.rs 258-286 (284: keepalive off when TE and CL), 328-354
 *        validate_request (338: HTTP/1.0 + TE rejected, 346-347: final TE not
 *        chunked rejected, 351: invalid CL rejected), 851-860, 862-895 (888:
 *        no CL means length 0); common.rs 145-176 (last TE header, last
 *        token, trimmed), 209-242 buf_to_content_length (Result)
 *   rfc  an independent reading of RFC 9112 6.1 and 6.3 for requests, used
 *        only as the yardstick. It is not code from either version. */
#ifndef PG_MODEL_H
#define PG_MODEL_H

#define PG_MAXH 8    /* header lines per field name */
#define PG_MAXV 128  /* bytes per header value */

typedef enum { PG_PRE, PG_POST, PG_RFC } pg_version;
typedef enum { PG_REJECT, PG_CHUNKED, PG_LEN, PG_UNTIL_CLOSE } pg_mode;
typedef enum { PG_AGREE, PG_STRICTER, PG_KEEPALIVE, PG_DESYNC } pg_verdict;
typedef enum { PG_CONN_NONE, PG_CONN_CLOSE, PG_CONN_KEEPALIVE } pg_conn;

typedef struct {
  int http10;                  /* 1: HTTP/1.0, 0: HTTP/1.1 */
  int nte, ncl;
  char te[PG_MAXH][PG_MAXV];   /* Transfer-Encoding values, in order */
  char cl[PG_MAXH][PG_MAXV];   /* Content-Length values, in order */
  pg_conn conn;
} pg_req;

typedef struct {
  pg_mode mode;
  unsigned long long len;      /* PG_LEN only */
  int keepalive;               /* meaningless for PG_REJECT */
} pg_frame;

/* Parse "10"/"11", "a|b" lists ("-" = no header) and "-"/"close"/"keep-alive".
 * Returns 0, or -1 outside the model's domain. */
int pg_parse(const char *ver, const char *te, const char *cl, const char *conn, pg_req *r);

pg_frame pg_frame_request(pg_version v, const pg_req *r);
pg_verdict pg_compare(pg_frame impl, pg_frame rfc);

/* Rust's str::parse::<i64>() (optional sign, then 1+ digits, no spaces). */
int pg_parse_i64(const char *s, long long *out);

const char *pg_version_name(pg_version v);
const char *pg_mode_name(pg_mode m);
const char *pg_verdict_name(pg_verdict v);
#endif
