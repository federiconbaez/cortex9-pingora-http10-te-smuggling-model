#include "pg_model.h"
#include <string.h>

static int lower(int c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }

static int eq_ic(const char *a, size_t n, const char *b) {
  size_t i;
  if (n != strlen(b)) return 0;
  for (i = 0; i < n; ++i)
    if (lower((unsigned char)a[i]) != lower((unsigned char)b[i])) return 0;
  return 1;
}

static int is_ws(int c) { return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r'; }

static int split_list(const char *s, char out[PG_MAXH][PG_MAXV], int *n) {
  *n = 0;
  if (strcmp(s, "-") == 0) return 0;
  for (;;) {
    const char *bar = strchr(s, '|');
    size_t len = bar ? (size_t)(bar - s) : strlen(s), i;
    if (*n >= PG_MAXH || len >= PG_MAXV) return -1;
    for (i = 0; i < len; ++i)
      if ((unsigned char)s[i] < 0x20 || (unsigned char)s[i] > 0x7e) return -1;
    /* the header parser trims surrounding whitespace: keep it out of the domain */
    if (len > 0 && (s[0] == ' ' || s[len - 1] == ' ')) return -1;
    memcpy(out[*n], s, len);
    out[*n][len] = '\0';
    (*n)++;
    if (!bar) return 0;
    s = bar + 1;
  }
}

int pg_parse(const char *ver, const char *te, const char *cl, const char *conn, pg_req *r) {
  memset(r, 0, sizeof *r);
  if (strcmp(ver, "10") == 0) r->http10 = 1;
  else if (strcmp(ver, "11") != 0) return -1;
  if (strcmp(conn, "-") == 0) r->conn = PG_CONN_NONE;
  else if (strcmp(conn, "close") == 0) r->conn = PG_CONN_CLOSE;
  else if (strcmp(conn, "keep-alive") == 0) r->conn = PG_CONN_KEEPALIVE;
  else return -1;
  if (split_list(te, r->te, &r->nte) != 0 || split_list(cl, r->cl, &r->ncl) != 0) return -1;
  return 0;
}

int pg_parse_i64(const char *s, long long *out) {
  int neg = 0;
  unsigned long long v = 0, lim;
  if (*s == '+' || *s == '-') neg = *s++ == '-';
  if (!*s) return -1;
  lim = neg ? 9223372036854775808ULL : 9223372036854775807ULL;
  for (; *s; ++s) {
    if (*s < '0' || *s > '9') return -1;
    if (v > (lim - (unsigned)(*s - '0')) / 10) return -1;
    v = v * 10 + (unsigned)(*s - '0');
  }
  if (neg) *out = v == 9223372036854775808ULL ? (-9223372036854775807LL - 1) : -(long long)v;
  else *out = (long long)v;
  return 0;
}

/* respect_keepalive(): pre 661-678, post 710-727 (same code). */
static int keepalive(const pg_req *r) {
  if (r->conn == PG_CONN_KEEPALIVE) return 1;
  if (r->conn == PG_CONN_CLOSE) return 0;
  return !r->http10;
}

/* post common.rs 145-176: last TE header, literal last token, trimmed. */
static int chunked_last(const pg_req *r) {
  const char *v, *comma, *tok, *end;
  if (r->nte == 0) return 0;
  v = r->te[r->nte - 1];
  if (eq_ic(v, strlen(v), "chunked")) return 1;
  comma = strrchr(v, ',');
  tok = comma ? comma + 1 : v;
  end = tok + strlen(tok);
  while (tok < end && is_ws((unsigned char)*tok)) ++tok;
  while (end > tok && is_ws((unsigned char)end[-1])) --end;
  return eq_ic(tok, (size_t)(end - tok), "chunked");
}

static pg_frame reject(void) {
  pg_frame f;
  memset(&f, 0, sizeof f);
  f.mode = PG_REJECT;
  return f;
}

static pg_frame frame_impl(int post, const pg_req *r) {
  pg_frame f;
  int has_te = r->nte > 0, has_cl = r->ncl > 0 && !(r->nte > 0); /* server.rs: CL removed if TE */
  long long n = 0;
  memset(&f, 0, sizeof f);
  f.keepalive = keepalive(r);
  if (post && r->nte > 0 && r->ncl > 0) f.keepalive = 0; /* post 283-285 */
  /* check_dup_content_length: TE present -> ok; else two CL lines -> error */
  if (!has_te && r->ncl >= 2) return reject();
  if (post && has_te) {
    if (r->http10) return reject();          /* post 338-343 */
    if (!chunked_last(r)) return reject();   /* post 346-347 */
  }
  if (post && has_cl && pg_parse_i64(r->cl[0], &n) != 0) return reject(); /* post 351 */
  if (post && has_cl && n < 0) return reject();
  if (post ? chunked_last(r) : (has_te && eq_ic(r->te[0], strlen(r->te[0]), "chunked"))) {
    f.mode = PG_CHUNKED;
    return f;
  }
  if (has_cl && pg_parse_i64(r->cl[0], &n) == 0 && n >= 0) {
    f.mode = PG_LEN;
    f.len = (unsigned long long)n;
    return f;
  }
  if (!post && r->http10) {
    f.mode = PG_UNTIL_CLOSE;                  /* pre 838-839 */
    return f;
  }
  f.mode = PG_LEN;                            /* pre 836, post 888 */
  f.len = 0;
  return f;
}

static int digits_only(const char *s, size_t n) {
  size_t i;
  if (n == 0) return 0;
  for (i = 0; i < n; ++i)
    if (s[i] < '0' || s[i] > '9') return 0;
  return 1;
}

/* RFC 9112 6.1 / 6.3, requests only. */
static pg_frame frame_rfc(const pg_req *r) {
  pg_frame f;
  int i;
  memset(&f, 0, sizeof f);
  f.keepalive = keepalive(r);
  if (r->nte > 0) {
    const char *last = NULL;
    size_t lastn = 0;
    if (r->http10) return reject(); /* 6.1-16: faulty framing */
    for (i = 0; i < r->nte; ++i) {
      const char *s = r->te[i];
      for (;;) {
        const char *c = strchr(s, ','), *e = c ? c : s + strlen(s), *b = s;
        while (b < e && (*b == ' ' || *b == '\t')) ++b;
        while (e > b && (e[-1] == ' ' || e[-1] == '\t')) --e;
        if (e > b) { last = b; lastn = (size_t)(e - b); }
        if (!c) break;
        s = c + 1;
      }
    }
    if (!last || !eq_ic(last, lastn, "chunked")) return reject(); /* 6.3-2.4.3 */
    if (r->ncl > 0) f.keepalive = 0;                                 /* 6.1-15 */
    f.mode = PG_CHUNKED;
    return f;
  }
  if (r->ncl > 0) {
    int seen = 0;
    unsigned long long v = 0;
    for (i = 0; i < r->ncl; ++i) {
      const char *s = r->cl[i];
      for (;;) {
        const char *c = strchr(s, ','), *e = c ? c : s + strlen(s), *b = s;
        unsigned long long x = 0;
        while (b < e && (*b == ' ' || *b == '\t')) ++b;
        while (e > b && (e[-1] == ' ' || e[-1] == '\t')) --e;
        if (!digits_only(b, (size_t)(e - b))) return reject();
        for (; b < e; ++b) {
          if (x > (9223372036854775807ULL - (unsigned)(*b - '0')) / 10) return reject();
          x = x * 10 + (unsigned)(*b - '0');
        }
        if (seen && x != v) return reject();
        v = x;
        seen = 1;
        if (!c) break;
        s = c + 1;
      }
    }
    f.mode = PG_LEN;
    f.len = v;
    return f;
  }
  f.mode = PG_LEN; /* 6.3-2.6: no body */
  f.len = 0;
  return f;
}

pg_frame pg_frame_request(pg_version v, const pg_req *r) {
  if (v == PG_RFC) return frame_rfc(r);
  return frame_impl(v == PG_POST, r);
}

pg_verdict pg_compare(pg_frame impl, pg_frame rfc) {
  if (impl.mode == PG_REJECT) return rfc.mode == PG_REJECT ? PG_AGREE : PG_STRICTER;
  if (rfc.mode == PG_REJECT) return PG_DESYNC;
  if (impl.mode != rfc.mode || (impl.mode == PG_LEN && impl.len != rfc.len)) return PG_DESYNC;
  if (impl.keepalive && !rfc.keepalive) return PG_KEEPALIVE;
  return PG_AGREE;
}

const char *pg_version_name(pg_version v) {
  return v == PG_PRE ? "pre" : v == PG_POST ? "post" : "rfc";
}
const char *pg_mode_name(pg_mode m) {
  static const char *n[] = {"REJECT", "CHUNKED", "LEN", "UNTIL_CLOSE"};
  return n[m];
}
const char *pg_verdict_name(pg_verdict v) {
  static const char *n[] = {"AGREE", "STRICTER", "KEEPALIVE", "DESYNC"};
  return n[v];
}
