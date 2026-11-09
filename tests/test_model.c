/* Tests for the Pingora request framing model. Run under ASan + UBSan
 * with -fno-sanitize-recover (scripts/build.sh test). */
#include "cx9_util.h"
#include "pg_model.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks, failures;
#define CHECK(c, what)                                                    \
  do {                                                                    \
    checks++;                                                             \
    if (!(c)) {                                                           \
      failures++;                                                         \
      printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, what);               \
    }                                                                     \
  } while (0)

#define MAXCASES 64
typedef struct {
  char id[64], kind[16], ver[8], conn[16], te[CX9_FIELD_MAX], cl[CX9_FIELD_MAX], hand[2][16];
} tcase;
static tcase cases[MAXCASES];
static int ncases;

static void load_cases(const char *dir) {
  static char line[3 * CX9_FIELD_MAX];
  char path[512];
  FILE *f;
  snprintf(path, sizeof path, "%s/cases.tsv", dir);
  f = fopen(path, "r");
  CHECK(f != NULL, "open cases.tsv");
  if (!f) return;
  while (fgets(line, sizeof line, f) && ncases < MAXCASES) {
    char *fl[CX9_MAX_FIELDS];
    tcase *c = &cases[ncases];
    if (line[0] == '#' || line[0] == '\n') continue;
    if (cx9_split_tsv(line, fl, CX9_MAX_FIELDS) != 8 || strlen(fl[0]) >= 64 ||
        strlen(fl[1]) >= 16 || strlen(fl[2]) >= 8 || strlen(fl[5]) >= 16 || strlen(fl[6]) >= 16 ||
        strlen(fl[7]) >= 16 || cx9_unescape(fl[3], c->te, sizeof c->te) < 0 ||
        cx9_unescape(fl[4], c->cl, sizeof c->cl) < 0) {
      CHECK(0, "cases.tsv row");
      continue;
    }
    strcpy(c->id, fl[0]);
    strcpy(c->kind, fl[1]);
    strcpy(c->ver, fl[2]);
    strcpy(c->conn, fl[5]);
    strcpy(c->hand[0], fl[6]);
    strcpy(c->hand[1], fl[7]);
    ncases++;
  }
  fclose(f);
  CHECK(ncases >= 30, "at least 30 fixture cases");
}

static pg_verdict verdict(pg_version v, const pg_req *r) {
  return pg_compare(pg_frame_request(v, r), pg_frame_request(PG_RFC, r));
}

/* Hand-derived labels in fixtures/cases.tsv. */
static void test_hand_labels(void) {
  int i, v, pos = 0, neg = 0, bad = 0;
  for (i = 0; i < ncases; ++i) {
    pg_req r;
    int ok = pg_parse(cases[i].ver, cases[i].te, cases[i].cl, cases[i].conn, &r) == 0;
    for (v = 0; v < 2; ++v)
      CHECK(strcmp(ok ? pg_verdict_name(verdict((pg_version)v, &r)) : "BAD_INPUT", cases[i].hand[v]) == 0,
            cases[i].id);
    if (!ok) {
      CHECK(strcmp(cases[i].kind, "bad") == 0, "only bad rows fall outside the domain");
      bad++;
      continue;
    }
    if (strcmp(cases[i].kind, "pos") == 0) {
      pg_verdict a = verdict(PG_PRE, &r), b = verdict(PG_POST, &r);
      CHECK((a == PG_DESYNC || a == PG_KEEPALIVE) && (b == PG_AGREE || b == PG_STRICTER),
            "pos: ambiguous before, consistent after");
      pos++;
    }
    if (strcmp(cases[i].kind, "neg") == 0) {
      CHECK(verdict(PG_PRE, &r) == PG_AGREE && verdict(PG_POST, &r) == PG_AGREE, "neg: agree in both");
      neg++;
    }
  }
  CHECK(pos >= 8 && neg >= 8 && bad >= 3, "enough positive, negative and bad fixtures");
}

/* fixtures/expected.tsv comes from scripts/derive_expected.py. */
static void test_expected(const char *dir) {
  static char line[3 * CX9_FIELD_MAX];
  char path[512];
  FILE *f;
  int rows = 0, i;
  snprintf(path, sizeof path, "%s/expected.tsv", dir);
  f = fopen(path, "r");
  CHECK(f != NULL, "open expected.tsv");
  if (!f) return;
  while (fgets(line, sizeof line, f)) {
    char *fl[CX9_MAX_FIELDS];
    int n;
    if (strncmp(line, "id\t", 3) == 0) continue;
    n = cx9_split_tsv(line, fl, CX9_MAX_FIELDS);
    CHECK(n == 6, "expected.tsv row");
    if (n != 6) continue;
    for (i = 0; i < ncases; ++i) {
      pg_version v = strcmp(fl[1], "pre") == 0 ? PG_PRE : strcmp(fl[1], "post") == 0 ? PG_POST : PG_RFC;
      pg_req r;
      pg_frame x;
      char buf[32];
      if (strcmp(cases[i].id, fl[0]) != 0) continue;
      rows++;
      if (pg_parse(cases[i].ver, cases[i].te, cases[i].cl, cases[i].conn, &r) != 0) {
        CHECK(strcmp(fl[2], "BAD_INPUT") == 0, fl[0]);
        continue;
      }
      x = pg_frame_request(v, &r);
      CHECK(strcmp(fl[2], pg_mode_name(x.mode)) == 0, fl[0]);
      if (x.mode == PG_LEN) snprintf(buf, sizeof buf, "%llu", x.len); else strcpy(buf, "-");
      CHECK(strcmp(fl[3], buf) == 0, fl[0]);
      if (x.mode == PG_REJECT) strcpy(buf, "-"); else snprintf(buf, sizeof buf, "%d", x.keepalive);
      CHECK(strcmp(fl[4], buf) == 0, fl[0]);
      CHECK(strcmp(fl[5], v == PG_RFC ? "-" : pg_verdict_name(verdict(v, &r))) == 0, fl[0]);
    }
  }
  fclose(f);
  CHECK(rows == 3 * ncases, "every case has pre, post and rfc rows");
}

static void test_i64(void) {
  static const struct { const char *s; int ok; long long v; } t[] = {
      {"+5", 1, 5}, {"-0", 1, 0}, {"05", 1, 5}, {"5 ", 0, 0}, {"", 0, 0}, {"+", 0, 0}, {"-1", 1, -1},
      {"9223372036854775807", 1, 9223372036854775807LL}, {"9223372036854775808", 0, 0},
      {"-9223372036854775808", 1, -9223372036854775807LL - 1}, {"-9223372036854775809", 0, 0},
      {"+-5", 0, 0}, {"0x5", 0, 0}, {" 5", 0, 0}};
  size_t i;
  for (i = 0; i < sizeof t / sizeof t[0]; ++i) {
    long long v = 0;
    int ok = pg_parse_i64(t[i].s, &v) == 0;
    CHECK(ok == t[i].ok && (!ok || v == t[i].v), t[i].s);
  }
}

static unsigned long long rng = 0x9e3779b97f4a7c15ULL;
static unsigned next(void) {
  rng ^= rng << 13;
  rng ^= rng >> 7;
  rng ^= rng << 17;
  return (unsigned)(rng >> 32);
}

/* Random request heads: properties of the fixed parser. */
static void test_invariants(void) {
  static const char *tetok[] = {"chunked", "Chunked", "identity", "gzip", "", "chunked,", ",chunked",
                                "gzip, chunked", "chunked, gzip", "x"};
  static const char *cltok[] = {"0", "5", "7", "+5", "-0", "-1", "abc", "5, 5", "", "00"};
  static const char *conns[] = {"-", "close", "keep-alive"};
  static char te[1024], cl[1024];
  int k, desync_pre = 0;
  for (k = 0; k < 40000; ++k) {
    int nte = (int)(next() % 4), ncl = (int)(next() % 3), j;
    pg_req r;
    pg_frame p, q, ref;
    te[0] = cl[0] = '\0';
    if (nte == 0) strcpy(te, "-");
    for (j = 0; j < nte; ++j) {
      if (j) strcat(te, "|");
      strcat(te, tetok[next() % (sizeof tetok / sizeof *tetok)]);
    }
    if (ncl == 0) strcpy(cl, "-");
    for (j = 0; j < ncl; ++j) {
      if (j) strcat(cl, "|");
      strcat(cl, cltok[next() % (sizeof cltok / sizeof *cltok)]);
    }
    CHECK(pg_parse(next() % 2 ? "11" : "10", te, cl, conns[next() % 3], &r) == 0, "in domain");
    p = pg_frame_request(PG_PRE, &r);
    q = pg_frame_request(PG_POST, &r);
    ref = pg_frame_request(PG_RFC, &r);
    if (pg_compare(p, ref) == PG_DESYNC) desync_pre++;
    CHECK(q.mode != PG_UNTIL_CLOSE, "post: requests are never close-delimited");
    CHECK(pg_compare(q, ref) != PG_KEEPALIVE, "post: TE+CL never stays reusable");
    if (r.http10 && r.nte > 0) CHECK(q.mode == PG_REJECT, "post: HTTP/1.0 + TE rejected");
    if (pg_compare(q, ref) == PG_DESYNC)
      CHECK(r.nte == 0 && r.ncl == 1 && (r.cl[0][0] == '+' || r.cl[0][0] == '-'),
            "post differs from RFC only on a signed Content-Length");
    if (r.nte == 0 && r.ncl <= 1 && !r.http10) {
      long long n;
      if (r.ncl == 0 || (pg_parse_i64(r.cl[0], &n) == 0 && n >= 0))
        CHECK(p.mode == q.mode && p.len == q.len, "plain HTTP/1.1 framing unchanged by the fix");
    }
    if (r.http10 && r.nte > 0) CHECK(ref.mode == PG_REJECT, "rfc: HTTP/1.0 + TE is faulty");
  }
  CHECK(desync_pre > 5000, "the generator reaches pre-fix desyncs");
}

/* Adversarial domain edges and buffer limits. */
static void test_adversarial(void) {
  static char big[PG_MAXV + 8], list[2048];
  pg_req r;
  int i;
  memset(big, 'a', PG_MAXV - 1);
  big[PG_MAXV - 1] = '\0';
  CHECK(pg_parse("11", big, "-", "-", &r) == 0, "127-byte value fits");
  CHECK(pg_frame_request(PG_POST, &r).mode == PG_REJECT, "long unknown coding rejected after fix");
  big[PG_MAXV - 1] = 'a';
  big[PG_MAXV] = '\0';
  CHECK(pg_parse("11", big, "-", "-", &r) != 0, "128-byte value is outside the domain");
  list[0] = '\0';
  for (i = 0; i < 8; ++i) strcat(list, i ? "|chunked" : "chunked");
  CHECK(pg_parse("11", list, "-", "-", &r) == 0 && r.nte == 8, "8 TE lines");
  strcat(list, "|chunked");
  CHECK(pg_parse("11", list, "-", "-", &r) != 0, "9 TE lines refused");
  CHECK(pg_parse("11", "chunked\x01", "-", "-", &r) != 0, "control byte refused");
  CHECK(pg_parse("11", "-", "5 ", "-", &r) != 0, "trailing space refused (parser trims)");
  CHECK(pg_parse("11", "-", "5", "Keep-Alive", &r) != 0, "connection spelled outside the domain");
  CHECK(pg_parse("1.1", "-", "5", "-", &r) != 0, "version spelling");
  CHECK(pg_parse("11", "-", "9223372036854775807", "-", &r) == 0 &&
            pg_frame_request(PG_POST, &r).len == 9223372036854775807ULL, "i64 max");
}

/* PRACTICE.md levels: each answer is checked here. */
static void test_practice(void) {
  pg_req r;
  pg_frame f;
  CHECK(pg_parse("11", "-", "5", "-", &r) == 0 && verdict(PG_PRE, &r) == PG_AGREE, "practice_level_1");
  CHECK(pg_parse("10", "-", "-", "-", &r) == 0 &&
            pg_frame_request(PG_PRE, &r).mode == PG_UNTIL_CLOSE &&
            pg_frame_request(PG_POST, &r).mode == PG_LEN, "practice_level_2");
  CHECK(pg_parse("10", "chunked", "-", "-", &r) == 0 && pg_frame_request(PG_PRE, &r).mode == PG_CHUNKED &&
            pg_frame_request(PG_POST, &r).mode == PG_REJECT, "practice_level_3");
  CHECK(pg_parse("11", "chunked|identity", "-", "-", &r) == 0 && verdict(PG_PRE, &r) == PG_DESYNC &&
            pg_frame_request(PG_POST, &r).mode == PG_REJECT, "practice_level_4");
  CHECK(pg_parse("11", "gzip, chunked", "-", "-", &r) == 0 && pg_frame_request(PG_PRE, &r).mode == PG_LEN &&
            pg_frame_request(PG_POST, &r).mode == PG_CHUNKED, "practice_level_5");
  CHECK(pg_parse("11", "chunked", "5", "-", &r) == 0, "parse 6");
  f = pg_frame_request(PG_PRE, &r);
  CHECK(f.keepalive == 1 && pg_frame_request(PG_POST, &r).keepalive == 0, "practice_level_6");
  CHECK(pg_parse("11", "-", "+5", "-", &r) == 0 && verdict(PG_POST, &r) == PG_DESYNC, "practice_level_7");
  CHECK(pg_parse("11", "chunked,", "-", "-", &r) == 0 && verdict(PG_POST, &r) == PG_STRICTER, "practice_level_8");
}

int main(int argc, char **argv) {
  const char *dir = argc > 1 ? argv[1] : "fixtures";
  load_cases(dir);
  test_hand_labels();
  test_expected(dir);
  test_i64();
  test_invariants();
  test_adversarial();
  test_practice();
  printf("%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
