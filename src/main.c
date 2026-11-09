/* CLI: regenerate results/ or inspect one request head.
 *   pgframe results fixtures/cases.tsv <dir>
 *   pgframe case 10|11 <te> <cl> <conn>     (lists use |, "-" = none)
 * Only header values are modelled; no socket is opened. */
#include "cx9_util.h"
#include "pg_model.h"
#include <stdio.h>
#include <string.h>

static void frame_cols(FILE *f, pg_frame x) {
  fprintf(f, "%s,", pg_mode_name(x.mode));
  if (x.mode == PG_LEN) fprintf(f, "%llu", x.len);
  fputc(',', f);
  if (x.mode != PG_REJECT) fprintf(f, "%d", x.keepalive);
}

static const char *SW_TE[] = {"-", "chunked", "CHUNKED", "identity", "gzip", "gzip, chunked",
                              "chunked, gzip", "chunked,", "chunked|identity", "identity|chunked",
                              "chunked|chunked", ""};
static const char *SW_CL[] = {"-", "5", "+5", "-0", "abc", "5|5", "5|6", "5, 5"};
static const char *SW_CONN[] = {"-", "close", "keep-alive"};

static void quoted(FILE *f, const char *s) {
  static char esc[4 * PG_MAXV * PG_MAXH];
  cx9_escape(s, strlen(s), esc, sizeof esc);
  cx9_csv_field(f, esc);
}

static int results(const char *cases, const char *dir) {
  static char line[3 * CX9_FIELD_MAX], te[CX9_FIELD_MAX], cl[CX9_FIELD_MAX];
  char path[1024];
  FILE *in = fopen(cases, "r"), *out, *sw;
  size_t a, b, c;
  int vv;
  if (!in) return 1;
  snprintf(path, sizeof path, "%s/cases.csv", dir);
  out = fopen(path, "w");
  if (!out) { fclose(in); return 1; }
  fputs("id,kind,version,framing,length,keepalive,verdict\n", out);
  while (fgets(line, sizeof line, in)) {
    char *f[CX9_MAX_FIELDS];
    pg_req r;
    if (line[0] == '#' || line[0] == '\n') continue;
    if (cx9_split_tsv(line, f, CX9_MAX_FIELDS) != 8 || cx9_unescape(f[3], te, sizeof te) < 0 ||
        cx9_unescape(f[4], cl, sizeof cl) < 0) {
      fclose(in); fclose(out);
      return 1;
    }
    if (pg_parse(f[2], te, cl, f[5], &r) != 0) {
      for (vv = 0; vv < 3; ++vv)
        fprintf(out, "%s,%s,%s,BAD_INPUT,,,\n", f[0], f[1], pg_version_name((pg_version)vv));
      continue;
    }
    {
      pg_frame ref = pg_frame_request(PG_RFC, &r);
      for (vv = 0; vv < 3; ++vv) {
        pg_frame x = pg_frame_request((pg_version)vv, &r);
        fprintf(out, "%s,%s,%s,", f[0], f[1], pg_version_name((pg_version)vv));
        frame_cols(out, x);
        fprintf(out, ",%s\n", vv == PG_RFC ? "" : pg_verdict_name(pg_compare(x, ref)));
      }
    }
  }
  fclose(in);
  fclose(out);
  snprintf(path, sizeof path, "%s/sweep.csv", dir);
  sw = fopen(path, "w");
  if (!sw) return 1;
  fputs("version,te,cl,connection,pre_framing,pre_length,pre_keepalive,pre_verdict,"
        "post_framing,post_length,post_keepalive,post_verdict,rfc_framing\n", sw);
  for (vv = 0; vv < 2; ++vv)
    for (a = 0; a < sizeof SW_TE / sizeof *SW_TE; ++a)
      for (b = 0; b < sizeof SW_CL / sizeof *SW_CL; ++b)
        for (c = 0; c < sizeof SW_CONN / sizeof *SW_CONN; ++c) {
          pg_req r;
          pg_frame p, q, ref;
          if (pg_parse(vv ? "11" : "10", SW_TE[a], SW_CL[b], SW_CONN[c], &r) != 0) { fclose(sw); return 1; }
          p = pg_frame_request(PG_PRE, &r);
          q = pg_frame_request(PG_POST, &r);
          ref = pg_frame_request(PG_RFC, &r);
          fprintf(sw, "%s,", vv ? "1.1" : "1.0");
          quoted(sw, SW_TE[a]);
          fputc(',', sw);
          quoted(sw, SW_CL[b]);
          fprintf(sw, ",%s,", SW_CONN[c]);
          frame_cols(sw, p);
          fprintf(sw, ",%s,", pg_verdict_name(pg_compare(p, ref)));
          frame_cols(sw, q);
          fprintf(sw, ",%s,%s\n", pg_verdict_name(pg_compare(q, ref)), pg_mode_name(ref.mode));
        }
  fclose(sw);
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 4 && strcmp(argv[1], "results") == 0) return results(argv[2], argv[3]);
  if (argc == 6 && strcmp(argv[1], "case") == 0) {
    static char te[CX9_FIELD_MAX], cl[CX9_FIELD_MAX];
    pg_req r;
    pg_frame ref;
    int v;
    if (cx9_unescape(argv[3], te, sizeof te) < 0 || cx9_unescape(argv[4], cl, sizeof cl) < 0 ||
        pg_parse(argv[2], te, cl, argv[5], &r) != 0) {
      puts("BAD_INPUT");
      return 0;
    }
    ref = pg_frame_request(PG_RFC, &r);
    for (v = 0; v < 3; ++v) {
      pg_frame x = pg_frame_request((pg_version)v, &r);
      printf("%-4s %-11s", pg_version_name((pg_version)v), pg_mode_name(x.mode));
      if (x.mode == PG_LEN) printf(" len=%llu", x.len);
      if (x.mode != PG_REJECT) printf(" keepalive=%d", x.keepalive);
      if (v != PG_RFC) printf("  -> %s", pg_verdict_name(pg_compare(x, ref)));
      putchar('\n');
    }
    return 0;
  }
  fprintf(stderr, "usage: %s results <cases.tsv> <dir> | case 10|11 <te> <cl> <conn>\n", argv[0]);
  return 2;
}
