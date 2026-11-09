# cortex9-pingora-http10-te-smuggling-model

Offline model of **CVE-2026-2835** (GHSA-hj7x-879w-vrp7, RUSTSEC-2026-0034,
CWE-444): before 0.8.0, Pingora's HTTP/1 server read an HTTP/1.0 request
without `Content-Length` as close-delimited, accepted `Transfer-Encoding` on
HTTP/1.0, and decided "chunked" from the *first* `Transfer-Encoding` value
by exact match. A front-end and a back-end could then disagree about where
a request ends. The GHSA names three fix commits, all in 0.8.0 and not in
0.7.0: 7f7166d, 40c3c1e and 87e2e2f.
Educational, deterministic, C11 checked with ASan/UBSan. **Pingora is not
built or run, no socket is opened.** The model frames a request head given
as header values.

Spanish: [README.es.md](README.es.md). Exercises: [PRACTICE.md](PRACTICE.md).

## What is modelled (tied to the code)

`pingora-core/src/protocols/http/v1/`, `pre` = 9ac75d0 (parent of 7f7166d),
`post` = 87e2e2f (after the three commits):

| Step | pre (9ac75d0) | post (87e2e2f) |
|---|---|---|
| TE and CL both present | server.rs 253-263: CL removed | 258-271 same, **283-285 keepalive off** (7f7166d) |
| HTTP/1.0 + TE | accepted | **server.rs 338-343: rejected** (7f7166d) |
| Which TE counts | common.rs 144-149: first value, exact `chunked` | **common.rs 145-176: last header, last token, trimmed** (7f7166d) |
| Final coding not chunked | treated as not chunked | **server.rs 346-347: rejected** (87e2e2f) |
| Invalid CL | common.rs 182-209: `None` | **server.rs 351, common.rs 209-242: rejected** (fc904c0, see LIMITATIONS) |
| No TE, no CL | server.rs 832-841: HTTP/1.1 length 0, **HTTP/1.0 until close** | **server.rs 883-889: length 0** (40c3c1e) |
| Duplicate CL lines | common.rs 252-270: rejected unless TE | same (285-303) |
| Keepalive | server.rs 661-678 | 710-727 (same) |

Every result is compared with `rfc`, an independent reading of RFC 9112
§6.1 and §6.3 for requests (not code from Pingora): `AGREE`, `STRICTER`
(Pingora rejects, RFC accepts), `KEEPALIVE` (same framing, but the
connection stays reusable where the RFC says close) or `DESYNC` (accepted
with a different framing, or accepted where the RFC rejects).

## Differential evidence (`results/`)

`results/sweep.csv`: 2 versions × 12 TE configurations × 8 CL
configurations × 3 Connection values = 576 request heads.

| | AGREE | STRICTER | KEEPALIVE | DESYNC | until close |
|---|---|---|---|---|---|
| pre | 45 | 6 | 42 | 483 | 177 |
| post | 528 | 36 | 0 | 12 | 0 |

All 12 remaining `post` desyncs are `Content-Length: +5` or `-0`: Rust's
`str::parse::<i64>()` accepts a sign (checked with rustc 1.99.1 here),
RFC 9112 says `1*DIGIT`. That is a **model observation**, not a finding.
`tests/test_model.c` checks on 40,000 random heads that `post` never reads
until close, never keeps a TE+CL connection alive, rejects every HTTP/1.0
request with TE, and only differs from the RFC on a signed length.

## Build and check

```sh
sh scripts/build.sh test
python3 scripts/derive_expected.py | diff - fixtures/expected.tsv
sh scripts/build.sh results /tmp/r && diff -r results /tmp/r
./build/pgframe case 10 chunked - -
./build/pgframe case 11 'chunked|identity' - -
```

Sources: [SOURCES.md](SOURCES.md). Limits: [LIMITATIONS.md](LIMITATIONS.md).
License: Apache-2.0.
