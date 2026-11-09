# Sources

Local copies under `security-research-45/sources/cve2026/` (not in this
repo), fetched read-only (GitHub API GET, raw.githubusercontent.com); the
SHA-256 of each copy is listed in that directory's `SHA256SUMS` and was
re-checked on 2026-11-09.

| Source | URL | Used for | SHA-256 of copy |
|---|---|---|---|
| Commit 7f7166d62fa916b9f11b2eb8f9e3c4999e8b9023 diff ("transfer-encoding parsing robustness", 2026-01-27, 5 files +364/-30, parent 9ac75d0) | https://github.com/cloudflare/pingora/commit/7f7166d62fa916b9f11b2eb8f9e3c4999e8b9023 | common.rs is_chunked_encoding_from_headers, server.rs keepalive off with TE+CL, HTTP/1.0 + TE rejected | 58bbfb93e882a8595bc9897b820aab874f60f41dbdcb96d19257ef8df92b355e |
| Commit 40c3c1e9a43a86b38adeab8da7a2f6eba68b83ad diff ("Avoid close delimit mode on http/1.0 req", 2026-01-31, 7 files +355/-137) | https://github.com/cloudflare/pingora/commit/40c3c1e9a43a86b38adeab8da7a2f6eba68b83ad | server.rs: request without length is length 0 | 9329d04e3ebf2145e106511431b21cdab91e199ec138108c516dbb273615abce |
| Commit 87e2e2fb37edf9be33e3b1d04726293ae6bf2052 diff ("Reject non-chunked transfer-encoding", 2026-02-11, 2 files +18/-15), fetched for this repo | https://github.com/cloudflare/pingora/commit/87e2e2fb37edf9be33e3b1d04726293ae6bf2052 | server.rs 336-348 | 76d741e760ff8f9d34fe0f108170d15126de01e5d75980a9029480e93f947323 |
| `server.rs` at 9ac75d0356f449d26097e08bf49af14de6271727 (blob 7a15651a9) | https://github.com/cloudflare/pingora/blob/9ac75d0356f449d26097e08bf49af14de6271727/pingora-core/src/protocols/http/v1/server.rs | pre lines 253-271, 313-320, 343-347, 642-644, 661-678, 802-842 | c00c0d1a483fa0c04a1016a08d9c4888339937fc9b6409b5602020ec704884f9 |
| `common.rs` at 9ac75d0 (blob adee99f4c) | same commit, `common.rs` | pre 79-121, 144-149, 182-209, 212-223, 252-270 | 7cdb5f5670efb8dd4737731872ec2095f927da2ca0181bd5d48745c8342dc1d6 |
| `server.rs` at 87e2e2f (blob 44a6a6bd9) | https://github.com/cloudflare/pingora/blob/87e2e2fb37edf9be33e3b1d04726293ae6bf2052/pingora-core/src/protocols/http/v1/server.rs | post 258-286, 328-354, 710-727, 851-895, tests 1679-1726 | adfb33d56468e35fb33114a2fb0792e050d8b4da2c4a4569031f90e58b9bc5f1 |
| `common.rs` at 87e2e2f (blob 93f4524c2) | same commit, `common.rs` | post 145-176, 209-242, 245-256, 285-303 | 87fca4e2d6f3e77c4e9f52d1f2936d800920367877a02a96d2c9efddacfd57b8 |
| `body.rs` at both commits (blobs 1f3b4d607, 72899257c) | same commits, `body.rs` | `HTTP1_0` / `UntilClose` state reads until close | 27ba8dab5be6a8b55c5e066e60adf6d89bdc8d9ed886a8af4cee6c8acc312b31 / ef7166230f6008137dd7090029893774e6c0b70253b97a6070a35033200168fa |
| Tag containment (compare API) and tag snapshots | `tags_CVE-2026-2835.txt` | the three commits are in 0.8.0, not in 0.7.0; tag vs snapshot differences (Upgrade branches only) | 0613661632f84dcae338abef1edcec4fef0fb283b64c7ec4c2d23d0196a9c4b4 |
| GHSA-hj7x-879w-vrp7 (GitHub advisory JSON) | https://github.com/advisories/GHSA-hj7x-879w-vrp7 | the three commits, `<= 0.7.0` -> 0.8.0, workaround list | e85a3acf298841f59c3e86cfee72f6d85e66bb32269ac41b69806b109865731d |
| NVD CVE-2026-2835 (Analyzed, published 2026-03-05) | https://nvd.nist.gov/vuln/detail/CVE-2026-2835 | description, CWE-444 | 5bd112902ef9f402ad4cec3b767b6e3213bb150a8d8107695e35efb34c0d41ab |
| cve.org CVE-2026-2835 (PUBLISHED, CNA cloudflare, 2026-03-04) | https://www.cve.org/CVERecord?id=CVE-2026-2835 | record state | a2ae0627c7d9b58719642478052a9ef27960816af196e20d139e1f5e83da2cc0 |

RFC 9112 is cited by section (§6.1 paragraphs 15-16, §6.3 items 4.3 and 6)
from the comments in the upstream code; no copy of the RFC is stored.
`str::parse::<i64>()` and `trim_ascii()` were checked with rustc 1.99.1 on
the build box. `HeaderMap::get` returning the first value comes from the
`http` crate's documented behaviour, not from a local copy.

No source contained instructions addressed to a tool or agent. The GHSA
credits a researcher; the name was not copied.
