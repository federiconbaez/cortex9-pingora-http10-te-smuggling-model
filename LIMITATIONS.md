# Limitations

- **A model, not a finding.** Nothing was reproduced against Pingora or a
  backend. It restates the advisory and two snapshots of three files.
- **Only the downstream request head.** Framing is decided from the header
  values given; body bytes, chunk parsing, trailers, the upstream
  (client.rs) side, `subrequest/` and how Pingora re-frames the request it
  forwards are **not modelled**. "DESYNC" means "differs from the RFC
  yardstick", not "a backend was desynchronized".
- **The yardstick is ours.** `rfc` is an independent, simplified reading of
  RFC 9112 §6.1/§6.3. It ignores "chunked applied twice", accepts a list of
  identical `Content-Length` values and caps lengths at `i64::MAX`. Another
  reading could label some edges differently.
- **Post snapshot includes more than the three named commits.** 87e2e2f
  also contains fc904c0 ("Reject invalid content-length v1 requests",
  2026-02-01), which the GHSA does not name; rejecting invalid lengths comes
  from it. Fixture rows `e09`-`e12` (overflowing, invalid or negative
  `Content-Length`) and the `abc` column of the sweep depend on it.
- **Tags vs snapshots.** 0.7.0 and 0.8.0 differ from 9ac75d0 and 87e2e2f in
  `init_body_reader` only by Upgrade branches (checked by diff, see
  `tags_CVE-2026-2835.txt`); Upgrade requests are outside the model.
- **Header parsing.** Values are taken as the header parser would deliver
  them: printable ASCII, no surrounding spaces, at most 8 lines per name.
  `HeaderMap::get` returning the first line is the `http` crate's
  documented behaviour, **not verified** from a local copy.
- **Signed Content-Length** (`+5`, `-0`) accepted after the fix is an
  observation about `str::parse::<i64>()` (checked with rustc 1.99.1),
  **not verified** against a running Pingora or reported upstream.
- **Connection** is `-`, `close` or `keep-alive` only; `upgrade` and token
  lists are out of the domain.
- Sweeps and random tests are grids, not proofs.
