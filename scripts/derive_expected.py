#!/usr/bin/env python3
"""Independent derivation of fixtures/expected.tsv.

Written from the Rust code in pingora-core/src/protocols/http/v1 at
9ac75d0 (pre) and 87e2e2f (post) and from RFC 9112 sections 6.1 and 6.3,
not from the C model. Rust's str::parse::<i64>() is restated with a regular
expression plus the i64 range (checked with rustc 1.99.1 on the build box:
"+5" -> 5, "-0" -> 0, "5 " -> error).
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cx9_util import read_cases, unescape  # noqa: E402

I64 = re.compile(r"[+-]?[0-9]+\Z")
I64_MIN, I64_MAX = -(2 ** 63), 2 ** 63 - 1


def rust_i64(s):
    if not I64.match(s):
        return None
    v = int(s, 10)
    return v if I64_MIN <= v <= I64_MAX else None


def parse(ver, te, cl, conn):
    if ver not in ("10", "11") or conn not in ("-", "close", "keep-alive"):
        return None
    lists = []
    for field in (te, cl):
        vals = [] if field == "-" else field.split("|")
        if len(vals) > 8:
            return None
        for v in vals:
            if len(v) >= 128 or any(not 0x20 <= ord(c) <= 0x7E for c in v):
                return None
            if v[:1] == " " or v[-1:] == " ":
                return None
        lists.append(vals)
    return {"http10": ver == "10", "te": lists[0], "cl": lists[1], "conn": conn}


def respect_keepalive(r):
    # server.rs pre 661-678 / post 710-727
    if r["conn"] == "keep-alive":
        return True
    if r["conn"] == "close":
        return False
    return not r["http10"]


def pingora(version, r):
    te, cl = r["te"], r["cl"]
    if te:          # server.rs pre 261-263 / post 269-271: remove CL
        cl = []
    ka = respect_keepalive(r)
    if version == "post" and r["te"] and r["cl"]:
        ka = False  # post 283-285
    if not te and len(cl) >= 2:   # common.rs check_dup_content_length
        return ("REJECT", None, None)
    if version == "pre":
        chunked = bool(te) and te[0].lower() == "chunked"   # common.rs 144-149: first value
        n = rust_i64(cl[0]) if cl else None
        n = n if n is not None and n >= 0 else None          # common.rs 182-209 -> None
    else:
        if te:
            last = te[-1]                                    # common.rs 156-176
            tok = last if last.lower() == "chunked" else last.rsplit(",", 1)[-1].strip(" \t\n\f\r")
            chunked = tok.lower() == "chunked"
        else:
            chunked = False
        if te and (r["http10"] or not chunked):              # server.rs 336-348
            return ("REJECT", None, None)
        if cl:
            n = rust_i64(cl[0])
            if n is None or n < 0:                           # server.rs 351, common.rs 209-242
                return ("REJECT", None, None)
        else:
            n = None
    if chunked:
        return ("CHUNKED", None, ka)
    if n is not None:
        return ("LEN", n, ka)
    if version == "pre" and r["http10"]:
        return ("UNTIL_CLOSE", None, ka)                     # server.rs pre 838-839
    return ("LEN", 0, ka)


def rfc(r):
    ka = respect_keepalive(r)
    if r["te"]:
        if r["http10"]:
            return ("REJECT", None, None)                    # 6.1-16
        toks = [t.strip(" \t") for v in r["te"] for t in v.split(",")]
        toks = [t for t in toks if t]
        if not toks or toks[-1].lower() != "chunked":
            return ("REJECT", None, None)                    # 6.3-2.4.3
        return ("CHUNKED", None, False if r["cl"] else ka)   # 6.1-15
    if r["cl"]:
        vals = [t.strip(" \t") for v in r["cl"] for t in v.split(",")]
        if not all(re.fullmatch(r"[0-9]+", t) for t in vals):
            return ("REJECT", None, None)
        nums = {int(t) for t in vals}
        if len(nums) != 1 or max(nums) > I64_MAX:
            return ("REJECT", None, None)
        return ("LEN", nums.pop(), ka)
    return ("LEN", 0, ka)


def compare(impl, ref):
    if impl[0] == "REJECT":
        return "AGREE" if ref[0] == "REJECT" else "STRICTER"
    if ref[0] == "REJECT" or impl[0] != ref[0] or impl[1] != ref[1]:
        return "DESYNC"
    if impl[2] and not ref[2]:
        return "KEEPALIVE"
    return "AGREE"


def fmt(f):
    mode, n, ka = f
    return f"{mode}\t{'-' if n is None else n}\t{'-' if ka is None else int(ka)}"


def main():
    root = Path(__file__).resolve().parent.parent
    print("id\tversion\tframing\tlength\tkeepalive\tverdict")
    for row in read_cases(root / "fixtures" / "cases.tsv"):
        r = parse(row[2], unescape(row[3]), unescape(row[4]), row[5])
        if r is None:
            for v in ("pre", "post", "rfc"):
                print(f"{row[0]}\t{v}\tBAD_INPUT\t-\t-\t-")
            continue
        ref = rfc(r)
        for v in ("pre", "post"):
            f = pingora(v, r)
            print(f"{row[0]}\t{v}\t{fmt(f)}\t{compare(f, ref)}")
        print(f"{row[0]}\trfc\t{fmt(ref)}\t-")


if __name__ == "__main__":
    main()
