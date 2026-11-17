#!/usr/bin/env python3
"""Write a share-safe copy of a HAR file.

Keeps the request timeline (method, host, path, status, content type, size, timings and a few harmless
response headers) and removes everything that can carry personal data, card data or credentials:
request and response bodies, cookies, auth headers, query-string values and long IDs in URL paths.

Before writing, it checks the copy against the original: no value from the original's bodies, cookies,
auth headers or query strings may appear, and neither may card-like numbers or email addresses. If any
does, nothing is written. It prints only counts, never values.

  python3 sanitize_har.py capture.har capture-safe.har

Standard library only, Python 3.8+.
"""
import argparse
import json
import os
import re
import sys
from urllib.parse import urlsplit, urlunsplit, parse_qsl

SAFE_HEADERS = {
    "content-type", "content-length", "cache-control", "content-encoding", "age", "vary", "via",
    "access-control-allow-origin", "access-control-allow-methods", "access-control-allow-headers",
    "cross-origin-resource-policy", "cross-origin-embedder-policy", "cross-origin-opener-policy",
    "x-frame-options", "content-security-policy", "content-security-policy-report-only",
    "x-content-type-options", "cf-cache-status", "x-cache", "sec-fetch-dest", "sec-fetch-mode",
    "sec-fetch-site", "accept",
}
URL_HEADERS = {"location", "referer", "origin"}
# Long opaque path segments (checkout ids, payment ids, session ids) often work as access tokens
TOKEN_SEGMENT = re.compile(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9_-]{20,}$")
# Plain parameter names are kept; some APIs (Google Maps) put data, even typed addresses, in the "names"
PLAIN_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.\-\[\]]{0,40}")
REMOVED = "[removed]"


def clean_name(name):
    return name if PLAIN_NAME.fullmatch(name) else REMOVED


def clean_url(url):
    if not url:
        return url
    if url.startswith("data:"):
        return "data:" + REMOVED
    u = urlsplit(url)
    path = "/".join("[id]" if TOKEN_SEGMENT.match(s) else s for s in u.path.split("/"))
    query = "&".join(f"{n}={REMOVED}" if n != REMOVED else REMOVED
                     for n in (clean_name(k) for k, _ in parse_qsl(u.query, keep_blank_values=True)))
    return urlunsplit((u.scheme, u.netloc, path, query, ""))


def clean_headers(headers):
    out = []
    for h in headers:
        name = h["name"].lower()
        if name in SAFE_HEADERS:
            out.append({"name": h["name"], "value": h["value"]})
        elif name in URL_HEADERS:
            out.append({"name": h["name"], "value": clean_url(h["value"])})
    return out


def drop_private_fields(d):
    """Browser-specific fields (Firefox and Chrome prefix them with _) can hold initiators, stack traces and more."""
    for k in [k for k in d if k.startswith("_")]:
        del d[k]


def sanitize(har):
    log = har["log"]
    for p in log.get("pages", []):
        p["title"] = clean_url(p.get("title", ""))
        drop_private_fields(p)
    for e in log["entries"]:
        rq, rs = e["request"], e["response"]
        drop_private_fields(e)
        drop_private_fields(rq)
        drop_private_fields(rs)
        e.pop("serverIPAddress", None)
        e.pop("connection", None)
        rq["url"] = clean_url(rq["url"])
        rq["headers"] = clean_headers(rq.get("headers", []))
        rq["cookies"] = []
        rq["queryString"] = [{"name": clean_name(q["name"]), "value": REMOVED} for q in rq.get("queryString", [])]
        if "postData" in rq:
            rq["postData"] = {"mimeType": rq["postData"].get("mimeType", ""), "text": REMOVED}
        rs["headers"] = clean_headers(rs.get("headers", []))
        rs["cookies"] = []
        rs["redirectURL"] = clean_url(rs.get("redirectURL", ""))
        c = rs.get("content", {})
        rs["content"] = {"size": c.get("size", 0), "mimeType": c.get("mimeType", "")}
    return har


def original_values(har):
    """Every string someone typed or a server handed out: bodies, cookies, auth headers and query values."""
    vals = set()

    def walk(o):
        if isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
        elif isinstance(o, str) and len(o) >= 5:
            vals.add(o)

    for e in har["log"]["entries"]:
        rq, rs = e["request"], e["response"]
        body = (rq.get("postData") or {}).get("text", "")
        try:
            walk(json.loads(body))
        except ValueError:
            vals.update(v for _, v in parse_qsl(body) if len(v) >= 5)
        for p in (rq.get("postData") or {}).get("params", []):
            walk(p.get("value"))
        for c in rq.get("cookies", []) + rs.get("cookies", []):
            walk(c.get("value"))
        for q in rq.get("queryString", []):
            walk(q.get("value"))
        for h in rq.get("headers", []) + rs.get("headers", []):
            if h["name"].lower() in ("cookie", "set-cookie", "authorization"):
                walk(h["value"])
    return vals


def luhn(digits):
    d = [int(c) for c in digits][::-1]
    return (sum(d[0::2]) + sum(sum(divmod(2 * x, 10)) for x in d[1::2])) % 10 == 0


def check(original, out, text):
    """Returns a list of problems; empty means the copy is safe to write."""
    entries = out["log"]["entries"]
    # Values that survive only as parts of the kept URLs, headers or the file's creator info (hosts, path words,
    # content types, browser name) are public; any other original value found in the copy is a leak
    kept = " ".join([e["request"]["url"] for e in entries]
                    + [h["value"] for e in entries for h in e["request"]["headers"] + e["response"]["headers"]]
                    + [json.dumps(out["log"].get("creator", {})), json.dumps(out["log"].get("browser", {}))])
    leaks = [v for v in original_values(original) if v in text and v not in kept]
    cards = [m for m in re.findall(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)", text)
             if luhn(re.sub(r"\D", "", m)) and len(set(re.sub(r"\D", "", m))) > 2]
    emails = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z.]{2,}", text)
    problems = []
    if leaks:
        problems.append(f"{len(leaks)} value(s) from the original's bodies, cookies or query strings")
    if cards:
        problems.append(f"{len(cards)} card-like number(s)")
    if emails:
        problems.append(f"{len(emails)} email address(es)")
    return problems


def main():
    ap = argparse.ArgumentParser(description="Write a share-safe copy of a HAR file.")
    ap.add_argument("input", help="the HAR exported from the browser")
    ap.add_argument("output", help="where to write the safe copy (must not exist)")
    args = ap.parse_args()
    if os.path.exists(args.output):
        sys.exit(f"{args.output} already exists; choose another name")

    with open(args.input, encoding="utf-8") as f:
        original = json.load(f)
    out = sanitize(json.loads(json.dumps(original)))
    text = json.dumps(out, indent=1)

    print(f"requests: {len(out['log']['entries'])}")
    problems = check(original, out, text)
    if problems:
        print("NOT WRITTEN, the copy would still contain: " + "; ".join(problems))
        print("Please open an issue (without attaching the HAR) describing which site it came from.")
        sys.exit(1)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"checks passed, written: {args.output} ({os.path.getsize(args.output) // 1024} KB)")


if __name__ == "__main__":
    main()
