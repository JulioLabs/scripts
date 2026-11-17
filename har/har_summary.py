#!/usr/bin/env python3
"""Print a HAR file as a request timeline, to see what a page loaded and what failed.

One line per request: time, method, status, size, content type and URL (query strings left out,
so tokens in them aren't printed). Ends with requests per host and every failed request.
It never prints bodies, headers or cookies, so it's safe to run on an unredacted HAR.

  python3 har_summary.py capture.har
  python3 har_summary.py capture.har --failed       # only status 0 and 4xx/5xx
  python3 har_summary.py capture.har --host stripe  # only hosts containing "stripe"

Standard library only, Python 3.8+.
"""
import argparse
import collections
import json
from urllib.parse import urlsplit


def main():
    ap = argparse.ArgumentParser(description="Print a HAR file as a request timeline.")
    ap.add_argument("har")
    ap.add_argument("--failed", action="store_true", help="only failed requests (status 0, 4xx, 5xx)")
    ap.add_argument("--host", help="only requests whose host contains this text")
    args = ap.parse_args()

    with open(args.har, encoding="utf-8") as f:
        log = json.load(f)["log"]
    entries = log["entries"]
    browser = log.get("browser") or log.get("creator") or {}
    print(f"{len(entries)} requests, recorded with {browser.get('name', '?')} {browser.get('version', '')}\n")

    hosts = collections.Counter()
    failed = []
    for e in entries:
        rq, rs = e["request"], e["response"]
        u = urlsplit(rq["url"])
        status = rs.get("status", 0)
        hosts[u.netloc or u.scheme] += 1
        bad = status == 0 or status >= 400
        url = f"{u.scheme}://{u.netloc}{u.path}" if u.netloc else rq["url"][:40]
        line = (f"{e.get('startedDateTime', '')[11:19]}  {rq['method']:7} {status:>3} "
                f"{rs.get('content', {}).get('size', 0):>9}  {rs.get('content', {}).get('mimeType', '')[:30]:30}  {url}")
        if bad:
            failed.append(line)
        if (args.failed and not bad) or (args.host and args.host not in u.netloc):
            continue
        print(line)

    print("\nrequests per host:")
    for host, n in hosts.most_common():
        print(f"  {n:>5}  {host}")
    print(f"\nfailed requests: {len(failed)}")
    for line in failed:
        print("  " + line)


if __name__ == "__main__":
    main()
