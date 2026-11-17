# scripts

Small, standalone scripts from the team behind [PresenceWave](https://presencewave.com). Each one uses only the
Python standard library, so there is nothing to install.

## HAR files (`har/`)

A HAR file is a recording of every request a browser page makes, exported from the browser's developer tools.
Support teams often ask for one when a page misbehaves. The catch: a HAR records everything, including what you typed
into forms (card numbers, addresses, phone numbers), your cookies and your session tokens. Browser "redact" options
don't always catch all of it: in one we checked, the card number was still in the body of a card-lookup request.

### `har_summary.py`: see what a page loaded and what failed

```sh
python3 har/har_summary.py capture.har            # every request, then requests per host and the failures
python3 har/har_summary.py capture.har --failed   # only status 0, 4xx and 5xx
python3 har/har_summary.py capture.har --host api # only hosts containing "api"
```

Prints one line per request (time, method, status, size, content type, URL without the query string). It never
prints bodies, headers or cookies, so it's safe to run on an unredacted HAR.

### `sanitize_har.py`: make a copy that's safe to share

```sh
python3 har/sanitize_har.py capture.har capture-safe.har
```

The copy keeps what's needed to debug loading problems:

- method, host and path of every request
- status, content type, size and timings
- harmless response headers: content type, caching, CORS (`Access-Control-*`), `Cross-Origin-*`, security policies

It removes:

- every request and response body (form fields, card numbers, API responses)
- all cookies, and the `Cookie`, `Set-Cookie` and `Authorization` headers
- every query-string value, and parameter names that aren't plain names (some APIs put data in them)
- long random-looking path segments, replaced by `[id]` (checkout, payment and session IDs often work as tokens)
- browser-specific fields (`_initiator` and similar) and server IP addresses

Before writing, it checks the copy: no value from the original's bodies, cookies, auth headers or query strings may
appear in it, and neither may card-like numbers (checked with the Luhn checksum) or email addresses. If anything is
found, nothing is written. The script prints only counts, never the values it found.

It can't know everything about every site, so look over the result before you send it. Hostnames and timestamps stay,
so whoever you send it to can still see which sites the page talked to and when.

### Recording a HAR

1. Open the page, then the developer tools (F12, or Ctrl+Shift+I; Cmd+Option+I on a Mac) and their **Network** tab.
2. Tick **Preserve log** (Chrome) or **Persist Logs** (Firefox) so the recording survives redirects.
3. Reload and reproduce the problem.
4. Right-click any request and choose **Save all as HAR** (Firefox) or **Save all as HAR with content** (Chrome).
5. Run `sanitize_har.py` on it, send the safe copy, and delete the original when you're done.

## License

[MIT](LICENSE)
