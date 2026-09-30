"""A deliberately throttled endpoint, for proving the threshold harness live.

This is a test fixture, not part of the product. It exists because the rate-limit
harness can only be trusted after it has seen a real 429 travel the whole path:
a mock cannot show that the status, the body and the refusal index survive the
HTTP hop. It serves two behaviours so both sides of the grade are exercised:

  /limited   refuses (429) once more than LIMIT requests have arrived, and
             reports the remaining budget the way a real limiter does, so the
             harness has headers to corroborate the refusal with.
  /open      never refuses, which is the control for the "no limit enforced"
             grade.

It binds to 0.0.0.0 so the probe containers can reach it over the compose
network, and it is intentionally as dumb as possible: in-memory counters, no
persistence, no auth, nothing to keep.
"""
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Small on purpose. The harness caps a sweep at 20 and the point is to refuse
# well inside that so there is room to show a partial sweep as well.
LIMIT = int(os.environ.get("FIXTURE_LIMIT", "4"))
WINDOW = float(os.environ.get("FIXTURE_WINDOW", "0"))
PORT = int(os.environ.get("PORT", "3001"))

_hits = {}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status, payload, extra_headers=None):
        body = payload.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _handle(self):
        path = self.path.split("?", 1)[0]

        # The budget never refills, so a run that consumed it would poison the
        # next one. A reset keeps each sweep starting from a known state, which
        # is what makes the refusal index comparable between runs.
        if path == "/reset":
            _hits.clear()
            self._send(200, '{"status":"reset"}')
            return

        if path not in ("/limited", "/open"):
            self._send(404, '{"error":"not found"}')
            return

        now = time.time()
        if path == "/open":
            # The control: this endpoint has no limiter at all.
            self._send(200, '{"status":"ok","limited":false}')
            return

        # A fixed window is enough to demonstrate a budget; a sliding one would
        # be more realistic but the harness is not trying to characterise the
        # limiter, only to locate the first refusal. WINDOW <= 0 means the
        # budget never refills, which is the simplest limiter that still
        # refuses -- a window of zero would otherwise forget every hit and
        # never refuse at all.
        seen = [t for t in _hits.setdefault(path, [])
                if WINDOW <= 0 or now - t < WINDOW]
        seen.append(now)
        _hits[path] = seen

        if len(seen) > LIMIT:
            self._send(
                429,
                '{"error":"too many requests","limit":%d}' % LIMIT,
                {
                    "Retry-After": "1",
                    "X-RateLimit-Limit": str(LIMIT),
                    "X-RateLimit-Remaining": "0",
                },
            )
            return

        self._send(
            200,
            '{"status":"ok","request":%d}' % len(seen),
            {
                "X-RateLimit-Limit": str(LIMIT),
                "X-RateLimit-Remaining": str(max(0, LIMIT - len(seen))),
            },
        )

    do_GET = do_POST = do_PUT = do_DELETE = _handle

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)


if __name__ == "__main__":
    print("throttle fixture on :%d (limit=%d window=%ss)"
          % (PORT, LIMIT, WINDOW), flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
