"""muster report server.

Serves the auditor-facing campaign report over HTTP so a judge can read a
real result without a Google Cloud account.

It serves a SNAPSHOT, not a live read, and says so on the page with the exact
collection timestamp. A page that claimed to be live while serving cached
JSON would be the same class of overclaim muster exists to catch.
"""
import html
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))

# Deployed, this directory is the whole build context and src/ sits inside it.
# Locally, src/ is the sibling of web/. Look for both rather than assuming, so
# the same file runs in either place.
for _cand in (os.path.join(HERE, "src"), os.path.join(HERE, "..", "src")):
    if os.path.isdir(_cand):
        sys.path.insert(0, _cand)
        break
else:  # nothing to import from — fail loudly at startup, not silently later
    raise SystemExit("muster src/ not found next to or inside %s" % HERE)

import collect as C  # noqa: E402
import report as R  # noqa: E402

PORT = int(os.environ.get("PORT", "8080"))
SNAPSHOT = os.path.join(HERE, "snapshot")

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>muster &mdash; certification report</title>
<style>
 :root{{color-scheme:light}}
 body{{margin:0;background:#fbfaf8;color:#1a1a1a;
   font:15px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif}}
 .wrap{{max-width:1000px;margin:0 auto;padding:40px 24px 80px}}
 h1{{font-size:34px;margin:0 0 4px;letter-spacing:-.02em}}
 .sub{{color:#6b6b6b;margin:0 0 28px}}
 .note{{background:#fff;border:1px solid #e3ded6;border-radius:10px;
   padding:16px 18px;margin:0 0 28px;color:#4a4a4a}}
 .note b{{color:#1a1a1a}}
 pre{{background:#fff;border:1px solid #e3ded6;border-radius:10px;
   padding:22px;overflow-x:auto;font-size:12.5px;line-height:1.45;
   font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#222}}
 a{{color:#1a5fb4}}
 footer{{margin-top:34px;color:#8a8a8a;font-size:13px}}
</style></head><body><div class="wrap">
<h1>muster</h1>
<p class="sub">access certification for AI agent fleets on Google Cloud</p>
<div class="note">
<b>This is a recorded campaign, not a live read.</b> The evidence below was
collected from a real Google Cloud project at <b>{collected}</b> and is served
from a snapshot. Nothing here is generated on request, and no synthetic data
was used. Source: <a href="https://github.com/seekdaseek/muster">github.com/seekdaseek/muster</a>
</div>
<pre>{body}</pre>
<footer>Verdicts are computed by deterministic rules over measured evidence.
No language model can reach one.</footer>
</div></body></html>"""


def render():
    data, manifest = C.load(SNAPSHOT)
    body = R.render(data, manifest)
    return PAGE.format(collected=html.escape(str(
        manifest.get("__collected_at__", "unknown"))),
        body=html.escape(body))


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/healthz", "/health"):
            payload, ctype = b"ok", "text/plain; charset=utf-8"
        else:
            try:
                payload = render().encode("utf-8")
            except Exception as e:
                payload = ("could not render the snapshot: %s: %s"
                           % (type(e).__name__, e)).encode("utf-8")
                self.send_response(500)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            ctype = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("", PORT), Handler).serve_forever()
