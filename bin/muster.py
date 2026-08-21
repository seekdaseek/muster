#!/usr/bin/env python3
"""muster - agent fleet inventory and certification.

  muster.py collect --project P [--location global] [--out shapes]
  muster.py report  [--in shapes]
  muster.py run     --project P        (collect then report)
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import collect as C  # noqa: E402
import report as R  # noqa: E402


def main():
    ap = argparse.ArgumentParser(prog="muster")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("collect", help="read live GCP state into a snapshot")
    c.add_argument("--project", required=True)
    c.add_argument("--location", default="global")
    c.add_argument("--out", default="shapes")

    r = sub.add_parser("report", help="render a saved snapshot")
    r.add_argument("--in", dest="indir", default="shapes")

    x = sub.add_parser("run", help="collect then report")
    x.add_argument("--project", required=True)
    x.add_argument("--location", default="global")
    x.add_argument("--out", default="shapes")

    a = ap.parse_args()

    if a.cmd in ("collect", "run"):
        data, manifest = C.collect(a.project, a.location, a.out)
        bad = [k for k, m in manifest.items()
               if isinstance(m, dict) and not m.get("ok")]
        if a.cmd == "collect":
            print("collected to %s/  (%d source(s) failed)" % (a.out, len(bad)))
            for k in bad:
                print("  FAILED %s: %s" % (k, (manifest[k].get("error") or "")[:120]))
            return 0
    else:
        data, manifest = C.load(a.indir)

    print(R.render(data, manifest))
    return 0


if __name__ == "__main__":
    sys.exit(main())
