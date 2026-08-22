"""muster collector.

Runs the read-only gcloud commands that produce the inventory snapshot.

The rule this module exists to enforce: a command that FAILED must never be
recorded as a resource that is ABSENT. Every read writes a manifest entry with
its exit code, and the report refuses to draw conclusions from a source whose
read did not succeed.
"""
import json
import os
import subprocess
import datetime
import urllib.request
import urllib.error

REGISTRY_GROUPS = ["agents", "bindings", "endpoints", "mcp-servers", "services"]


def _run(argv, timeout=120):
    """Run a command. Returns (ok, stdout, stderr, code). Never raises."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode == 0, p.stdout, p.stderr.strip(), p.returncode
    except FileNotFoundError as e:
        return False, "", "command not found: %s" % e, 127
    except subprocess.TimeoutExpired:
        return False, "", "timeout after %ss" % timeout, 124


def _count(parsed):
    """Record count for the manifest.

    A getIamPolicy document is a dict, not a list; reporting None for it made
    a successful read look like a read that returned nothing. Count its
    bindings instead. Only a failed read (None) has no count.
    """
    if parsed is None:
        return None
    if isinstance(parsed, list):
        return len(parsed)
    if isinstance(parsed, dict):
        if "__parse_error__" in parsed:
            return None
        if "bindings" in parsed:
            return len(parsed["bindings"])
        return len(parsed)
    return None


def _parse(ok, out):
    """Parse JSON only if the command succeeded. Failure is not emptiness."""
    if not ok:
        return None
    try:
        return json.loads(out) if out.strip() else []
    except json.JSONDecodeError as e:
        return {"__parse_error__": str(e)}


def _access_token():
    ok, out, err, code = _run(["gcloud", "auth", "print-access-token"])
    return (out.strip() if ok else None), err, code


def _model_armor(project, fetch=None):
    """Read Model Armor templates from the GLOBAL host, not the regional one.

    Returns (ok, payload, error, code). `fetch` is injectable for tests.
    """
    url = ("https://modelarmor.googleapis.com/v1/projects/%s"
           "/locations/global/templates" % project)
    token, err, code = _access_token()
    if not token:
        return False, None, "no access token: %s" % err, code
    fetch = fetch or _http_get
    return fetch(url, token)


def _http_get(url, token):
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            body = r.read().decode("utf-8")
        parsed = json.loads(body) if body.strip() else {}
        if isinstance(parsed, dict) and "error" in parsed:
            return False, None, str(parsed["error"])[:400], parsed["error"].get("code", 0)
        return True, parsed.get("templates", []) if isinstance(parsed, dict) else parsed, None, 200
    except urllib.error.HTTPError as e:
        return False, None, e.read().decode("utf-8", "replace")[:400], e.code
    except Exception as e:
        return False, None, "%s: %s" % (type(e).__name__, e), -1


AGENT_CARD_PATH = "/.well-known/agent-card.json"


def probe_agent_card(url, fetch=None):
    """Does this URL serve an A2A agent card?

    Returns THREE values: (state, card, detail).

      state   "card" (it advertises itself as an agent), "no_card" (it
              answered, and what came back is not an agent card), or
              UNREACHABLE. Unreachable is NOT no_card — a service behind auth
              or a cold start is unmeasured, not innocent.
      card    ALWAYS a dict or None. Never a string. The previous version
              returned the error message in this slot on failure, and the
              caller then called .get() on it, which is how a live fleet run
              died inside collect with 'str' object has no attribute 'get'.
      detail  the reason, as a string, or None. Reasons belong in their own
              slot where nothing will mistake one for a payload.

    The classification table, in full:

      no HTTP response at all (transport, DNS, timeout)  -> UNREACHABLE
      HTTP 401 / 403, behind auth                        -> UNREACHABLE
      HTTP 5xx                                           -> UNREACHABLE
      HTTP 404                                           -> no_card
      HTTP 2xx, body is not JSON                         -> no_card
      HTTP 2xx, JSON that is not an object               -> no_card
      HTTP 2xx, object with neither name nor skills      -> no_card
      HTTP 2xx, object with name or skills               -> card

    The four 2xx rows are the point: a body that ARRIVED and did not parse is
    an answer about this service, not a failure to reach it. Measured on the
    live fleet, https://muster-report-...run.app serves HTTP 200 text/html at
    the well-known path, and the old code filed that reachable service under
    UNREACHABLE because the JSON parse raised inside a bare except.
    """
    if not url or url == "UNMEASURED":
        return "UNREACHABLE", None, "no address to probe"
    fetch = fetch or _plain_get
    ok, payload, detail, code = fetch(url.rstrip("/") + AGENT_CARD_PATH)
    if not ok:
        if code == 404:
            return "no_card", None, detail or "HTTP 404"
        return "UNREACHABLE", None, detail
    if not isinstance(payload, dict):
        return "no_card", None, detail or "response body was not a JSON object"
    if payload.get("name") or payload.get("skills"):
        return "card", payload, None
    return "no_card", None, "JSON object served, carrying neither name nor skills"


def _plain_get(url):
    """Fetch a URL. Returns (ok, payload, detail, code).

    `ok` means A RESPONSE ARRIVED, not that it was useful. A 200 whose body is
    not JSON returns ok=True with payload None and a detail naming the parse
    failure, so the caller can tell "this service answered with something that
    is not a card" apart from "this service could not be reached at all".
    json.JSONDecodeError is caught on its own for exactly that reason; folded
    into the generic except below, it turned every HTML page into an outage.
    """
    try:
        with urllib.request.urlopen(url, timeout=20) as r:
            body = r.read().decode("utf-8")
            code = getattr(r, "status", None) or r.getcode() or 200
    except urllib.error.HTTPError as e:
        return False, None, "HTTP %s" % e.code, e.code
    except Exception as e:
        return False, None, "%s: %s" % (type(e).__name__, e), -1
    try:
        return True, json.loads(body) if body.strip() else {}, None, code
    except json.JSONDecodeError as e:
        return True, None, "response body is not JSON: %s" % e, code


def probe_run_services(run_services, fetch=None):
    """Probe every Cloud Run service for an agent card. Returns url -> row."""
    out = {}
    for svc in run_services or []:
        url = (svc.get("status") or {}).get("url")
        if not url:
            continue
        state, card, detail = probe_agent_card(url, fetch=fetch)
        # card is guaranteed a dict or None by the contract above, so .get()
        # here can no longer meet a string.
        card = card if isinstance(card, dict) else {}
        out[url.rstrip("/")] = {
            "state": state,
            "detail": detail,
            "declared_name": card.get("name"),
            "declared_skills": [s.get("id") or s.get("name")
                                for s in card.get("skills") or []],
        }
    return out


AUDIT_FILTER = ('protoPayload."@type"='
                '"type.googleapis.com/google.cloud.audit.AuditLog"')


def _iso_days_ago(ts, now=None):
    """Whole days between an RFC3339 timestamp and now. None if unparseable."""
    if not ts:
        return None
    s = ts.strip().replace("Z", "+00:00")
    # Python's fromisoformat rejects >6 fractional digits; trim them.
    if "." in s:
        head, rest = s.split(".", 1)
        frac = ""
        while rest and rest[0].isdigit():
            frac += rest[0]
            rest = rest[1:]
        s = "%s.%s%s" % (head, frac[:6], rest)
    try:
        then = datetime.datetime.fromisoformat(s)
    except ValueError:
        return None
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return max(0, (now - then).days)


def usage_from_audit_logs(project, limit=1000):
    """What each principal was OBSERVED doing, from Cloud Audit Logs.

    Admin Activity logs are always on and cannot be disabled, so this works
    retroactively to project creation. Data Access logs are a separate switch
    (see inventory.audit_config) — their absence is why an empty result here
    is never proof of inactivity.

    Returns (usage_by_principal, meta). meta carries the things that decide
    whether the record can support a verdict at all:
      window_days   how far back observation actually reaches
      truncated     the read hit its limit, so the record is INCOMPLETE
      unattributed  entries with no principal — real activity by nobody we
                    can name, which is not the same as no activity
    """
    meta = {"window_days": None, "oldest": None, "truncated": False,
            "unattributed": 0, "entries": 0, "ok": False, "error": None}

    ok, out, err, code = _run(
        ["gcloud", "logging", "read", AUDIT_FILTER, "--project", project,
         "--order", "asc", "--limit", "1", "--format",
         "value(timestamp)"], timeout=180)
    oldest = out.strip().splitlines()[0] if ok and out.strip() else None

    ok2, out2, err2, code2 = _run(
        ["gcloud", "projects", "describe", project,
         "--format=value(createTime)"])
    created = out2.strip() if ok2 else None

    # The window reaches back to the older of the two, but never further than
    # the project has existed.
    candidates = [d for d in (_iso_days_ago(oldest), _iso_days_ago(created))
                  if d is not None]
    meta["oldest"] = oldest
    meta["window_days"] = min(candidates) if candidates else None

    ok3, out3, err3, code3 = _run(
        ["gcloud", "logging", "read", AUDIT_FILTER, "--project", project,
         "--limit", str(limit), "--format",
         "value(protoPayload.authenticationInfo.principalEmail,"
         "protoPayload.methodName)"], timeout=300)
    if not ok3:
        meta["error"] = (err3 or "")[:300]
        return {}, meta

    usage = {}
    lines = [l for l in out3.splitlines() if l.strip()]
    meta["entries"] = len(lines)
    meta["truncated"] = len(lines) >= limit
    meta["ok"] = True
    for line in lines:
        parts = line.split("\t") if "\t" in line else line.split(None, 1)
        who = parts[0].strip() if parts and parts[0].strip() else ""
        what = parts[1].strip() if len(parts) > 1 else ""
        if not who or "@" not in who:
            meta["unattributed"] += 1
            continue
        member = "user:%s" % who if not who.endswith(
            ".gserviceaccount.com") else "serviceAccount:%s" % who
        usage.setdefault(member, set()).add(what or "UNMEASURED")
    return {k: sorted(v) for k, v in usage.items()}, meta


def project_number(project):
    """Needed to derive the project-number Cloud Run URL form."""
    ok, out, err, code = _run(["gcloud", "projects", "describe", project,
                               "--format=value(projectNumber)"])
    return out.strip() if ok and out.strip() else None


def collect(project, location="global", outdir="shapes"):
    """Collect every source. Returns (data, manifest)."""
    os.makedirs(outdir, exist_ok=True)
    data, manifest = {}, {}

    sources = []
    for g in REGISTRY_GROUPS:
        sources.append((g, ["gcloud", "agent-registry", g, "list",
                            "--project", project, "--location", location,
                            "--format", "json"]))
    sources += [
        ("iam", ["gcloud", "projects", "get-iam-policy", project, "--format", "json"]),
        ("sa", ["gcloud", "iam", "service-accounts", "list",
                "--project", project, "--format", "json"]),
        ("run", ["gcloud", "run", "services", "list",
                 "--project", project, "--format", "json"]),
    ]

    for key, argv in sources:
        ok, out, err, code = _run(argv)
        parsed = _parse(ok, out)
        data[key] = parsed
        manifest[key] = {
            "ok": ok,
            "exit_code": code,
            "error": err[:400] if err else None,
            "records": _count(parsed),
            "command": " ".join(argv),
        }
        if ok:
            with open(os.path.join(outdir, key + ".json"), "w") as f:
                json.dump(parsed, f, indent=2)

    # Model Armor: gcloud routes to the regional *.rep.googleapis.com host,
    # which returns 403 on this project. MEASURED 2026-08-21: the plain
    # global host answers 200 with the same credentials. So we bypass gcloud
    # and call the global host directly.
    ok, payload, err, code = _model_armor(project)
    data["model_armor"] = payload
    manifest["model_armor"] = {
        "ok": ok,
        "exit_code": code,
        "error": err[:400] if err else None,
        "records": _count(payload),
        "command": "GET https://modelarmor.googleapis.com/v1/projects/%s/locations/global/templates" % project,
    }
    if ok:
        with open(os.path.join(outdir, "model_armor.json"), "w") as f:
            json.dump(payload, f, indent=2)

    # Probe every runtime workload for a self-declared agent card.
    probes = probe_run_services(data.get("run"))
    data["card_probes"] = probes
    with open(os.path.join(outdir, "card_probes.json"), "w") as f:
        json.dump(probes, f, indent=2)
    manifest["card_probes"] = {
        "ok": True, "exit_code": 0, "error": None,
        "records": len(probes),
        "command": "GET <each Cloud Run url>%s" % AGENT_CARD_PATH,
    }

    usage, umeta = usage_from_audit_logs(project)
    data["usage"] = usage
    data["usage_meta"] = umeta
    with open(os.path.join(outdir, "usage.json"), "w") as f:
        json.dump({"usage": usage, "meta": umeta}, f, indent=2)
    manifest["usage"] = {
        "ok": umeta["ok"], "exit_code": 0 if umeta["ok"] else 1,
        "error": umeta.get("error"), "records": len(usage),
        "command": "gcloud logging read <cloud audit logs>",
    }

    num = project_number(project)
    data["project_number"] = num
    manifest["__project_number__"] = num or "UNMEASURED"

    manifest["__collected_at__"] = datetime.datetime.now(
        datetime.timezone.utc).isoformat()
    manifest["__project__"] = project
    manifest["__location__"] = location
    with open(os.path.join(outdir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    return data, manifest


def load(indir="shapes"):
    """Load a previously collected snapshot plus its manifest."""
    data = {}
    for key in REGISTRY_GROUPS + ["iam", "sa", "run", "model_armor", "card_probes"]:
        path = os.path.join(indir, key + ".json")
        if os.path.exists(path):
            with open(path) as f:
                data[key] = json.load(f)
        else:
            data[key] = None
    mpath = os.path.join(indir, "manifest.json")
    manifest = json.load(open(mpath)) if os.path.exists(mpath) else {}
    upath = os.path.join(indir, "usage.json")
    if os.path.exists(upath):
        blob = json.load(open(upath))
        data["usage"] = blob.get("usage") or {}
        data["usage_meta"] = blob.get("meta") or {}
    else:
        data["usage"], data["usage_meta"] = {}, {}
    n = manifest.get("__project_number__")
    data["project_number"] = None if n in (None, "UNMEASURED") else n
    return data, manifest
