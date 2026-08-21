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

    Returns one of: "card" (it advertises itself as an agent), "no_card"
    (reachable, nothing there), or UNREACHABLE. Unreachable is NOT no_card —
    a service behind auth or a cold start is unmeasured, not innocent.
    """
    if not url or url == "UNMEASURED":
        return "UNREACHABLE", None
    fetch = fetch or _plain_get
    ok, payload, err, code = fetch(url.rstrip("/") + AGENT_CARD_PATH)
    if not ok:
        if code == 404:
            return "no_card", None
        return "UNREACHABLE", err
    if isinstance(payload, dict) and (payload.get("name") or payload.get("skills")):
        return "card", payload
    return "no_card", None


def _plain_get(url):
    try:
        with urllib.request.urlopen(url, timeout=20) as r:
            body = r.read().decode("utf-8")
        return True, json.loads(body) if body.strip() else {}, None, 200
    except urllib.error.HTTPError as e:
        return False, None, "HTTP %s" % e.code, e.code
    except Exception as e:
        return False, None, "%s: %s" % (type(e).__name__, e), -1


def probe_run_services(run_services, fetch=None):
    """Probe every Cloud Run service for an agent card. Returns url -> row."""
    out = {}
    for svc in run_services or []:
        url = (svc.get("status") or {}).get("url")
        if not url:
            continue
        state, card = probe_agent_card(url, fetch=fetch)
        out[url.rstrip("/")] = {
            "state": state,
            "declared_name": (card or {}).get("name"),
            "declared_skills": [s.get("id") or s.get("name")
                                for s in (card or {}).get("skills") or []],
        }
    return out


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
    n = manifest.get("__project_number__")
    data["project_number"] = None if n in (None, "UNMEASURED") else n
    return data, manifest
