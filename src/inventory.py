"""muster inventory core.

Pure functions over Agent Registry and Google Cloud JSON. No I/O, no network,
no clock. Every function returns evidence alongside every claim, and marks
anything it could not measure as UNMEASURED rather than guessing a default.

Field names here were read off real `gcloud ... --format=json` output from
project ata-agentfleet-2026 on 2026-08-21. Nothing is invented.
"""

UNMEASURED = "UNMEASURED"

# Top-level keys observed on real records. Anything outside these sets is
# reported by unknown_keys() so a field we have never seen surfaces itself
# on first contact instead of being silently dropped.
AGENT_KEYS = {
    "agentId", "createTime", "description", "displayName", "location",
    "name", "protocols", "skills", "uid", "updateTime", "version",
}
MCP_KEYS = {
    "createTime", "description", "displayName", "interfaces",
    "mcpServerId", "name", "tools", "updateTime",
}

# Annotation states. A tool is only "declared" when readOnlyHint is actually
# present. "partial" means an annotations block exists but omits readOnlyHint.
# "absent" means no annotations block at all. Collapsing partial into absent
# overclaims, which is why they are separate.
DECLARED, PARTIAL, ABSENT = "declared", "partial", "absent"

# Registry metadata problems, worst first.
MISLABELLED, UNDESCRIBED = "mislabelled", "undescribed"

# Primitive roles. Google's own guidance is that these are too broad for
# workload identities; roles/editor on a default service account is the
# canonical real-world case.
PRIMITIVE_ROLES = {"roles/owner", "roles/editor", "roles/viewer"}


def unknown_keys(records, known):
    """Top-level keys present on records that we do not model, sorted."""
    seen = set()
    for r in records or []:
        seen |= set(r.keys())
    return sorted(seen - known)


def _agent_location(record):
    """The agent's own location field, never the one spliced into `name`.

    MEASURED 2026-08-21: listing the registry at five different --location
    values returned the SAME agent five times. The `name` path echoed back
    whichever location was requested while `location` and `agentId` stayed
    fixed at the true value. Trusting `name` inflates the inventory.
    """
    loc = record.get("location")
    return loc if loc else UNMEASURED


def _path_location(name):
    """The location embedded in a resource path, or UNMEASURED."""
    parts = (name or "").split("/")
    if "locations" in parts:
        i = parts.index("locations")
        if i + 1 < len(parts):
            return parts[i + 1]
    return UNMEASURED


def canonical_agents(records):
    """Collapse registry agent records to one row per agentId.

    Returns (agents, duplication) where duplication maps agentId to the list
    of path locations it was returned under. A duplication entry with more
    than one path location is an artifact of the list API, not two agents.
    """
    agents = {}
    duplication = {}
    for r in records or []:
        aid = r.get("agentId")
        if not aid:
            aid = UNMEASURED
        duplication.setdefault(aid, []).append(_path_location(r.get("name")))
        if aid in agents:
            continue
        agents[aid] = {
            "agent_id": aid,
            "display_name": r.get("displayName", UNMEASURED),
            "location": _agent_location(r),
            "created": r.get("createTime", UNMEASURED),
            "updated": r.get("updateTime", UNMEASURED),
            "uid": r.get("uid", UNMEASURED),
            "version": r.get("version", UNMEASURED),
            "endpoints": _agent_endpoints(r),
            "skills": [s.get("id") or s.get("name") or UNMEASURED
                       for s in r.get("skills") or []],
            "evidence": r.get("name", UNMEASURED),
        }
    for aid in duplication:
        duplication[aid] = sorted(set(duplication[aid]))
    return [agents[k] for k in sorted(agents)], duplication


def _agent_endpoints(record):
    """Flatten protocols[].interfaces[] to (type, binding, url) rows."""
    out = []
    for p in record.get("protocols") or []:
        ptype = p.get("type", UNMEASURED)
        for iface in p.get("interfaces") or []:
            out.append({
                "protocol": ptype,
                "binding": iface.get("protocolBinding", UNMEASURED),
                "url": iface.get("url", UNMEASURED),
            })
    return out


def annotation_state(tool):
    """DECLARED / PARTIAL / ABSENT for one tool record.

    MEASURED 2026-08-21 across 177 tools on 15 auto-registered MCP servers:
    all three states occur in Google's own catalog. update_endpoint carries
    idempotentHint but no readOnlyHint (PARTIAL); create_service carries no
    annotations block at all (ABSENT). Reporting both as "no annotations"
    would be false, so they stay distinct.
    """
    ann = tool.get("annotations")
    if not isinstance(ann, dict):
        return ABSENT
    if "readOnlyHint" in ann:
        return DECLARED
    return PARTIAL


def declared_tools(mcp_records):
    """Flatten MCP server tools, preserving declared safety annotations.

    read_only/idempotent are only ever the declared value or UNMEASURED.
    Nothing is inferred from a tool's name: create_* is not assumed to write.
    """
    rows = []
    for s in mcp_records or []:
        server = s.get("mcpServerId", UNMEASURED)
        label = s.get("displayName", UNMEASURED)
        for t in s.get("tools") or []:
            ann = t.get("annotations") if isinstance(t.get("annotations"), dict) else {}
            rows.append({
                "server": server,
                "server_label": label,
                "tool": t.get("name", UNMEASURED),
                "read_only": ann.get("readOnlyHint", UNMEASURED),
                "idempotent": ann.get("idempotentHint", UNMEASURED),
                "annotation_state": annotation_state(t),
                "evidence": s.get("name", UNMEASURED),
            })
    return rows


def tool_collisions(rows):
    """Tool names offered by more than one MCP server, with the servers.

    MEASURED: get_service and list_services are offered by BOTH the Agent
    Registry server and the Cloud Run server with different semantics. An
    agent wired to both has an ambiguous call target. Same-name-same-server
    duplicates are not collisions and are excluded.
    """
    byname = {}
    for r in rows:
        byname.setdefault(r["tool"], set()).add(r["server_label"])
    return {t: sorted(s) for t, s in sorted(byname.items()) if len(s) > 1}


def servers_summary(rows):
    """Per-server counts: total, declared read-only, declared write, unmeasured."""
    out = {}
    for r in rows:
        e = out.setdefault(r["server_label"], {
            "tools": 0, "read_only": 0, "declared_write": 0,
            "partial": 0, "absent": 0})
        e["tools"] += 1
        if r["read_only"] is True:
            e["read_only"] += 1
        elif r["read_only"] is False:
            e["declared_write"] += 1
        if r["annotation_state"] == PARTIAL:
            e["partial"] += 1
        elif r["annotation_state"] == ABSENT:
            e["absent"] += 1
    return dict(sorted(out.items()))


def _service_id_from_urn(urn):
    """Last segment of an mcpServerId URN, or UNMEASURED."""
    if not urn or ":" not in urn:
        return UNMEASURED
    return urn.rsplit(":", 1)[-1] or UNMEASURED


def _service_id_from_url(url):
    """First host label of an interface URL, or UNMEASURED.

    https://billingbudgets.googleapis.com/mcp -> billingbudgets
    """
    if not url or "://" not in url:
        return UNMEASURED
    host = url.split("://", 1)[1].split("/", 1)[0]
    return host.split(".", 1)[0] or UNMEASURED


def metadata_findings(mcp_records):
    """Registry entries whose own metadata will not survive a human triage.

    MEASURED 2026-08-21: one server on this project has displayName "unused"
    while its URN and endpoint both say billingbudgets, and it carries no
    description. Its five tools include create/update/delete_budget. A
    reviewer scanning the catalog by label would skip it.

    The check is deterministic, not a judgement: a label is accepted when it
    contains the service id taken from the URN or from the endpoint host.
    """
    rows = []
    for s in mcp_records or []:
        label = (s.get("displayName") or "").strip()
        from_urn = _service_id_from_urn(s.get("mcpServerId"))
        ifaces = s.get("interfaces") or []
        from_url = _service_id_from_url(ifaces[0].get("url") if ifaces else None)
        ids = [i for i in (from_urn, from_url) if i != UNMEASURED]
        mismatch = bool(ids) and not any(i in label.lower() for i in ids)
        desc = (s.get("description") or "").strip()
        if not mismatch and desc:
            continue
        rows.append({
            "server": s.get("mcpServerId", UNMEASURED),
            "label": label or UNMEASURED,
            "service_from_urn": from_urn,
            "service_from_endpoint": from_url,
            "label_identifies_service": not mismatch,
            "has_description": bool(desc),
            # Two different problems. A label naming the wrong service
            # actively misleads a reviewer; a missing description merely
            # leaves them uninformed. Reporting them under one headline
            # inflates the mild case to match the severe one.
            "severity": MISLABELLED if mismatch else UNDESCRIBED,
            "tools": [t.get("name", UNMEASURED) for t in s.get("tools") or []],
            "evidence": s.get("name", UNMEASURED),
        })
    return rows


def iam_principals(policy):
    """member -> sorted list of roles, from a getIamPolicy document."""
    out = {}
    for b in (policy or {}).get("bindings") or []:
        role = b.get("role", UNMEASURED)
        for m in b.get("members") or []:
            out.setdefault(m, set()).add(role)
    return {m: sorted(r) for m, r in sorted(out.items())}


def is_default_service_account(member):
    """Google-managed default SAs that receive broad roles at project creation."""
    if not member.startswith("serviceAccount:"):
        return False
    email = member.split(":", 1)[1]
    return (email.endswith("@developer.gserviceaccount.com")
            or email.endswith("@appspot.gserviceaccount.com"))


def overprivileged(principals):
    """Principals holding a primitive role, with the reason stated.

    Human owners are reported but not flagged: a project needs an owner.
    A non-human identity holding a primitive role is the finding.
    """
    findings = []
    for member, roles in principals.items():
        hits = sorted(set(roles) & PRIMITIVE_ROLES)
        if not hits:
            continue
        human = member.startswith("user:")
        findings.append({
            "principal": member,
            "roles": hits,
            "human": human,
            "default_service_account": is_default_service_account(member),
            "flagged": not human,
            "reason": ("expected: a project requires an owner" if human
                       else "non-human identity holds a primitive project role"),
        })
    return findings


RUN_LOCATION_LABEL = "cloud.googleapis.com/location"


def run_service_urls(svc, project_number=None):
    """Every address this Cloud Run service is known to answer on.

    MEASURED 2026-08-21: the API reports ONE url. `status.url` and
    `status.address.url` were byte-identical and `status.traffic` carried no
    url at all — yet the project-number form
    https://SERVICE-PROJECTNUMBER.REGION.run.app returned HTTP 200 on the
    same service and appears NOWHERE in the resource.

    So the API-reported set is incomplete, and matching on it alone can call
    a registered agent a shadow. The derived form is added as a CANDIDATE,
    and only when both the project number and the region are known. Region
    comes from the resource's own location label; if it is absent we do NOT
    invent one.

    Returns (urls, derived_ok).
    """
    st = svc.get("status") or {}
    urls = set()
    for u in (st.get("url"), (st.get("address") or {}).get("url")):
        if u:
            urls.add(u.rstrip("/"))
    for t in st.get("traffic") or []:
        if t.get("url"):
            urls.add(t["url"].rstrip("/"))

    name = (svc.get("metadata") or {}).get("name")
    region = ((svc.get("metadata") or {}).get("labels") or {}).get(RUN_LOCATION_LABEL)
    if name and region and project_number:
        urls.add("https://%s-%s.%s.run.app" % (name, project_number, region))
        return urls, True
    return urls, False


def _sa_from_run_service(svc):
    """serviceAccountName off a Cloud Run service record, or UNMEASURED."""
    spec = (svc.get("spec") or {}).get("template", {}).get("spec", {})
    return spec.get("serviceAccountName") or UNMEASURED


def shadow_candidates(run_services, agents, card_probes=None, project_number=None):
    """Runtime workloads with no corresponding entry in the registry.

    A Cloud Run service is a shadow candidate when nothing in the registry
    points at its URL. Returns rows, never a bare count: the evidence for
    'not registered' is the set of registered URLs it was compared against.
    """
    registered = set()
    for a in agents or []:
        for e in a.get("endpoints") or []:
            if e.get("url") and e["url"] != UNMEASURED:
                registered.add(e["url"].rstrip("/"))
    rows = []
    for svc in run_services or []:
        url = (svc.get("status") or {}).get("url", UNMEASURED)
        name = (svc.get("metadata") or {}).get("name", UNMEASURED)
        urls, derived_ok = run_service_urls(svc, project_number)
        matched = bool(urls & registered)
        probe = (card_probes or {}).get((url or "").rstrip("/"), {})
        state = probe.get("state", UNMEASURED)
        rows.append({
            "workload": name,
            "url": url,
            "identity": _sa_from_run_service(svc),
            "registered": matched,
            "compared_against": len(registered),
            "urls_checked": sorted(urls),
            "derived_url_available": derived_ok,
            # "card" means the workload advertises itself as an agent at the
            # A2A well-known path. Combined with registered=False that is a
            # proven shadow agent, not an unmatched URL. UNREACHABLE is not
            # evidence of innocence.
            "card_state": state,
            "declared_name": probe.get("declared_name"),
            "declared_skills": probe.get("declared_skills") or [],
            "shadow_agent": (not matched) and state == "card",
        })
    return rows


def summarise(agents, duplication, tools, principals, shadows, mcp_records=None):
    """One dict carrying counts AND the caveats that make them readable."""
    inflated = {a: locs for a, locs in duplication.items() if len(locs) > 1}
    return {
        "agents": len(agents),
        "agent_records_seen": sum(len(v) for v in duplication.values()),
        "duplicate_agent_ids": inflated,
        "tools": len(tools),
        "servers": servers_summary(tools),
        "collisions": tool_collisions(tools),
        "metadata_findings": metadata_findings(mcp_records),
        "tools_no_annotations": [t["tool"] for t in tools
                                 if t["annotation_state"] == ABSENT],
        "tools_partial_annotations": [t["tool"] for t in tools
                                      if t["annotation_state"] == PARTIAL],
        "read_only_unmeasured": [t["tool"] for t in tools
                                 if t["read_only"] == UNMEASURED],
        "declared_write": [t["tool"] for t in tools if t["read_only"] is False],
        "principals": len(principals),
        "overprivileged": overprivileged(principals),
        "runtime_workloads": len(shadows),
        "unregistered_workloads": [s["workload"] for s in shadows if not s["registered"]],
        "shadow_agents": [s["workload"] for s in shadows if s.get("shadow_agent")],
        "urls_incomplete": [s["workload"] for s in shadows
                            if not s.get("derived_url_available")],
        "unreachable_workloads": [s["workload"] for s in shadows
                                  if s.get("card_state") == UNMEASURED
                                  or s.get("card_state") == "UNREACHABLE"],
    }
