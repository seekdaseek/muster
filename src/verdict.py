"""muster verdict engine.

Deterministic. Pure. No model, no network, no clock.

The whole claim of this project is that it cannot rubber-stamp. That claim is
only true if the language model has no code path to a verdict. So verdicts are
decided here, by rules over measured evidence, and the reviewer agent's job is
to gather evidence, call this, and explain the result in English. It cannot
change one.

Three verdicts:

  REVOKE   the evidence for a problem is COMPLETE and needs no usage data.
  CERTIFY  held permissions fully enumerated AND usage evidence present AND
           everything used is within what is held AND nothing is UNMEASURED.
  ABSTAIN  anything else, with the missing evidence named explicitly.

CERTIFY is deliberately hard to reach. On a project with no runtime traces it
is unreachable, and a campaign that returns zero certifications is the engine
working, not failing.
"""
import inventory as inv

REVOKE, CERTIFY, ABSTAIN = "REVOKE", "CERTIFY", "ABSTAIN"


def _ev(claim, source):
    """One piece of evidence: what is claimed, and the artifact it came from."""
    return {"claim": claim, "source": source}


def _verdict(subject, kind, verdict, rule, evidence, missing=None):
    return {
        "subject": subject,
        "kind": kind,
        "verdict": verdict,
        "rule": rule,
        "evidence": evidence,
        "missing_evidence": missing or [],
    }


# --------------------------------------------------------------- principals

def judge_principals(principals, usage=None):
    """One verdict per IAM principal.

    usage is the record of what each principal actually did. On a project with
    no traces it is empty, and every principal that is not already REVOKE-able
    must ABSTAIN — we know what they HOLD and nothing about what they USE.
    """
    usage = usage or {}
    out = []
    for finding in inv.overprivileged(principals):
        if finding["flagged"]:
            ev = [_ev("holds %s" % ", ".join(finding["roles"]),
                      "projects.getIamPolicy"),
                  _ev(finding["reason"], "rule: primitive roles are not scoped")]
            if finding["default_service_account"]:
                ev.append(_ev("Google-managed default service account, granted "
                              "this role at project creation",
                              "principal naming convention"))
            out.append(_verdict(finding["principal"], "principal", REVOKE,
                                "primitive-role-on-non-human-identity", ev))
    judged = {v["subject"] for v in out}
    for member, roles in principals.items():
        if member in judged:
            continue
        ev = [_ev("holds %s" % ", ".join(roles), "projects.getIamPolicy")]
        used = usage.get(member)
        if used is None:
            out.append(_verdict(member, "principal", ABSTAIN,
                                "no-usage-evidence", ev,
                                ["what this principal actually invoked "
                                 "(runtime traces)"]))
            continue
        excess = sorted(set(roles) - set(used))
        if excess:
            out.append(_verdict(
                member, "principal", REVOKE, "held-exceeds-used",
                ev + [_ev("used only %s" % ", ".join(sorted(used)), "traces")],
            ))
        else:
            out.append(_verdict(
                member, "principal", CERTIFY, "used-within-held",
                ev + [_ev("used %s, all within what is held" % ", ".join(sorted(used)),
                          "traces")]))
    return sorted(out, key=lambda v: v["subject"])


# ---------------------------------------------------------------- workloads

def judge_workloads(shadows):
    """One verdict per runtime workload."""
    out = []
    for w in shadows:
        base = [_ev("running at %s" % w["url"], "run.services.list"),
                _ev("runs as %s" % w["identity"], "spec.template.spec.serviceAccountName")]
        if w.get("shadow_agent"):
            out.append(_verdict(
                w["workload"], "workload", REVOKE, "self-declared-agent-not-registered",
                base + [
                    _ev("serves an A2A agent card naming itself %r"
                        % (w.get("declared_name") or inv.UNMEASURED),
                            "GET /.well-known/agent-card.json"),
                    _ev("absent from the registry after checking %d address(es) "
                        "against %d registered endpoint(s)"
                        % (len(w.get("urls_checked") or []), w["compared_against"]),
                        "agent-registry agents list"),
                ]))
            continue
        if w.get("card_state") == "UNREACHABLE":
            out.append(_verdict(
                w["workload"], "workload", ABSTAIN, "agent-card-unreachable", base,
                ["whether this workload is an agent — its card could not be read, "
                 "which is not the same as it having none"]))
            continue
        if not w["registered"]:
            missing = ["whether this workload is an agent at all"]
            if not w.get("derived_url_available"):
                missing.append("the full address set — the Cloud Run API reports "
                               "one URL but a service can answer on more")
            out.append(_verdict(
                w["workload"], "workload", ABSTAIN, "unregistered-but-not-an-agent",
                base + [_ev("no agent card at the A2A well-known path",
                            "GET /.well-known/agent-card.json")], missing))
            continue
        out.append(_verdict(
            w["workload"], "workload", ABSTAIN, "no-usage-evidence",
            base + [_ev("matched a registered endpoint", "agent-registry agents list")],
            ["what this workload actually invoked (runtime traces)"]))
    return sorted(out, key=lambda v: v["subject"])


# ------------------------------------------------------------- mcp servers

def judge_servers(mcp_records, tools):
    """One verdict per MCP server."""
    meta = {m["server"]: m for m in inv.metadata_findings(mcp_records)}
    by_server = {}
    for t in tools:
        by_server.setdefault(t["server"], []).append(t)

    out = []
    for s in mcp_records or []:
        urn = s.get("mcpServerId", inv.UNMEASURED)
        label = s.get("displayName", inv.UNMEASURED)
        rows = by_server.get(urn, [])
        base = [_ev("exposes %d tool(s)" % len(rows), "agent-registry mcp-servers list")]
        m = meta.get(urn)

        if m and m["severity"] == inv.MISLABELLED:
            out.append(_verdict(
                label, "mcp_server", REVOKE, "catalog-label-misidentifies-service",
                base + [
                    _ev("labelled %r while its URN and endpoint both say %r"
                        % (m["label"], m["service_from_endpoint"]), "mcpServerId, interfaces[].url"),
                    _ev("a reviewer triaging by label cannot see what this is",
                        "rule: the label is the only human-readable identifier"),
                ]))
            continue

        unmeasured = [t["tool"] for t in rows if t["read_only"] == inv.UNMEASURED]
        missing = []
        if unmeasured:
            missing.append("declared write capability for %d of %d tools "
                           "(readOnlyHint absent: %s)"
                           % (len(unmeasured), len(rows),
                              ", ".join(unmeasured[:5])
                              + (" …" if len(unmeasured) > 5 else "")))
        if m and m["severity"] == inv.UNDESCRIBED:
            missing.append("a description — the entry ships none")
        missing.append("which of these tools were actually called (runtime traces)")
        out.append(_verdict(label, "mcp_server", ABSTAIN,
                            "capability-not-fully-declared", base, missing))
    return sorted(out, key=lambda v: v["subject"])


# ----------------------------------------------------------- registry agents

def judge_agents(agents, usage=None):
    """One verdict per registered agent."""
    usage = usage or {}
    out = []
    for a in agents:
        ev = [_ev("registered as %s version %s" % (a["agent_id"], a["version"]),
                  "agent-registry agents list"),
              _ev("declares %d skill(s): %s"
                  % (len(a["skills"]), ", ".join(a["skills"]) or "none"),
                  "agents[].skills")]
        if a["agent_id"] not in usage:
            out.append(_verdict(a["display_name"], "registry_agent", ABSTAIN,
                                "no-usage-evidence", ev,
                                ["what this agent actually invoked (runtime traces)",
                                 "which tools it is bound to — the registry "
                                 "bindings list is empty"]))
        else:
            out.append(_verdict(a["display_name"], "registry_agent", ABSTAIN,
                                "bindings-not-enumerated", ev,
                                ["the agent's tool bindings"]))
    return sorted(out, key=lambda v: v["subject"])


# ------------------------------------------------------------------ campaign

def run_campaign(data, agents, tools, principals, shadows, usage=None):
    """Every subject, one verdict each, plus the honest tally."""
    verdicts = (judge_principals(principals, usage)
                + judge_workloads(shadows)
                + judge_servers(data.get("mcp-servers"), tools)
                + judge_agents(agents, usage))
    tally = {REVOKE: 0, CERTIFY: 0, ABSTAIN: 0}
    for v in verdicts:
        tally[v["verdict"]] += 1
    return verdicts, tally


def certify_reachable(usage):
    """Is CERTIFY even possible with the evidence available?

    Stating this up front is the difference between "we found nothing to
    certify" and "we could not have certified anything".
    """
    return bool(usage)
