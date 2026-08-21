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

# Gap kinds. An ABSTAIN names its missing evidence with one of these so a
# reviewer agent can DISPATCH on it instead of parsing prose. Every gap is
# either closeable by a known tool call or explicitly marked NOT_CLOSEABLE,
# so the agent never loops on something it cannot obtain.
GAP_USAGE_EVIDENCE = "usage_evidence"
GAP_AUDIT_LOGGING_OFF = "audit_logging_disabled"
GAP_OBSERVATION_WINDOW = "insufficient_observation_window"
GAP_TRUNCATED_RECORD = "usage_record_truncated"

# How long an identity must be watched before "it did nothing" means
# anything. Access recertification runs on quarterly or annual cycles, so a
# month is the shortest window that survives an auditor asking "and how long
# did you look?". Configurable, but never zero: a record that is complete and
# five minutes long is complete about almost nothing.
MIN_OBSERVATION_DAYS = 30
GAP_AGENT_CARD = "agent_card_unreadable"
GAP_TOOL_BINDINGS = "tool_bindings"
GAP_UNDECLARED_CAPABILITY = "undeclared_write_capability"
GAP_ADDRESS_SET = "incomplete_address_set"
GAP_NO_DESCRIPTION = "no_description"

# Which gaps an agent can actually do something about, and with what.
GAP_ACTIONS = {
    GAP_USAGE_EVIDENCE: "logging.entries.list over cloud audit logs, "
                        "scoped to this principal",
    # The reviewer cannot enable audit logging on someone else's project.
    # It reports the switch; the owner throws it.
    GAP_AUDIT_LOGGING_OFF: None,
    # Only time closes this one. No tool call helps.
    GAP_OBSERVATION_WINDOW: None,
    GAP_TRUNCATED_RECORD: "re-read the audit log with a higher limit",
    GAP_AGENT_CARD: "re-probe the workload's A2A well-known path",
    GAP_TOOL_BINDINGS: "agent-registry bindings list",
    GAP_ADDRESS_SET: "resolve the project number and region, then rebuild "
                     "the address set",
    # Not closeable by us: the catalog owner declares these, not the reviewer.
    GAP_UNDECLARED_CAPABILITY: None,
    GAP_NO_DESCRIPTION: None,
}


def _gap(kind, detail):
    """One missing-evidence item: dispatchable kind + human detail."""
    return {"kind": kind, "detail": detail, "action": GAP_ACTIONS.get(kind)}


def closeable(gaps):
    """The subset a reviewer agent can attempt to close."""
    return [g for g in gaps if g.get("action")]


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

def observed_usage(usage, principals, read_ok):
    """Turn a successful audit read into an observation for EVERY principal.

    A principal that never appears in a log we READ SUCCESSFULLY was observed
    doing nothing — that is `[]`, an observation. `None` means one thing only:
    we could not read the log. Collapsing the two makes an identity with a
    perfect clean record indistinguishable from one we never looked at, and
    it would abstain forever no matter how long the window grew.
    """
    if not read_ok:
        return {}
    out = dict(usage or {})
    for member in principals:
        out.setdefault(member, [])
    return out


def judge_principals(principals, usage=None, audit=None):
    """One verdict per IAM principal.

    `usage` is what each principal was OBSERVED to do. `audit` is what the
    project actually records. The second gates the first: if Data Access
    audit logs are off, read activity is not written down anywhere, so an
    absence of observed reads is not evidence of no reads, and CERTIFY is
    unreachable no matter how quiet the logs look.

    Silence in an incomplete record is not innocence.
    """
    usage = usage or {}
    audit = audit or {"complete": False, "data_read": False, "data_write": False}
    out = []
    for finding in inv.overprivileged(principals):
        if finding["flagged"]:
            allr = finding.get("all_roles") or finding["roles"]
            ev = [_ev("holds %d role(s): %s" % (len(allr), ", ".join(allr)),
                      "projects.getIamPolicy"),
                  _ev("the rule fires on %s" % ", ".join(finding["roles"]),
                      "rule: primitive roles are not scoped"),
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
        ev = [_ev("holds %d role(s): %s" % (len(roles), ", ".join(roles)),
                  "projects.getIamPolicy")]
        used = usage.get(member)
        if used is None:
            out.append(_verdict(member, "principal", ABSTAIN,
                                "no-usage-evidence", ev,
                                [_gap(GAP_USAGE_EVIDENCE,
                                      "what this principal actually invoked")]))
            continue
        if audit.get("truncated"):
            out.append(_verdict(
                member, "principal", ABSTAIN, "usage-record-truncated",
                ev + [_ev("the audit read hit its limit, so this principal's "
                          "activity is a sample, not a record",
                          "cloud audit logs")],
                [_gap(GAP_TRUNCATED_RECORD,
                      "a complete read — a sample cannot show that something "
                      "was never done")]))
            continue
        window = audit.get("window_days")
        if window is None or window < MIN_OBSERVATION_DAYS:
            out.append(_verdict(
                member, "principal", ABSTAIN, "observation-window-too-short",
                ev + [_ev("observed %d operation(s) over %s day(s)"
                          % (len(used),
                             "an unrecorded number of" if window is None else window),
                          "cloud audit logs")],
                [_gap(GAP_OBSERVATION_WINDOW,
                      "at least %d days of observation — an identity that did "
                      "nothing for %s is not an identity that does nothing"
                      % (MIN_OBSERVATION_DAYS,
                         "an unknown period" if window is None
                         else "%d day(s)" % window))]))
            continue
        if not audit.get("complete"):
            missing = [_gap(GAP_AUDIT_LOGGING_OFF,
                            "Data Access audit logs are not enabled, so read "
                            "activity is not recorded — an absence of observed "
                            "reads is not evidence that none happened")]
            out.append(_verdict(
                member, "principal", ABSTAIN, "usage-record-incomplete",
                ev + [_ev("observed %d operation(s): %s"
                          % (len(used), ", ".join(sorted(used)) or "none"),
                          "cloud audit logs (Admin Activity only)")],
                missing))
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
                [_gap(GAP_AGENT_CARD,
                      "its card could not be read, which is not the same as "
                      "it having none")]))
            continue
        if not w["registered"]:
            missing = [_gap(GAP_AGENT_CARD, "whether this workload is an agent at all")]
            if not w.get("derived_url_available"):
                missing.append(_gap(GAP_ADDRESS_SET,
                                    "the Cloud Run API reports one URL but a "
                                    "service can answer on more"))
            out.append(_verdict(
                w["workload"], "workload", ABSTAIN, "unregistered-but-not-an-agent",
                base + [_ev("no agent card at the A2A well-known path",
                            "GET /.well-known/agent-card.json")], missing))
            continue
        out.append(_verdict(
            w["workload"], "workload", ABSTAIN, "no-usage-evidence",
            base + [_ev("matched a registered endpoint", "agent-registry agents list")],
            [_gap(GAP_USAGE_EVIDENCE, "what this workload actually invoked")]))
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
            missing.append(_gap(
                GAP_UNDECLARED_CAPABILITY,
                "declared write capability for %d of %d tools "
                "(readOnlyHint absent: %s)"
                % (len(unmeasured), len(rows),
                   ", ".join(unmeasured[:5]) + (" …" if len(unmeasured) > 5 else ""))))
        if m and m["severity"] == inv.UNDESCRIBED:
            missing.append(_gap(GAP_NO_DESCRIPTION, "the entry ships none"))
        missing.append(_gap(GAP_USAGE_EVIDENCE, "which of these tools were actually called"))
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
                                [_gap(GAP_USAGE_EVIDENCE, "what this agent actually invoked"),
                                 _gap(GAP_TOOL_BINDINGS,
                                      "which tools it is bound to — the registry "
                                      "bindings list is empty")]))
        else:
            out.append(_verdict(a["display_name"], "registry_agent", ABSTAIN,
                                "bindings-not-enumerated", ev,
                                [_gap(GAP_TOOL_BINDINGS, "the agent's tool bindings")]))
    return sorted(out, key=lambda v: v["subject"])


# ------------------------------------------------------------------ campaign

def run_campaign(data, agents, tools, principals, shadows, usage=None, audit=None):
    """Every subject, one verdict each, plus the honest tally."""
    verdicts = (judge_principals(principals, usage, audit)
                + judge_workloads(shadows)
                + judge_servers(data.get("mcp-servers"), tools)
                + judge_agents(agents, usage))
    tally = {REVOKE: 0, CERTIFY: 0, ABSTAIN: 0}
    for v in verdicts:
        tally[v["verdict"]] += 1
    return verdicts, tally


def window_sufficient(audit):
    w = (audit or {}).get("window_days")
    return w is not None and w >= MIN_OBSERVATION_DAYS


def certify_reachable(usage, audit=None):
    """Is CERTIFY even possible with the evidence this project records?

    Two conditions, and the second is the one everyone forgets: you need
    observations AND a record complete enough for their absence to mean
    something. Stating this up front is the difference between "we found
    nothing to certify" and "we could not have certified anything".
    """
    return (bool(usage) and bool((audit or {}).get("complete"))
            and window_sufficient(audit)
            and not (audit or {}).get("truncated"))


def certification_blockers(usage, audit=None):
    """What must change before any CERTIFY is possible here. Actionable."""
    audit = audit or {}
    out = []
    if not usage:
        out.append("no usage observations were gathered for any principal")
    if not audit.get("data_read"):
        out.append("DATA_READ audit logs are disabled — enable them in the "
                   "project IAM policy auditConfigs, or read activity stays "
                   "unrecorded")
    if not audit.get("data_write"):
        out.append("DATA_WRITE audit logs are disabled — same fix")
    if audit.get("truncated"):
        out.append("the audit read was truncated at its limit — raise the "
                   "limit, a sample cannot prove a negative")
    if not window_sufficient(audit):
        w = audit.get("window_days")
        out.append("only %s of observation — %d days are required before "
                   "an absence of activity means anything, and enabling audit "
                   "logs is not retroactive, so the clock starts when you "
                   "switch them on"
                   % ("an unrecorded period" if w is None else "%d day(s)" % w,
                      MIN_OBSERVATION_DAYS))
    return out
