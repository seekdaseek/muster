"""Real gap closers. Each returns (ok, payload, note).

These are the only things that go and fetch evidence. They are read-only,
they never raise past the reviewer loop, and critically they distinguish
"ran and found nothing" from "could not run" — because the first closes a
gap and the second does not.
"""
import collect as C
import verdict as V


def _agent_registry_bindings(subject, item, project=None, location="global"):
    ok, out, err, code = C._run(
        ["gcloud", "agent-registry", "bindings", "list",
         "--project", project, "--location", location, "--format", "json"])
    if not ok:
        return False, None, "bindings list failed (exit %s): %s" % (code, (err or "")[:120])
    parsed = C._parse(True, out)
    if isinstance(parsed, dict) and "__parse_error__" in parsed:
        return False, None, "bindings list returned unparseable JSON"
    if not parsed:
        return True, [], ("no bindings exist on this project, so this agent "
                          "is bound to no tools")
    return True, parsed, "%d binding(s) found" % len(parsed)


def _agent_card(subject, item, urls=None):
    for url in urls or []:
        state, card, detail = C.probe_agent_card(url)
        if state == "card":
            return True, card, "agent card served at %s" % url
        if state == "no_card":
            # The reason is carried, not asserted. no_card now covers a 404, a
            # body that did not parse, and JSON with no agent fields; claiming
            # "confirmed by a 404" for the other two would invent evidence.
            return True, [], "no agent card at %s (%s)" % (
                url, detail or "nothing agent-shaped served")
    return False, None, "no address for this workload could be reached"


def _usage_reread(subject, item, project=None, limit=5000):
    # Audit logs are keyed by PRINCIPAL. A subject that is not a principal
    # cannot be looked up here at all, and returning [] for it would report
    # "we looked and found nothing" when the truth is "we looked in the wrong
    # place". A false answer is worse than an open gap.
    if (item or {}).get("kind") != "principal":
        return False, None, (
            "audit logs are keyed by principal; this subject is a %s, so its "
            "activity cannot be looked up this way"
            % ((item or {}).get("kind") or "non-principal"))
    usage, meta = C.usage_from_audit_logs(project, limit=limit)
    if not meta.get("ok"):
        return False, None, "audit read failed: %s" % (meta.get("error") or "unknown")
    if meta.get("truncated"):
        return False, None, ("still truncated at %d entries — raise the limit "
                             "again" % limit)
    return True, usage.get(subject, []), (
        "read %d entries over %s day(s)"
        % (meta.get("entries", 0), meta.get("window_days")))


def build(project, location="global", run_urls=None):
    """Bind the closers to a project. Returns the kind -> closer map."""
    return {
        V.GAP_TOOL_BINDINGS:
            lambda s, i: _agent_registry_bindings(s, i, project, location),
        V.GAP_AGENT_CARD:
            lambda s, i: _agent_card(s, i, (run_urls or {}).get(s)),
        V.GAP_USAGE_EVIDENCE:
            lambda s, i: _usage_reread(s, i, project),
        V.GAP_TRUNCATED_RECORD:
            lambda s, i: _usage_reread(s, i, project, limit=20000),
    }
