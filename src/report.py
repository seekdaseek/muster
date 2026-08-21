"""muster report rendering. Pure: takes data + manifest, returns text."""
import inventory as inv
import verdict as V

BAR = "=" * 66


def _n(rows, one, many):
    return one if len(rows) == 1 else many


def _tools(names, limit=8):
    """Tool lists run to 15+. Show enough to judge, then say how many more."""
    if len(names) <= limit:
        return ", ".join(names)
    return "%s  (+%d more)" % (", ".join(names[:limit]), len(names) - limit)


def render(data, manifest):
    L = []
    A = L.append
    A(BAR)
    A("muster  agent fleet inventory")
    A("project   %s" % manifest.get("__project__", inv.UNMEASURED))
    A("location  %s" % manifest.get("__location__", inv.UNMEASURED))
    A("collected %s" % manifest.get("__collected_at__", inv.UNMEASURED))
    A(BAR)

    failed = [k for k, m in (manifest or {}).items()
              if isinstance(m, dict) and not m.get("ok")]
    A("")
    A("SOURCES")
    for k, m in sorted((manifest or {}).items()):
        if not isinstance(m, dict):
            continue
        if m.get("ok"):
            n = m.get("records")
            A("  ok       %-14s %s records" % (k, inv.UNMEASURED if n is None else n))
        else:
            A("  FAILED   %-14s exit %s  %s" % (k, m.get("exit_code"),
                                                (m.get("error") or "")[:70]))
    if failed:
        A("")
        A("  %d source(s) failed. Their resources are UNMEASURED, not absent." % len(failed))
        A("  No finding below is derived from a failed source.")

    agents, dup = inv.canonical_agents(data.get("agents"))
    tools = inv.declared_tools(data.get("mcp-servers"))
    principals = inv.iam_principals(data.get("iam") or {})
    shadows = inv.shadow_candidates(data.get("run"), agents,
                                    data.get("card_probes"),
                                    data.get("project_number"))
    s = inv.summarise(agents, dup, tools, principals, shadows,
                      data.get("mcp-servers"))

    A("")
    A("REGISTERED AGENTS  (%d unique from %d records)"
      % (s["agents"], s["agent_records_seen"]))
    if not agents:
        A("  none")
    for a in agents:
        A("  %s" % a["display_name"])
        A("      id       %s" % a["agent_id"])
        A("      uid      %s   version %s" % (a["uid"], a["version"]))
        A("      location %s   created %s" % (a["location"], a["created"]))
        A("      updated  %s" % a["updated"])
        for e in a["endpoints"]:
            A("      endpoint %s  %s  %s" % (e["protocol"], e["binding"], e["url"]))
        A("      skills   %s" % (", ".join(a["skills"]) or "none declared"))
    if s["duplicate_agent_ids"]:
        A("")
        A("  note: the list API returned the same agentId under several")
        A("  --location values. Deduplicated on agentId, not resource name:")
        for aid, locs in s["duplicate_agent_ids"].items():
            A("    %s  seen at: %s" % (aid.split(":")[-1], ", ".join(locs)))

    # --- tool surface, grouped. 177 rows is not a report.
    A("")
    A("TOOL SURFACE  (%d tools across %d MCP servers, none declared by hand)"
      % (s["tools"], len(s["servers"])))
    if s["servers"]:
        A("  %-34s %5s %5s %5s %5s %5s"
          % ("server", "tools", "ro", "write", "part", "none"))
    for name, e in s["servers"].items():
        A("  %-34s %5d %5d %5d %5d %5d"
          % (name[:34], e["tools"], e["read_only"], e["declared_write"],
             e["partial"], e["absent"]))

    unk = len(s["read_only_unmeasured"])
    if unk:
        none_n = len(s["tools_no_annotations"])
        part_n = len(s["tools_partial_annotations"])
        A("")
        A("  FINDING  %d of %d tools do not declare readOnlyHint (%d%%)."
          % (unk, s["tools"], round(100.0 * unk / s["tools"])))
        # Only name the categories that actually occur. Reporting a zero
        # bucket alongside a real one reads as if both were found.
        if none_n and part_n:
            A("           %d carry no annotations block; %d carry a block that"
              % (none_n, part_n))
            A("           omits readOnlyHint. Both are UNMEASURED, neither is safe.")
        elif part_n:
            A("           All %d carry an annotations block that omits" % part_n)
            A("           readOnlyHint. UNMEASURED is not safe.")
        else:
            A("           All %d carry no annotations block at all." % none_n)
        A("           muster infers nothing from a tool's name.")

    if s["tools"] and not s["declared_write"]:
        A("")
        A("  FINDING  not one of the %d tools declares readOnlyHint=false."
          % s["tools"])
        A("           The catalog can say 'this is safe' and never says")
        A("           'this writes'. Every mutating tool is silent, so")
        A("           readOnlyHint alone cannot gate an agent's permissions.")

    if s["collisions"]:
        A("")
        A("  FINDING  %d tool name(s) offered by more than one server."
          % len(s["collisions"]))
        A("           An agent wired to both has an ambiguous call target:")
        for t, servers in list(s["collisions"].items())[:12]:
            A("    %-26s %s" % (t, "  |  ".join(x[:26] for x in servers)))

    meta = s["metadata_findings"]
    mislabelled = [m for m in meta if m["severity"] == inv.MISLABELLED]
    undescribed = [m for m in meta if m["severity"] == inv.UNDESCRIBED]
    if mislabelled:
        A("")
        A("  FINDING  %d registry %s labelled as something %s is not."
          % (len(mislabelled), _n(mislabelled, "entry", "entries"),
             "it" if len(mislabelled) == 1 else "they"))
        A("           The label is what a reviewer scans. This one misleads:")
        for m in mislabelled:
            A("    label %-16s but URN and endpoint both say %s"
              % ('"%s"' % m["label"], m["service_from_endpoint"]))
            if not m["has_description"]:
                A("      no description either")
            if m["tools"]:
                A("      exposes: %s" % _tools(m["tools"]))
    if undescribed:
        A("")
        A("  FINDING  %d correctly labelled %s ship%s no description."
          % (len(undescribed), _n(undescribed, "server", "servers"),
             "s" if len(undescribed) == 1 else ""))
        A("           Less severe than a wrong label, still unreviewable:")
        for m in undescribed:
            A("    %s" % m["label"])
            if m["tools"]:
                A("      exposes: %s" % _tools(m["tools"]))

    A("")
    A("PROJECT ENTITLEMENTS  (%d principals)" % s["principals"])
    for m, roles in principals.items():
        A("  %-62s %s" % (m, ", ".join(roles)))
    flagged = [f for f in s["overprivileged"] if f["flagged"]]
    A("")
    if flagged:
        A("  FINDING  %d non-human principal(s) hold a primitive project role:"
          % len(flagged))
        for f in flagged:
            A("    %s" % f["principal"])
            A("        holds  %s" % ", ".join(f["roles"]))
            A("        why    %s" % f["reason"])
            if f["default_service_account"]:
                A("        note   Google-managed default service account,")
                A("               granted this role at project creation")
    else:
        A("  no non-human principal holds a primitive project role")

    A("")
    A("RUNTIME WORKLOADS vs REGISTRY  (%d workloads)" % s["runtime_workloads"])
    if not shadows:
        A("  no runtime workloads deployed")
    for r in shadows:
        state = "registered" if r["registered"] else "NOT IN REGISTRY"
        A("  %-28s %-16s %s" % (r["workload"], state, r["url"]))
        A("      identity %s" % r["identity"])
        if r["card_state"] == "card":
            A("      serves an A2A agent card, calling itself %r"
              % (r["declared_name"] or inv.UNMEASURED))
            if r["declared_skills"]:
                A("      declared skills: %s" % _tools(r["declared_skills"]))
        elif r["card_state"] == "no_card":
            A("      no agent card at the A2A well-known path")
        else:
            A("      agent card UNMEASURED (unreachable, not cleared)")
        if not r["registered"]:
            A("      %d address(es) checked against %d registered endpoint(s)"
              % (len(r["urls_checked"]), r["compared_against"]))
            if not r["derived_url_available"]:
                A("      WARNING the Cloud Run API reports one address but a")
                A("      service can answer on more; region or project number")
                A("      unknown here, so the address set is INCOMPLETE and")
                A("      this workload could be registered under another URL")
    if s["shadow_agents"]:
        A("")
        A("  FINDING  %d workload(s) advertise themselves as agents and are"
          % len(s["shadow_agents"]))
        A("           absent from the registry: %s"
          % ", ".join(s["shadow_agents"]))
        A("           Self-declared, not inferred from a naming convention.")

    ma = data.get("model_armor")
    A("")
    if ma is None:
        A("MODEL ARMOR  read failed, see SOURCES. Templates UNMEASURED.")
    else:
        A("MODEL ARMOR  %d template(s) configured" % len(ma))
        if not ma:
            A("  no templates yet, so no content findings exist to read")

    # ---- the campaign. Rules decide; no model touches a verdict.
    usage = data.get("usage") or {}
    verdicts, tally = V.run_campaign(data, agents, tools, principals, shadows, usage)
    A("")
    A(BAR)
    A("CERTIFICATION CAMPAIGN   %d subject(s)" % len(verdicts))
    A("  REVOKE %-4d CERTIFY %-4d ABSTAIN %d"
      % (tally[V.REVOKE], tally[V.CERTIFY], tally[V.ABSTAIN]))
    kinds = {}
    for v in verdicts:
        kinds[v["kind"]] = kinds.get(v["kind"], 0) + 1
    A("  subjects: %s" % "  ".join("%s %d" % (k, n) for k, n in sorted(kinds.items())))
    if not V.certify_reachable(usage):
        A("")
        A("  CERTIFY WAS NOT REACHABLE IN THIS CAMPAIGN. No runtime traces")
        A("  exist on this project, so nothing could be shown to use only")
        A("  what it holds. Zero certifications is the engine working.")
    A(BAR)
    for want in (V.REVOKE, V.CERTIFY, V.ABSTAIN):
        rows = [v for v in verdicts if v["verdict"] == want]
        if not rows:
            continue
        A("")
        A("%s  (%d)" % (want, len(rows)))
        for v in rows:
            A("  %s   [%s]" % (v["subject"], v["kind"]))
            A("      rule  %s" % v["rule"])
            for e in v["evidence"]:
                A("      +  %s" % e["claim"])
                A("         via %s" % e["source"])
            for m in v["missing_evidence"]:
                A("      ?  MISSING %s" % m)

    A("")
    unk_a = inv.unknown_keys(data.get("agents"), inv.AGENT_KEYS)
    unk_m = inv.unknown_keys(data.get("mcp-servers"), inv.MCP_KEYS)
    if unk_a or unk_m:
        A("UNMODELLED FIELDS SEEN  (schema moved under us)")
        if unk_a:
            A("  agents:      %s" % ", ".join(unk_a))
        if unk_m:
            A("  mcp-servers: %s" % ", ".join(unk_m))
    else:
        A("schema check: no unmodelled fields on agents or mcp-servers")
    A(BAR)
    return "\n".join(L)
