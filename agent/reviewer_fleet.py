#!/usr/bin/env python3
"""muster's reviewer fleet: three specialised agents, one deterministic
coordinator.

    Surveyor      inventories the fleet.        tool: survey_fleet
    Investigator  closes evidence gaps.         tool: investigate_gaps
    Recorder      writes the auditor's record.  tool: read_campaign

The coordinator is code, not a model. It routes by dependency — nothing is
investigated before the fleet is known, nothing is recorded before
investigation has had its single pass — and it owns the loop guard and the
claim check.

No agent can reach another's tools. No agent can reach a verdict. Every
worker's prose is checked against measured evidence before it enters the
record, and if any worker fails the campaign degrades to the deterministic
engine result with its verdicts untouched.

    python3 agent/reviewer_fleet.py --project PROJECT_ID
"""
import argparse
import asyncio
import inspect
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

import closers as CL  # noqa: E402
import collect as C  # noqa: E402
import envload  # noqa: E402
import fleet as F  # noqa: E402
import inventory as inv  # noqa: E402
import reviewer as R  # noqa: E402
import verdict as V  # noqa: E402

MODEL = "gemini-3.5-flash"

_STATE = {"project": None, "location": "global", "guard": None,
          "events": [], "engine": None, "evidence": set()}

_COMMON = """You are one agent in muster's reviewer fleet, running an access
certification campaign over an organisation's AI agents, tools and identities.

You do not decide verdicts. A deterministic rule engine does that over
measured evidence, and nothing you say can change one.

Stay inside your role. You have exactly the tools your role needs and none of
another role's. If you want something outside your remit, say so and stop —
another agent owns it.

Call each tool once. A repeat with the same arguments returns nothing new and
will be refused.

Never state an identifier, an account, a URL, a role name or a count that did
not come back from your tool. Every one is checked against the measured
evidence, and anything invented is stripped from the record and logged
against you."""

INSTRUCTIONS = {
    F.SURVEYOR: _COMMON + """

YOUR ROLE: Surveyor. Call survey_fleet once and report what the project
actually contains — how many agents, tools, servers, identities and runtime
workloads, and which subjects the engine could not decide. Do not speculate
about causes. You cannot gather evidence; the Investigator does that.""",
    F.INVESTIGATOR: _COMMON + """

YOUR ROLE: Investigator. Call investigate_gaps once and report what you
obtained, what came back empty, and what failed. Empty is an answer: it means
the tool ran and there was nothing. Failed is not: it means we still do not
know. Never report a failure as an empty result. You cannot inventory and you
cannot write the final record.""",
    F.RECORDER: _COMMON + """

YOUR ROLE: Recorder. Call read_campaign once and write the record an auditor
will read: what was revoked and on what evidence, what was abstained and
precisely what is missing, and what could not be certified at all and why.
Be brief and concrete. If nothing was certified, say so plainly and give the
reason — never round an abstention up to a pass.""",
}


# --------------------------------------------------------------- the tools

def _guarded(role, tool_name, fn):
    """Wrap a tool so the loop guard and the transcript see every call."""
    allowed, reason = _STATE["guard"].check(role, tool_name, {})
    if not allowed:
        _STATE["events"].append({"role": role, "kind": "refused",
                                 "tool": tool_name})
        return {"refused": reason}
    _STATE["events"].append({"role": role, "kind": "call", "tool": tool_name})
    result = fn()
    # Whatever the tool returned is, by definition, supported evidence —
    # including figures it computed rather than copied.
    _STATE["evidence"] = F.absorb(_STATE["evidence"], result)
    return result


def _compute_campaign():
    project = _STATE["project"]
    data, manifest = C.collect(project, _STATE["location"])
    agents, dup = inv.canonical_agents(data.get("agents"))
    tools = inv.declared_tools(data.get("mcp-servers"))
    principals = inv.iam_principals(data.get("iam") or {})
    umeta = data.get("usage_meta") or {}
    usage = V.observed_usage(data.get("usage"), principals, umeta.get("ok", False))
    audit = inv.audit_config(data.get("iam") or {})
    audit["window_days"] = umeta.get("window_days")
    audit["truncated"] = umeta.get("truncated", False)
    shadows = inv.shadow_candidates(data.get("run"), agents,
                                    data.get("card_probes"),
                                    data.get("project_number"))
    verdicts, tally = V.run_campaign(data, agents, tools, principals, shadows,
                                     usage, audit)
    _STATE.update({"data": data, "verdicts": verdicts, "audit": audit,
                   "usage": usage, "agents": agents, "tally": tally})
    _STATE["evidence"] = F.evidence_index(data, principals, usage, verdicts)
    _STATE["engine"] = {"tally": tally, "verdicts": len(verdicts)}
    return verdicts, tally


def survey_fleet() -> dict:
    """Inventory the project: agents, tools, MCP servers, identities and
    runtime workloads, plus the undecided subjects. Read-only."""
    def work():
        verdicts, tally = _compute_campaign()
        return {
            "tally": tally,
            "subjects": len(verdicts),
            "agents": len(_STATE["agents"]),
            "mcp_servers": len(_STATE["data"].get("mcp-servers") or []),
            "tools": len(inv.declared_tools(_STATE["data"].get("mcp-servers"))),
            "identities": len(inv.iam_principals(_STATE["data"].get("iam") or {})),
            "runtime_workloads": len(_STATE["data"].get("run") or []),
            "undecided": [v["subject"] for v in verdicts
                          if v["verdict"] == V.ABSTAIN][:25],
        }
    return _guarded(F.SURVEYOR, "survey_fleet", work)


def investigate_gaps() -> dict:
    """Attempt every evidence gap that has a route. One pass. Reports what was
    obtained, what came back empty, and what failed. Read-only."""
    def work():
        verdicts = _STATE.get("verdicts")
        if not verdicts:
            return {"error": "the fleet has not been surveyed yet"}
        run_urls = {}
        for s in (_STATE["data"].get("run") or []):
            name = (s.get("metadata") or {}).get("name")
            urls, _ = inv.run_service_urls(s, _STATE["data"].get("project_number"))
            if name:
                run_urls[name] = sorted(urls)
        log = R.run(verdicts, CL.build(_STATE["project"], _STATE["location"],
                                       run_urls))
        _STATE["log"] = log
        return {"summary": R.summarise(log),
                "attempts": [{"subject": a["subject"], "gap": a["gap"],
                              "outcome": a["outcome"], "note": a["note"]}
                             for a in log],
                "no_route": R.unclosable_report(verdicts)}
    return _guarded(F.INVESTIGATOR, "investigate_gaps", work)


def read_campaign() -> dict:
    """Read the decided verdicts and the certification blockers. Cannot change
    anything."""
    def work():
        verdicts = _STATE.get("verdicts")
        if not verdicts:
            return {"error": "the fleet has not been surveyed yet"}
        usage, audit = _STATE["usage"], _STATE["audit"]
        return {
            "tally": _STATE["tally"],
            "certify_reachable": V.certify_reachable(usage, audit),
            "certification_blockers": V.certification_blockers(usage, audit),
            "revoked": [{"subject": v["subject"], "rule": v["rule"],
                         "evidence": [e["claim"] for e in v["evidence"]]}
                        for v in verdicts if v["verdict"] == V.REVOKE],
            "abstained": [{"subject": v["subject"], "rule": v["rule"],
                           "missing": [g["detail"] for g in v["missing_evidence"]]}
                          for v in verdicts if v["verdict"] == V.ABSTAIN][:25],
        }
    return _guarded(F.RECORDER, "read_campaign", work)


TOOL_FNS = {"survey_fleet": survey_fleet,
            "investigate_gaps": investigate_gaps,
            "read_campaign": read_campaign}


def build_role(role):
    from google.adk.agents import Agent
    return Agent(
        name="muster_%s" % role,
        model=MODEL,
        description=F.ROLE_PURPOSE[role],
        instruction=INSTRUCTIONS[role],
        tools=[TOOL_FNS[t] for t in F.tools_for(role)],
    )


# ---------------------------------------------------------- the coordinator

async def _run_role(role, ask):
    from google.adk import Runner
    from google.adk.sessions import InMemorySessionService
    runner = Runner(agent=build_role(role), app_name="muster_%s" % role,
                    session_service=InMemorySessionService())
    result = runner.run_debug(ask)
    events = await result if inspect.iscoroutine(result) else result
    out = []
    for e in events:
        content = getattr(e, "content", None)
        for part in (getattr(content, "parts", None) or []):
            if getattr(part, "text", None):
                out.append(part.text)
    return "\n".join(out)


def _checked(role, text, ignore):
    """Strip nothing silently: report unsupported claims and record them."""
    bad = F.verify_claims(text, _STATE["evidence"], ignore_numbers=ignore)
    for b in bad:
        _STATE["events"].append({"role": role, "kind": "unsupported_claim",
                                 "token": b["token"]})
    return bad


async def _campaign(ask):
    state, transcript = {}, []
    ignore = tuple(str(n) for n in range(0, 11))
    while True:
        role = F.route(state)
        if role is None:
            break
        try:
            text = await asyncio.wait_for(_run_role(role, ask), timeout=180)
        except Exception as e:
            return F.degrade("%s failed: %s: %s" % (role, type(e).__name__, e),
                             _STATE.get("engine") or {}), transcript
        bad = _checked(role, text, ignore)
        transcript.append({"role": role, "text": text, "unsupported": bad})
        state["%s%s" % ({F.SURVEYOR: "survey", F.INVESTIGATOR: "investigat",
                         F.RECORDER: "record"}[role], "ed")] = True
    return {"degraded": False, "campaign": _STATE.get("engine")}, transcript


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True)
    ap.add_argument("--location", default="global")
    ap.add_argument("--ask", default="Do your part of the certification "
                                     "campaign on this project.")
    a = ap.parse_args()
    _STATE["project"] = a.project
    _STATE["location"] = a.location
    _STATE["guard"] = F.LoopGuard(limit=3)

    path, keys = envload.load(os.path.join(HERE, ".."))
    print("env: %s" % envload.describe(path, keys))
    if not os.environ.get("GOOGLE_API_KEY"):
        print("GOOGLE_API_KEY is not set. The fleet needs it to reach the "
              "model; the rule engine does not.")
        return 2

    result, transcript = asyncio.run(_campaign(a.ask))

    for entry in transcript:
        print("\n" + "=" * 66)
        print("%s  —  %s" % (entry["role"].upper(), F.ROLE_PURPOSE[entry["role"]]))
        print("=" * 66)
        print(entry["text"])
        if entry["unsupported"]:
            print("\n  !! UNSUPPORTED CLAIMS, stripped from the record:")
            for u in entry["unsupported"]:
                print("     %s (%s) — not present in the measured evidence"
                      % (u["token"], u["kind"]))

    print("\n" + "=" * 66)
    print("FLEET TRANSCRIPT")
    print("=" * 66)
    for role, s in F.transcript_summary(_STATE["events"]).items():
        print("  %-13s calls %d  refused %d  unsupported claims %d"
              % (role, s["calls"], s["refused"], s["unsupported"]))
    if _STATE["guard"].refusals:
        print("\n  loop guard refusals:")
        for r in _STATE["guard"].refusals:
            print("    %s" % r["reason"])
    if result.get("degraded"):
        print("\n  DEGRADED: %s" % result["reason"])
        print("  Verdicts are unaffected — the rule engine had already "
              "decided them.")
    print("\n  engine result: %s" % json.dumps(_STATE.get("engine") or {}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
