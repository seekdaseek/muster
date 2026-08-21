#!/usr/bin/env python3
"""muster's reviewer agent.

An ADK agent that runs a certification campaign over a Google Cloud project.

THE CONSTRAINT THAT MAKES THIS DEFENSIBLE: the model has no tool that returns
a verdict, and no tool that accepts one. It can inspect the fleet, read the
campaign result, attempt to close evidence gaps, and explain what happened.
Verdicts are computed in src/verdict.py by deterministic rules over measured
evidence, before and after the model does anything.

A reviewer that can be persuaded is not a reviewer.

    python3 agent/reviewer_agent.py --project PROJECT_ID
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
import envload  # noqa: E402
import collect as C  # noqa: E402
import inventory as inv  # noqa: E402
import reviewer as R  # noqa: E402
import verdict as V  # noqa: E402

MODEL = "gemini-3.5-flash"

INSTRUCTION = """You are muster's reviewer agent. You run access certification
campaigns over an organisation's AI agents, tools and identities.

You do not decide verdicts. A deterministic rule engine does that, over
evidence, and you cannot change its output. Your job is to run a campaign,
look at what it could not decide, go and fetch the missing evidence where a
route exists, run it again, and explain the result plainly.

Work in this order:
1. run_campaign to get the current state.
2. Read the abstentions. Some name gaps that can be closed, some name gaps
   that cannot.
3. gather_evidence to attempt every closeable gap. One pass. Do not ask for
   a second: a closer that failed will fail again.
4. run_campaign again and compare.
5. Report: what is REVOKE and on what evidence, what remains ABSTAIN and
   precisely what is missing, and what could not be certified at all and why.

Rules for how you speak:
- Never call something certified. If the engine did not certify it, it is not
  certified, and saying otherwise is the failure this system exists to prevent.
- An absence of evidence is not evidence of absence. If a record is
  incomplete or the observation window is short, say so rather than treating
  silence as a clean result.
- When you could not obtain something, say what you tried and what stopped
  you. Do not round it to "no issues found".
- Be brief. An auditor reads this."""

_STATE = {"project": None, "location": "global", "data": None,
          "verdicts": None, "log": None}


def run_campaign() -> dict:
    """Collect the project's current state and compute a verdict for every
    subject. Returns tallies, the abstention reasons, and what blocks
    certification. Does not modify anything."""
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
                   "usage": usage, "agents": agents})
    return {
        "tally": tally,
        "certify_reachable": V.certify_reachable(usage, audit),
        "certification_blockers": V.certification_blockers(usage, audit),
        "revoked": [{"subject": v["subject"], "rule": v["rule"],
                     "evidence": [e["claim"] for e in v["evidence"]]}
                    for v in verdicts if v["verdict"] == V.REVOKE],
        "abstained": [{"subject": v["subject"], "rule": v["rule"],
                       "missing": [g["detail"] for g in v["missing_evidence"]]}
                      for v in verdicts if v["verdict"] == V.ABSTAIN][:25],
        "closeable_gaps": len(R.plan(verdicts)),
    }


def gather_evidence() -> dict:
    """Attempt to close every evidence gap that has a route. One pass only.
    Returns what was obtained, what came back empty (which is an answer), and
    what failed (which is not). Read-only."""
    verdicts = _STATE.get("verdicts")
    if not verdicts:
        return {"error": "run_campaign first"}
    run_urls = {}
    for s in (_STATE["data"].get("run") or []):
        name = (s.get("metadata") or {}).get("name")
        urls, _ = inv.run_service_urls(s, _STATE["data"].get("project_number"))
        if name:
            run_urls[name] = sorted(urls)
    log = R.run(verdicts, CL.build(_STATE["project"], _STATE["location"], run_urls))
    _STATE["log"] = log
    return {
        "summary": R.summarise(log),
        "attempts": [{"subject": a["subject"], "gap": a["gap"],
                      "outcome": a["outcome"], "note": a["note"]} for a in log],
        "no_route": R.unclosable_report(verdicts),
    }


def build_agent():
    from google.adk.agents import Agent
    return Agent(
        name="muster_reviewer",
        model=MODEL,
        description="Runs agent access certification campaigns.",
        instruction=INSTRUCTION,
        tools=[run_campaign, gather_evidence],
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True)
    ap.add_argument("--location", default="global")
    ap.add_argument("--ask", default="Run a certification campaign on this "
                                      "project and report what you find.")
    a = ap.parse_args()
    _STATE["project"] = a.project
    _STATE["location"] = a.location

    # The API key lives in a .env beside the working directory, not in the
    # repo. Load it by name only — the value never reaches stdout.
    path, keys = envload.load(os.path.join(HERE, ".."))
    print("env: %s" % envload.describe(path, keys))
    if not os.environ.get("GOOGLE_API_KEY"):
        print("GOOGLE_API_KEY is not set. The agent needs it to reach the "
              "model; the rest of muster does not.")
        return 2

    from google.adk import Runner
    from google.adk.sessions import InMemorySessionService

    runner = Runner(agent=build_agent(), app_name="muster",
                    session_service=InMemorySessionService())

    # MEASURED against google-adk 2.7.1: run_debug is `async def` even though
    # it annotates `-> list[Event]`. inspect.signature does not reveal that;
    # inspect.iscoroutinefunction does. Detect rather than assume, so a
    # future ADK that makes it synchronous keeps working.
    result = runner.run_debug(a.ask)
    events = asyncio.run(result) if inspect.iscoroutine(result) else result
    for e in events:
        content = getattr(e, "content", None)
        for part in (getattr(content, "parts", None) or []):
            if getattr(part, "text", None):
                print(part.text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
