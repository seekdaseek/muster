"""muster reviewer loop.

The agent's actual job. A campaign that just reports ABSTAIN is a report; a
reviewer goes and gets the missing evidence, then decides. This module runs
that loop deterministically so the language model orchestrates it rather than
performs it.

What the model may do: choose to run a campaign, call a closer, read results,
explain them.

What the model may NOT do: decide a verdict, or mark a gap closed. Closers
return evidence; the verdict engine re-runs over it. There is no code path
from a model output to a verdict.

Outcomes of a closure attempt, and the distinctions are the whole point:

  obtained    evidence came back and it says something
  empty       the tool ran and returned nothing, and nothing IS the answer
              (no bindings exist) — this closes the gap
  failed      the tool errored; the gap stays open and stays unmeasured
  no_closer   nothing can close this one; the agent must not retry it
"""
import verdict as V

OBTAINED, EMPTY, FAILED, NO_CLOSER = "obtained", "empty", "failed", "no_closer"


def plan(verdicts):
    """Every gap worth attempting, worst-blocked subjects first.

    Returns a list of work items. Uncloseable gaps are excluded here rather
    than attempted and skipped, so the agent never burns a turn on something
    that has no route.
    """
    items = []
    for v in verdicts:
        if v["verdict"] != V.ABSTAIN:
            continue
        for gap in V.closeable(v["missing_evidence"]):
            items.append({
                "subject": v["subject"],
                "kind": v["kind"],
                "gap": gap["kind"],
                "action": gap["action"],
                "detail": gap["detail"],
            })
    return items


def unclosable_report(verdicts):
    """What no amount of agent effort will fix, grouped by obstacle.

    An auditor reading a campaign needs to know the difference between "we
    did not look" and "there is nothing to look at".
    """
    out = {}
    for v in verdicts:
        for gap in v["missing_evidence"]:
            if gap.get("action"):
                continue
            reason = gap.get("blocked_by") or "no route to this evidence"
            out.setdefault(reason, []).append(v["subject"])
    return {k: sorted(set(vs)) for k, vs in sorted(out.items())}


def attempt(item, closers):
    """Run one closure attempt. Never raises; a failure is a recorded outcome."""
    closer = (closers or {}).get(item["gap"])
    if closer is None:
        return {**item, "outcome": NO_CLOSER, "evidence": None,
                "note": "no closer is registered for this gap"}
    try:
        ok, payload, note = closer(item["subject"], item)
    except Exception as e:  # a broken closer must not end the campaign
        return {**item, "outcome": FAILED, "evidence": None,
                "note": "closer raised %s: %s" % (type(e).__name__, e)}
    if not ok:
        return {**item, "outcome": FAILED, "evidence": None,
                "note": note or "closer reported failure"}
    if payload in (None, [], {}, ""):
        return {**item, "outcome": EMPTY, "evidence": payload,
                "note": note or "ran and returned nothing, which is the answer"}
    return {**item, "outcome": OBTAINED, "evidence": payload, "note": note}


def run(verdicts, closers, max_attempts=50):
    """Attempt every closeable gap once. Returns the attempt log.

    One pass, not a retry loop: a closer that failed will fail again, and an
    agent that keeps trying is burning turns to look busy.
    """
    log = []
    for item in plan(verdicts)[:max_attempts]:
        log.append(attempt(item, closers))
    return log


def summarise(log):
    counts = {OBTAINED: 0, EMPTY: 0, FAILED: 0, NO_CLOSER: 0}
    for a in log:
        counts[a["outcome"]] = counts.get(a["outcome"], 0) + 1
    return {
        "attempted": len(log),
        "counts": counts,
        # Gaps that moved from unknown to known, either way.
        "resolved": [a["subject"] for a in log
                     if a["outcome"] in (OBTAINED, EMPTY)],
        "still_unmeasured": [a["subject"] for a in log
                             if a["outcome"] in (FAILED, NO_CLOSER)],
    }


def render(log, unclosable):
    """The part an auditor reads: what was tried, and what cannot be tried."""
    L = []
    A = L.append
    s = summarise(log)
    A("EVIDENCE GATHERING   %d attempt(s)" % s["attempted"])
    A("  obtained %d   empty %d   failed %d   no closer %d"
      % (s["counts"][OBTAINED], s["counts"][EMPTY],
         s["counts"][FAILED], s["counts"][NO_CLOSER]))
    for a in log:
        A("  %-10s %s [%s]" % (a["outcome"], a["subject"], a["gap"]))
        A("      tried  %s" % a["action"])
        if a.get("note"):
            A("      result %s" % a["note"])
    if unclosable:
        A("")
        A("NOT ATTEMPTED — no route exists")
        for reason, subjects in unclosable.items():
            A("  %s" % reason)
            for sub in subjects[:6]:
                A("      %s" % sub)
            if len(subjects) > 6:
                A("      (+%d more)" % (len(subjects) - 6))
    return "\n".join(L)
