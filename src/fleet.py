"""muster's fleet orchestration.

Three specialised reviewer agents, a deterministic coordinator, and the
machinery that makes a worker agent's failure survivable.

SEPARATION OF CONCERNS IS ENFORCED, NOT REQUESTED. Each role owns a disjoint
set of tools. The Surveyor cannot fetch evidence. The Investigator cannot
inventory. The Recorder cannot do either — it only reads what the rule engine
already decided. A prompt asking an agent to stay in its lane is a suggestion;
a tool it does not possess is a wall.

FAILURE TOLERANCE, the three ways a worker goes wrong:

  it loops        LoopGuard refuses a tool call it has already served with
                  identical arguments, and the refusal is recorded.
  it invents      verify_claims() checks every identifier and number in the
                  worker's prose against the measured evidence. Anything not
                  found is flagged UNSUPPORTED and does not reach the record.
  it dies         the campaign degrades to the deterministic engine output.
                  No verdict has ever depended on a worker succeeding.

The last one is the important one. The agents make the report readable. They
were never what made it true.
"""
import re

SURVEYOR, INVESTIGATOR, RECORDER = "surveyor", "investigator", "recorder"

# Disjoint by construction. Tested, not trusted.
ROLE_TOOLS = {
    SURVEYOR: ("survey_fleet",),
    INVESTIGATOR: ("investigate_gaps",),
    RECORDER: ("read_campaign",),
}

ROLE_PURPOSE = {
    SURVEYOR: "inventory the fleet and hand over what exists",
    INVESTIGATOR: "attempt to close evidence gaps that have a route",
    RECORDER: "write the auditor-facing record from decided verdicts",
}


def tools_are_disjoint():
    """No tool may be reachable from two roles."""
    seen = set()
    for tools in ROLE_TOOLS.values():
        for t in tools:
            if t in seen:
                return False
            seen.add(t)
    return True


def tools_for(role):
    return list(ROLE_TOOLS.get(role, ()))


def role_of(tool):
    for role, tools in ROLE_TOOLS.items():
        if tool in tools:
            return role
    return None


class LoopGuard:
    """Refuses a repeat of a call already served, per worker.

    An agent that calls the same tool with the same arguments twice is not
    making progress; it is spending turns. The second call is refused with a
    reason the agent can read, and the refusal is recorded so the transcript
    shows it happened rather than hiding it.
    """

    def __init__(self, limit=3):
        self.limit = limit
        self.seen = {}
        self.refusals = []

    @staticmethod
    def signature(role, tool, args):
        return "%s|%s|%s" % (role, tool, repr(sorted((args or {}).items())))

    def check(self, role, tool, args=None):
        """(allowed, reason). Reason is None when allowed."""
        sig = self.signature(role, tool, args)
        count = self.seen.get(sig, 0)
        if count >= 1:
            reason = ("%s already called %s with these arguments; a repeat "
                      "cannot return anything new" % (role, tool))
            self.refusals.append({"role": role, "tool": tool, "reason": reason})
            return False, reason
        total = sum(self.seen.values())
        if total >= self.limit:
            reason = ("%s has used its %d tool calls for this campaign"
                      % (role, self.limit))
            self.refusals.append({"role": role, "tool": tool, "reason": reason})
            return False, reason
        self.seen[sig] = count + 1
        return True, None


# Tokens worth checking: identifiers a worker could invent, and integers it
# could miscount. Ordinary prose is left alone — this is a conservative check
# over things that must have come from evidence, not a semantic truth test.
_IDENT = re.compile(
    r"""(
        [A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+          # emails / service accounts
      | urn:[A-Za-z0-9:._-]+                      # URNs
      | https?://[^\s`'"),]+                      # URLs
      | roles/[A-Za-z0-9._]+                      # IAM roles
    )""", re.VERBOSE)
_NUMBER = re.compile(r"(?<![\w.])(\d{1,9})(?![\w.])")


def evidence_index(*sources):
    """A flat set of every string and number the measured evidence contains."""
    index = set()

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                index.add(str(k))
                walk(v)
        elif isinstance(node, (list, tuple, set)):
            for v in node:
                walk(v)
        elif node is None or isinstance(node, bool):
            return
        else:
            index.add(str(node))

    for s in sources:
        walk(s)
    return index


def absorb(index, result):
    """Fold a tool's RETURN VALUE into the evidence index.

    Necessary, and the reason is a real bug this caught: a tool that COMPUTES
    a figure — a count, a total, a percentage — returns a number that appears
    nowhere in the raw sources it was derived from. Indexing only the sources
    flags the agent for correctly repeating its own tool's output.

    "Supported" must mean "came back from a tool or was measured", because
    that is exactly what the agents are instructed to confine themselves to.
    """
    index |= evidence_index(result)
    return index


def verify_claims(text, index, ignore_numbers=()):
    """Identifiers and numbers in `text` that the evidence does not contain.

    Conservative on purpose. A token counts as supported if it appears
    anywhere in the measured evidence, as a whole value or inside one. Small
    numbers that are ordinary prose ("the three findings") are not evidence
    claims, so callers may ignore a set of them.

    This does not detect a false statement built entirely from true tokens.
    It detects the thing a language model actually does wrong under pressure:
    producing an identifier or a count that was never measured.
    """
    haystack = "\n".join(sorted(index))
    unsupported = []
    for match in _IDENT.finditer(text or ""):
        token = match.group(1).rstrip(".,;:)")
        if token not in haystack:
            unsupported.append({"token": token, "kind": "identifier"})
    for match in _NUMBER.finditer(text or ""):
        token = match.group(1)
        if token in ignore_numbers:
            continue
        if token not in haystack:
            unsupported.append({"token": token, "kind": "number"})
    seen, out = set(), []
    for u in unsupported:
        if u["token"] in seen:
            continue
        seen.add(u["token"])
        out.append(u)
    return out


def route(state):
    """Which role acts next. Deterministic — the coordinator is not a model.

    Order is forced by dependency, not preference: nothing can be
    investigated before the fleet is known, and nothing can be recorded
    before investigation has had its one pass.
    """
    if not state.get("surveyed"):
        return SURVEYOR
    if not state.get("investigated"):
        return INVESTIGATOR
    if not state.get("recorded"):
        return RECORDER
    return None


def degrade(reason, engine_output):
    """What the campaign returns when a worker agent cannot be used.

    The deterministic result is not a consolation prize; it is the actual
    answer. The agents were only ever going to describe it.
    """
    return {
        "degraded": True,
        "reason": reason,
        "verdicts_unaffected": True,
        "campaign": engine_output,
    }


def transcript_summary(events):
    """What each role did, for the record an auditor reads."""
    out = {}
    for e in events:
        role = e.get("role", "unknown")
        entry = out.setdefault(role, {"calls": 0, "refused": 0, "unsupported": 0,
                                      "purpose": ROLE_PURPOSE.get(role, "")})
        if e.get("kind") == "call":
            entry["calls"] += 1
        elif e.get("kind") == "refused":
            entry["refused"] += 1
        elif e.get("kind") == "unsupported_claim":
            entry["unsupported"] += 1
    return out
