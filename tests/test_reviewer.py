"""The reviewer loop: try what can be tried, record what happened, never
pretend a failure was an answer."""
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
FIX = os.path.join(ROOT, "fixtures")

import inventory as inv  # noqa: E402
import verdict as V  # noqa: E402
import reviewer as R  # noqa: E402


def fx(name):
    with open(os.path.join(FIX, name)) as f:
        return json.load(f)


def campaign():
    data = {"mcp-servers": fx("mcp-servers.json")}
    agents, dup = inv.canonical_agents(fx("agents.json"))
    tools = inv.declared_tools(fx("mcp-servers.json"))
    principals = inv.iam_principals(fx("iam.json"))
    shadows = inv.shadow_candidates(fx("run.json"), agents)
    return V.run_campaign(data, agents, tools, principals, shadows)[0]


class TestPlanOnlyIncludesReachableWork(unittest.TestCase):
    def test_uncloseable_gaps_are_never_planned(self):
        items = R.plan(campaign())
        for i in items:
            self.assertIsNotNone(i["action"])
            self.assertNotIn(i["gap"], (V.GAP_OBSERVATION_WINDOW,
                                        V.GAP_AGENT_IDENTITY,
                                        V.GAP_NO_DESCRIPTION,
                                        V.GAP_UNDECLARED_CAPABILITY,
                                        V.GAP_AUDIT_LOGGING_OFF))

    def test_revoked_and_certified_subjects_are_not_planned(self):
        verdicts = campaign()
        planned = {i["subject"] for i in R.plan(verdicts)}
        for v in verdicts:
            if v["verdict"] != V.ABSTAIN:
                self.assertNotIn(v["subject"], planned)

    def test_every_planned_item_carries_the_tool_to_run(self):
        for i in R.plan(campaign()):
            self.assertTrue(i["action"])
            self.assertTrue(i["detail"])

    def test_an_empty_campaign_plans_nothing(self):
        self.assertEqual(R.plan([]), [])


class TestOutcomesStayDistinct(unittest.TestCase):
    """empty is an answer. failed is not. Collapsing them is the bug this
    whole project exists to avoid."""

    ITEM = {"subject": "s", "kind": "registry_agent", "gap": V.GAP_TOOL_BINDINGS,
            "action": "agent-registry bindings list", "detail": "d"}

    def test_a_tool_returning_nothing_is_empty_and_that_closes_it(self):
        a = R.attempt(self.ITEM, {V.GAP_TOOL_BINDINGS: lambda s, i: (True, [], None)})
        self.assertEqual(a["outcome"], R.EMPTY)
        self.assertIn("which is the answer", a["note"])

    def test_a_tool_that_errors_is_failed_not_empty(self):
        a = R.attempt(self.ITEM,
                      {V.GAP_TOOL_BINDINGS: lambda s, i: (False, None, "403")})
        self.assertEqual(a["outcome"], R.FAILED)
        self.assertEqual(a["note"], "403")

    def test_a_closer_that_raises_is_recorded_not_propagated(self):
        def boom(s, i):
            raise RuntimeError("network gone")
        a = R.attempt(self.ITEM, {V.GAP_TOOL_BINDINGS: boom})
        self.assertEqual(a["outcome"], R.FAILED)
        self.assertIn("RuntimeError", a["note"])
        self.assertIn("network gone", a["note"])

    def test_a_missing_closer_is_its_own_outcome(self):
        a = R.attempt(self.ITEM, {})
        self.assertEqual(a["outcome"], R.NO_CLOSER)

    def test_real_evidence_is_obtained(self):
        a = R.attempt(self.ITEM,
                      {V.GAP_TOOL_BINDINGS: lambda s, i: (True, [{"tool": "x"}], "ok")})
        self.assertEqual(a["outcome"], R.OBTAINED)
        self.assertEqual(a["evidence"], [{"tool": "x"}])

    def test_failed_and_no_closer_both_stay_unmeasured(self):
        log = [R.attempt(self.ITEM, {}),
               R.attempt(self.ITEM, {V.GAP_TOOL_BINDINGS: lambda s, i: (False, None, "x")}),
               R.attempt(self.ITEM, {V.GAP_TOOL_BINDINGS: lambda s, i: (True, [], None)})]
        s = R.summarise(log)
        self.assertEqual(len(s["still_unmeasured"]), 2)
        self.assertEqual(len(s["resolved"]), 1)


class TestAClosersScopeIsHonest(unittest.TestCase):
    """Looking in the wrong place is not the same as looking and finding
    nothing. A closer that cannot apply must FAIL, never return empty."""

    def test_usage_closer_refuses_a_non_principal_subject(self):
        import closers as CL
        ok, payload, note = CL._usage_reread(
            "pubsub.googleapis.com",
            {"kind": "mcp_server"}, project="p")
        self.assertFalse(ok)
        self.assertIsNone(payload)
        self.assertIn("keyed by principal", note)
        self.assertIn("mcp_server", note)

    def test_that_refusal_records_as_failed_not_empty(self):
        import closers as CL
        item = {"subject": "pubsub.googleapis.com", "kind": "mcp_server",
                "gap": V.GAP_USAGE_EVIDENCE, "action": "x", "detail": "d"}
        a = R.attempt(item, {V.GAP_USAGE_EVIDENCE:
                             lambda s, i: CL._usage_reread(s, i, project="p")})
        self.assertEqual(a["outcome"], R.FAILED)
        self.assertNotEqual(a["outcome"], R.EMPTY)

    def test_a_missing_kind_is_also_refused(self):
        import closers as CL
        ok, _, note = CL._usage_reread("x", {}, project="p")
        self.assertFalse(ok)
        self.assertIn("non-principal", note)


class TestOnePassNotARetryLoop(unittest.TestCase):
    def test_each_gap_is_attempted_once(self):
        calls = []

        def counter(s, i):
            calls.append(s)
            return False, None, "still broken"
        log = R.run(campaign(), {k: counter for k in V.GAP_ACTIONS})
        self.assertEqual(len(calls), len(log))
        self.assertEqual(len(calls), len(set(
            (a["subject"], a["gap"]) for a in log)))

    def test_max_attempts_is_respected(self):
        log = R.run(campaign(), {k: lambda s, i: (True, [], None)
                                 for k in V.GAP_ACTIONS}, max_attempts=1)
        self.assertLessEqual(len(log), 1)


class TestTheAuditorFacingOutput(unittest.TestCase):
    def test_unclosable_report_groups_by_obstacle(self):
        rep = R.unclosable_report(campaign())
        self.assertTrue(rep)
        for reason, subjects in rep.items():
            self.assertTrue(reason)
            self.assertTrue(subjects)
            self.assertEqual(subjects, sorted(set(subjects)))

    def test_render_names_what_was_tried_and_what_cannot_be(self):
        verdicts = campaign()
        log = R.run(verdicts, {V.GAP_TOOL_BINDINGS: lambda s, i: (True, [], None)})
        text = R.render(log, R.unclosable_report(verdicts))
        self.assertIn("EVIDENCE GATHERING", text)
        self.assertIn("NOT ATTEMPTED — no route exists", text)
        self.assertIn("tried  agent-registry bindings list", text)

    def test_render_survives_an_empty_log(self):
        text = R.render([], {})
        self.assertIn("0 attempt(s)", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)


def _adk_available():
    try:
        import google.adk  # noqa: F401
        return True
    except Exception:
        return False


class TestTheModelCannotReachAVerdict(unittest.TestCase):
    """The architectural claim, enforced as a test rather than asserted in a
    README. If a tool ever accepts or returns a verdict, this fails."""

    def _tools(self):
        sys.path.insert(0, os.path.join(ROOT, "agent"))
        import reviewer_agent as RA
        return RA, [RA.run_campaign, RA.gather_evidence]

    def test_no_tool_accepts_an_argument_at_all(self):
        import inspect
        _, tools = self._tools()
        for t in tools:
            self.assertEqual(list(inspect.signature(t).parameters), [],
                             "%s takes input the model could steer" % t.__name__)

    def test_no_tool_name_suggests_deciding(self):
        _, tools = self._tools()
        for t in tools:
            for banned in ("certify", "revoke", "approve", "decide", "verdict",
                           "override", "set_"):
                self.assertNotIn(banned, t.__name__.lower())

    @unittest.skipUnless(_adk_available(),
                         "google-adk not installed in this interpreter; the "
                         "rest of the suite stays dependency-free on purpose")
    def test_the_agent_has_exactly_the_two_readonly_tools(self):
        RA, _ = self._tools()
        agent = RA.build_agent()
        self.assertEqual(sorted(t.__name__ for t in agent.tools),
                         ["gather_evidence", "run_campaign"])

    def test_the_instruction_forbids_claiming_certification(self):
        RA, _ = self._tools()
        self.assertIn("Never call something certified", RA.INSTRUCTION)
        self.assertIn("absence of evidence is not evidence of absence",
                      RA.INSTRUCTION)

    @unittest.skipUnless(_adk_available(), "google-adk not installed")
    def test_the_runner_entrypoint_is_handled_for_what_it_actually_is(self):
        """run_debug annotates `-> list[Event]` but is `async def`. The
        annotation lied; iscoroutinefunction did not. If a future ADK flips
        it either way, main() detects instead of assuming — but this test
        records what was measured so the drift is visible."""
        import inspect as I
        from google.adk import Runner
        self.assertTrue(I.iscoroutinefunction(Runner.run_debug))
        RA, _ = self._tools()
        src = I.getsource(RA.main)
        self.assertIn("iscoroutine", src)
        self.assertIn("asyncio.run", src)

    def test_the_model_string_meets_the_hackathon_floor(self):
        RA, _ = self._tools()
        self.assertTrue(RA.MODEL.startswith("gemini-3."))
