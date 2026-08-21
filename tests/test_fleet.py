"""The fleet: three roles that cannot reach into each other's work, and a
campaign that survives any of them failing."""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import fleet as F  # noqa: E402


class TestSeparationIsEnforcedNotRequested(unittest.TestCase):
    def test_no_tool_is_reachable_from_two_roles(self):
        self.assertTrue(F.tools_are_disjoint())

    def test_the_surveyor_cannot_gather_evidence(self):
        self.assertNotIn("investigate_gaps", F.tools_for(F.SURVEYOR))

    def test_the_investigator_cannot_inventory(self):
        self.assertNotIn("survey_fleet", F.tools_for(F.INVESTIGATOR))

    def test_the_recorder_can_only_read(self):
        self.assertEqual(F.tools_for(F.RECORDER), ["read_campaign"])
        self.assertNotIn("survey_fleet", F.tools_for(F.RECORDER))
        self.assertNotIn("investigate_gaps", F.tools_for(F.RECORDER))

    def test_every_tool_traces_back_to_exactly_one_role(self):
        for role, tools in F.ROLE_TOOLS.items():
            for t in tools:
                self.assertEqual(F.role_of(t), role)
        self.assertIsNone(F.role_of("set_verdict"))

    def test_every_role_has_a_stated_purpose(self):
        for role in F.ROLE_TOOLS:
            self.assertTrue(F.ROLE_PURPOSE[role])


class TestAWorkerThatLoops(unittest.TestCase):
    def test_the_same_call_twice_is_refused(self):
        g = F.LoopGuard()
        ok, reason = g.check(F.SURVEYOR, "survey_fleet", {})
        self.assertTrue(ok)
        self.assertIsNone(reason)
        ok, reason = g.check(F.SURVEYOR, "survey_fleet", {})
        self.assertFalse(ok)
        self.assertIn("cannot return anything new", reason)

    def test_the_refusal_is_recorded_not_hidden(self):
        g = F.LoopGuard()
        g.check(F.SURVEYOR, "survey_fleet", {})
        g.check(F.SURVEYOR, "survey_fleet", {})
        self.assertEqual(len(g.refusals), 1)
        self.assertEqual(g.refusals[0]["tool"], "survey_fleet")

    def test_different_arguments_are_not_a_loop(self):
        g = F.LoopGuard()
        self.assertTrue(g.check(F.INVESTIGATOR, "investigate_gaps", {"a": 1})[0])
        self.assertTrue(g.check(F.INVESTIGATOR, "investigate_gaps", {"a": 2})[0])

    def test_a_total_call_budget_stops_a_creative_loop(self):
        """An agent that varies its arguments forever still runs out."""
        g = F.LoopGuard(limit=2)
        self.assertTrue(g.check(F.INVESTIGATOR, "investigate_gaps", {"a": 1})[0])
        self.assertTrue(g.check(F.INVESTIGATOR, "investigate_gaps", {"a": 2})[0])
        ok, reason = g.check(F.INVESTIGATOR, "investigate_gaps", {"a": 3})
        self.assertFalse(ok)
        self.assertIn("tool calls for this campaign", reason)

    def test_signatures_ignore_argument_order(self):
        a = F.LoopGuard.signature("r", "t", {"x": 1, "y": 2})
        b = F.LoopGuard.signature("r", "t", {"y": 2, "x": 1})
        self.assertEqual(a, b)


class TestAWorkerThatInvents(unittest.TestCase):
    def setUp(self):
        self.index = F.evidence_index(
            {"principals": {
                "serviceAccount:000000000000-compute@developer.gserviceaccount.com":
                    ["roles/editor"]},
             "agents": [{"agentId": "urn:agent:googleapis.com:x",
                         "url": "https://invoice-triage-f43zg6mqya-uc.a.run.app"}],
             "counts": {"tools": 177, "servers": 15}})

    def test_a_real_identifier_is_supported(self):
        out = F.verify_claims(
            "The account serviceAccount:000000000000-compute@developer."
            "gserviceaccount.com holds roles/editor.", self.index)
        self.assertEqual(out, [])

    def test_an_invented_service_account_is_caught(self):
        out = F.verify_claims(
            "We also found serviceAccount:ghost@fake.gserviceaccount.com.",
            self.index)
        # The email is the identifier; "serviceAccount:" is a type marker.
        self.assertEqual([u["token"] for u in out],
                         ["ghost@fake.gserviceaccount.com"])

    def test_a_bare_email_matches_a_prefixed_one_in_evidence(self):
        """Evidence stores serviceAccount:x@y; a worker writing the bare
        email must still count as supported."""
        self.assertEqual(F.verify_claims(
            "000000000000-compute@developer.gserviceaccount.com is over-broad.",
            self.index), [])

    def test_a_count_a_tool_computed_is_supported_after_absorb(self):
        """THE FALSE POSITIVE THAT CAUGHT US: a tool returns {"tools": 177}.
        177 appears nowhere in the raw records it was counted from, so
        indexing only the sources flags the agent for repeating its own
        tool's output correctly."""
        sources = F.evidence_index({"mcp": [{"name": "a"}, {"name": "b"}]})
        self.assertNotEqual(F.verify_claims("There are 177 tools.", sources), [])
        after = F.absorb(sources, {"tools": 177, "servers": 15})
        self.assertEqual(F.verify_claims("There are 177 tools.", after), [])

    def test_absorb_does_not_launder_a_number_no_tool_returned(self):
        sources = F.evidence_index({"a": 1})
        after = F.absorb(sources, {"tools": 177})
        self.assertEqual([u["token"] for u in
                          F.verify_claims("There are 942 tools.", after)],
                         ["942"])

    def test_absorb_returns_the_same_set_it_was_given(self):
        idx = F.evidence_index({"a": 1})
        self.assertIs(F.absorb(idx, {"b": 2}), idx)

    def test_absorb_handles_an_empty_or_odd_result(self):
        idx = F.evidence_index({"a": 1})
        F.absorb(idx, {})
        F.absorb(idx, None)
        F.absorb(idx, [])
        self.assertIn("1", idx)

    def test_an_invented_count_is_caught(self):
        out = F.verify_claims("There are 942 tools across 15 servers.", self.index)
        self.assertEqual([u["token"] for u in out], ["942"])

    def test_a_real_count_is_supported(self):
        self.assertEqual(F.verify_claims("177 tools, 15 servers.", self.index), [])

    def test_an_invented_url_is_caught(self):
        out = F.verify_claims("Running at https://evil.example.com/x", self.index)
        self.assertTrue(any("evil.example.com" in u["token"] for u in out))

    def test_an_invented_role_is_caught(self):
        out = F.verify_claims("It holds roles/owner and roles/editor.", self.index)
        self.assertEqual([u["token"] for u in out], ["roles/owner"])

    def test_trailing_punctuation_does_not_create_a_false_positive(self):
        self.assertEqual(F.verify_claims("It holds roles/editor.", self.index), [])

    def test_prose_numbers_can_be_ignored_by_the_caller(self):
        out = F.verify_claims("There are 3 findings.", self.index,
                              ignore_numbers=("3",))
        self.assertEqual(out, [])

    def test_each_bad_token_is_reported_once(self):
        out = F.verify_claims("942 and 942 and 942.", self.index)
        self.assertEqual(len(out), 1)

    def test_empty_text_is_not_an_error(self):
        self.assertEqual(F.verify_claims("", self.index), [])
        self.assertEqual(F.verify_claims(None, self.index), [])

    def test_the_index_survives_nested_and_empty_structures(self):
        idx = F.evidence_index({}, [], None, {"a": [{"b": [1, None, True]}]})
        self.assertIn("1", idx)
        self.assertIn("b", idx)


class TestRoutingIsDeterministic(unittest.TestCase):
    def test_the_order_is_forced_by_dependency(self):
        s = {}
        self.assertEqual(F.route(s), F.SURVEYOR)
        s["surveyed"] = True
        self.assertEqual(F.route(s), F.INVESTIGATOR)
        s["investigated"] = True
        self.assertEqual(F.route(s), F.RECORDER)
        s["recorded"] = True
        self.assertIsNone(F.route(s))

    def test_nothing_is_investigated_before_the_fleet_is_known(self):
        self.assertEqual(F.route({"investigated": True, "recorded": True}),
                         F.SURVEYOR)


class TestAWorkerThatDies(unittest.TestCase):
    def test_the_campaign_degrades_to_the_engine_result(self):
        out = F.degrade("investigator timed out", {"tally": {"REVOKE": 3}})
        self.assertTrue(out["degraded"])
        self.assertTrue(out["verdicts_unaffected"])
        self.assertEqual(out["campaign"]["tally"]["REVOKE"], 3)

    def test_the_reason_is_carried_not_swallowed(self):
        self.assertIn("timed out", F.degrade("investigator timed out", {})["reason"])


class TestTheTranscriptIsAuditable(unittest.TestCase):
    def test_calls_refusals_and_bad_claims_are_counted_per_role(self):
        events = [
            {"role": F.SURVEYOR, "kind": "call"},
            {"role": F.INVESTIGATOR, "kind": "call"},
            {"role": F.INVESTIGATOR, "kind": "refused"},
            {"role": F.RECORDER, "kind": "unsupported_claim"},
        ]
        s = F.transcript_summary(events)
        self.assertEqual(s[F.SURVEYOR]["calls"], 1)
        self.assertEqual(s[F.INVESTIGATOR]["refused"], 1)
        self.assertEqual(s[F.RECORDER]["unsupported"], 1)
        self.assertTrue(s[F.SURVEYOR]["purpose"])

    def test_an_empty_transcript_is_not_an_error(self):
        self.assertEqual(F.transcript_summary([]), {})


if __name__ == "__main__":
    unittest.main(verbosity=2)


def _adk_available():
    try:
        import google.adk  # noqa: F401
        return True
    except Exception:
        return False


class TestTheBuiltAgentsMatchTheDeclaredRoles(unittest.TestCase):
    """The separation is only real if the constructed agents honour it."""

    def _mod(self):
        sys.path.insert(0, os.path.join(ROOT, "agent"))
        import reviewer_fleet as AF
        return AF

    def test_no_tool_function_accepts_an_argument(self):
        import inspect
        AF = self._mod()
        for name, fn in AF.TOOL_FNS.items():
            self.assertEqual(list(inspect.signature(fn).parameters), [],
                             "%s takes input the model could steer" % name)

    def test_no_tool_name_suggests_deciding(self):
        AF = self._mod()
        for name in AF.TOOL_FNS:
            for banned in ("certify", "revoke", "approve", "decide", "verdict",
                           "override", "set_"):
                self.assertNotIn(banned, name.lower())

    def test_the_tool_registry_matches_the_role_map(self):
        AF = self._mod()
        self.assertEqual(sorted(AF.TOOL_FNS),
                         sorted(t for ts in F.ROLE_TOOLS.values() for t in ts))

    def test_every_role_has_an_instruction_that_forbids_inventing(self):
        AF = self._mod()
        for role in F.ROLE_TOOLS:
            # Normalise wrapping before matching — the instruction is
            # hard-wrapped prose, and asserting an exact substring against
            # it tests the line breaks, not the meaning.
            text = " ".join(AF.INSTRUCTIONS[role].split())
            self.assertIn("do not decide verdicts", text.lower())
            self.assertIn("checked against the measured evidence", text)
            self.assertIn("anything invented is stripped from the record", text)

    def test_the_investigator_is_told_empty_is_not_failed(self):
        AF = self._mod()
        text = " ".join(AF.INSTRUCTIONS[F.INVESTIGATOR].split())
        self.assertIn("Never report a failure as an empty result", text)

    def test_the_recorder_is_told_not_to_round_an_abstention_up(self):
        AF = self._mod()
        self.assertIn("never round an abstention up to a pass",
                      " ".join(AF.INSTRUCTIONS[F.RECORDER].split()))

    def test_the_model_meets_the_mandated_floor(self):
        self.assertTrue(self._mod().MODEL.startswith("gemini-3."))

    @unittest.skipUnless(_adk_available(), "google-adk not installed")
    def test_each_constructed_agent_holds_only_its_own_tools(self):
        AF = self._mod()
        for role in F.ROLE_TOOLS:
            agent = AF.build_role(role)
            self.assertEqual(sorted(t.__name__ for t in agent.tools),
                             sorted(F.tools_for(role)))

    @unittest.skipUnless(_adk_available(), "google-adk not installed")
    def test_no_two_constructed_agents_share_a_tool(self):
        AF = self._mod()
        owners = {}
        for role in F.ROLE_TOOLS:
            for t in AF.build_role(role).tools:
                owners.setdefault(t.__name__, []).append(role)
        for name, roles in owners.items():
            self.assertEqual(len(roles), 1,
                             "%s is reachable from %s" % (name, roles))
