"""The verdict engine's one job: never certify without evidence."""
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
FIX = os.path.join(ROOT, "fixtures")

import inventory as inv  # noqa: E402
import verdict as V  # noqa: E402


def fx(name):
    with open(os.path.join(FIX, name)) as f:
        return json.load(f)


COMPLETE_AUDIT = {"complete": True, "data_read": True, "data_write": True,
                  "admin_activity": True, "window_days": 90}
FRESH_AUDIT = {"complete": True, "data_read": True, "data_write": True,
               "admin_activity": True, "window_days": 0}
DEFAULT_AUDIT = {"complete": False, "data_read": False, "data_write": False,
                 "admin_activity": True, "window_days": None}


def snapshot():
    data = {"mcp-servers": fx("mcp-servers.json")}
    agents, dup = inv.canonical_agents(fx("agents.json"))
    tools = inv.declared_tools(fx("mcp-servers.json"))
    principals = inv.iam_principals(fx("iam.json"))
    shadows = inv.shadow_candidates(fx("run.json"), agents)
    return data, agents, tools, principals, shadows


class TestCertifyIsHardToReach(unittest.TestCase):
    def test_no_usage_evidence_means_zero_certifications(self):
        data, agents, tools, principals, shadows = snapshot()
        verdicts, tally = V.run_campaign(data, agents, tools, principals, shadows)
        self.assertEqual(tally[V.CERTIFY], 0)

    def test_even_with_observations_a_default_project_certifies_nothing(self):
        data, agents, tools, principals, shadows = snapshot()
        usage = {m: [] for m in principals}
        _, tally = V.run_campaign(data, agents, tools, principals, shadows,
                                  usage, DEFAULT_AUDIT)
        self.assertEqual(tally[V.CERTIFY], 0)
        _, tally = V.run_campaign(data, agents, tools, principals, shadows,
                                  usage, FRESH_AUDIT)
        self.assertEqual(tally[V.CERTIFY], 0)

    def test_certify_needs_observations_AND_a_complete_record(self):
        u = {"user:a@b.com": ["roles/viewer"]}
        self.assertFalse(V.certify_reachable({}, COMPLETE_AUDIT))
        self.assertFalse(V.certify_reachable(None, COMPLETE_AUDIT))
        self.assertFalse(V.certify_reachable(u, DEFAULT_AUDIT))
        self.assertFalse(V.certify_reachable(u, FRESH_AUDIT))
        self.assertTrue(V.certify_reachable(u, COMPLETE_AUDIT))

    def test_blockers_name_the_switch_to_throw(self):
        b = V.certification_blockers({}, DEFAULT_AUDIT)
        self.assertTrue(any("no usage observations" in x for x in b))
        self.assertTrue(any("DATA_READ" in x and "auditConfigs" in x for x in b))
        self.assertTrue(any("DATA_WRITE" in x for x in b))
        self.assertEqual(V.certification_blockers({"a": []}, COMPLETE_AUDIT), [])

    def test_blockers_warn_that_enabling_logs_is_not_retroactive(self):
        b = V.certification_blockers({"a": []}, FRESH_AUDIT)
        self.assertTrue(any("not retroactive" in x for x in b))
        self.assertTrue(any("clock starts when you switch them on" in x for x in b))

    def test_a_freshly_enabled_log_certifies_and_revokes_nothing(self):
        """The trap: turn audit logging on, run a campaign ten minutes later,
        and every principal looks unused. It is not unused. It is unobserved."""
        p = {"serviceAccount:app@x.iam.gserviceaccount.com": ["roles/storage.admin"]}
        v = V.judge_principals(p, {"serviceAccount:app@x.iam.gserviceaccount.com": []},
                               FRESH_AUDIT)[0]
        self.assertEqual(v["verdict"], V.ABSTAIN)
        self.assertEqual(v["rule"], "observation-window-too-short")
        self.assertEqual([g["kind"] for g in v["missing_evidence"]],
                         [V.GAP_OBSERVATION_WINDOW])

    def test_an_unrecorded_window_is_treated_as_too_short(self):
        p = {"serviceAccount:app@x.iam.gserviceaccount.com": ["roles/storage.admin"]}
        a = dict(COMPLETE_AUDIT); a["window_days"] = None
        v = V.judge_principals(p, {"serviceAccount:app@x.iam.gserviceaccount.com": []}, a)[0]
        self.assertEqual(v["rule"], "observation-window-too-short")

    def test_a_truncated_read_is_a_sample_not_a_record(self):
        """Hitting the read limit means we saw some activity, not all of it.
        A sample cannot prove a negative."""
        p = {"serviceAccount:app@x.iam.gserviceaccount.com": ["roles/storage.admin"]}
        a = dict(COMPLETE_AUDIT); a["truncated"] = True
        v = V.judge_principals(p, {"serviceAccount:app@x.iam.gserviceaccount.com": []}, a)[0]
        self.assertEqual(v["verdict"], V.ABSTAIN)
        self.assertEqual(v["rule"], "usage-record-truncated")
        self.assertEqual([g["kind"] for g in v["missing_evidence"]],
                         [V.GAP_TRUNCATED_RECORD])

    def test_truncation_beats_a_long_window(self):
        a = dict(COMPLETE_AUDIT); a["truncated"] = True
        self.assertFalse(V.certify_reachable({"a": []}, a))
        self.assertTrue(any("truncated" in x
                            for x in V.certification_blockers({"a": []}, a)))

    def test_truncation_is_closeable_by_reading_again(self):
        g = V._gap(V.GAP_TRUNCATED_RECORD, "x")
        self.assertIn("higher limit", g["action"])

    def test_only_time_closes_the_window_gap(self):
        self.assertIsNone(V.GAP_ACTIONS[V.GAP_OBSERVATION_WINDOW])
        self.assertEqual(V.closeable([V._gap(V.GAP_OBSERVATION_WINDOW, "x")]), [])

    def test_window_boundary(self):
        self.assertFalse(V.window_sufficient({"window_days": V.MIN_OBSERVATION_DAYS - 1}))
        self.assertTrue(V.window_sufficient({"window_days": V.MIN_OBSERVATION_DAYS}))
        self.assertFalse(V.window_sufficient({}))

    def test_silence_in_an_incomplete_record_is_not_innocence(self):
        """The whole point. Observed nothing + reads not logged = ABSTAIN,
        never CERTIFY and never REVOKE."""
        p = {"serviceAccount:app@x.iam.gserviceaccount.com": ["roles/storage.admin"]}
        long_but_incomplete = dict(DEFAULT_AUDIT)
        long_but_incomplete["window_days"] = 365
        v = V.judge_principals(p, {"serviceAccount:app@x.iam.gserviceaccount.com": []},
                               long_but_incomplete)[0]
        self.assertEqual(v["verdict"], V.ABSTAIN)
        self.assertEqual(v["rule"], "usage-record-incomplete")
        self.assertEqual([g["kind"] for g in v["missing_evidence"]],
                         [V.GAP_AUDIT_LOGGING_OFF])
        self.assertTrue(any("not evidence that none happened" in g["detail"]
                            for g in v["missing_evidence"]))

    def test_certify_requires_used_within_held(self):
        principals = {"serviceAccount:app@x.iam.gserviceaccount.com": ["roles/run.invoker"]}
        usage = {"serviceAccount:app@x.iam.gserviceaccount.com": ["roles/run.invoker"]}
        v = V.judge_principals(principals, usage, COMPLETE_AUDIT)[0]
        self.assertEqual(v["verdict"], V.CERTIFY)
        self.assertEqual(v["rule"], "used-within-held")

    def test_held_beyond_used_is_revoke_not_certify(self):
        principals = {"serviceAccount:app@x.iam.gserviceaccount.com":
                      ["roles/run.invoker", "roles/storage.admin"]}
        usage = {"serviceAccount:app@x.iam.gserviceaccount.com": ["roles/run.invoker"]}
        v = V.judge_principals(principals, usage, COMPLETE_AUDIT)[0]
        self.assertEqual(v["verdict"], V.REVOKE)
        self.assertEqual(v["rule"], "held-exceeds-used")

    def test_an_empty_usage_record_is_not_the_same_as_no_usage_record(self):
        """A principal that provably did nothing CAN be judged; one we have no
        trace for cannot. None means unmeasured, [] means measured-and-empty."""
        p = {"serviceAccount:app@x.iam.gserviceaccount.com": ["roles/storage.admin"]}
        self.assertEqual(V.judge_principals(p, {}, COMPLETE_AUDIT)[0]["verdict"],
                         V.ABSTAIN)
        self.assertEqual(
            V.judge_principals(p, {"serviceAccount:app@x.iam.gserviceaccount.com": []},
                               COMPLETE_AUDIT)[0]["verdict"],
            V.REVOKE)


class TestRevokeNeedsCompleteEvidence(unittest.TestCase):
    def test_primitive_role_on_service_account_is_revoke_without_usage(self):
        principals = inv.iam_principals(fx("iam.json"))
        v = [x for x in V.judge_principals(principals) if x["verdict"] == V.REVOKE]
        self.assertEqual(len(v), 1)
        self.assertIn("compute@developer", v[0]["subject"])
        self.assertEqual(v[0]["rule"], "primitive-role-on-non-human-identity")

    def test_evidence_lists_every_role_held_not_just_the_triggering_one(self):
        """An evidence pack that understates an entitlement is not defensible."""
        principals = {"serviceAccount:x@developer.gserviceaccount.com":
                      ["roles/cloudbuild.builds.builder", "roles/editor"]}
        v = V.judge_principals(principals)[0]
        self.assertEqual(v["verdict"], V.REVOKE)
        held = [e for e in v["evidence"] if e["claim"].startswith("holds")][0]
        self.assertIn("roles/editor", held["claim"])
        self.assertIn("roles/cloudbuild.builds.builder", held["claim"])
        self.assertIn("2 role(s)", held["claim"])
        fires = [e for e in v["evidence"] if e["claim"].startswith("the rule fires")][0]
        self.assertIn("roles/editor", fires["claim"])
        self.assertNotIn("cloudbuild", fires["claim"])

    def test_abstaining_principal_evidence_also_counts_roles(self):
        p = {"serviceAccount:a@x.iam.gserviceaccount.com":
             ["roles/pubsub.serviceAgent", "roles/run.invoker"]}
        v = V.judge_principals(p)[0]
        self.assertIn("2 role(s)", v["evidence"][0]["claim"])

    def test_human_owner_abstains_rather_than_revoked(self):
        principals = inv.iam_principals(fx("iam.json"))
        v = [x for x in V.judge_principals(principals)
             if x["subject"] == "user:redacted@example.com"][0]
        self.assertEqual(v["verdict"], V.ABSTAIN)

    def test_shadow_agent_is_revoke(self):
        shadows = [{"workload": "invoice-triage", "url": "https://x",
                    "identity": "sa@x", "registered": False, "compared_against": 1,
                    "urls_checked": ["https://x", "https://y"],
                    "derived_url_available": True, "card_state": "card",
                    "declared_name": "invoice-triage",
                    "declared_skills": ["triage_invoice"], "shadow_agent": True}]
        v = V.judge_workloads(shadows)[0]
        self.assertEqual(v["verdict"], V.REVOKE)
        self.assertEqual(v["rule"], "self-declared-agent-not-registered")
        self.assertTrue(any("agent card" in e["claim"] for e in v["evidence"]))

    def test_mislabelled_server_is_revoke(self):
        tools = inv.declared_tools(fx("mcp-servers.json"))
        v = [x for x in V.judge_servers(fx("mcp-servers.json"), tools)
             if x["verdict"] == V.REVOKE]
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0]["subject"], "unused")
        self.assertEqual(v[0]["rule"], "catalog-label-misidentifies-service")


class TestAbstainNamesWhatIsMissing(unittest.TestCase):
    def test_every_abstain_names_at_least_one_missing_item(self):
        data, agents, tools, principals, shadows = snapshot()
        verdicts, _ = V.run_campaign(data, agents, tools, principals, shadows)
        for v in verdicts:
            if v["verdict"] == V.ABSTAIN:
                self.assertTrue(v["missing_evidence"],
                                "%s abstained without saying why" % v["subject"])

    def test_no_revoke_or_certify_carries_missing_evidence(self):
        data, agents, tools, principals, shadows = snapshot()
        verdicts, _ = V.run_campaign(data, agents, tools, principals, shadows)
        for v in verdicts:
            if v["verdict"] != V.ABSTAIN:
                self.assertEqual(v["missing_evidence"], [])

    def test_unreachable_card_abstains_and_says_so(self):
        shadows = [{"workload": "locked", "url": "https://x", "identity": "sa",
                    "registered": False, "compared_against": 1,
                    "urls_checked": ["https://x"], "derived_url_available": True,
                    "card_state": "UNREACHABLE", "shadow_agent": False}]
        v = V.judge_workloads(shadows)[0]
        self.assertEqual(v["verdict"], V.ABSTAIN)
        self.assertEqual([m["kind"] for m in v["missing_evidence"]],
                         [V.GAP_AGENT_CARD])
        self.assertTrue(any("not the same as it having none" in m["detail"]
                            for m in v["missing_evidence"]))

    def test_incomplete_address_set_is_named_in_the_abstain(self):
        shadows = [{"workload": "web", "url": "https://x", "identity": "sa",
                    "registered": False, "compared_against": 1,
                    "urls_checked": ["https://x"], "derived_url_available": False,
                    "card_state": "no_card", "shadow_agent": False}]
        v = V.judge_workloads(shadows)[0]
        kinds = [m["kind"] for m in v["missing_evidence"]]
        self.assertIn(V.GAP_ADDRESS_SET, kinds)
        self.assertIn(V.GAP_AGENT_CARD, kinds)

    def test_server_abstain_names_the_undeclared_tools(self):
        tools = inv.declared_tools(fx("mcp-servers.json"))
        v = [x for x in V.judge_servers(fx("mcp-servers.json"), tools)
             if x["subject"] == "pubsub.googleapis.com"][0]
        self.assertEqual(v["verdict"], V.ABSTAIN)
        kinds = [m["kind"] for m in v["missing_evidence"]]
        self.assertIn(V.GAP_UNDECLARED_CAPABILITY, kinds)
        self.assertIn(V.GAP_NO_DESCRIPTION, kinds)
        self.assertIn(V.GAP_USAGE_EVIDENCE, kinds)
        self.assertTrue(any("readOnlyHint absent" in m["detail"]
                            for m in v["missing_evidence"]))

    def test_registered_agent_abstains_on_empty_bindings(self):
        agents, _ = inv.canonical_agents(fx("agents.json"))
        v = V.judge_agents(agents)[0]
        self.assertEqual(v["verdict"], V.ABSTAIN)
        self.assertIn(V.GAP_TOOL_BINDINGS, [m["kind"] for m in v["missing_evidence"]])
        self.assertTrue(any("bindings list is empty" in m["detail"]
                            for m in v["missing_evidence"]))


class TestGapsAreDispatchable(unittest.TestCase):
    """An agent must be able to act on a gap without parsing prose."""

    def test_every_gap_has_a_known_kind(self):
        data, agents, tools, principals, shadows = snapshot()
        verdicts, _ = V.run_campaign(data, agents, tools, principals, shadows)
        for v in verdicts:
            for g in v["missing_evidence"]:
                self.assertIn(g["kind"], V.GAP_ACTIONS,
                              "%s has an undispatchable gap" % v["subject"])
                self.assertTrue(g["detail"])

    def test_closeable_excludes_gaps_the_reviewer_cannot_fix(self):
        gaps = [V._gap(V.GAP_USAGE_EVIDENCE, "x"),
                V._gap(V.GAP_UNDECLARED_CAPABILITY, "y"),
                V._gap(V.GAP_NO_DESCRIPTION, "z")]
        self.assertEqual([g["kind"] for g in V.closeable(gaps)],
                         [V.GAP_USAGE_EVIDENCE])

    def test_a_closeable_gap_names_the_tool_that_would_close_it(self):
        g = V._gap(V.GAP_TOOL_BINDINGS, "x")
        self.assertIn("bindings list", g["action"])

    def test_catalog_owned_gaps_have_no_action_so_the_agent_cannot_loop(self):
        for kind in (V.GAP_UNDECLARED_CAPABILITY, V.GAP_NO_DESCRIPTION):
            self.assertIsNone(V.GAP_ACTIONS[kind])


class TestEveryVerdictCarriesEvidence(unittest.TestCase):
    def test_no_verdict_is_issued_without_a_source(self):
        data, agents, tools, principals, shadows = snapshot()
        verdicts, _ = V.run_campaign(data, agents, tools, principals, shadows)
        self.assertTrue(verdicts)
        for v in verdicts:
            self.assertTrue(v["evidence"], "%s has no evidence" % v["subject"])
            for e in v["evidence"]:
                self.assertTrue(e["claim"])
                self.assertTrue(e["source"])

    def test_one_verdict_per_subject(self):
        data, agents, tools, principals, shadows = snapshot()
        verdicts, tally = V.run_campaign(data, agents, tools, principals, shadows)
        subjects = [(v["kind"], v["subject"]) for v in verdicts]
        self.assertEqual(len(subjects), len(set(subjects)))
        self.assertEqual(sum(tally.values()), len(verdicts))

    def test_campaign_on_an_empty_project_returns_nothing_not_a_crash(self):
        verdicts, tally = V.run_campaign({}, [], [], {}, [])
        self.assertEqual(verdicts, [])
        self.assertEqual(tally, {V.REVOKE: 0, V.CERTIFY: 0, V.ABSTAIN: 0})


if __name__ == "__main__":
    unittest.main(verbosity=2)
