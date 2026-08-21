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

    def test_certify_is_declared_unreachable_when_usage_is_empty(self):
        self.assertFalse(V.certify_reachable({}))
        self.assertFalse(V.certify_reachable(None))
        self.assertTrue(V.certify_reachable({"user:a@b.com": ["roles/viewer"]}))

    def test_certify_requires_used_within_held(self):
        principals = {"serviceAccount:app@x.iam.gserviceaccount.com": ["roles/run.invoker"]}
        usage = {"serviceAccount:app@x.iam.gserviceaccount.com": ["roles/run.invoker"]}
        v = V.judge_principals(principals, usage)[0]
        self.assertEqual(v["verdict"], V.CERTIFY)
        self.assertEqual(v["rule"], "used-within-held")

    def test_held_beyond_used_is_revoke_not_certify(self):
        principals = {"serviceAccount:app@x.iam.gserviceaccount.com":
                      ["roles/run.invoker", "roles/storage.admin"]}
        usage = {"serviceAccount:app@x.iam.gserviceaccount.com": ["roles/run.invoker"]}
        v = V.judge_principals(principals, usage)[0]
        self.assertEqual(v["verdict"], V.REVOKE)
        self.assertEqual(v["rule"], "held-exceeds-used")

    def test_an_empty_usage_record_is_not_the_same_as_no_usage_record(self):
        """A principal that provably did nothing CAN be judged; one we have no
        trace for cannot. None means unmeasured, [] means measured-and-empty."""
        p = {"serviceAccount:app@x.iam.gserviceaccount.com": ["roles/storage.admin"]}
        self.assertEqual(V.judge_principals(p, {})[0]["verdict"], V.ABSTAIN)
        self.assertEqual(
            V.judge_principals(p, {"serviceAccount:app@x.iam.gserviceaccount.com": []})[0]["verdict"],
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
        self.assertTrue(any("not the same as it having none" in m
                            for m in v["missing_evidence"]))

    def test_incomplete_address_set_is_named_in_the_abstain(self):
        shadows = [{"workload": "web", "url": "https://x", "identity": "sa",
                    "registered": False, "compared_against": 1,
                    "urls_checked": ["https://x"], "derived_url_available": False,
                    "card_state": "no_card", "shadow_agent": False}]
        v = V.judge_workloads(shadows)[0]
        self.assertTrue(any("full address set" in m for m in v["missing_evidence"]))

    def test_server_abstain_names_the_undeclared_tools(self):
        tools = inv.declared_tools(fx("mcp-servers.json"))
        v = [x for x in V.judge_servers(fx("mcp-servers.json"), tools)
             if x["subject"] == "pubsub.googleapis.com"][0]
        self.assertEqual(v["verdict"], V.ABSTAIN)
        self.assertTrue(any("readOnlyHint absent" in m for m in v["missing_evidence"]))
        self.assertTrue(any("ships none" in m for m in v["missing_evidence"]))

    def test_registered_agent_abstains_on_empty_bindings(self):
        agents, _ = inv.canonical_agents(fx("agents.json"))
        v = V.judge_agents(agents)[0]
        self.assertEqual(v["verdict"], V.ABSTAIN)
        self.assertTrue(any("bindings list is empty" in m
                            for m in v["missing_evidence"]))


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
