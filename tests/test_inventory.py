"""Offline tests for muster's inventory core. No network, no clock."""
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
FIX = os.path.join(ROOT, "fixtures")

import inventory as inv  # noqa: E402


def fx(name):
    with open(os.path.join(FIX, name)) as f:
        return json.load(f)


class TestRegionTrap(unittest.TestCase):
    """The measured API artifact that would have inflated the inventory 5x."""

    def test_same_agent_across_locations_collapses_to_one(self):
        agents, dup = inv.canonical_agents(fx("agents.json"))
        self.assertEqual(len(agents), 1)

    def test_duplication_is_reported_not_hidden(self):
        _, dup = inv.canonical_agents(fx("agents.json"))
        aid = "urn:agent:googleapis.com:locations:global:workspaceagent:workspaceagent--a2a"
        self.assertEqual(dup[aid], ["global", "us-east4"])

    def test_true_location_comes_from_the_record_not_the_path(self):
        agents, _ = inv.canonical_agents(fx("agents.json"))
        self.assertEqual(agents[0]["location"], "global")

    def test_path_location_parser(self):
        self.assertEqual(inv._path_location("projects/p/locations/us-east4/agents/x"), "us-east4")
        self.assertEqual(inv._path_location("garbage"), inv.UNMEASURED)
        self.assertEqual(inv._path_location(None), inv.UNMEASURED)

    def test_summary_shows_records_seen_and_agents_separately(self):
        agents, dup = inv.canonical_agents(fx("agents.json"))
        s = inv.summarise(agents, dup, [], {}, [])
        self.assertEqual(s["agents"], 1)
        self.assertEqual(s["agent_records_seen"], 2)
        self.assertTrue(s["duplicate_agent_ids"])


class TestAgentShape(unittest.TestCase):
    def test_endpoints_flattened_from_protocols(self):
        agents, _ = inv.canonical_agents(fx("agents.json"))
        eps = agents[0]["endpoints"]
        self.assertEqual(len(eps), 1)
        self.assertEqual(eps[0]["protocol"], "A2A_AGENT")
        self.assertEqual(eps[0]["binding"], "HTTP_JSON")
        self.assertEqual(eps[0]["url"], "https://workspaceagent.googleapis.com/a2a")

    def test_live_discovered_fields_are_carried(self):
        """uid, updateTime and version were surfaced by the schema check."""
        agents, _ = inv.canonical_agents(fx("agents.json"))
        self.assertEqual(agents[0]["uid"], "a1b2c3d4")
        self.assertEqual(agents[0]["version"], "1")
        self.assertTrue(agents[0]["updated"].startswith("2026-"))

    def test_absent_version_is_unmeasured(self):
        agents, _ = inv.canonical_agents([{"agentId": "x"}])
        self.assertEqual(agents[0]["version"], inv.UNMEASURED)
        self.assertEqual(agents[0]["uid"], inv.UNMEASURED)

    def test_skills_read_off_the_agent_record(self):
        agents, _ = inv.canonical_agents(fx("agents.json"))
        self.assertEqual(agents[0]["skills"], ["create_presentation"])

    def test_missing_agent_id_is_unmeasured_not_dropped(self):
        agents, _ = inv.canonical_agents([{"displayName": "nameless"}])
        self.assertEqual(agents[0]["agent_id"], inv.UNMEASURED)

    def test_unknown_keys_surface_themselves(self):
        recs = fx("agents.json") + [{"agentId": "x", "brandNewField": 1}]
        self.assertEqual(inv.unknown_keys(recs, inv.AGENT_KEYS), ["brandNewField"])

    def test_real_fixture_has_no_unknown_keys(self):
        self.assertEqual(inv.unknown_keys(fx("agents.json"), inv.AGENT_KEYS), [])


class TestDeclaredTools(unittest.TestCase):
    def test_annotations_are_read_not_defaulted(self):
        rows = inv.declared_tools(fx("mcp-servers.json"))
        by = {r["tool"]: r for r in rows}
        self.assertIs(by["list_agents"]["read_only"], True)
        self.assertIs(by["create_agent"]["read_only"], False)

    def test_partial_is_not_reported_as_absent(self):
        """update_endpoint carries idempotentHint but no readOnlyHint."""
        rows = inv.declared_tools(fx("mcp-servers.json"))
        by = {r["tool"]: r for r in rows}
        self.assertEqual(by["update_endpoint"]["annotation_state"], inv.PARTIAL)
        self.assertIs(by["update_endpoint"]["idempotent"], True)
        self.assertEqual(by["update_endpoint"]["read_only"], inv.UNMEASURED)
        s = inv.summarise([], {}, rows, {}, [])
        self.assertIn("update_endpoint", s["tools_partial_annotations"])
        self.assertNotIn("update_endpoint", s["tools_no_annotations"])
        self.assertIn("update_endpoint", s["read_only_unmeasured"])

    def test_annotation_state_three_way(self):
        self.assertEqual(inv.annotation_state({"annotations": {"readOnlyHint": False}}), inv.DECLARED)
        self.assertEqual(inv.annotation_state({"annotations": {"idempotentHint": True}}), inv.PARTIAL)
        self.assertEqual(inv.annotation_state({}), inv.ABSENT)
        self.assertEqual(inv.annotation_state({"annotations": None}), inv.ABSENT)

    def test_nothing_is_inferred_from_a_tool_name(self):
        """create_* must not be assumed to write."""
        rows = inv.declared_tools([{"displayName": "s", "mcpServerId": "u",
                                    "tools": [{"name": "delete_everything"}]}])
        self.assertEqual(rows[0]["read_only"], inv.UNMEASURED)

    def test_declared_write_is_only_an_explicit_false(self):
        rows = inv.declared_tools(fx("mcp-servers.json"))
        s = inv.summarise([], {}, rows, {}, [])
        self.assertEqual(s["declared_write"], ["create_agent"])

    def test_no_declared_write_finding_fires_on_a_silent_catalog(self):
        """MEASURED live: 0 of 177 real tools declare readOnlyHint=false."""
        rows = inv.declared_tools([{"displayName": "s", "mcpServerId": "u", "tools": [
            {"name": "read_it", "annotations": {"readOnlyHint": True}},
            {"name": "write_it", "annotations": {"idempotentHint": True}}]}])
        s = inv.summarise([], {}, rows, {}, [])
        self.assertEqual(s["declared_write"], [])
        self.assertEqual(s["tools_partial_annotations"], ["write_it"])
        self.assertEqual(s["tools_no_annotations"], [])

    def test_cross_server_name_collision_is_reported(self):
        rows = inv.declared_tools(fx("mcp-servers.json"))
        col = inv.tool_collisions(rows)
        self.assertEqual(col["list_services"],
                         ["agentregistry.googleapis.com", "run.googleapis.com"])

    def test_same_name_same_server_is_not_a_collision(self):
        rows = inv.declared_tools([{"displayName": "s", "mcpServerId": "u",
                                    "tools": [{"name": "x"}, {"name": "x"}]}])
        self.assertEqual(inv.tool_collisions(rows), {})

    def test_server_rollup_counts(self):
        rows = inv.declared_tools(fx("mcp-servers.json"))
        e = inv.servers_summary(rows)["agentregistry.googleapis.com"]
        self.assertEqual(e["tools"], 5)
        self.assertEqual(e["declared_write"], 1)
        self.assertEqual(e["partial"], 1)
        self.assertEqual(e["absent"], 1)

    def test_absent_annotations_are_unmeasured_not_false(self):
        rows = inv.declared_tools(fx("mcp-servers.json"))
        by = {r["tool"]: r for r in rows}
        self.assertEqual(by["mystery_tool"]["read_only"], inv.UNMEASURED)
        self.assertEqual(by["mystery_tool"]["idempotent"], inv.UNMEASURED)

    def test_unannotated_tools_are_listed_in_the_summary(self):
        rows = inv.declared_tools(fx("mcp-servers.json"))
        s = inv.summarise([], {}, rows, {}, [])
        self.assertIn("mystery_tool", s["tools_no_annotations"])

    def test_tool_carries_its_server_evidence(self):
        rows = inv.declared_tools(fx("mcp-servers.json"))
        self.assertTrue(all(r["evidence"].startswith("projects/") for r in rows))

    def test_mcp_fixture_has_no_unknown_keys(self):
        self.assertEqual(inv.unknown_keys(fx("mcp-servers.json"), inv.MCP_KEYS), [])


class TestRegistryMetadata(unittest.TestCase):
    """MEASURED 2026-08-21: a server labelled "unused" is billing budgets,
    exposes create/update/delete_budget, and carries no description."""

    def test_the_unused_server_is_flagged_as_mislabelled(self):
        rows = inv.metadata_findings(fx("mcp-servers.json"))
        f = [r for r in rows if r["severity"] == inv.MISLABELLED]
        self.assertEqual(len(f), 1)
        f = f[0]
        self.assertEqual(f["label"], "unused")
        self.assertEqual(f["service_from_urn"], "billingbudgets")
        self.assertEqual(f["service_from_endpoint"], "billingbudgets")
        self.assertFalse(f["label_identifies_service"])
        self.assertFalse(f["has_description"])
        self.assertIn("delete_budget", f["tools"])

    def test_pubsub_is_undescribed_not_mislabelled(self):
        """Its label DOES identify the service. Grouping it with "unused"
        would inflate a mild problem to match a severe one."""
        rows = inv.metadata_findings(fx("mcp-servers.json"))
        p = [r for r in rows if r["label"] == "pubsub.googleapis.com"]
        self.assertEqual(len(p), 1)
        self.assertEqual(p[0]["severity"], inv.UNDESCRIBED)
        self.assertTrue(p[0]["label_identifies_service"])
        self.assertFalse(p[0]["has_description"])

    def test_the_two_severities_do_not_mix(self):
        rows = inv.metadata_findings(fx("mcp-servers.json"))
        self.assertEqual(
            sorted({r["severity"] for r in rows}),
            [inv.MISLABELLED, inv.UNDESCRIBED])

    def test_a_correctly_labelled_server_is_not_flagged(self):
        rows = inv.metadata_findings([{
            "displayName": "agentregistry.googleapis.com",
            "description": "MCP server which exposes AgentRegistry APIs.",
            "mcpServerId": "urn:mcp:googleapis.com:projects:1:locations:global:agentregistry",
            "interfaces": [{"url": "https://agentregistry.googleapis.com/mcp"}],
            "tools": []}])
        self.assertEqual(rows, [])

    def test_missing_description_alone_is_a_finding(self):
        rows = inv.metadata_findings([{
            "displayName": "pubsub.googleapis.com",
            "mcpServerId": "urn:mcp:googleapis.com:projects:1:locations:global:pubsub",
            "interfaces": [{"url": "https://pubsub.googleapis.com/mcp"}],
            "tools": []}])
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["label_identifies_service"])
        self.assertFalse(rows[0]["has_description"])
        self.assertEqual(rows[0]["severity"], inv.UNDESCRIBED)

    def test_service_id_parsers(self):
        self.assertEqual(inv._service_id_from_urn("urn:a:b:billingbudgets"), "billingbudgets")
        self.assertEqual(inv._service_id_from_urn("nocolons"), inv.UNMEASURED)
        self.assertEqual(inv._service_id_from_url("https://run.googleapis.com/mcp"), "run")
        self.assertEqual(inv._service_id_from_url("garbage"), inv.UNMEASURED)

    def test_unmeasured_ids_do_not_produce_a_false_mismatch(self):
        rows = inv.metadata_findings([{"displayName": "x", "description": "d",
                                       "tools": []}])
        self.assertEqual(rows, [])


class TestIam(unittest.TestCase):
    def test_principals_collapse_bindings(self):
        p = inv.iam_principals(fx("iam.json"))
        self.assertEqual(p["user:redacted@example.com"], ["roles/owner"])
        self.assertEqual(
            p["serviceAccount:000000000000-compute@developer.gserviceaccount.com"],
            ["roles/editor"])

    def test_the_real_finding_default_compute_sa_holds_editor(self):
        p = inv.iam_principals(fx("iam.json"))
        flagged = [f for f in inv.overprivileged(p) if f["flagged"]]
        self.assertEqual(len(flagged), 1)
        f = flagged[0]
        self.assertIn("000000000000-compute@developer.gserviceaccount.com", f["principal"])
        self.assertEqual(f["roles"], ["roles/editor"])
        self.assertTrue(f["default_service_account"])

    def test_human_owner_reported_but_not_flagged(self):
        p = inv.iam_principals(fx("iam.json"))
        owner = [f for f in inv.overprivileged(p) if f["human"]][0]
        self.assertFalse(owner["flagged"])
        self.assertIn("requires an owner", owner["reason"])

    def test_service_agents_are_not_flagged(self):
        p = inv.iam_principals(fx("iam.json"))
        names = [f["principal"] for f in inv.overprivileged(p)]
        self.assertFalse(any("gcp-sa-pubsub" in n for n in names))

    def test_default_sa_detector(self):
        self.assertTrue(inv.is_default_service_account(
            "serviceAccount:1-compute@developer.gserviceaccount.com"))
        self.assertTrue(inv.is_default_service_account(
            "serviceAccount:p@appspot.gserviceaccount.com"))
        self.assertFalse(inv.is_default_service_account("user:a@b.com"))
        self.assertFalse(inv.is_default_service_account(
            "serviceAccount:custom@ata-agentfleet-2026.iam.gserviceaccount.com"))

    def test_empty_policy_yields_nothing(self):
        self.assertEqual(inv.iam_principals({}), {})
        self.assertEqual(inv.overprivileged({}), [])


class TestAuditConfig(unittest.TestCase):
    """DATA_READ/DATA_WRITE audit logs are OFF by default on GCP."""

    def test_a_default_project_records_no_data_access(self):
        a = inv.audit_config(fx("iam.json"))
        self.assertTrue(a["admin_activity"])
        self.assertFalse(a["data_read"])
        self.assertFalse(a["data_write"])
        self.assertFalse(a["complete"])

    def test_fully_configured_project_is_complete(self):
        a = inv.audit_config({"auditConfigs": [
            {"service": "allServices",
             "auditLogConfigs": [{"logType": "DATA_READ"}, {"logType": "DATA_WRITE"}]}]})
        self.assertTrue(a["complete"])
        self.assertEqual(a["configured_services"]["allServices"],
                         ["DATA_READ", "DATA_WRITE"])

    def test_partial_config_is_not_complete(self):
        a = inv.audit_config({"auditConfigs": [
            {"service": "storage.googleapis.com",
             "auditLogConfigs": [{"logType": "DATA_READ"}]}]})
        self.assertTrue(a["data_read"])
        self.assertFalse(a["data_write"])
        self.assertFalse(a["complete"])

    def test_empty_policy_does_not_crash(self):
        self.assertFalse(inv.audit_config({})["complete"])
        self.assertFalse(inv.audit_config(None)["complete"])


class TestShadowDetection(unittest.TestCase):
    def test_no_workloads_yet_is_an_empty_list_not_an_error(self):
        agents, _ = inv.canonical_agents(fx("agents.json"))
        self.assertEqual(inv.shadow_candidates(fx("run.json"), agents), [])

    def test_unregistered_workload_is_flagged_with_its_comparison_set(self):
        agents, _ = inv.canonical_agents(fx("agents.json"))
        svc = [{"metadata": {"name": "rogue-agent"},
                "status": {"url": "https://rogue-agent-xyz.a.run.app"},
                "spec": {"template": {"spec": {"serviceAccountName": "sa@x.iam.gserviceaccount.com"}}}}]
        rows = inv.shadow_candidates(svc, agents)
        self.assertFalse(rows[0]["registered"])
        self.assertEqual(rows[0]["identity"], "sa@x.iam.gserviceaccount.com")
        self.assertEqual(rows[0]["compared_against"], 1)

    def test_registered_workload_is_not_flagged(self):
        agents, _ = inv.canonical_agents(fx("agents.json"))
        svc = [{"metadata": {"name": "known"},
                "status": {"url": "https://workspaceagent.googleapis.com/a2a"},
                "spec": {}}]
        rows = inv.shadow_candidates(svc, agents)
        self.assertTrue(rows[0]["registered"])

    def test_missing_identity_is_unmeasured(self):
        svc = [{"metadata": {"name": "n"}, "status": {"url": "https://x"}, "spec": {}}]
        self.assertEqual(inv.shadow_candidates(svc, [])[0]["identity"], inv.UNMEASURED)

    def test_self_declared_agent_absent_from_registry_is_a_shadow_agent(self):
        svc = [{"metadata": {"name": "invoice-triage"},
                "status": {"url": "https://invoice-triage-abc.a.run.app"},
                "spec": {"template": {"spec": {"serviceAccountName": "sa@x"}}}}]
        probes = {"https://invoice-triage-abc.a.run.app":
                  {"state": "card", "declared_name": "invoice-triage",
                   "declared_skills": ["triage_invoice", "export_ledger"]}}
        rows = inv.shadow_candidates(svc, [], probes)
        self.assertTrue(rows[0]["shadow_agent"])
        self.assertEqual(rows[0]["declared_name"], "invoice-triage")
        self.assertIn("export_ledger", rows[0]["declared_skills"])

    def test_unreachable_is_not_treated_as_cleared(self):
        svc = [{"metadata": {"name": "locked"},
                "status": {"url": "https://locked.a.run.app"}, "spec": {}}]
        probes = {"https://locked.a.run.app": {"state": "UNREACHABLE"}}
        rows = inv.shadow_candidates(svc, [], probes)
        self.assertFalse(rows[0]["shadow_agent"])
        s = inv.summarise([], {}, [], {}, rows)
        self.assertEqual(s["unreachable_workloads"], ["locked"])
        self.assertEqual(s["shadow_agents"], [])

    def test_plain_service_with_no_card_is_not_a_shadow_agent(self):
        svc = [{"metadata": {"name": "web"},
                "status": {"url": "https://web.a.run.app"}, "spec": {}}]
        probes = {"https://web.a.run.app": {"state": "no_card"}}
        rows = inv.shadow_candidates(svc, [], probes)
        self.assertFalse(rows[0]["shadow_agent"])
        self.assertEqual(rows[0]["card_state"], "no_card")

    def test_registered_agent_with_a_card_is_not_flagged(self):
        agents, _ = inv.canonical_agents(fx("agents.json"))
        svc = [{"metadata": {"name": "known"},
                "status": {"url": "https://workspaceagent.googleapis.com/a2a"},
                "spec": {}}]
        probes = {"https://workspaceagent.googleapis.com/a2a": {"state": "card",
                  "declared_name": "Workspace Agent", "declared_skills": []}}
        rows = inv.shadow_candidates(svc, agents, probes)
        self.assertTrue(rows[0]["registered"])
        self.assertFalse(rows[0]["shadow_agent"])

    def test_no_probes_leaves_card_state_unmeasured(self):
        svc = [{"metadata": {"name": "x"}, "status": {"url": "https://x"}, "spec": {}}]
        rows = inv.shadow_candidates(svc, [])
        self.assertEqual(rows[0]["card_state"], inv.UNMEASURED)
        self.assertFalse(rows[0]["shadow_agent"])

    def test_api_reports_one_url_but_derived_form_also_serves(self):
        """MEASURED: status.url == status.address.url, traffic has no url,
        yet https://SERVICE-PROJNUM.REGION.run.app returned 200."""
        svc = {"metadata": {"name": "invoice-triage",
                            "labels": {"cloud.googleapis.com/location": "us-central1"}},
               "status": {"url": "https://invoice-triage-f43zg6mqya-uc.a.run.app",
                          "address": {"url": "https://invoice-triage-f43zg6mqya-uc.a.run.app"},
                          "traffic": [{"latestRevision": True, "percent": 100}]}}
        urls, ok = inv.run_service_urls(svc, "000000000000")
        self.assertTrue(ok)
        self.assertIn("https://invoice-triage-000000000000.us-central1.run.app", urls)
        self.assertIn("https://invoice-triage-f43zg6mqya-uc.a.run.app", urls)

    def test_registered_under_the_other_url_form_is_not_a_shadow(self):
        """The false positive this exists to prevent."""
        agents = [{"endpoints": [{"url": "https://invoice-triage-000000000000.us-central1.run.app"}]}]
        svc = [{"metadata": {"name": "invoice-triage",
                             "labels": {"cloud.googleapis.com/location": "us-central1"}},
                "status": {"url": "https://invoice-triage-f43zg6mqya-uc.a.run.app"}}]
        probes = {"https://invoice-triage-f43zg6mqya-uc.a.run.app": {"state": "card"}}
        rows = inv.shadow_candidates(svc, agents, probes, "000000000000")
        self.assertTrue(rows[0]["registered"])
        self.assertFalse(rows[0]["shadow_agent"])

    def test_without_the_project_number_it_would_be_a_false_positive(self):
        agents = [{"endpoints": [{"url": "https://invoice-triage-000000000000.us-central1.run.app"}]}]
        svc = [{"metadata": {"name": "invoice-triage",
                             "labels": {"cloud.googleapis.com/location": "us-central1"}},
                "status": {"url": "https://invoice-triage-f43zg6mqya-uc.a.run.app"}}]
        rows = inv.shadow_candidates(svc, agents, None, None)
        self.assertFalse(rows[0]["registered"])
        self.assertFalse(rows[0]["derived_url_available"])

    def test_no_region_label_means_no_derivation_not_a_guess(self):
        svc = {"metadata": {"name": "x"}, "status": {"url": "https://x-abc-uc.a.run.app"}}
        urls, ok = inv.run_service_urls(svc, "999")
        self.assertFalse(ok)
        self.assertEqual(urls, {"https://x-abc-uc.a.run.app"})

    def test_incomplete_address_sets_are_listed_in_the_summary(self):
        svc = [{"metadata": {"name": "x"}, "status": {"url": "https://x"}}]
        rows = inv.shadow_candidates(svc, [], None, None)
        s = inv.summarise([], {}, [], {}, rows)
        self.assertEqual(s["urls_incomplete"], ["x"])

    def test_summary_names_unregistered_workloads(self):
        svc = [{"metadata": {"name": "rogue"}, "status": {"url": "https://r"}, "spec": {}}]
        s = inv.summarise([], {}, [], {}, inv.shadow_candidates(svc, []))
        self.assertEqual(s["unregistered_workloads"], ["rogue"])


class TestEmptyGroups(unittest.TestCase):
    """bindings, endpoints and services all measured empty on 2026-08-21."""

    def test_empty_registry_groups_do_not_crash_anything(self):
        for name in ("bindings.json", "endpoints.json", "services.json"):
            self.assertEqual(fx(name), [])
        agents, dup = inv.canonical_agents([])
        self.assertEqual(agents, [])
        self.assertEqual(dup, {})
        self.assertEqual(inv.declared_tools([]), [])
        self.assertEqual(inv.declared_tools(None), [])

    def test_full_pass_over_the_real_project_snapshot(self):
        agents, dup = inv.canonical_agents(fx("agents.json"))
        tools = inv.declared_tools(fx("mcp-servers.json"))
        principals = inv.iam_principals(fx("iam.json"))
        shadows = inv.shadow_candidates(fx("run.json"), agents)
        s = inv.summarise(agents, dup, tools, principals, shadows)
        self.assertEqual(s["agents"], 1)
        self.assertEqual(s["tools"], 15)
        self.assertEqual(s["principals"], 5)
        self.assertEqual(s["runtime_workloads"], 0)
        self.assertEqual(len([f for f in s["overprivileged"] if f["flagged"]]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
