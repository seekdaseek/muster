"""The collector's one job: never let a failed read look like an absent resource."""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import collect as C  # noqa: E402
import report as R  # noqa: E402
import inventory as inv  # noqa: E402


class TestParseSemantics(unittest.TestCase):
    def test_failed_command_parses_to_none_not_empty_list(self):
        self.assertIsNone(C._parse(False, ""))
        self.assertIsNone(C._parse(False, "[]"))

    def test_successful_empty_output_is_an_empty_list(self):
        self.assertEqual(C._parse(True, ""), [])
        self.assertEqual(C._parse(True, "[]"), [])

    def test_malformed_json_is_reported_not_swallowed(self):
        out = C._parse(True, "{not json")
        self.assertIn("__parse_error__", out)

    def test_missing_binary_is_captured_not_raised(self):
        ok, out, err, code = C._run(["definitely-not-a-real-binary-xyz"])
        self.assertFalse(ok)
        self.assertEqual(code, 127)
        self.assertIn("not found", err)

    def test_real_command_succeeds(self):
        ok, out, err, code = C._run(["echo", "hi"])
        self.assertTrue(ok)
        self.assertEqual(out.strip(), "hi")
        self.assertEqual(code, 0)


class TestRecordCount(unittest.TestCase):
    """A successful dict read reported None records. That looked like a
    read returning nothing. Defect found by the live run 2026-08-21."""

    def test_iam_policy_dict_counts_its_bindings(self):
        self.assertEqual(C._count({"bindings": [1, 2, 3, 4, 5]}), 5)

    def test_failed_read_has_no_count(self):
        self.assertIsNone(C._count(None))

    def test_parse_error_has_no_count(self):
        self.assertIsNone(C._count({"__parse_error__": "boom"}))

    def test_lists_count_normally(self):
        self.assertEqual(C._count([]), 0)
        self.assertEqual(C._count([1, 2]), 2)


class TestModelArmorHost(unittest.TestCase):
    """gcloud routes to modelarmor.us.rep.googleapis.com which 403s on this
    project; the plain global host answers 200. MEASURED 2026-08-21."""

    def test_uses_the_global_host_not_the_regional_one(self):
        seen = {}

        def fake(url, token):
            seen["url"] = url
            return True, [], None, 200
        C._access_token = lambda: ("tok", None, 0)
        ok, payload, err, code = C._model_armor("p", fetch=fake)
        self.assertTrue(ok)
        self.assertIn("https://modelarmor.googleapis.com/", seen["url"])
        self.assertNotIn(".rep.googleapis.com", seen["url"])
        self.assertIn("/locations/global/templates", seen["url"])

    def test_no_token_is_a_failure_not_an_empty_result(self):
        C._access_token = lambda: (None, "not logged in", 1)
        ok, payload, err, code = C._model_armor("p", fetch=lambda u, t: (True, [], None, 200))
        self.assertFalse(ok)
        self.assertIsNone(payload)
        self.assertIn("no access token", err)

    def test_error_payload_is_a_failure(self):
        C._access_token = lambda: ("tok", None, 0)
        ok, payload, err, code = C._model_armor(
            "p", fetch=lambda u, t: (False, None, "PERMISSION_DENIED", 403))
        self.assertFalse(ok)
        self.assertIsNone(payload)


class TestReportRefusesFailedSources(unittest.TestCase):
    def _manifest(self, **over):
        m = {k: {"ok": True, "exit_code": 0, "error": None, "records": 0}
             for k in ["agents", "bindings", "endpoints", "mcp-servers",
                       "services", "iam", "sa", "run"]}
        m.update(over)
        m["__project__"] = "p"
        m["__location__"] = "global"
        m["__collected_at__"] = "2026-08-21T00:00:00+00:00"
        return m

    def test_failed_source_is_labelled_failed_in_the_report(self):
        man = self._manifest(iam={"ok": False, "exit_code": 7,
                                  "error": "PERMISSION_DENIED", "records": None})
        data = {k: [] for k in ["agents", "mcp-servers", "run"]}
        data["iam"] = None
        text = R.render(data, man)
        self.assertIn("FAILED   iam", text)
        self.assertIn("UNMEASURED, not absent", text)

    def test_zero_findings_is_not_claimed_when_a_source_failed(self):
        man = self._manifest(iam={"ok": False, "exit_code": 7,
                                  "error": "denied", "records": None})
        data = {"agents": [], "mcp-servers": [], "run": [], "iam": None}
        text = R.render(data, man)
        self.assertIn("No finding below is derived from a failed source.", text)

    def test_model_armor_absent_is_unmeasured_not_zero(self):
        man = self._manifest(model_armor={"ok": False, "exit_code": 403,
                                          "error": "denied", "records": None})
        data = {"agents": [], "mcp-servers": [], "run": [], "iam": {},
                "model_armor": None}
        text = R.render(data, man)
        self.assertIn("Templates UNMEASURED", text)

    def test_model_armor_empty_list_is_reported_as_zero_templates(self):
        man = self._manifest()
        data = {"agents": [], "mcp-servers": [], "run": [], "iam": {},
                "model_armor": []}
        text = R.render(data, man)
        self.assertIn("0 template(s) configured", text)

    def test_zero_bucket_is_not_named_alongside_a_real_one(self):
        """Live data had 0 absent and 72 partial. Saying 'both' would lie."""
        man = self._manifest()
        data = {"agents": [], "run": [], "iam": {}, "model_armor": [],
                "mcp-servers": [{"displayName": "s", "mcpServerId": "u", "tools": [
                    {"name": "a", "annotations": {"readOnlyHint": True}},
                    {"name": "b", "annotations": {"idempotentHint": True}}]}]}
        text = R.render(data, man)
        self.assertIn("All 1 carry an annotations block that omits", text)
        self.assertNotIn("carry no annotations block;", text)

    def test_silent_catalog_finding_appears(self):
        man = self._manifest()
        data = {"agents": [], "run": [], "iam": {}, "model_armor": [],
                "mcp-servers": [{"displayName": "s", "mcpServerId": "u", "tools": [
                    {"name": "a", "annotations": {"readOnlyHint": True}}]}]}
        text = R.render(data, man)
        self.assertIn("not one of the 1 tools declares readOnlyHint=false", text)

    def test_mislabelled_and_undescribed_get_separate_headlines(self):
        man = self._manifest()
        data = {"agents": [], "run": [], "iam": {}, "model_armor": [],
                "mcp-servers": [
                    {"displayName": "unused",
                     "mcpServerId": "urn:m:g:locations:global:billingbudgets",
                     "interfaces": [{"url": "https://billingbudgets.googleapis.com/mcp"}],
                     "tools": [{"name": "delete_budget"}]},
                    {"displayName": "pubsub.googleapis.com",
                     "mcpServerId": "urn:m:g:locations:global:pubsub",
                     "interfaces": [{"url": "https://pubsub.googleapis.com/mcp"}],
                     "tools": [{"name": "publish"}]}]}
        text = R.render(data, man)
        self.assertIn("labelled as something it is not", text)
        self.assertIn("correctly labelled server ships no description", text)
        self.assertNotIn("from its own", text)

    def test_long_tool_lists_are_truncated(self):
        names = ["t%d" % i for i in range(15)]
        out = R._tools(names)
        self.assertIn("(+7 more)", out)
        self.assertNotIn("t9,", out)

    def test_incomplete_address_set_is_warned_about_in_the_report(self):
        man = self._manifest()
        data = {"agents": [], "mcp-servers": [], "iam": {}, "model_armor": [],
                "project_number": None,
                "run": [{"metadata": {"name": "x"}, "status": {"url": "https://x"}}]}
        text = R.render(data, man)
        self.assertIn("address set is INCOMPLETE", text)

    def test_complete_address_set_gets_no_warning(self):
        man = self._manifest()
        data = {"agents": [], "mcp-servers": [], "iam": {}, "model_armor": [],
                "project_number": "000000000000",
                "run": [{"metadata": {"name": "x", "labels": {"cloud.googleapis.com/location": "us-central1"}},
                         "status": {"url": "https://x"}}]}
        text = R.render(data, man)
        self.assertNotIn("address set is INCOMPLETE", text)

    def test_all_ok_report_has_no_failure_banner(self):
        man = self._manifest()
        data = {"agents": [], "mcp-servers": [], "run": [], "iam": {}}
        text = R.render(data, man)
        self.assertNotIn("UNMEASURED, not absent", text)

    def test_render_survives_every_source_being_none(self):
        man = self._manifest(**{k: {"ok": False, "exit_code": 1,
                                    "error": "x", "records": None}
                                for k in ["agents", "iam", "run", "mcp-servers"]})
        data = {"agents": None, "mcp-servers": None, "run": None, "iam": None}
        text = R.render(data, man)
        self.assertIn("muster  agent fleet inventory", text)


class TestAgentCardProbe(unittest.TestCase):
    def test_a_served_card_is_detected(self):
        state, card = C.probe_agent_card(
            "https://x.a.run.app",
            fetch=lambda u: (True, {"name": "invoice-triage",
                                    "skills": [{"id": "triage_invoice"}]}, None, 200))
        self.assertEqual(state, "card")
        self.assertEqual(card["name"], "invoice-triage")

    def test_404_is_no_card(self):
        state, _ = C.probe_agent_card(
            "https://x.a.run.app", fetch=lambda u: (False, None, "HTTP 404", 404))
        self.assertEqual(state, "no_card")

    def test_timeout_is_unreachable_not_no_card(self):
        state, err = C.probe_agent_card(
            "https://x.a.run.app", fetch=lambda u: (False, None, "timeout", -1))
        self.assertEqual(state, "UNREACHABLE")

    def test_auth_wall_is_unreachable(self):
        state, _ = C.probe_agent_card(
            "https://x.a.run.app", fetch=lambda u: (False, None, "HTTP 403", 403))
        self.assertEqual(state, "UNREACHABLE")

    def test_json_without_agent_fields_is_no_card(self):
        state, _ = C.probe_agent_card(
            "https://x.a.run.app", fetch=lambda u: (True, {"hello": "world"}, None, 200))
        self.assertEqual(state, "no_card")

    def test_probe_uses_the_a2a_well_known_path(self):
        seen = {}

        def f(u):
            seen["u"] = u
            return True, {"name": "n"}, None, 200
        C.probe_agent_card("https://x.a.run.app/", fetch=f)
        self.assertEqual(seen["u"], "https://x.a.run.app/.well-known/agent-card.json")


class TestSnapshotRoundTrip(unittest.TestCase):
    def test_load_reports_missing_files_as_none(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "agents.json"), "w") as f:
                json.dump([], f)
            data, man = C.load(d)
            self.assertEqual(data["agents"], [])
            self.assertIsNone(data["iam"])
            self.assertEqual(man, {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
