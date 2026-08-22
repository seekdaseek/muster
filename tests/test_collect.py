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


FIXTURES = os.path.join(ROOT, "fixtures")


def _fixture(name):
    with open(os.path.join(FIXTURES, name)) as fh:
        return fh.read()


class _FakeResponse:
    """Stands in for the object urlopen returns, so the REAL _plain_get runs."""

    def __init__(self, body, status=200):
        self._body = body.encode("utf-8")
        self.status = status

    def read(self):
        return self._body

    def getcode(self):
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestAgentCardProbe(unittest.TestCase):
    """One test per row of the classification table in probe_agent_card.

    The rule the table encodes: UNREACHABLE means no HTTP answer arrived or the
    door was shut. Everything that ANSWERED is a measurement about the service,
    even when what it answered with is useless.
    """

    # ---- rows that arrived at no answer: UNREACHABLE ----
    def test_transport_error_is_unreachable(self):
        state, card, detail = C.probe_agent_card(
            "https://x.a.run.app",
            fetch=lambda u: (False, None, "URLError: timed out", -1))
        self.assertEqual(state, "UNREACHABLE")
        self.assertIsNone(card)
        self.assertIn("timed out", detail)

    def test_401_is_unreachable(self):
        state, card, _ = C.probe_agent_card(
            "https://x.a.run.app", fetch=lambda u: (False, None, "HTTP 401", 401))
        self.assertEqual(state, "UNREACHABLE")
        self.assertIsNone(card)

    def test_auth_wall_is_unreachable(self):
        state, card, _ = C.probe_agent_card(
            "https://x.a.run.app", fetch=lambda u: (False, None, "HTTP 403", 403))
        self.assertEqual(state, "UNREACHABLE")
        self.assertIsNone(card)

    def test_5xx_is_unreachable(self):
        state, card, _ = C.probe_agent_card(
            "https://x.a.run.app", fetch=lambda u: (False, None, "HTTP 503", 503))
        self.assertEqual(state, "UNREACHABLE")
        self.assertIsNone(card)

    def test_no_address_at_all_is_unreachable(self):
        self.assertEqual(C.probe_agent_card("UNMEASURED")[0], "UNREACHABLE")
        self.assertEqual(C.probe_agent_card("")[0], "UNREACHABLE")

    # ---- rows that answered: no_card ----
    def test_404_is_no_card(self):
        state, card, _ = C.probe_agent_card(
            "https://x.a.run.app", fetch=lambda u: (False, None, "HTTP 404", 404))
        self.assertEqual(state, "no_card")
        self.assertIsNone(card)

    def test_200_with_a_body_that_is_not_json_is_no_card(self):
        state, card, detail = C.probe_agent_card(
            "https://x.a.run.app",
            fetch=lambda u: (True, None, "response body is not JSON: "
                                         "Expecting value: line 1 column 1", 200))
        self.assertEqual(state, "no_card")
        self.assertIsNone(card)
        self.assertIn("not JSON", detail)

    def test_200_with_json_that_is_not_a_dict_is_no_card(self):
        state, card, _ = C.probe_agent_card(
            "https://x.a.run.app", fetch=lambda u: (True, ["a", "list"], None, 200))
        self.assertEqual(state, "no_card")
        self.assertIsNone(card)

    def test_json_without_agent_fields_is_no_card(self):
        state, card, detail = C.probe_agent_card(
            "https://x.a.run.app", fetch=lambda u: (True, {"hello": "world"}, None, 200))
        self.assertEqual(state, "no_card")
        self.assertIsNone(card)
        self.assertIn("neither name nor skills", detail)

    # ---- the row that is a card ----
    def test_a_served_card_is_detected(self):
        state, card, detail = C.probe_agent_card(
            "https://x.a.run.app",
            fetch=lambda u: (True, {"name": "invoice-triage",
                                    "skills": [{"id": "triage_invoice"}]}, None, 200))
        self.assertEqual(state, "card")
        self.assertEqual(card["name"], "invoice-triage")
        self.assertIsNone(detail)

    def test_the_real_invoice_triage_card_is_a_card(self):
        """The captured response from the live public endpoint."""
        payload = json.loads(_fixture("agent_card_invoice_triage.json"))
        state, card, _ = C.probe_agent_card(
            "https://x.a.run.app", fetch=lambda u: (True, payload, None, 200))
        self.assertEqual(state, "card")
        self.assertEqual(card["name"], "invoice-triage")
        self.assertEqual([s["id"] for s in card["skills"]],
                         ["triage_invoice", "export_ledger"])

    def test_probe_uses_the_a2a_well_known_path(self):
        seen = {}

        def f(u):
            seen["u"] = u
            return True, {"name": "n"}, None, 200
        C.probe_agent_card("https://x.a.run.app/", fetch=f)
        self.assertEqual(seen["u"], "https://x.a.run.app/.well-known/agent-card.json")


class TestTheProbeTupleContract(unittest.TestCase):
    """card is ALWAYS a dict or None — never the error string.

    A live fleet run died in collect with "'str' object has no attribute
    'get'" because the failure branch put the reason in the card slot and the
    caller called .get() on it. The contract is now checked on every branch.
    """

    BRANCHES = [
        ("transport", lambda u: (False, None, "URLError: nope", -1)),
        ("401", lambda u: (False, None, "HTTP 401", 401)),
        ("500", lambda u: (False, None, "HTTP 500", 500)),
        ("404", lambda u: (False, None, "HTTP 404", 404)),
        ("unparseable", lambda u: (True, None, "response body is not JSON: x", 200)),
        ("not a dict", lambda u: (True, ["x"], None, 200)),
        ("empty dict", lambda u: (True, {}, None, 200)),
        ("card", lambda u: (True, {"name": "n"}, None, 200)),
    ]

    def test_card_is_never_a_string_on_any_branch(self):
        for label, fetch in self.BRANCHES:
            with self.subTest(branch=label):
                state, card, detail = C.probe_agent_card("https://x.a.run.app",
                                                         fetch=fetch)
                self.assertTrue(card is None or isinstance(card, dict),
                                "card was %r on the %s branch" % (type(card), label))
                self.assertTrue(detail is None or isinstance(detail, str))
                self.assertIn(state, ("card", "no_card", "UNREACHABLE"))

    def test_probe_run_services_survives_an_unreachable_service(self):
        """The exact crash: a failing probe must not stop the collection."""
        rows = C.probe_run_services(
            [{"status": {"url": "https://down.a.run.app"}}],
            fetch=lambda u: (False, None, "HTTP 500", 500))
        row = rows["https://down.a.run.app"]
        self.assertEqual(row["state"], "UNREACHABLE")
        self.assertIsNone(row["declared_name"])
        self.assertEqual(row["declared_skills"], [])
        self.assertIn("500", row["detail"])

    def test_probe_run_services_reports_a_served_card(self):
        rows = C.probe_run_services(
            [{"status": {"url": "https://x.a.run.app/"}}],
            fetch=lambda u: (True, {"name": "invoice-triage",
                                    "skills": [{"id": "triage_invoice"}]}, None, 200))
        row = rows["https://x.a.run.app"]
        self.assertEqual(row["state"], "card")
        self.assertEqual(row["declared_name"], "invoice-triage")
        self.assertEqual(row["declared_skills"], ["triage_invoice"])


class TestABodyThatArrivedIsNotAnOutage(unittest.TestCase):
    """json.JSONDecodeError is split out of the generic except in _plain_get.

    Measured on the live fleet: the report service answers the well-known path
    with HTTP 200 and text/html. Folded into the generic except, that reachable
    service was filed as UNREACHABLE — an outage that was not happening.
    """

    def _with_body(self, body, status=200):
        import unittest.mock as mock
        with mock.patch.object(C.urllib.request, "urlopen",
                               return_value=_FakeResponse(body, status)):
            return C._plain_get("https://x.a.run.app/.well-known/agent-card.json")

    def test_html_at_200_is_ok_with_a_parse_detail_not_a_transport_failure(self):
        ok, payload, detail, code = self._with_body(_fixture("no_card_page.html"))
        self.assertTrue(ok, "a body that arrived is not a failure to reach")
        self.assertIsNone(payload)
        self.assertIn("not JSON", detail)
        self.assertEqual(code, 200)

    def test_html_at_200_classifies_as_no_card_end_to_end(self):
        import unittest.mock as mock
        with mock.patch.object(C.urllib.request, "urlopen",
                               return_value=_FakeResponse(_fixture("no_card_page.html"))):
            state, card, detail = C.probe_agent_card("https://x.a.run.app")
        self.assertEqual(state, "no_card")
        self.assertIsNone(card)
        self.assertIn("not JSON", detail)

    def test_a_real_card_still_parses_end_to_end(self):
        import unittest.mock as mock
        body = _fixture("agent_card_invoice_triage.json")
        with mock.patch.object(C.urllib.request, "urlopen",
                               return_value=_FakeResponse(body)):
            state, card, _ = C.probe_agent_card("https://x.a.run.app")
        self.assertEqual(state, "card")
        self.assertEqual(card["name"], "invoice-triage")

    def test_an_empty_body_at_200_is_no_card_not_unreachable(self):
        ok, payload, detail, code = self._with_body("")
        self.assertTrue(ok)
        self.assertEqual(payload, {})
        self.assertIsNone(detail)


class TestAuditWindow(unittest.TestCase):
    """The window is bounded by project age, not by a switch."""

    def setUp(self):
        import datetime
        self.now = datetime.datetime(2026, 8, 21, 2, 0, 0,
                                     tzinfo=datetime.timezone.utc)

    def test_parses_a_normal_timestamp(self):
        self.assertEqual(C._iso_days_ago("2026-08-18T11:59:11.060391Z", self.now), 2)

    def test_parses_nine_fractional_digits(self):
        """gcloud emits 9-digit fractions; fromisoformat rejects them."""
        self.assertEqual(C._iso_days_ago("2026-08-21T01:16:09.943957369Z", self.now), 0)

    def test_unparseable_is_none_not_zero(self):
        self.assertIsNone(C._iso_days_ago("not-a-time", self.now))
        self.assertIsNone(C._iso_days_ago(None, self.now))
        self.assertIsNone(C._iso_days_ago("", self.now))

    def test_a_future_timestamp_clamps_to_zero(self):
        self.assertEqual(C._iso_days_ago("2027-01-01T00:00:00Z", self.now), 0)


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
