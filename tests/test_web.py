"""The report page must never claim to be live while serving a snapshot."""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "web"))


class TestThePageIsHonestAboutBeingASnapshot(unittest.TestCase):
    def _render(self, collected="2026-08-21T05:00:00+00:00"):
        import main
        d = tempfile.mkdtemp()
        for k in ("agents", "bindings", "endpoints", "mcp-servers",
                  "services", "run", "sa", "model_armor"):
            json.dump([], open(os.path.join(d, k + ".json"), "w"))
        json.dump({}, open(os.path.join(d, "iam.json"), "w"))
        json.dump({"__collected_at__": collected, "__project__": "p",
                   "__location__": "global"},
                  open(os.path.join(d, "manifest.json"), "w"))
        main.SNAPSHOT = d
        return main.render()

    def test_it_says_recorded_not_live(self):
        page = self._render()
        self.assertIn("recorded campaign, not a live read", page)
        self.assertNotIn("live report", page.lower())

    def test_it_shows_the_collection_timestamp(self):
        self.assertIn("2026-08-21T05:00:00", self._render())

    def test_it_states_no_model_can_reach_a_verdict(self):
        self.assertIn("No language model can reach one", self._render())

    def test_it_links_the_source(self):
        self.assertIn("github.com/seekdaseek/muster", self._render())

    def test_it_renders_the_campaign_block(self):
        self.assertIn("CERTIFICATION CAMPAIGN", self._render())

    def test_an_unknown_timestamp_is_labelled_not_faked(self):
        import main
        d = tempfile.mkdtemp()
        json.dump({}, open(os.path.join(d, "manifest.json"), "w"))
        main.SNAPSHOT = d
        self.assertIn("unknown", main.render())


if __name__ == "__main__":
    unittest.main(verbosity=2)
