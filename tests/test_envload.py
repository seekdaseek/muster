"""The env loader's one job: get the key into the process without ever
exposing it. Every test here uses a canary value and asserts it never
appears in anything the loader hands back."""
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import envload as E  # noqa: E402

CANARY = "sk-CANARY-must-never-be-printed-9f3a"


class TestTheValueNeverEscapes(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        with open(os.path.join(self.dir, ".env"), "w") as f:
            f.write("GOOGLE_API_KEY=%s\n" % CANARY)
        self._saved = os.environ.pop("GOOGLE_API_KEY", None)

    def tearDown(self):
        os.environ.pop("GOOGLE_API_KEY", None)
        if self._saved is not None:
            os.environ["GOOGLE_API_KEY"] = self._saved

    def test_load_returns_names_not_values(self):
        path, keys = E.load(self.dir)
        self.assertEqual(keys, ["GOOGLE_API_KEY"])
        self.assertNotIn(CANARY, str(keys))
        self.assertNotIn(CANARY, path)

    def test_describe_shows_a_length_never_the_secret(self):
        path, keys = E.load(self.dir)
        line = E.describe(path, keys)
        self.assertNotIn(CANARY, line)
        self.assertIn("len %d" % len(CANARY), line)

    def test_the_value_does_reach_the_environment(self):
        E.load(self.dir)
        self.assertEqual(os.environ["GOOGLE_API_KEY"], CANARY)

    def test_describe_with_no_env_file_says_so_safely(self):
        line = E.describe(None, [])
        self.assertIn("no .env found", line)
        self.assertNotIn(CANARY, line)


class TestPrecedenceAndParsing(unittest.TestCase):
    def test_an_existing_export_wins_over_the_file(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, ".env"), "w") as f:
            f.write("MUSTER_T=from_file\n")
        os.environ["MUSTER_T"] = "from_shell"
        try:
            E.load(d)
            self.assertEqual(os.environ["MUSTER_T"], "from_shell")
            E.load(d, override=True)
            self.assertEqual(os.environ["MUSTER_T"], "from_file")
        finally:
            os.environ.pop("MUSTER_T", None)

    def test_quotes_are_stripped(self):
        self.assertEqual(E.parse('A="x"\nB=\'y\'\n'), {"A": "x", "B": "y"})

    def test_comments_blanks_and_junk_are_ignored(self):
        self.assertEqual(E.parse("# c\n\nnoequals\n=novalue\nK=v\n"), {"K": "v"})

    def test_values_containing_equals_survive(self):
        self.assertEqual(E.parse("K=a=b=c\n"), {"K": "a=b=c"})

    def test_find_env_walks_up_to_a_parent(self):
        d = tempfile.mkdtemp()
        child = os.path.join(d, "a", "b")
        os.makedirs(child)
        with open(os.path.join(d, ".env"), "w") as f:
            f.write("K=v\n")
        self.assertEqual(E.find_env(child), os.path.join(d, ".env"))

    def test_find_env_returns_none_rather_than_looping_forever(self):
        d = tempfile.mkdtemp()
        self.assertIsNone(E.find_env(d))

    def test_an_unreadable_env_is_not_a_crash(self):
        d = tempfile.mkdtemp()
        os.mkdir(os.path.join(d, ".env"))  # a directory, not a file
        path, keys = E.load(d)
        self.assertEqual(keys, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
