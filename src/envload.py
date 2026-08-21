"""Load .env into os.environ without the value ever being visible.

The key never passes through a print, a log line, a shell echo, or an
exception message. Callers get back only the NAMES of what was loaded and
the path it came from — enough to debug a missing key, never enough to leak
one.
"""
import os

CANDIDATE_NAMES = (".env",)


def find_env(start):
    """Nearest .env at `start` or a parent, up to the filesystem root."""
    cur = os.path.abspath(start)
    while True:
        for name in CANDIDATE_NAMES:
            path = os.path.join(cur, name)
            if os.path.isfile(path):
                return path
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        cur = parent


def parse(text):
    """KEY=VALUE lines. Ignores blanks, comments, and malformed lines."""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        out[key] = value
    return out


def load(start=".", override=False):
    """Load the nearest .env. Returns (path, sorted key NAMES) — never values.

    An already-set environment variable wins unless override=True, so an
    explicit export in the shell always beats a file on disk.
    """
    path = find_env(start)
    if not path:
        return None, []
    try:
        with open(path) as f:
            pairs = parse(f.read())
    except OSError:
        return path, []
    loaded = []
    for key, value in pairs.items():
        if override or not os.environ.get(key):
            os.environ[key] = value
        loaded.append(key)
    return path, sorted(loaded)


def describe(path, keys):
    """A line safe to print. Names only, and lengths, never contents."""
    if not path:
        return "no .env found; relying on the ambient environment"
    if not keys:
        return "read %s but found no usable KEY=VALUE lines" % path
    shown = ", ".join("%s(len %d)" % (k, len(os.environ.get(k, ""))) for k in keys)
    return "loaded from %s: %s" % (path, shown)
