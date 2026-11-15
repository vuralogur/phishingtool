import os
import sys
import pathlib

import pytest

# Make the project root importable so `import detector` works under pytest.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

# Test modules build their context at import time (CTX = build_context(...)),
# before any fixture runs - so the threat-list folder is pinned here, not in a
# fixture. Without it a developer who ran `phishingtool feeds update` would test
# against today's block lists and get a different answer tomorrow.
os.environ["PHISHINGTOOL_FEEDS"] = str(
    pathlib.Path(__file__).resolve().parent / "_no_feeds_here")


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """No test reaches the network: both HTTP helpers fail loudly if called."""
    from detector import feeds, rdap

    def refuse(url, *args, **kwargs):
        raise AssertionError("test aga cikmaya calisti: " + str(url))

    monkeypatch.setattr(feeds, "_http_get", refuse)
    monkeypatch.setattr(rdap, "_http_get", refuse)
    rdap._cache.clear()
