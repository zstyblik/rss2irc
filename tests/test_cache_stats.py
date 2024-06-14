#!/usr/bin/env python3
"""Unit tests for cache_stats.py."""
import io
import os
import sys
import time
from unittest.mock import patch

import cache_stats  # noqa:I202
import rss2irc  # noqa:I202

SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))


def test_main_ideal(fixture_cache_file):
    """Simple run-through test."""
    rss_url = "https://example.com/rss"

    cache = rss2irc.CachedData()
    cache.items = {
        "a": int(time.time()),
        "b": int(time.time()),
        "c": int(time.time()),
        "d": int(time.time()) - 60,
        "e": int(time.time()) - 120,
        "f": int(time.time()) - 120,
        "g": int(time.time()) - 120,
    }
    source1 = cache.get_source_by_url(rss_url)
    source1.http_etag = ""
    source1.http_last_modified = ""
    source1.last_used_ts = int(time.time()) - 2 * 86400
    rss2irc.write_cache(cache, fixture_cache_file)

    exception = None
    args = [
        "./cache_stats.py",
        "--cache",
        fixture_cache_file,
    ]

    print("Cache file: {:s}".format(fixture_cache_file))

    saved_stdout = sys.stdout
    out = io.StringIO()
    sys.stdout = out

    with patch.object(sys, "argv", args):
        try:
            cache_stats.main()
        except SystemExit as sys_exit:
            exception = sys_exit
        finally:
            sys.stdout = saved_stdout

    assert isinstance(exception, SystemExit) is True
    assert exception.code == 0
    assert out.getvalue().strip() == ""
