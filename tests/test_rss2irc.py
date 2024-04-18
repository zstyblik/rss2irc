#!/usr/bin/env python3
"""Unit tests for rss2irc.py."""
import io
import logging
import os
import sys
import time
from unittest.mock import patch

import pytest

import rss2irc  # noqa:I202

SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))


@pytest.mark.parametrize(
    "url,msg_attrs,handle,expected",
    [
        ("http://example.com", ("title", ""), "", "http://example.com\n"),
        (
            "http://example.com",
            ("title", None),
            "handle",
            "[handle] title | http://example.com\n",
        ),
        (
            "http://example.com",
            ("title", "category"),
            "handle",
            "[handle-category] title | http://example.com\n",
        ),
    ],
)
def test_format_message(url, msg_attrs, handle, expected):
    """Test format_message()."""
    result = rss2irc.format_message(url, msg_attrs, handle)
    assert result == expected


@patch("rss2irc.stat.S_ISFIFO")
def test_main_ideal(
    mock_s_isfifo, fixture_http_server, fixture_cache_file, fixture_output_file
):
    """End-to-end test - ideal environment."""
    handle = "test"
    http_timeout = "10"
    expected_cache_keys = [
        "http://www.example.com/scan.php?page=news_item&px=item1",
        "http://www.example.com/scan.php?page=news_item&px=item2",
    ]
    expected_output = [
        (
            b"[test] Item1 | "
            b"http://www.example.com/scan.php?page=news_item&px=item1\n"
        ),
        (
            b"[test] Item2 | "
            b"http://www.example.com/scan.php?page=news_item&px=item2\n"
        ),
    ]

    logger = logging.getLogger("test")
    rss_fname = os.path.join(SCRIPT_PATH, "files", "rss.xml")
    with open(rss_fname, "rb") as fhandle:
        fixture_http_server.serve_content(fhandle.read().decode("utf-8"), 200)

    mock_s_isfifo.return_value = True

    rss_url = fixture_http_server.url

    exception = None
    args = [
        "./rss2irc.py",
        "--rss-url",
        rss_url,
        "--rss-http-timeout",
        http_timeout,
        "--handle",
        handle,
        "--cache",
        fixture_cache_file,
        "--output",
        fixture_output_file,
    ]

    print("URL: {:s}".format(rss_url))
    print("Handle: {:s}".format(handle))
    print("Cache file: {:s}".format(fixture_cache_file))
    print("Output file: {:s}".format(fixture_output_file))

    saved_stdout = sys.stdout
    out = io.StringIO()
    sys.stdout = out

    with patch.object(sys, "argv", args):
        try:
            rss2irc.main()
        except SystemExit as sys_exit:
            exception = sys_exit
        finally:
            sys.stdout = saved_stdout

    with open(fixture_output_file, "rb") as fhandle:
        output = fhandle.readlines()

    assert isinstance(exception, SystemExit) is True
    assert exception.code == 0
    assert out.getvalue().strip() == ""
    # Check cache and keys in it
    cache = rss2irc.read_cache(logger, fixture_cache_file)
    print("Cache: {}".format(cache))
    assert list(cache.items.keys()) == expected_cache_keys
    # check output file
    assert sorted(output) == sorted(expected_output)


def test_scrub_cache():
    """Test scrub_cache()."""
    logging.basicConfig(level=logging.CRITICAL)
    logger = logging.getLogger()
    logger.disabled = True

    item_expiration = int(time.time()) + 60
    test_cache = rss2irc.CachedData(
        items={
            "foo": item_expiration,
            "bar": int(time.time()) - 3600,
            "lar": "efg",
        }
    )
    expected = {
        "foo": item_expiration,
    }
    rss2irc.scrub_cache(logger, test_cache)
    assert test_cache.items == expected
