#!/usr/bin/env python3
"""Unit tests for phpbb2slack.py."""
import io
import json
import logging
import os
import sys
import time
from unittest.mock import patch

import pytest

import phpbb2slack  # noqa:I100,I202
import rss2irc

ITEM_EXPIRATION = int(time.time())
SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))


def get_item_expiration():
    """Return U*nix timestamp as int.

    Hack around time-related tests and unwillingness to mock time.
    """
    return int(time.time())


@pytest.mark.parametrize(
    "test_data",
    [
        {
            "url": "http://www.example.com",
            "attrs": {
                "category": "test",
                "comments_cnt": 12,
                "title": "someTitle",
            },
            "handle": "someHandle",
            "expected": {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        "[someHandle-test] <http://www.example.com|someTitle>"
                        " (12)"
                    ),
                },
            },
        },
        {
            "url": "http://www.example.com",
            "attrs": {
                "category": "",
                "comments_cnt": 1,
                "title": "someTitle",
            },
            "handle": "someHandle",
            "expected": {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        "[someHandle] <http://www.example.com|someTitle>" " (1)"
                    ),
                },
            },
        },
    ],
)
def test_format_message(test_data):
    """Test format_message()."""
    message = phpbb2slack.format_message(
        test_data["url"], test_data["attrs"], test_data["handle"]
    )
    assert message == test_data["expected"]


@pytest.mark.parametrize(
    "input_file,expected_authors",
    [
        (
            "authors.txt",
            [
                "author1",
                "author2",
            ],
        ),
    ],
)
def test_get_authors_from_file(input_file, expected_authors):
    """Test get_authors_from_file()."""
    authors_file = os.path.join(SCRIPT_PATH, "files", input_file)
    logger = logging.getLogger()
    logger.disabled = True
    authors = phpbb2slack.get_authors_from_file(logger, authors_file)
    assert authors == expected_authors


def test_get_authors_from_file_no_file():
    """Test get_authors_from_file() when no file is given."""
    authors_file = ""
    expected_authors = []
    logger = logging.getLogger()
    logger.disabled = True
    authors = phpbb2slack.get_authors_from_file(logger, authors_file)
    assert authors == expected_authors


def test_main_ideal(
    monkeypatch, fixture_mock_requests, fixture_cache_file, fixture_http_server
):
    """End-to-end test - ideal environment."""
    handle = "test"
    http_timeout = "10"
    rss_url = "http://rss.example.com"
    expected_cache_keys = [
        "https://phpbb.example.com/threads/something-of-something.424837/",
    ]
    expected_slack_channel = "test"

    # Mock/set SLACK_TOKEN
    monkeypatch.setenv("SLACK_TOKEN", "test")
    # Mock HTTP RSS
    rss_fname = os.path.join(SCRIPT_PATH, "files", "phpbb-rss.xml")
    with open(rss_fname, "rb") as fhandle:
        rss_data = fhandle.read().decode("utf-8")

    mock_http_rss = fixture_mock_requests.get(rss_url, text=rss_data)
    # Mock Slack HTTP request
    fixture_http_server.serve_content(
        '{"ok": "true", "error": ""}',
        200,
        {"Content-Type": "application/json"},
    )
    fixture_http_server.capture_requests = True
    expected_slack_requests = [
        {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "[test] <https://phpbb.example.com/threads/"
                            + "something-of-something.424837/"
                            + "|Some other problem> (0)"
                        ),
                    },
                }
            ],
            "channel": expected_slack_channel,
        }
    ]
    #
    authors_file = os.path.join(SCRIPT_PATH, "files", "authors.txt")
    exception = None
    args = [
        "./phpbb2slack.py",
        "--authors-of-interest",
        authors_file,
        "--cache",
        fixture_cache_file,
        "--handle",
        handle,
        "--rss-url",
        rss_url,
        "--rss-http-timeout",
        http_timeout,
        "--slack-base-url",
        fixture_http_server.url,
        "--slack-channel",
        expected_slack_channel,
        "--slack-timeout",
        "10",
        "-v",
    ]

    print("RSS URL: {:s}".format(rss_url))
    print("Slack URL: {:s}".format(fixture_http_server.url))
    print("Handle: {:s}".format(handle))
    print("Cache file: {:s}".format(fixture_cache_file))

    saved_stdout = sys.stdout
    out = io.StringIO()
    sys.stdout = out

    with patch.object(sys, "argv", args):
        try:
            phpbb2slack.main()
        except SystemExit as sys_exit:
            exception = sys_exit
        finally:
            sys.stdout = saved_stdout

    assert isinstance(exception, SystemExit) is True
    assert exception.code == 0
    assert out.getvalue().strip() == ""
    # Check cache and keys in it
    logger = logging.getLogger("test")
    cache = rss2irc.read_cache(logger, fixture_cache_file)
    print("Cache: {}".format(cache))
    assert list(cache.items.keys()) == expected_cache_keys
    # Check HTTP RSS mock
    assert mock_http_rss.called is True
    assert mock_http_rss.call_count == 1
    assert mock_http_rss.last_request.text is None
    # Check HTTP Slack
    # Note: this is just a shallow check, but it's better than nothing.
    assert len(fixture_http_server.requests) == 1

    req0 = fixture_http_server.captured_requests[0]
    assert req0[0] == "POST"
    data = json.loads(req0[1])
    assert data == expected_slack_requests[0]


@pytest.mark.parametrize(
    "cache,expected_cache",
    [
        (
            rss2irc.CachedData(
                items={
                    "foo": {
                        "expiration": get_item_expiration() + 60,
                    },
                    "bar": {
                        "expiration": get_item_expiration() - 3600,
                    },
                    "lar": {
                        "abc": "efg",
                    },
                }
            ),
            {
                "foo": {
                    "expiration": get_item_expiration() + 60,
                },
            },
        )
    ],
)
def test_scrub_cache(cache, expected_cache):
    """Test scrub_cache()."""
    logger = logging.getLogger()
    logger.disabled = True
    phpbb2slack.scrub_cache(logger, cache)
    assert cache.items == expected_cache


@pytest.mark.parametrize(
    "news,cache,expected_cache,item_expiration",
    [
        (
            {
                "http://example.com": {
                    "comments_cnt": 2,
                },
                "http://www.example.com": {
                    "comments_cnt": 20,
                },
            },
            rss2irc.CachedData(
                items={
                    "http://example.com": {
                        "expiration": 0,
                        "comments_cnt": 1,
                    },
                }
            ),
            {
                "http://example.com": {
                    "expiration": get_item_expiration() + 60,
                    "comments_cnt": 2,
                },
                "http://www.example.com": {
                    "expiration": get_item_expiration() + 60,
                    "comments_cnt": 20,
                },
            },
            get_item_expiration() + 60,
        )
    ],
)
def test_update_cache(news, cache, expected_cache, item_expiration):
    """Test update_cache()."""
    phpbb2slack.update_cache(cache, news, item_expiration)
    assert cache.items == expected_cache
