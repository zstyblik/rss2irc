#!/usr/bin/env python3
"""Unit tests for rss2slack.py."""
import io
import logging
import os
import sys
import time
from unittest.mock import patch

import pytest

import rss2irc  # noqa: I100, I202
import rss2slack  # noqa: I100, I202
from lib import CachedData  # noqa: I100, I202
from lib import config_options  # noqa: I100, I202

SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))


@pytest.mark.parametrize(
    "url,msg_attrs,handle,expected",
    [
        (
            "http://example.com",
            ("title", ""),
            "",
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "<http://example.com|title>",
                },
            },
        ),
        (
            "http://example.com",
            ("title", None),
            "handle",
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "[handle] <http://example.com|title>",
                },
            },
        ),
        (
            "http://example.com",
            ("title", "category"),
            "handle",
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "[handle-category] <http://example.com|title>",
                },
            },
        ),
    ],
)
def test_format_message(url, msg_attrs, handle, expected):
    """Test format_message()."""
    result = rss2slack.format_message(url, msg_attrs, handle)
    assert result == expected


def test_get_slack_token(monkeypatch):
    """Test get_slack_token()."""
    monkeypatch.setenv("SLACK_TOKEN", "test")

    token = rss2slack.get_slack_token()
    assert token == "test"


def test_get_slack_token_no_token():
    """Test get_slack_token() when ENV variable is not set."""
    exception = None
    try:
        rss2slack.get_slack_token()
    except ValueError as value_error:
        exception = value_error

    assert isinstance(exception, ValueError) is True
    assert exception.args[0] == "SLACK_TOKEN must be set."


def test_main_ideal(
    monkeypatch, fixture_mock_requests, fixture_cache_file, fixture_http_server
):
    """End-to-end test - ideal environment."""
    handle = "test"
    http_timeout = "10"
    rss_url = "http://rss.example.com"
    expected_cache_keys = [
        "http://www.example.com/scan.php?page=news_item&px=item1",
        "http://www.example.com/scan.php?page=news_item&px=item2",
    ]
    expected_slack_channel = "test"
    expected_slack_requests = [
        {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "[test] <http://www.example.com/scan.php?"
                            + "page=news_item&px=item1|Item1>"
                        ),
                    },
                }
            ],
            "channel": expected_slack_channel,
        },
        {
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            "[test] <http://www.example.com/scan.php?"
                            + "page=news_item&px=item2|Item2>"
                        ),
                    },
                }
            ],
            "channel": expected_slack_channel,
        },
    ]
    # Mock/set SLACK_TOKEN
    monkeypatch.setenv("SLACK_TOKEN", "test")
    # Mock HTTP RSS
    rss_fname = os.path.join(SCRIPT_PATH, "files", "rss.xml")
    with open(rss_fname, "rb") as fhandle:
        rss_data = fhandle.read().decode("utf-8")

    mock_http_rss = fixture_mock_requests.get(
        rss_url,
        text=rss_data,
        headers={
            "ETag": "pytest_etag",
            "Last-Modified": "pytest_lm",
        },
    )
    # Mock Slack HTTP request
    fixture_http_server.serve_content(
        '{"ok": "true", "error": ""}',
        200,
        {"Content-Type": "application/json"},
    )
    fixture_http_server.store_request_data = True

    cache = CachedData()
    source1 = cache.get_source_by_url(rss_url)
    source1.http_etag = ""
    source1.http_last_modified = ""
    source1.last_used_ts = int(time.time()) - 2 * 86400
    source2 = cache.get_source_by_url("http://delete.example.com")
    source2.last_used_ts = (
        int(time.time()) - 2 * config_options.DATA_SOURCE_EXPIRATION
    )
    rss2irc.write_cache(cache, fixture_cache_file)

    #
    exception = None
    args = [
        "./rss2slack.py",
        "--rss-url",
        rss_url,
        "--rss-http-timeout",
        http_timeout,
        "--handle",
        handle,
        "--cache",
        fixture_cache_file,
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
            rss2slack.main()
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
    assert rss_url in cache.data_sources.keys()
    source = cache.get_source_by_url(rss_url)
    assert source.url == rss_url
    assert source.http_etag == "pytest_etag"
    assert source.http_last_modified == "pytest_lm"
    assert source.last_used_ts > int(time.time()) - 60
    assert "http://delete.example.com" not in cache.data_sources
    # Check HTTP RSS mock
    assert mock_http_rss.called is True
    assert mock_http_rss.call_count == 1
    assert mock_http_rss.last_request.text is None
    # Check HTTP Slack
    # Note: this is just a shallow check, but it's better than nothing.
    assert len(fixture_http_server.requests) == 2

    req0 = fixture_http_server.requests[0]
    assert req0.method == "POST"
    data = req0.get_json()
    assert data == expected_slack_requests[0]

    req1 = fixture_http_server.requests[1]
    assert req1.method == "POST"
    data = req1.get_json()
    assert data == expected_slack_requests[1]


def test_main_cache_hit(
    monkeypatch, fixture_mock_requests, fixture_cache_file, fixture_http_server
):
    """Test that HTTP Status Code 304 is handled as expected."""
    handle = "test"
    http_timeout = "10"
    rss_url = "http://rss.example.com"
    expected_cache_keys = []
    expected_slack_channel = "test"
    # Mock/set SLACK_TOKEN
    monkeypatch.setenv("SLACK_TOKEN", "test")
    # Mock HTTP RSS
    mock_http_rss = fixture_mock_requests.get(
        rss_url,
        status_code=304,
        text="",
        headers={
            "ETag": "pytest_etag",
            "Last-Modified": "pytest_lm",
        },
    )
    # Mock Slack HTTP request
    fixture_http_server.serve_content(
        "Should not be called",
        500,
        {"Content-Type": "application/json"},
    )

    cache = CachedData()
    source1 = cache.get_source_by_url(rss_url)
    source1.http_etag = "pytest_etag"
    source1.http_last_modified = "pytest_lm"
    source1.last_used_ts = int(time.time()) - 2 * 86400
    rss2irc.write_cache(cache, fixture_cache_file)
    #
    exception = None
    args = [
        "./rss2slack.py",
        "--rss-url",
        rss_url,
        "--rss-http-timeout",
        http_timeout,
        "--handle",
        handle,
        "--cache",
        fixture_cache_file,
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
            rss2slack.main()
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
    assert rss_url in cache.data_sources.keys()
    source = cache.get_source_by_url(rss_url)
    assert source.url == rss_url
    assert source.http_etag == "pytest_etag"
    assert source.http_last_modified == "pytest_lm"
    assert source.last_used_ts > int(time.time()) - 60
    # Check HTTP RSS mock
    assert mock_http_rss.called is True
    assert mock_http_rss.call_count == 1
    assert mock_http_rss.last_request.text is None
    # Check HTTP Slack
    # Note: this is just a shallow check, but it's better than nothing.
    assert len(fixture_http_server.requests) == 0
