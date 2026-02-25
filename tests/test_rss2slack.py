#!/usr/bin/env python3
"""Unit tests for rss2slack.py."""
import io
import logging
import os
import sys
import time
from unittest.mock import Mock
from unittest.mock import patch

import pytest

import rss2irc
import rss2slack
from lib import CachedData
from lib import config_options
from lib.exceptions import CacheReadError
from lib.exceptions import EmptyResponseError
from lib.exceptions import SlackTokenError

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
    except SlackTokenError as value_error:
        exception = value_error

    assert isinstance(exception, SlackTokenError) is True
    assert exception.args[0] == "SLACK_TOKEN env variable must be set"


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
            "text": (
                "[test] <http://www.example.com/scan.php?"
                + "page=news_item&px=item1|Item1>"
            ),
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
            "text": (
                "[test] <http://www.example.com/scan.php?"
                + "page=news_item&px=item2|Item2>"
            ),
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


@pytest.mark.parametrize(
    "extra_args,expected_retcode",
    [
        ([], 0),
        (["--return-error"], 1),
    ],
)
@patch("rss2slack.rss2irc.wrap_write_cache")
@patch("rss2slack.rss2irc.read_cache")
def test_main_slack_token_error(
    mock_read_cache,
    mock_wrap_write_cache,
    extra_args,
    expected_retcode,
    caplog,
):
    """Test that SlackTokenError is handled as expected."""
    expected_log_records = [
        (
            "rss2slack",
            40,
            "Environment variable SLACK_TOKEN must be set.",
        ),
    ]
    handle = "test"
    http_timeout = "10"
    rss_url = "http://rss.example.com"
    slack_base_url = "https://slack.example.com"
    expected_slack_channel = "test"
    fixture_cache_file = "/path/not/exist/cache.file"

    mock_read_cache.return_value = CachedData()

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
        slack_base_url,
        "--slack-channel",
        expected_slack_channel,
        "--slack-timeout",
        "10",
        "-v",
    ] + extra_args

    print("RSS URL: {:s}".format(rss_url))
    print("Slack URL: {:s}".format(slack_base_url))
    print("Handle: {:s}".format(handle))
    print("Cache file: {:s}".format(fixture_cache_file))

    with patch.object(sys, "argv", args):
        try:
            rss2slack.main()
        except SystemExit as sys_exit:
            exception = sys_exit

    assert isinstance(exception, SystemExit) is True
    assert exception.code == expected_retcode
    mock_wrap_write_cache.assert_not_called()
    assert caplog.record_tuples == expected_log_records


@pytest.mark.parametrize(
    "extra_args,expected_retcode",
    [
        ([], 0),
        (["--return-error"], 1),
    ],
)
@patch("rss2irc.wrap_write_cache")
@patch("rss2irc.read_cache")
def test_main_cache_read_error(
    mock_read_cache,
    mock_wrap_write_cache,
    extra_args,
    expected_retcode,
    monkeypatch,
    caplog,
):
    """Test that CacheReadError is handled as expected."""
    expected_log_records = [
        (
            "rss2slack",
            40,
            "Error while reading cache file '/path/not/exist/cache.file'.",
        ),
    ]
    handle = "test"
    http_timeout = "10"
    rss_url = "http://rss.example.com"
    slack_base_url = "https://slack.example.com"
    expected_slack_channel = "test"
    fixture_cache_file = "/path/not/exist/cache.file"

    # Mock/set SLACK_TOKEN
    monkeypatch.setenv("SLACK_TOKEN", "test")
    mock_read_cache.side_effect = CacheReadError("pytest")

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
        slack_base_url,
        "--slack-channel",
        expected_slack_channel,
        "--slack-timeout",
        "10",
        "-v",
    ] + extra_args

    print("RSS URL: {:s}".format(rss_url))
    print("Slack URL: {:s}".format(slack_base_url))
    print("Handle: {:s}".format(handle))
    print("Cache file: {:s}".format(fixture_cache_file))

    with patch.object(sys, "argv", args):
        try:
            rss2slack.main()
        except SystemExit as sys_exit:
            exception = sys_exit

    assert isinstance(exception, SystemExit) is True
    assert exception.code == expected_retcode
    mock_read_cache.assert_called_once()
    mock_wrap_write_cache.assert_not_called()
    assert caplog.record_tuples == expected_log_records


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


@pytest.mark.parametrize(
    "extra_args,expected_retcode",
    [
        ([], 0),
        (["--return-error"], 1),
    ],
)
@patch("rss2irc.wrap_write_cache")
@patch("rss2irc.get_rss")
@patch("rss2irc.read_cache")
def test_main_empty_response_error(
    mock_read_cache,
    mock_get_rss,
    mock_wrap_write_cache,
    extra_args,
    expected_retcode,
    monkeypatch,
    caplog,
):
    """Test that EmptyResponseError is handled as expected."""
    expected_log_records = [
        (
            "rss2slack",
            40,
            "Got empty response from 'http://rss.example.com'.",
        ),
    ]
    handle = "test"
    http_timeout = "10"
    rss_url = "http://rss.example.com"
    slack_base_url = "https://slack.example.com"
    expected_slack_channel = "test"
    cache_key = "http://example.com"
    frozen_ts = int(time.time())
    fixture_cache_file = "/path/not/exist/cache.file"

    cache = CachedData()
    cache.items[cache_key] = frozen_ts + 60
    cache.items["https://expired.example.com"] = 123456
    source1 = cache.get_source_by_url(rss_url)
    source1.http_error_count = 0
    source1.http_etag = ""
    source1.http_last_modified = ""
    source1.last_used_ts = frozen_ts - 2 * 86400
    source2 = cache.get_source_by_url("http://delete.example.com")
    source2.last_used_ts = frozen_ts - 2 * config_options.DATA_SOURCE_EXPIRATION

    # Mock/set SLACK_TOKEN
    monkeypatch.setenv("SLACK_TOKEN", "test")
    mock_read_cache.return_value = cache
    mock_get_rss.side_effect = EmptyResponseError("pytest")
    mock_wrap_write_cache.return_value = 0

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
        slack_base_url,
        "--slack-channel",
        expected_slack_channel,
        "--slack-timeout",
        "10",
        "-v",
    ] + extra_args

    print("RSS URL: {:s}".format(rss_url))
    print("Slack URL: {:s}".format(slack_base_url))
    print("Handle: {:s}".format(handle))
    print("Cache file: {:s}".format(fixture_cache_file))

    with patch.object(sys, "argv", args):
        try:
            rss2slack.main()
        except SystemExit as sys_exit:
            exception = sys_exit

    assert isinstance(exception, SystemExit) is True
    assert exception.code == expected_retcode
    mock_read_cache.assert_called_once()
    mock_get_rss.assert_called_once()
    mock_wrap_write_cache.assert_called_once()
    assert caplog.record_tuples == expected_log_records
    assert source1.http_error_count == 1


@pytest.mark.parametrize(
    "extra_args,expected_retcode",
    [
        ([], 0),
        (["--return-error"], 0),
    ],
)
@patch("rss2irc.wrap_write_cache")
@patch("rss2irc.get_rss")
@patch("rss2irc.read_cache")
def test_main_no_news_error(
    mock_read_cache,
    mock_get_rss,
    mock_wrap_write_cache,
    extra_args,
    expected_retcode,
    monkeypatch,
    caplog,
):
    """Test that NoNewsError is handled as expected."""
    expected_log_records = [
        (
            "rss2slack",
            20,
            "No news from 'http://rss.example.com'?",
        ),
    ]
    handle = "test"
    http_timeout = "10"
    rss_url = "http://rss.example.com"
    slack_base_url = "https://slack.example.com"
    expected_slack_channel = "test"
    cache_key = "http://example.com"
    frozen_ts = int(time.time())
    fixture_cache_file = "/path/not/exist/cache.file"

    cache = CachedData()
    cache.items[cache_key] = frozen_ts + 60
    cache.items["https://expired.example.com"] = 123456
    source1 = cache.get_source_by_url(rss_url)
    source1.http_error_count = 1
    source1.http_etag = ""
    source1.http_last_modified = ""
    source1.last_used_ts = frozen_ts - 2 * 86400
    source2 = cache.get_source_by_url("http://delete.example.com")
    source2.last_used_ts = frozen_ts - 2 * config_options.DATA_SOURCE_EXPIRATION

    # Mock/set SLACK_TOKEN
    monkeypatch.setenv("SLACK_TOKEN", "test")
    mock_read_cache.return_value = cache
    mock_rss_fname = os.path.join(SCRIPT_PATH, "files", "rss_no_news.xml")
    mock_rsp = Mock()
    with open(mock_rss_fname, "r", encoding="utf-8") as fhandle:
        mock_rsp.text = fhandle.read()

    mock_get_rss.return_value = mock_rsp
    mock_wrap_write_cache.return_value = 0

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
        slack_base_url,
        "--slack-channel",
        expected_slack_channel,
        "--slack-timeout",
        "10",
        "-vv",
    ] + extra_args

    print("RSS URL: {:s}".format(rss_url))
    print("Slack URL: {:s}".format(slack_base_url))
    print("Handle: {:s}".format(handle))
    print("Cache file: {:s}".format(fixture_cache_file))

    with patch.object(sys, "argv", args):
        try:
            rss2slack.main()
        except SystemExit as sys_exit:
            exception = sys_exit

    assert isinstance(exception, SystemExit) is True
    assert exception.code == expected_retcode
    mock_read_cache.assert_called_once()
    mock_get_rss.assert_called_once()
    mock_wrap_write_cache.assert_called_once()
    assert caplog.record_tuples == expected_log_records
    assert source1.http_error_count == 1
    # NOTE(zstyblik): check that we have all items and expiration has been
    # updated.
    assert len(cache.items) == 2
    for key in cache.items:
        assert cache.items[key] > frozen_ts


@pytest.mark.parametrize(
    "extra_args,expected_retcode",
    [
        ([], 0),
        (["--return-error"], 1),
    ],
)
@patch("rss2irc.wrap_write_cache")
@patch("rss2slack.get_slack_token")
@patch("rss2irc.read_cache")
def test_main_random_exception(
    mock_read_cache,
    mock_get_slack_token,
    mock_wrap_write_cache,
    extra_args,
    expected_retcode,
    caplog,
):
    """Test that unexpected exception is handled as expected."""
    expected_log_records = [
        (
            "rss2slack",
            40,
            "Unexpected exception has occurred.",
        ),
    ]
    handle = "test"
    http_timeout = "10"
    rss_url = "http://rss.example.com"
    slack_base_url = "https://slack.example.com"
    expected_slack_channel = "test"
    cache_key = "http://example.com"
    frozen_ts = int(time.time())
    fixture_cache_file = "/path/not/exist/cache.file"

    cache = CachedData()
    cache.items[cache_key] = frozen_ts
    cache.items["https://expired.example.com"] = frozen_ts
    source1 = cache.get_source_by_url(rss_url)
    source1.http_error_count = 1
    source1.http_etag = ""
    source1.http_last_modified = ""
    source1.last_used_ts = frozen_ts - 2 * 86400
    source2 = cache.get_source_by_url("http://delete.example.com")
    source2.last_used_ts = frozen_ts - 2 * config_options.DATA_SOURCE_EXPIRATION

    mock_read_cache.return_value = cache
    mock_get_slack_token.side_effect = ValueError("pytest")
    mock_wrap_write_cache.return_value = 0

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
        slack_base_url,
        "--slack-channel",
        expected_slack_channel,
        "--slack-timeout",
        "10",
        "-vv",
    ] + extra_args

    print("RSS URL: {:s}".format(rss_url))
    print("Slack URL: {:s}".format(slack_base_url))
    print("Handle: {:s}".format(handle))
    print("Cache file: {:s}".format(fixture_cache_file))

    with patch.object(sys, "argv", args):
        try:
            rss2slack.main()
        except SystemExit as sys_exit:
            exception = sys_exit

    assert isinstance(exception, SystemExit) is True
    assert exception.code == expected_retcode
    mock_read_cache.assert_called_once()
    mock_wrap_write_cache.assert_called_once()
    assert caplog.record_tuples == expected_log_records
    assert source1.http_error_count == 2
    # NOTE(zstyblik): check that we have all items and expiration is the same.
    assert len(cache.items) == 2
    for key in cache.items:
        assert cache.items[key] == frozen_ts


@pytest.mark.parametrize(
    "extra_args,expected_retcode",
    [
        (["--cache-init"], 0),
        (["--return-error", "--cache-init"], 1),
    ],
)
@patch("rss2irc.wrap_write_cache")
@patch("rss2irc.get_rss")
@patch("rss2irc.read_cache")
def test_main_wrap_write_cache_error(
    mock_read_cache,
    mock_get_rss,
    mock_wrap_write_cache,
    monkeypatch,
    extra_args,
    expected_retcode,
    caplog,
):
    """Test that error from wrap_write_cache_error() is handled as expected."""
    expected_log_records = []
    handle = "test"
    http_timeout = "10"
    rss_url = "http://rss.example.com"
    slack_base_url = "https://slack.example.com"
    expected_slack_channel = "test"
    fixture_cache_file = "/path/not/exist/cache.file"

    cache = CachedData()

    # Mock/set SLACK_TOKEN
    monkeypatch.setenv("SLACK_TOKEN", "test")
    mock_read_cache.return_value = cache
    mock_rss_fname = os.path.join(SCRIPT_PATH, "files", "rss.xml")
    mock_rsp = Mock()
    mock_rsp.headers = {}
    with open(mock_rss_fname, "r", encoding="utf-8") as fhandle:
        mock_rsp.text = fhandle.read()

    mock_get_rss.return_value = mock_rsp
    mock_wrap_write_cache.return_value = 1

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
        slack_base_url,
        "--slack-channel",
        expected_slack_channel,
        "--slack-timeout",
        "10",
        "-vv",
    ] + extra_args

    print("RSS URL: {:s}".format(rss_url))
    print("Slack URL: {:s}".format(slack_base_url))
    print("Handle: {:s}".format(handle))
    print("Cache file: {:s}".format(fixture_cache_file))

    with patch.object(sys, "argv", args):
        try:
            rss2slack.main()
        except SystemExit as sys_exit:
            exception = sys_exit

    assert isinstance(exception, SystemExit) is True
    assert exception.code == expected_retcode
    mock_read_cache.assert_called_once()
    mock_get_rss.assert_called_once()
    mock_wrap_write_cache.assert_called_once()
    assert caplog.record_tuples == expected_log_records
