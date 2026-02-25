#!/usr/bin/env python3
"""Unit tests for phpbb2slack.py."""
import io
import logging
import os
import sys
import time
from unittest.mock import patch

import pytest

import phpbb2slack
import rss2irc
from lib import CachedData
from lib import config_options
from lib.exceptions import CacheReadError
from lib.exceptions import EmptyResponseError

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
    current_time = int(time.time())
    expected_cache_keys = [
        "https://phpbb.example.com/threads/something-of-something.424837/",
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
                            "[test] <https://phpbb.example.com/threads/"
                            + "something-of-something.424837/"
                            + "|Some other problem> (0)"
                        ),
                    },
                }
            ],
            "channel": expected_slack_channel,
            "text": (
                "[test] <https://phpbb.example.com/threads/"
                + "something-of-something.424837/"
                + "|Some other problem> (0)"
            ),
        }
    ]

    # Mock/set SLACK_TOKEN
    monkeypatch.setenv("SLACK_TOKEN", "test")
    # Mock HTTP RSS
    rss_fname = os.path.join(SCRIPT_PATH, "files", "phpbb-rss.xml")
    with open(rss_fname, "rb") as fhandle:
        rss_data = fhandle.read().decode("utf-8")

    mock_http_rss = fixture_mock_requests.get(
        rss_url,
        text=rss_data,
        headers={"ETag": "pytest_etag", "Last-Modified": "pytest_lm"},
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
    source1.last_used_ts = current_time - 2 * 86400
    source2 = cache.get_source_by_url("http://delete.example.com")
    source2.last_used_ts = (
        current_time - 2 * config_options.DATA_SOURCE_EXPIRATION
    )
    rss2irc.write_cache(cache, fixture_cache_file)
    #
    authors_file = os.path.join(SCRIPT_PATH, "files", "authors.txt")
    logger = logging.getLogger("test")
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
    cache = rss2irc.read_cache(logger, fixture_cache_file)
    print("Cache: {}".format(cache))
    assert list(cache.items.keys()) == expected_cache_keys
    for expected_key in expected_cache_keys:
        assert expected_key in cache.items
        assert cache.items[expected_key]["expiration"] > current_time

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
    assert len(fixture_http_server.requests) == 1

    req0 = fixture_http_server.requests[0]
    assert req0.method == "POST"
    data = req0.get_json()
    assert data == expected_slack_requests[0]


def test_main_cache_hit(
    monkeypatch, fixture_mock_requests, fixture_cache_file, fixture_http_server
):
    """Test that HTTP Status Code 304 is handled as expected."""
    handle = "test"
    http_timeout = "10"
    rss_url = "http://rss.example.com"
    current_time = int(time.time())
    expected_cache_keys = [
        "https://phpbb.example.com/threads/something.424837/",
    ]
    expected_slack_channel = "test"

    # Mock/set SLACK_TOKEN
    monkeypatch.setenv("SLACK_TOKEN", "test")
    # Mock HTTP RSS
    mock_http_rss = fixture_mock_requests.get(
        rss_url,
        status_code=304,
        text="",
        headers={"ETag": "pytest_etag", "Last-Modified": "pytest_lm"},
    )
    # Mock Slack HTTP request
    fixture_http_server.serve_content(
        "Should not be called",
        500,
        {"Content-Type": "application/json"},
    )
    fixture_http_server.store_request_data = True

    cache = CachedData()
    source1 = cache.get_source_by_url(rss_url)
    source1.http_etag = "pytest_etag"
    source1.http_last_modified = "pytest_lm"
    source1.last_used_ts = current_time - 2 * 86400
    cache.items["https://phpbb.example.com/threads/something.424837/"] = {
        "expiration": current_time - 2 * 86400,
        "comments_cnt": 0,
    }
    rss2irc.write_cache(cache, fixture_cache_file)
    #
    authors_file = os.path.join(SCRIPT_PATH, "files", "authors.txt")
    logger = logging.getLogger("test")
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
    cache = rss2irc.read_cache(logger, fixture_cache_file)
    print("Cache: {}".format(cache))
    assert list(cache.items.keys()) == expected_cache_keys
    for expected_key in expected_cache_keys:
        assert expected_key in cache.items
        assert cache.items[expected_key]["expiration"] > current_time

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
    assert len(fixture_http_server.requests) == 0


@pytest.mark.parametrize(
    "extra_args,expected_retcode",
    [
        ([], 0),
        (["--return-error"], 1),
    ],
)
@patch("phpbb2slack.rss2irc.wrap_write_cache")
@patch("phpbb2slack.rss2irc.read_cache")
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
            "phpbb2slack",
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

    cache = CachedData()
    mock_read_cache.return_value = cache
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
            phpbb2slack.main()
        except SystemExit as sys_exit:
            exception = sys_exit

    assert isinstance(exception, SystemExit) is True
    assert exception.code == expected_retcode
    mock_read_cache.assert_called_once()
    mock_wrap_write_cache.assert_not_called()
    assert caplog.record_tuples == expected_log_records


@pytest.mark.parametrize(
    "extra_args,expected_retcode",
    [
        ([], 0),
        (["--return-error"], 1),
    ],
)
@patch("phpbb2slack.rss2irc.wrap_write_cache")
@patch("phpbb2slack.rss2irc.read_cache")
def test_main_cache_read_error(
    mock_read_cache,
    mock_wrap_write_cache,
    extra_args,
    expected_retcode,
    caplog,
):
    """Test that CacheReadError is handled as expected."""
    expected_log_records = [
        (
            "phpbb2slack",
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

    mock_read_cache.side_effect = CacheReadError("pytest")
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
            phpbb2slack.main()
        except SystemExit as sys_exit:
            exception = sys_exit

    assert isinstance(exception, SystemExit) is True
    assert exception.code == expected_retcode
    mock_read_cache.assert_called_once()
    mock_wrap_write_cache.assert_not_called()
    assert caplog.record_tuples == expected_log_records


@pytest.mark.parametrize(
    "extra_args,expected_retcode",
    [
        ([], 0),
        (["--return-error"], 1),
    ],
)
@patch("phpbb2slack.rss2irc.wrap_write_cache")
@patch("phpbb2slack.rss2irc.get_rss")
@patch("phpbb2slack.rss2irc.read_cache")
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
            "phpbb2slack",
            40,
            "Got empty response from 'http://rss.example.com'.",
        ),
    ]
    expected_cache_keys = [
        "https://phpbb.example.com/threads/something.424837/",
    ]
    handle = "test"
    http_timeout = "10"
    rss_url = "http://rss.example.com"
    slack_base_url = "https://slack.example.com"
    expected_slack_channel = "test"
    fixture_cache_file = "/path/not/exist/cache.file"
    current_time = int(time.time())

    cache = CachedData()
    source1 = cache.get_source_by_url(rss_url)
    source1.http_etag = "pytest_etag"
    source1.http_last_modified = "pytest_lm"
    source1.last_used_ts = current_time - 2 * 86400
    cache.items["https://phpbb.example.com/threads/something.424837/"] = {
        "expiration": current_time,
        "comments_cnt": 0,
    }

    mock_read_cache.return_value = cache
    mock_get_rss.side_effect = EmptyResponseError("pytest")
    mock_wrap_write_cache.return_value = 0
    authors_file = os.path.join(SCRIPT_PATH, "files", "authors.txt")
    # Mock/set SLACK_TOKEN
    monkeypatch.setenv("SLACK_TOKEN", "test")

    mock_get_rss.side_effect = EmptyResponseError("pytest")

    exception = None
    args = [
        "./phpbb2slack.py",
        "--authors-of-interest",
        authors_file,
        "--cache",
        fixture_cache_file,
        "--cache-init",
        "--handle",
        handle,
        "--rss-url",
        rss_url,
        "--rss-http-timeout",
        http_timeout,
        "--slack-base-url",
        slack_base_url,
        "--slack-channel",
        expected_slack_channel,
        "--slack-timeout",
        "10",
        "-vvv",
    ] + extra_args

    print("RSS URL: {:s}".format(rss_url))
    print("Slack URL: {:s}".format(slack_base_url))
    print("Handle: {:s}".format(handle))
    print("Cache file: {:s}".format(fixture_cache_file))

    with patch.object(sys, "argv", args):
        try:
            phpbb2slack.main()
        except SystemExit as sys_exit:
            exception = sys_exit

    assert isinstance(exception, SystemExit) is True
    assert exception.code == expected_retcode
    mock_read_cache.assert_called_once()
    mock_wrap_write_cache.assert_called_once()
    assert caplog.record_tuples == expected_log_records
    print(caplog.record_tuples)
    # Check HTTP RSS mock
    mock_get_rss.assert_called_once()
    # Check cache and keys in it
    print("Cache: {}".format(cache))
    assert list(cache.items.keys()) == expected_cache_keys
    for expected_key in expected_cache_keys:
        assert expected_key in cache.items
        assert cache.items[expected_key]["expiration"] == current_time

    # Check HTTP source
    assert rss_url in cache.data_sources.keys()
    source = cache.get_source_by_url(rss_url)
    assert source.url == rss_url
    assert source.http_etag == "pytest_etag"
    assert source.http_last_modified == "pytest_lm"
    assert source.last_used_ts > int(time.time()) - 60
    assert source.http_error_count == 1


@pytest.mark.parametrize(
    "extra_args,expected_retcode",
    [
        ([], 0),
        (["--return-error"], 0),
    ],
)
@patch("phpbb2slack.rss2irc.wrap_write_cache")
@patch("phpbb2slack.rss2irc.read_cache")
def test_main_no_news_error(
    mock_read_cache,
    mock_wrap_write_cache,
    extra_args,
    expected_retcode,
    fixture_mock_requests,
    monkeypatch,
    caplog,
):
    """Test that EmptyResponseError is handled as expected."""
    expected_log_records = []
    expected_cache_keys = [
        "https://phpbb.example.com/threads/something.424837/",
    ]
    handle = "test"
    http_timeout = "10"
    rss_url = "http://rss.example.com"
    slack_base_url = "https://slack.example.com"
    expected_slack_channel = "test"
    fixture_cache_file = "/path/not/exist/cache.file"
    current_time = int(time.time())

    cache = CachedData()
    source1 = cache.get_source_by_url(rss_url)
    source1.http_etag = "pytest_etag"
    source1.http_last_modified = "pytest_lm"
    source1.last_used_ts = current_time - 2 * 86400
    cache.items["https://phpbb.example.com/threads/something.424837/"] = {
        "expiration": current_time - 2 * 86400,
        "comments_cnt": 0,
    }

    mock_read_cache.return_value = cache
    mock_wrap_write_cache.return_value = 0
    authors_file = os.path.join(SCRIPT_PATH, "files", "authors.txt")
    # Mock/set SLACK_TOKEN
    monkeypatch.setenv("SLACK_TOKEN", "test")

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

    exception = None
    args = [
        "./phpbb2slack.py",
        "--authors-of-interest",
        authors_file,
        "--cache",
        fixture_cache_file,
        "--cache-init",
        "--handle",
        handle,
        "--rss-url",
        rss_url,
        "--rss-http-timeout",
        http_timeout,
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
            phpbb2slack.main()
        except SystemExit as sys_exit:
            exception = sys_exit

    assert isinstance(exception, SystemExit) is True
    assert exception.code == expected_retcode
    mock_read_cache.assert_called_once()
    mock_wrap_write_cache.assert_called_once()
    assert caplog.record_tuples == expected_log_records
    # Check HTTP RSS mock
    assert mock_http_rss.called is True
    assert mock_http_rss.call_count == 1
    assert mock_http_rss.last_request.text is None
    # Check cache and keys in it
    print("Cache: {}".format(cache))
    assert list(cache.items.keys()) == expected_cache_keys
    for expected_key in expected_cache_keys:
        assert expected_key in cache.items
        assert cache.items[expected_key]["expiration"] > current_time

    # Check HTTP source
    assert rss_url in cache.data_sources.keys()
    source = cache.get_source_by_url(rss_url)
    assert source.url == rss_url
    assert source.http_etag == "pytest_etag"
    assert source.http_last_modified == "pytest_lm"
    assert source.last_used_ts > int(time.time()) - 60
    assert source.http_error_count == 0


@pytest.mark.parametrize(
    "extra_args,expected_retcode",
    [
        ([], 0),
        (["--return-error"], 1),
    ],
)
@patch("phpbb2slack.rss2irc.wrap_write_cache")
@patch("phpbb2slack.rss2slack.get_slack_token")
@patch("phpbb2slack.rss2irc.read_cache")
def test_main_random_exception(
    mock_read_cache,
    mock_get_slack_token,
    mock_wrap_write_cache,
    extra_args,
    expected_retcode,
    caplog,
):
    """Test that unexpected exception is handled correctly."""
    expected_log_records = [
        (
            "phpbb2slack",
            40,
            "Unexpected exception has occurred.",
        ),
    ]
    handle = "test"
    http_timeout = "10"
    rss_url = "http://rss.example.com"
    slack_base_url = "https://slack.example.com"
    expected_slack_channel = "test"
    fixture_cache_file = "/path/not/exist/cache.file"

    cache = CachedData()
    mock_read_cache.return_value = cache
    mock_get_slack_token.side_effect = ValueError("pytest")
    mock_wrap_write_cache.return_value = 0
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
            phpbb2slack.main()
        except SystemExit as sys_exit:
            exception = sys_exit

    assert isinstance(exception, SystemExit) is True
    assert exception.code == expected_retcode
    mock_read_cache.assert_called_once()
    mock_get_slack_token.assert_called_once()
    mock_wrap_write_cache.assert_called_once()
    assert caplog.record_tuples == expected_log_records
    # Check HTTP source errors
    source = cache.get_source_by_url(rss_url)
    assert source.http_error_count == 1


@pytest.mark.parametrize(
    "extra_args,expected_retcode",
    [
        ([], 0),
        (["--return-error"], 1),
    ],
)
@patch("phpbb2slack.rss2irc.wrap_write_cache")
@patch("phpbb2slack.rss2irc.read_cache")
def test_main_wrap_write_cache_error(
    mock_read_cache,
    mock_wrap_write_cache,
    extra_args,
    expected_retcode,
    fixture_mock_requests,
    monkeypatch,
    caplog,
):
    """Test that error in wrap_write_cache is handled as expected."""
    expected_log_records = []
    expected_cache_keys = [
        "https://phpbb.example.com/threads/something-of-something.424837/",
    ]
    handle = "test"
    http_timeout = "10"
    rss_url = "http://rss.example.com"
    slack_base_url = "https://slack.example.com"
    expected_slack_channel = "test"
    fixture_cache_file = "/path/not/exist/cache.file"

    cache = CachedData()
    mock_read_cache.return_value = cache
    mock_wrap_write_cache.return_value = 1
    authors_file = os.path.join(SCRIPT_PATH, "files", "authors.txt")
    # Mock/set SLACK_TOKEN
    monkeypatch.setenv("SLACK_TOKEN", "test")

    rss_fname = os.path.join(SCRIPT_PATH, "files", "phpbb-rss.xml")
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

    exception = None
    args = [
        "./phpbb2slack.py",
        "--authors-of-interest",
        authors_file,
        "--cache",
        fixture_cache_file,
        "--cache-init",
        "--handle",
        handle,
        "--rss-url",
        rss_url,
        "--rss-http-timeout",
        http_timeout,
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
            phpbb2slack.main()
        except SystemExit as sys_exit:
            exception = sys_exit

    assert isinstance(exception, SystemExit) is True
    assert exception.code == expected_retcode
    mock_read_cache.assert_called_once()
    mock_wrap_write_cache.assert_called_once()
    assert caplog.record_tuples == expected_log_records
    # Check HTTP RSS mock
    assert mock_http_rss.called is True
    assert mock_http_rss.call_count == 1
    assert mock_http_rss.last_request.text is None
    # Check cache and keys in it
    print("Cache: {}".format(cache))
    assert list(cache.items.keys()) == expected_cache_keys
    assert rss_url in cache.data_sources.keys()
    source = cache.get_source_by_url(rss_url)
    assert source.url == rss_url
    assert source.http_etag == "pytest_etag"
    assert source.http_last_modified == "pytest_lm"
    assert source.last_used_ts > int(time.time()) - 60
    # Check HTTP source errors
    assert source.http_error_count == 0


def test_parse_news():
    """Test parse_news()."""
    expected_news = {
        "https://phpbb.example.com/threads/something-of-something.424837/": {
            "title": "Some other problem",
            "category": None,
            "comments_cnt": 0,
        },
        "https://phpbb.example.com/threads/something-not-received.424836/": {
            "title": "Something not received",
            "category": None,
            "comments_cnt": 1,
        },
    }

    rss_fname = os.path.join(SCRIPT_PATH, "files", "phpbb-rss.xml")
    with open(rss_fname, "rb") as fhandle:
        rss_data = fhandle.read().decode("utf-8")

    result = phpbb2slack.parse_news(rss_data, [])
    assert result == expected_news


@pytest.mark.parametrize(
    "cache,expected_cache",
    [
        (
            CachedData(
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
def test_scrub_items(cache, expected_cache):
    """Test scrub_items()."""
    logger = logging.getLogger()
    logger.disabled = True
    phpbb2slack.scrub_items(logger, cache)
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
            CachedData(
                items={
                    "http://example.com": {
                        "expiration": 0,
                        "comments_cnt": 1,
                    },
                }
            ),
            {
                "http://example.com": {
                    "expiration": 1717576487 + 60,
                    "comments_cnt": 2,
                },
                "http://www.example.com": {
                    "expiration": 1717576487 + 60,
                    "comments_cnt": 20,
                },
            },
            60,
        )
    ],
)
@patch("phpbb2slack.time.time")
def test_update_items_expiration(
    mock_time, news, cache, expected_cache, item_expiration
):
    """Test update_items_expiration()."""
    mock_time.return_value = 1717576487
    phpbb2slack.update_items_expiration(cache, news, item_expiration)
    assert cache.items == expected_cache
