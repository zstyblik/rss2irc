#!/usr/bin/env python3
"""Unit tests for gh2slack.py."""
import io
import json
import logging
import os
import sys
import time
import urllib.parse
from unittest.mock import call
from unittest.mock import patch

import pytest

import gh2slack  # noqa: I100, I202
import rss2irc  # noqa: I100, I202
from lib import CachedData  # noqa: I100, I202

SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))


class MockedResponse:
    """Mocked `requests.Response`."""

    def __init__(self, response, headers=None):  # noqa: D107
        self.response = response
        if headers:
            self.headers = headers
        else:
            self.headers = {}

        self.status_code = 200
        self._raise_for_status_called = False

    def raise_for_status(self):
        """Record that raise_for_status has been called."""
        self._raise_for_status_called = True

    def json(self):
        """Return response as a JSON."""
        return self.response


@pytest.mark.parametrize(
    "cache_item,expected_message",
    [
        (
            {
                "number": 99,
                "repository_url": "http://repo-url.example.com",
                "title": "Some title",
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        "[<http://repo-url.example.com|owner/repo>] "
                        "<http://example.com|section#99> | Some title"
                    ),
                },
            },
        )
    ],
)
def test_format_message(cache_item, expected_message):
    """Test format_message()."""
    logger = logging.getLogger("test")
    message = gh2slack.format_message(
        logger, "owner", "repo", "section", "http://example.com", cache_item
    )

    assert message == expected_message


def test_get_gh_api_url():
    """Test get_gh_api_url()."""
    result = gh2slack.get_gh_api_url("foo", "bar", "lar")
    assert result == "https://api.github.com/repos/foo/bar/lar"


def test_get_gh_repository_url():
    """Test get_gh_repository_url()."""
    result = gh2slack.get_gh_repository_url("foo", "bar")
    assert result == "https://github.com/foo/bar"


@patch("requests.get")
def test_gh_request(mock_get):
    """Test gh_request()."""
    mocked_response = MockedResponse("foo")
    mock_get.return_value = mocked_response
    url = "https://api.github.com/repos/foo/bar"

    logger = logging.getLogger("test")
    response = gh2slack.gh_request(logger, url)

    assert response == ["foo"]
    assert mock_get.call_args[0] == (url,)
    assert mocked_response._raise_for_status_called is True


@patch("gh2slack.time.time")
@patch("requests.get")
def test_gh_request_follows_link_header(mock_get, mock_time):
    """Test gh_request() follows up on 'Link' header."""
    url = "https://api.github.com/repos/foo/bar"
    mock_time.return_value = 123
    mocked_response1 = MockedResponse(
        "foo", {"link": '<http://example.com>; rel="next"'}
    )
    mocked_response2 = MockedResponse("bar", {"link": "no-next"})
    mock_get.side_effect = [mocked_response1, mocked_response2]
    expected_mock_calls = [
        call(
            "https://api.github.com/repos/foo/bar",
            headers={
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "gh2slack_123",
            },
            params={"sort": "created", "state": "open"},
            timeout=30,
        ),
        call(
            "http://example.com",
            headers={
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "gh2slack_123",
            },
            params={"sort": "created", "state": "open"},
            timeout=30,
        ),
    ]

    logger = logging.getLogger("test")
    response = gh2slack.gh_request(logger, url)

    assert response == ["foo", "bar"]
    assert mock_get.mock_calls == expected_mock_calls
    assert mocked_response1._raise_for_status_called is True
    assert mocked_response2._raise_for_status_called is True


def test_gh_request_follows_link_header_multi_page(fixture_mock_requests):
    """Test gh_request() follows up on 'Link' header multiple times."""
    url1 = "https://example.com/repos/foo/bar"
    headers1 = {
        "link": (
            "<https://example.com/user/6183869/repos"
            '?page=2&state=open&sort=created>; rel="next", '
            "<https://example.com/user/6183869/repos"
            '?page=3&state=open&sort=created>; rel="last"'
        )
    }
    mock_http1 = fixture_mock_requests.get(url1, json="foo", headers=headers1)

    url2 = (
        "https://example.com/user/6183869/repos"
        "?page=2&state=open&sort=created"
    )
    headers2 = {
        "link": (
            "<https://example.com/user/6183869/repos"
            '?page=1&state=open&sort=created>; rel="prev", '
            "<https://example.com/user/6183869/repos"
            '?page=3&state=open&sort=created>; rel="next", '
            "<https://example.com/user/6183869/repos"
            '?page=3&state=open&sort=created>; rel="last", '
            "<https://example.com/user/6183869/repos"
            '?page=1&state=open&sort=created>; rel="first"'
        )
    }
    mock_http2 = fixture_mock_requests.get(url2, json="bar", headers=headers2)

    url3 = (
        "https://example.com/user/6183869/repos"
        "?page=3&state=open&sort=created"
    )
    headers3 = {
        "link": (
            "<https://example.com/user/6183869/repos"
            '?page=1&state=open&sort=created>; rel="prev", '
            "<https://example.com/user/6183869/repos"
            '?page=3&state=open&sort=created>; rel="last", '
            "<https://example.com/user/6183869/repos"
            '?page=1&state=open&sort=created>; rel="first"'
        )
    }
    mock_http3 = fixture_mock_requests.get(url3, json="lar", headers=headers3)

    logger = logging.getLogger("test")
    response = gh2slack.gh_request(logger, url1)

    assert response == ["foo", "bar", "lar"]
    # Check that requests have been made.
    assert mock_http1.called is True
    assert mock_http1.call_count == 1
    assert mock_http2.called is True
    assert mock_http2.call_count == 1
    assert mock_http3.called is True
    assert mock_http3.call_count == 1
    # Check that 'state' and 'sort' params are present and passed only once.
    assert "state=open&sort=created" == mock_http1.request_history[0].query
    parsed2 = urllib.parse.urlparse(url2)
    assert parsed2.query == mock_http2.request_history[0].query
    parsed3 = urllib.parse.urlparse(url3)
    assert parsed3.query == mock_http3.request_history[0].query


def test_main_ideal(
    monkeypatch, fixture_mock_requests, fixture_cache_file, fixture_http_server
):
    """End-to-end test - ideal environment."""
    gh_repo = "test-repo"
    gh_owner = "test-user"
    gh_section = "pulls"
    gh_url = gh2slack.get_gh_api_url(gh_owner, gh_repo, gh_section)
    expected_cache_keys = [
        "http://example.com/foo",
        "http://example.com/bar",
    ]
    expected_slack_channel = "test"

    # Mock/set SLACK_TOKEN
    monkeypatch.setenv("SLACK_TOKEN", "test")
    # Mock HTTP RSS
    pages = [
        {
            "html_url": "http://example.com/foo",
            "number": 0,
            "title": "some title#1",
        },
        {
            "html_url": "http://example.com/bar",
            "number": 1,
            "title": "some title#2",
        },
    ]
    mock_http_rss = fixture_mock_requests.get(gh_url, text=json.dumps(pages))
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
                            "[<https://github.com/test-user/test-repo|"
                            + "test-user/test-repo>] <http://example.com/bar|"
                            + "pr#1> | some title#2"
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
                            "[<https://github.com/test-user/test-repo|"
                            + "test-user/test-repo>] "
                            + "<http://example.com/foo|pr#0> | some title#1"
                        ),
                    },
                }
            ],
            "channel": expected_slack_channel,
        },
    ]
    #
    exception = None
    args = [
        "./gh2slack.py",
        "--cache",
        fixture_cache_file,
        "--gh-owner",
        gh_owner,
        "--gh-repo",
        gh_repo,
        "--gh-section",
        gh_section,
        "--slack-base-url",
        fixture_http_server.url,
        "--slack-channel",
        expected_slack_channel,
        "--slack-timeout",
        "10",
        "-v",
    ]

    print("Slack URL: {:s}".format(fixture_http_server.url))
    print("Cache file: {:s}".format(fixture_cache_file))

    saved_stdout = sys.stdout
    out = io.StringIO()
    sys.stdout = out

    with patch.object(sys, "argv", args):
        try:
            gh2slack.main()
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
    assert len(fixture_http_server.requests) == 2
    # NOTE(zstyblik): this isn't really optimal.
    req0 = fixture_http_server.captured_requests[0]
    assert req0[0] == "POST"
    data = json.loads(req0[1])
    assert data in expected_slack_requests

    req1 = fixture_http_server.captured_requests[1]
    assert req1[0] == "POST"
    data = json.loads(req1[1])
    assert data in expected_slack_requests


def test_process_page_items():
    """Test process_page_items()."""
    pages = [
        [
            {
                "html_url": "http://example.com/foo",
                "number": 0,
                "title": "some title#1",
            },
        ],
        [
            {
                "html_url": "http://example.com/bar",
                "number": 1,
                "title": "some title#2",
            },
        ],
    ]
    repository_url = "http://example.com"
    cache = CachedData(
        items={
            "http://example.com/bar": {
                "expiration": 0,
                "number": 1,
                "repository_url": repository_url,
                "title": "some title#2",
            }
        }
    )
    expiration = 20

    expected_cache = {
        "http://example.com/foo": {
            "expiration": expiration,
            "number": 0,
            "repository_url": repository_url,
            "title": "some title#1",
        },
        "http://example.com/bar": {
            "expiration": expiration,
            "number": 1,
            "repository_url": repository_url,
            "title": "some title#2",
        },
    }
    expected_to_publish = set(["http://example.com/foo"])

    logger = logging.getLogger("test")
    to_publish = gh2slack.process_page_items(
        logger, cache, pages, expiration, repository_url
    )

    assert cache.items == expected_cache
    assert to_publish == expected_to_publish


def test_scrub_items():
    """Test scrub_items()."""
    item_expiration = int(time.time()) + 60
    test_cache = CachedData(
        items={
            "foo": {
                "expiration": item_expiration,
            },
            "bar": {
                "expiration": int(time.time()) - 3600,
            },
            "lar": {
                "abc": "efg",
            },
        }
    )
    expected = {
        "foo": {
            "expiration": item_expiration,
        }
    }

    logger = logging.getLogger("test")
    gh2slack.scrub_items(logger, test_cache)

    assert test_cache.items == expected
