#!/usr/bin/env python3
"""Unit tests for rss2slack.py."""
import io
import json
import logging
import os
import sys
from unittest.mock import patch

import pytest

import rss2irc  # noqa:I100,I202
import rss2slack  # noqa:I100,I202

SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))


@pytest.mark.parametrize(
    'url,msg_attrs,handle,expected',
    [
        (
            'http://example.com',
            ('title', ''),
            '',
            {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': '<http://example.com|title>'
                }
            }
        ),
        (
            'http://example.com',
            ('title', None),
            'handle',
            {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': '[handle] <http://example.com|title>'
                }
            }
        ),
        (
            'http://example.com',
            ('title', 'category'),
            'handle',
            {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': '[handle-category] <http://example.com|title>'
                }
            }
        ),
    ],
)
def test_format_message(url, msg_attrs, handle, expected):
    """Test format_message()."""
    result = rss2slack.format_message(url, msg_attrs, handle)
    assert result == expected


def test_get_slack_token(monkeypatch):
    """Test get_slack_token()."""
    monkeypatch.setenv('SLACK_TOKEN', 'test')

    token = rss2slack.get_slack_token()
    assert token == 'test'


def test_get_slack_token_no_token():
    """Test get_slack_token() when ENV variable is not set."""
    exception = None
    try:
        rss2slack.get_slack_token()
    except ValueError as value_error:
        exception = value_error

    assert isinstance(exception, ValueError) is True
    assert exception.args[0] == 'SLACK_TOKEN must be set.'


def test_main_ideal(
        monkeypatch, fixture_mock_requests, fixture_cache_file,
        fixture_http_server
):
    """End-to-end test - ideal environment."""
    handle = 'test'
    http_timeout = '10'
    rss_url = 'http://rss.example.com'
    expected_cache_keys = [
        'http://www.example.com/scan.php?page=news_item&px=item1',
        'http://www.example.com/scan.php?page=news_item&px=item2',
    ]
    expected_slack_channel = 'test'

    # Mock/set SLACK_TOKEN
    monkeypatch.setenv('SLACK_TOKEN', 'test')
    # Mock HTTP RSS
    rss_fname = os.path.join(SCRIPT_PATH, 'files', 'rss.xml')
    with open(rss_fname, 'rb') as fhandle:
        rss_data = fhandle.read().decode('utf-8')

    mock_http_rss = fixture_mock_requests.get(rss_url, text=rss_data)
    # Mock Slack HTTP request
    fixture_http_server.serve_content(
        '{"ok": "true", "error": ""}', 200,
        {'Content-Type': 'application/json'},
    )
    fixture_http_server.capture_requests = True
    expected_slack_requests = [
        {
            'blocks': [
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': (
                            '[test] <http://www.example.com/scan.php?'
                            + 'page=news_item&px=item1|Item1>'
                        )
                    }
                }
            ],
            'channel': expected_slack_channel
        },
        {
            'blocks': [
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': (
                            '[test] <http://www.example.com/scan.php?'
                            + 'page=news_item&px=item2|Item2>'
                        )
                    }
                }
            ],
            'channel': expected_slack_channel
        }
    ]
    #
    exception = None
    args = [
        './rss2slack.py',
        '--rss-url',
        rss_url,
        '--rss-http-timeout',
        http_timeout,
        '--handle',
        handle,
        '--cache',
        fixture_cache_file,
        '--slack-base-url',
        fixture_http_server.url,
        '--slack-channel',
        expected_slack_channel,
        '--slack-timeout',
        '10',
        '-v',
    ]

    print('RSS URL: {:s}'.format(rss_url))
    print('Slack URL: {:s}'.format(fixture_http_server.url))
    print('Handle: {:s}'.format(handle))
    print('Cache file: {:s}'.format(fixture_cache_file))

    saved_stdout = sys.stdout
    out = io.StringIO()
    sys.stdout = out

    with patch.object(sys, 'argv', args):
        try:
            rss2slack.main()
        except SystemExit as sys_exit:
            exception = sys_exit
        finally:
            sys.stdout = saved_stdout

    assert isinstance(exception, SystemExit) is True
    assert exception.code == 0
    assert out.getvalue().strip() == ''
    # Check cache and keys in it
    logger = logging.getLogger('test')
    cache = rss2irc.read_cache(logger, fixture_cache_file)
    print('Cache: {}'.format(cache))
    assert list(cache.items.keys()) == expected_cache_keys
    # Check HTTP RSS mock
    assert mock_http_rss.called is True
    assert mock_http_rss.call_count == 1
    assert mock_http_rss.last_request.text is None
    # Check HTTP Slack
    # Note: this is just a shallow check, but it's better than nothing.
    assert len(fixture_http_server.requests) == 2

    req0 = fixture_http_server.captured_requests[0]
    assert req0[0] == 'POST'
    data = json.loads(req0[1])
    assert data == expected_slack_requests[0]

    req1 = fixture_http_server.captured_requests[1]
    assert req1[0] == 'POST'
    data = json.loads(req1[1])
    assert data == expected_slack_requests[1]
