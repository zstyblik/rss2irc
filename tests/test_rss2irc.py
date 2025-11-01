#!/usr/bin/env python3
"""Unit tests for rss2irc.py."""
import io
import logging
import os
import sys
import time
from unittest.mock import patch

import pytest

import rss2irc  # noqa: I202
from lib import CachedData  # noqa: I202
from lib import config_options  # noqa: I202

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

    mock_s_isfifo.return_value = True
    rss_url = fixture_http_server.url
    rss_fname = os.path.join(SCRIPT_PATH, "files", "rss.xml")
    with open(rss_fname, "rb") as fhandle:
        fixture_http_server.serve_content(
            fhandle.read().decode("utf-8"),
            200,
            {"ETag": "pytest_etag", "Last-Modified": "pytest_lm"},
        )

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

    logger = logging.getLogger("test")
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
    assert mock_s_isfifo.called is True
    # Check cache - keys in it and sources
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
    # check output file
    assert sorted(output) == sorted(expected_output)


@patch("rss2irc.stat.S_ISFIFO")
@patch("rss2irc.time.time")
def test_main_cache_operations(
    mock_time,
    mock_s_isfifo,
    fixture_http_server,
    fixture_cache_file,
    fixture_output_file,
):
    """End-to-end test - verify cache scrubbing and expiration refresh."""
    handle = "test"
    http_timeout = "10"
    rss_url = fixture_http_server.url
    expected_cache_keys = [
        "http://www.example.com/scan.php?page=news_item&px=item1",
        "http://www.example.com/scan.php?page=news_item&px=item2",
    ]
    expected_output = [
        (
            b"[test] Item2 | "
            b"http://www.example.com/scan.php?page=news_item&px=item2\n"
        ),
    ]
    cache_key = "http://www.example.com/scan.php?page=news_item&px=item1"
    frozen_ts = 1218002161

    mock_s_isfifo.return_value = True
    mock_time.return_value = frozen_ts
    rss_fname = os.path.join(SCRIPT_PATH, "files", "rss.xml")
    with open(rss_fname, "rb") as fhandle:
        fixture_http_server.serve_content(
            fhandle.read().decode("utf-8"),
            200,
            {"ETag": "pytest_etag", "Last-Modified": "pytest_lm"},
        )

    cache = CachedData()
    cache.items[cache_key] = frozen_ts + 60
    cache.items["https://expired.example.com"] = 123456
    source1 = cache.get_source_by_url(rss_url)
    source1.http_etag = ""
    source1.http_last_modified = ""
    source1.last_used_ts = frozen_ts - 2 * 86400
    source2 = cache.get_source_by_url("http://delete.example.com")
    source2.last_used_ts = frozen_ts - 2 * config_options.DATA_SOURCE_EXPIRATION
    rss2irc.write_cache(cache, fixture_cache_file)

    logger = logging.getLogger("test")
    exception = None
    args = [
        "./rss2irc.py",
        "-v",
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
    assert mock_s_isfifo.called is True
    # Check cache - keys in it and sources
    cache = rss2irc.read_cache(logger, fixture_cache_file)
    print("Cache: {}".format(cache))
    assert list(cache.items.keys()) == expected_cache_keys
    # Verify item expiration is updated
    assert cache.items[cache_key] == frozen_ts + config_options.CACHE_EXPIRATION
    # Verify data sources
    assert rss_url in cache.data_sources.keys()
    source = cache.get_source_by_url(rss_url)
    assert source.url == rss_url
    assert source.http_etag == "pytest_etag"
    assert source.http_last_modified == "pytest_lm"
    assert source.last_used_ts == frozen_ts
    assert "http://delete.example.com" not in cache.data_sources
    # check output file
    assert sorted(output) == sorted(expected_output)


@patch("rss2irc.stat.S_ISFIFO")
def test_main_cache_hit(
    mock_s_isfifo,
    fixture_mock_requests,
    fixture_cache_file,
    fixture_output_file,
):
    """Test that HTTP Status Code 304 is handled as expected."""
    handle = "test"
    http_timeout = "10"
    rss_url = "http://rss.example.com"
    expected_cache_keys = []
    expected_output = []

    mock_s_isfifo.return_value = True
    mock_http_rss = fixture_mock_requests.get(
        rss_url,
        status_code=304,
        text="",
        headers={
            "ETag": "pytest_etag",
            "Last-Modified": "pytest_last_modified",
        },
    )

    cache = CachedData()
    source1 = cache.get_source_by_url(rss_url)
    source1.http_etag = "pytest_etag"
    source1.http_last_modified = "pytest_last_modified"
    source1.last_used_ts = int(time.time()) - 2 * 86400
    rss2irc.write_cache(cache, fixture_cache_file)

    logger = logging.getLogger("test")
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
    assert mock_s_isfifo.called is False
    # Check HTTP call
    assert mock_http_rss.called is True
    assert mock_http_rss.call_count == 1
    assert mock_http_rss.last_request.text is None
    # Check cache and keys in it
    cache = rss2irc.read_cache(logger, fixture_cache_file)
    print("Cache: {}".format(cache))
    assert list(cache.items.keys()) == expected_cache_keys
    assert rss_url in cache.data_sources.keys()
    source = cache.get_source_by_url(rss_url)
    assert source.url == rss_url
    assert source.http_etag == "pytest_etag"
    assert source.http_last_modified == "pytest_last_modified"
    assert source.last_used_ts > int(time.time()) - 60
    # check output file
    assert sorted(output) == sorted(expected_output)


def test_parse_news():
    """Test parse_news()."""
    expected_news = {
        "http://www.example.com/scan.php?page=news_item&px=item1": (
            "Item1",
            "",
        ),
        "http://www.example.com/scan.php?page=news_item&px=item2": (
            "Item2",
            "",
        ),
    }

    rss_fname = os.path.join(SCRIPT_PATH, "files", "rss.xml")
    with open(rss_fname, "rb") as fhandle:
        rss_data = fhandle.read().decode("utf-8")

    result = rss2irc.parse_news(rss_data)
    assert result == expected_news


def test_scrub_items():
    """Test scrub_items()."""
    logging.basicConfig(level=logging.CRITICAL)
    logger = logging.getLogger()
    logger.disabled = True

    item_expiration = int(time.time()) + 60
    test_cache = CachedData(
        items={
            "foo": item_expiration,
            "bar": int(time.time()) - 3600,
            "lar": "efg",
        }
    )
    expected = {
        "foo": item_expiration,
    }
    rss2irc.scrub_items(logger, test_cache)
    assert test_cache.items == expected


@patch("rss2irc.time.time")
def test_update_items_expiration_cache_items_as_news(mock_time):
    """Test that it's possible to self-update TTL of cached items."""
    mock_timestamp = 1717428210
    mock_time.return_value = mock_timestamp
    expiration = 60
    expected_expiration = mock_timestamp + expiration

    cache = CachedData()
    cache.items["http://example.com/item1"] = 171742800
    cache.items["http://example.com/item2"] = 171742800

    rss2irc.update_items_expiration(cache, cache.items, expiration)

    assert cache.items["http://example.com/item1"] == expected_expiration
    assert cache.items["http://example.com/item2"] == expected_expiration
