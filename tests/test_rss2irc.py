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
    "source,input_data,expected",
    [
        # No attrs should bet set
        (
            rss2irc.HTTPSource(),
            {},
            {"etag": "", "last_modified": ""},
        ),
        # Reset aatrs
        (
            rss2irc.HTTPSource(
                http_etag="et_test", http_last_modified="lm_test"
            ),
            {"header1": "firt", "header2": "second"},
            {"etag": "", "last_modified": ""},
        ),
        # Set attrs
        (
            rss2irc.HTTPSource(
                http_etag="et_test", http_last_modified="lm_test"
            ),
            {"ETag": "test123", "Last-Modified": "abc123", "some": "header"},
            {"etag": "test123", "last_modified": "abc123"},
        ),
    ],
)
def test_http_source_extract_caching_headers(source, input_data, expected):
    """Test that HTTPSource.extract_caching_headers() works as expected."""
    source.extract_caching_headers(input_data)
    assert source.http_etag == expected["etag"]
    assert source.http_last_modified == expected["last_modified"]


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            rss2irc.HTTPSource(),
            {},
        ),
        (
            rss2irc.HTTPSource(http_etag="et_test"),
            {"if-none-match": "et_test"},
        ),
        (
            rss2irc.HTTPSource(http_last_modified="lm_test"),
            {"if-modified-since": "lm_test"},
        ),
        (
            rss2irc.HTTPSource(
                http_etag="et_test", http_last_modified="lm_test"
            ),
            {"if-modified-since": "lm_test", "if-none-match": "et_test"},
        ),
    ],
)
def test_http_source_make_caching_headers(source, expected):
    """Test that HTTPSource.make_caching_headers() works as expected."""
    result = source.make_caching_headers()
    assert result == expected


@patch("rss2irc.time.time")
def test_cache_get_source_by_url(mock_time):
    """Test that CachedData.get_source_by_url() sets last_used_ts attr."""
    mock_time.return_value = 1717428213
    url = "http://example.com"
    source = rss2irc.HTTPSource(
        last_used_ts=0,
        url=url,
    )
    cache = rss2irc.CachedData(
        data_sources={
            url: source,
        }
    )
    result = cache.get_source_by_url(url)
    assert result == source
    assert result.last_used_ts == 1717428213


def test_cache_scrub_data_sources_empty(cache):
    """Test that CachedData.scrub_data_sources() when there are no sources."""
    cache = rss2irc.CachedData()
    assert not cache.data_sources
    cache.scrub_data_sources()
    assert not cache.data_sources


def test_cache_scrub_data_sources(cache):
    """Test that CachedData.scrub_data_sources() expired source is removed."""
    source1_url = "http://ww1.example.com"
    source2_url = "http://ww2.example.com"
    cache = rss2irc.CachedData()
    source1 = cache.get_source_by_url(source1_url)
    assert source1.last_used_ts > 0
    source1.last_used_ts = int(time.time()) - 2 * rss2irc.DATA_SOURCE_EXPIRATION

    source2 = cache.get_source_by_url(source2_url)
    assert source2.last_used_ts > 0

    assert "http://ww1.example.com" in cache.data_sources
    assert source1.url == source1_url
    assert "http://ww2.example.com" in cache.data_sources
    assert source2.url == source2_url

    cache.scrub_data_sources()

    assert "http://ww1.example.com" not in cache.data_sources
    assert "http://ww2.example.com" in cache.data_sources


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

    cache = rss2irc.CachedData()
    source1 = cache.get_source_by_url(rss_url)
    source1.http_etag = ""
    source1.http_last_modified = ""
    source1.last_used_ts = int(time.time()) - 2 * 86400
    source2 = cache.get_source_by_url("http://delete.example.com")
    source2.last_used_ts = int(time.time()) - 2 * rss2irc.DATA_SOURCE_EXPIRATION
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

    cache = rss2irc.CachedData()
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
    rss2irc.scrub_items(logger, test_cache)
    assert test_cache.items == expected
