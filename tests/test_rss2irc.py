#!/usr/bin/env python3
"""Unit tests for rss2irc.py."""
import io
import logging
import os
import sys
import time
from unittest.mock import Mock
from unittest.mock import patch

import pytest

import rss2irc
from lib import CachedData
from lib import config_options
from lib.exceptions import CacheReadError
from lib.exceptions import CacheWriteError
from lib.exceptions import EmptyResponseError

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
    assert source.http_error_count == 0
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
    assert source.http_error_count == 0
    assert source.url == rss_url
    assert source.http_etag == "pytest_etag"
    assert source.http_last_modified == "pytest_lm"
    assert source.last_used_ts == frozen_ts
    assert "http://delete.example.com" not in cache.data_sources
    # check output file
    assert sorted(output) == sorted(expected_output)


@pytest.mark.parametrize(
    "extra_args,expected_retcode",
    [
        ([], 0),
        (["--return-error"], 1),
    ],
)
@patch("rss2irc.wrap_write_cache")
@patch("rss2irc.read_cache")
@patch("rss2irc.os.path.exists")
def test_main_cache_read_error(
    mock_path_exists,
    mock_read_cache,
    mock_wrap_write_cache,
    extra_args,
    expected_retcode,
    caplog,
):
    """Test that CacheReadError is handled as expected."""
    expected_log_records = [
        (
            "rss2irc",
            40,
            "Error while reading cache file '/path/not/exist/cache.file'.",
        )
    ]
    handle = "test"
    http_timeout = "10"
    rss_url = "http://127.0.0.2:49991"
    fixture_cache_file = "/path/not/exist/cache.file"
    fixture_output_file = "/path/not/exist/output"

    mock_path_exists.return_value = True
    mock_read_cache.side_effect = CacheReadError("pytest")

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
    ] + extra_args

    print("URL: {:s}".format(rss_url))
    print("Handle: {:s}".format(handle))
    print("Cache file: {:s}".format(fixture_cache_file))
    print("Output file: {:s}".format(fixture_output_file))

    exception = None
    with patch.object(sys, "argv", args):
        try:
            rss2irc.main()
        except SystemExit as sys_exit:
            exception = sys_exit

    assert isinstance(exception, SystemExit) is True
    assert exception.code == expected_retcode
    mock_path_exists.assert_called_with(fixture_output_file)
    mock_read_cache.assert_called_once()
    mock_wrap_write_cache.assert_not_called()
    assert caplog.record_tuples == expected_log_records


@patch("rss2irc.stat.S_ISFIFO")
def test_main_cache_hit(
    mock_s_isfifo,
    fixture_mock_requests,
    fixture_cache_file,
    fixture_output_file,
):
    """Test that NotModified/HTTP Status Code 304 is handled as expected."""
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
    assert source.http_error_count == 0
    assert source.url == rss_url
    assert source.http_etag == "pytest_etag"
    assert source.http_last_modified == "pytest_last_modified"
    assert source.last_used_ts > int(time.time()) - 60
    # check output file
    assert sorted(output) == sorted(expected_output)


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
@patch("rss2irc.os.path.exists")
def test_main_empty_response_error(
    mock_path_exists,
    mock_read_cache,
    mock_get_rss,
    mock_wrap_write_cache,
    extra_args,
    expected_retcode,
    caplog,
):
    """Test that EmptyResponseError is handled as expected."""
    expected_log_records = [
        (
            "rss2irc",
            40,
            "Got empty response from 'http://127.0.0.2:49991'.",
        ),
    ]
    handle = "test"
    http_timeout = "10"
    rss_url = "http://127.0.0.2:49991"
    fixture_cache_file = "/fake/path/cache.file"
    fixture_output_file = "/fake/path/output"
    cache_key = "http://example.com"
    frozen_ts = int(time.time())

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

    mock_path_exists.return_value = True
    mock_read_cache.return_value = cache
    mock_get_rss.side_effect = EmptyResponseError("pytest")
    mock_wrap_write_cache.return_value = 0

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
    ] + extra_args

    print("URL: {:s}".format(rss_url))
    print("Handle: {:s}".format(handle))
    print("Cache file: {:s}".format(fixture_cache_file))
    print("Output file: {:s}".format(fixture_output_file))

    exception = None
    with patch.object(sys, "argv", args):
        try:
            rss2irc.main()
        except SystemExit as sys_exit:
            exception = sys_exit

    assert isinstance(exception, SystemExit) is True
    assert exception.code == expected_retcode
    mock_path_exists.assert_called_with(fixture_output_file)
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
@patch("rss2irc.os.path.exists")
def test_main_no_news_error(
    mock_path_exists,
    mock_read_cache,
    mock_get_rss,
    mock_wrap_write_cache,
    extra_args,
    expected_retcode,
    caplog,
):
    """Test that EmptyResponseError is handled as expected."""
    expected_log_records = [
        (
            "rss2irc",
            20,
            "No news from 'http://127.0.0.2:49991'?",
        ),
    ]
    handle = "test"
    http_timeout = "10"
    rss_url = "http://127.0.0.2:49991"
    fixture_cache_file = "/fake/path/cache.file"
    fixture_output_file = "/fake/path/output"
    frozen_ts = int(time.time())

    cache = CachedData()
    cache.items["http://example.com"] = frozen_ts - 3600
    cache.items["https://expired.example.com"] = frozen_ts - 2 * 86400
    source1 = cache.get_source_by_url(rss_url)
    source1.http_error_count = 10
    source1.http_etag = ""
    source1.http_last_modified = ""
    source1.last_used_ts = frozen_ts - 2 * 86400

    mock_path_exists.return_value = True
    mock_read_cache.return_value = cache
    mock_rss_fname = os.path.join(SCRIPT_PATH, "files", "rss_no_news.xml")
    mock_rsp = Mock()
    with open(mock_rss_fname, "r", encoding="utf-8") as fhandle:
        mock_rsp.text = fhandle.read()

    mock_get_rss.return_value = mock_rsp
    mock_wrap_write_cache.return_value = 0

    args = [
        "./rss2irc.py",
        "-vv",
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
    ] + extra_args

    print("URL: {:s}".format(rss_url))
    print("Handle: {:s}".format(handle))
    print("Cache file: {:s}".format(fixture_cache_file))
    print("Output file: {:s}".format(fixture_output_file))

    exception = None
    with patch.object(sys, "argv", args):
        try:
            rss2irc.main()
        except SystemExit as sys_exit:
            exception = sys_exit

    assert isinstance(exception, SystemExit) is True
    assert exception.code == expected_retcode
    mock_path_exists.assert_called_with(fixture_output_file)
    mock_read_cache.assert_called_once()
    mock_get_rss.assert_called_once()
    mock_wrap_write_cache.assert_called_once()
    assert caplog.record_tuples == expected_log_records
    assert source1.http_error_count == 10
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
@patch("rss2irc.get_rss")
@patch("rss2irc.read_cache")
@patch("rss2irc.os.path.exists")
def test_main_random_exception(
    mock_path_exists,
    mock_read_cache,
    mock_get_rss,
    mock_wrap_write_cache,
    extra_args,
    expected_retcode,
    caplog,
):
    """Test that unexpected exception is handled correctly."""
    expected_log_records = [
        (
            "rss2irc",
            40,
            "Unexpected exception has occurred.",
        ),
    ]
    handle = "test"
    http_timeout = "10"
    rss_url = "http://127.0.0.2:49991"
    fixture_cache_file = "/fake/path/cache.file"
    fixture_output_file = "/fake/path/output"
    cache_key = "http://example.com"
    frozen_ts = int(time.time())

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

    mock_path_exists.return_value = True
    mock_read_cache.return_value = cache
    mock_get_rss.side_effect = ValueError("pytest")
    mock_wrap_write_cache.return_value = 0

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
    ] + extra_args

    print("URL: {:s}".format(rss_url))
    print("Handle: {:s}".format(handle))
    print("Cache file: {:s}".format(fixture_cache_file))
    print("Output file: {:s}".format(fixture_output_file))

    exception = None
    with patch.object(sys, "argv", args):
        try:
            rss2irc.main()
        except SystemExit as sys_exit:
            exception = sys_exit

    assert isinstance(exception, SystemExit) is True
    assert exception.code == expected_retcode
    mock_path_exists.assert_called_with(fixture_output_file)
    mock_read_cache.assert_called_once()
    mock_get_rss.assert_called_once()
    mock_wrap_write_cache.assert_called_once()
    assert caplog.record_tuples == expected_log_records
    assert source1.http_error_count == 1


@pytest.mark.parametrize(
    "extra_args,expected_retcode",
    [
        ([], 0),
        (["--return-error"], 1),
    ],
)
@patch("rss2irc.stat.S_ISFIFO")
@patch("rss2irc.wrap_write_cache")
@patch("rss2irc.read_cache")
def test_main_wrap_write_cache_error(
    mock_read_cache,
    mock_wrap_write_cache,
    mock_s_isfifo,
    extra_args,
    expected_retcode,
    fixture_http_server,
    fixture_output_file,
):
    """Test that error in wrap_write_cache is handled as expected."""
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

    handle = "test"
    http_timeout = "10"
    rss_url = fixture_http_server.url
    fixture_cache_file = "/fake/path/cache.file"

    cache = CachedData()
    mock_read_cache.return_value = cache
    mock_wrap_write_cache.return_value = 1
    mock_s_isfifo.return_value = True

    rss_fname = os.path.join(SCRIPT_PATH, "files", "rss.xml")
    with open(rss_fname, "rb") as fhandle:
        fixture_http_server.serve_content(
            fhandle.read().decode("utf-8"),
            200,
            {"ETag": "pytest_etag", "Last-Modified": "pytest_lm"},
        )

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
    ] + extra_args

    print("URL: {:s}".format(rss_url))
    print("Handle: {:s}".format(handle))
    print("Cache file: {:s}".format(fixture_cache_file))
    print("Output file: {:s}".format(fixture_output_file))

    exception = None
    with patch.object(sys, "argv", args):
        try:
            rss2irc.main()
        except SystemExit as sys_exit:
            exception = sys_exit

    assert isinstance(exception, SystemExit) is True
    assert exception.code == expected_retcode

    assert list(cache.items.keys()) == expected_cache_keys
    assert rss_url in cache.data_sources.keys()
    source = cache.get_source_by_url(rss_url)
    assert source.http_error_count == 0
    assert source.url == rss_url
    assert source.http_etag == "pytest_etag"
    assert source.http_last_modified == "pytest_lm"
    assert source.last_used_ts > int(time.time()) - 60
    # check output file
    with open(fixture_output_file, "rb") as fhandle:
        output = fhandle.readlines()

    assert sorted(output) == sorted(expected_output)

    mock_read_cache.assert_called_once()
    mock_wrap_write_cache.assert_called_once()


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


def test_wrap_write_cache(fixture_cache_file):
    """Test happy path in wrap_write_cache_exception()."""
    cache = CachedData()
    logger = logging.getLogger("rss2irc")

    result = rss2irc.wrap_write_cache(logger, cache, fixture_cache_file)

    assert result == 0


@patch("rss2irc.write_cache")
def test_wrap_write_cache_exception(mock_write_cache, caplog):
    """Test exception handling in wrap_write_cache_exception()."""
    expected_record = (
        "rss2irc",
        logging.ERROR,
        "Failed to write data into cache file '/path/does/not/exist'.",
    )
    cache = CachedData()
    cache_file = "/path/does/not/exist"
    logger = logging.getLogger("rss2irc")
    mock_write_cache.side_effect = CacheWriteError("pytest")

    result = rss2irc.wrap_write_cache(logger, cache, cache_file)

    assert result == 1
    assert expected_record in caplog.record_tuples
