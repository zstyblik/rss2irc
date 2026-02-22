#!/usr/bin/env python3
"""Unit tests for cache_stats.py."""
import io
import logging
import os
import sys
import time
from datetime import datetime
from unittest.mock import patch

import cache_stats
import rss2irc
from lib import CachedData

SCRIPT_PATH = os.path.dirname(os.path.realpath(__file__))


def test_main_ideal(fixture_cache_file, caplog):
    """Simple run-through test."""
    rss_url = "https://example.com/rss"

    cache = CachedData()
    cache.items = {
        "a": int(time.time()),
        "b": int(time.time()),
        "c": int(time.time()),
        "d": int(time.time()) - 60,
        "e": int(time.time()) - 120,
        "f": int(time.time()) - 120,
        "g": int(time.time()) - 120,
    }
    source1 = cache.get_source_by_url(rss_url)
    source1.http_etag = ""
    source1.http_last_modified = ""
    source1.last_used_ts = int(time.time()) - 2 * 86400
    rss2irc.write_cache(cache, fixture_cache_file)

    expected_log_tuples = [
        (
            "cache_stats",
            20,
            "Number of items in cache '{:s}' is 7.".format(fixture_cache_file),
        ),
        (
            "cache_stats",
            20,
            "Source URL: '{:s}'".format(rss_url),
        ),
    ]

    exception = None
    args = [
        "./cache_stats.py",
        "--cache",
        fixture_cache_file,
    ]

    print("Cache file: {:s}".format(fixture_cache_file))

    saved_stdout = sys.stdout
    out = io.StringIO()
    sys.stdout = out

    with patch.object(sys, "argv", args):
        try:
            cache_stats.main()
        except SystemExit as sys_exit:
            exception = sys_exit
        finally:
            sys.stdout = saved_stdout

    assert isinstance(exception, SystemExit) is True
    assert exception.code == 0
    assert out.getvalue().strip() == ""
    assert expected_log_tuples[0] in caplog.record_tuples
    assert expected_log_tuples[1] in caplog.record_tuples


def test_print_data_source_info_no_sources(caplog):
    """Test print_data_source_info() when cache has no data sources."""
    expected_log_tuples = [
        (
            "test_cache_stats",
            10,
            "Cache has no data sources - nothing to printout.",
        ),
    ]
    logger = logging.getLogger("test_cache_stats")
    logger.setLevel(logging.DEBUG)
    cache = CachedData()

    cache_stats.print_data_source_info(logger, cache)
    assert expected_log_tuples == caplog.record_tuples


def test_print_data_source_info_one_source(caplog):
    """Test printout of one data source in print_data_source_info()."""
    rss_url = "https://example.com/rss"
    error_count = 20
    current_ts = int(time.time())
    current_dt = datetime.fromtimestamp(current_ts)
    dt_formatted = current_dt.strftime("%Y-%m-%d")

    expected_log_tuples = [
        (
            "test_cache_stats",
            20,
            "---",
        ),
        (
            "test_cache_stats",
            20,
            "Source URL: '{:s}'".format(rss_url),
        ),
        (
            "test_cache_stats",
            20,
            "Last used: '{:s}'".format(dt_formatted),
        ),
        (
            "test_cache_stats",
            20,
            "Error count: '{:d}'".format(error_count),
        ),
    ]

    logger = logging.getLogger("test_cache_stats")
    logger.setLevel(logging.DEBUG)
    cache = CachedData()
    source1 = cache.get_source_by_url(rss_url)
    source1.http_error_count = error_count
    source1.last_used_ts = current_ts

    cache_stats.print_data_source_info(logger, cache)
    assert expected_log_tuples == caplog.record_tuples


def test_print_data_source_info_multiple_sources(caplog):
    """Test printout of multiple data sources in print_data_source_info()."""
    rss_url1 = "https://one.example.com/rss"
    rss_url2 = "https://two.example.com/rss"
    error_count = 20
    current_ts = int(time.time())
    current_dt = datetime.fromtimestamp(current_ts)
    dt_formatted = current_dt.strftime("%Y-%m-%d")

    expected_log_tuples = [
        (
            "test_cache_stats",
            20,
            "---",
        ),
        (
            "test_cache_stats",
            20,
            "Source URL: '{:s}'".format(rss_url1),
        ),
        (
            "test_cache_stats",
            20,
            "Last used: '{:s}'".format(dt_formatted),
        ),
        (
            "test_cache_stats",
            20,
            "Error count: '{:d}'".format(error_count),
        ),
        (
            "test_cache_stats",
            20,
            "Source URL: 'https://two.example.com/rss'",
        ),
        (
            "test_cache_stats",
            20,
            "Last used: '{:s}'".format(dt_formatted),
        ),
        (
            "test_cache_stats",
            20,
            "Error count: '0'",
        ),
    ]

    logger = logging.getLogger("test_cache_stats")
    logger.setLevel(logging.DEBUG)
    cache = CachedData()
    source1 = cache.get_source_by_url(rss_url1)
    source1.http_error_count = error_count
    source1.last_used_ts = current_ts
    source2 = cache.get_source_by_url(rss_url2)
    source2.http_error_count = 0
    source2.last_used_ts = current_ts

    cache_stats.print_data_source_info(logger, cache)
    assert expected_log_tuples == caplog.record_tuples


def test_print_data_source_info_invalid_last_used(caplog):
    """Test handling of invalid last_used value in print_data_source_info()."""
    rss_url = "https://example.com/rss"
    error_count = 20

    expected_log_tuples = [
        (
            "test_cache_stats",
            20,
            "---",
        ),
        (
            "test_cache_stats",
            20,
            "Source URL: '{:s}'".format(rss_url),
        ),
        (
            "test_cache_stats",
            40,
            "Failed to convert 'abcefg' to datetime due to exception.",
        ),
        (
            "test_cache_stats",
            20,
            "Last used: 'error'",
        ),
        (
            "test_cache_stats",
            20,
            "Error count: '{:d}'".format(error_count),
        ),
    ]

    logger = logging.getLogger("test_cache_stats")
    logger.setLevel(logging.DEBUG)
    cache = CachedData()
    source1 = cache.get_source_by_url(rss_url)
    source1.http_error_count = error_count
    source1.last_used_ts = "abcefg"

    cache_stats.print_data_source_info(logger, cache)
    assert expected_log_tuples == caplog.record_tuples
