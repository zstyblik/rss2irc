#!/usr/bin/env python3
"""Unit tests for cached_data.py."""
import time
from unittest.mock import patch

from lib import CachedData
from lib import config_options
from lib import HTTPSource  # noqa: I100


@patch("lib.cached_data.time.time")
def test_cache_get_source_by_url(mock_time):
    """Test that CachedData.get_source_by_url() sets last_used_ts attr."""
    mock_time.return_value = 1717428213
    url = "http://example.com"
    source = HTTPSource(
        last_used_ts=0,
        url=url,
    )
    cache = CachedData(
        data_sources={
            url: source,
        }
    )
    result = cache.get_source_by_url(url)
    assert result == source
    assert result.last_used_ts == 1717428213


def test_cache_scrub_data_sources_empty(cache):
    """Test that CachedData.scrub_data_sources() when there are no sources."""
    cache = CachedData()
    assert not cache.data_sources
    cache.scrub_data_sources()
    assert not cache.data_sources


def test_cache_scrub_data_sources(cache):
    """Test that CachedData.scrub_data_sources() expired source is removed."""
    source1_url = "http://ww1.example.com"
    source2_url = "http://ww2.example.com"
    cache = CachedData()
    source1 = cache.get_source_by_url(source1_url)
    assert source1.last_used_ts > 0
    source1.last_used_ts = (
        int(time.time()) - 2 * config_options.DATA_SOURCE_EXPIRATION
    )

    source2 = cache.get_source_by_url(source2_url)
    assert source2.last_used_ts > 0

    assert "http://ww1.example.com" in cache.data_sources
    assert source1.url == source1_url
    assert "http://ww2.example.com" in cache.data_sources
    assert source2.url == source2_url

    cache.scrub_data_sources()

    assert "http://ww1.example.com" not in cache.data_sources
    assert "http://ww2.example.com" in cache.data_sources
