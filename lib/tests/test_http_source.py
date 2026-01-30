#!/usr/bin/env python3
"""Unit tests for http_source.py."""
import pytest

from lib import HTTPSource


@pytest.mark.parametrize(
    "source,input_data,expected",
    [
        # No attrs should bet set
        (
            HTTPSource(),
            {},
            {"etag": "", "last_modified": ""},
        ),
        # Reset attrs
        (
            HTTPSource(http_etag="et_test", http_last_modified="lm_test"),
            {"header1": "firt", "header2": "second"},
            {"etag": "", "last_modified": ""},
        ),
        # Set attrs
        (
            HTTPSource(http_etag="et_test", http_last_modified="lm_test"),
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
            HTTPSource(),
            {},
        ),
        (
            HTTPSource(http_etag="et_test"),
            {"if-none-match": "et_test"},
        ),
        (
            HTTPSource(http_last_modified="lm_test"),
            {"if-modified-since": "lm_test"},
        ),
        (
            HTTPSource(http_etag="et_test", http_last_modified="lm_test"),
            {"if-modified-since": "lm_test", "if-none-match": "et_test"},
        ),
    ],
)
def test_http_source_make_caching_headers(source, expected):
    """Test that HTTPSource.make_caching_headers() works as expected."""
    result = source.make_caching_headers()
    assert result == expected
