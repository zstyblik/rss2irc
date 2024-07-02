#!/usr/bin/env python3
"""Code related to HTTP Source.

I love how black and reorder-python-imports play nicely together and no
workarounds are needed what so ever.
"""
from dataclasses import dataclass
from dataclasses import field
from typing import Dict


@dataclass
class HTTPSource:
    """Class represents HTTP data source."""

    http_etag: str = field(default_factory=str)
    http_last_modified: str = field(default_factory=str)
    last_used_ts: int = 0
    url: str = field(default_factory=str)

    def extract_caching_headers(self, headers: Dict[str, str]) -> None:
        """Extract cache related headers from given dict."""
        self.http_etag = ""
        self.http_last_modified = ""
        for key, value in headers.items():
            key = key.lower()
            if key == "etag":
                self.http_etag = value
            elif key == "last-modified":
                self.http_last_modified = value

    def make_caching_headers(self) -> Dict[str, str]:
        """Return cache related headers as a dict."""
        headers = {}
        if self.http_etag:
            headers["if-none-match"] = self.http_etag

        if self.http_last_modified:
            headers["if-modified-since"] = self.http_last_modified

        return headers
