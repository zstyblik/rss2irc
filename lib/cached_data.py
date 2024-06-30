#!/usr/bin/env python3
"""Code related to Cache.

I love how black and reorder-python-imports play nicely together and no
workarounds are needed what so ever.
"""
import time
from dataclasses import dataclass
from dataclasses import field

from .config_options import DATA_SOURCE_EXPIRATION
from .http_source import HTTPSource


@dataclass
class CachedData:
    """CachedData represents locally cached data and state."""

    data_sources: dict = field(default_factory=dict)
    items: dict = field(default_factory=dict)

    def get_source_by_url(self, url: str) -> HTTPSource:
        """Return source by URL.

        If source doesn't exist, it will be created.
        """
        source = self.data_sources.get(url, None)
        if source:
            source.last_used_ts = int(time.time())
            return source

        self.data_sources[url] = HTTPSource(
            last_used_ts=int(time.time()), url=url
        )
        return self.get_source_by_url(url)

    def scrub_data_sources(
        self, expiration: int = DATA_SOURCE_EXPIRATION
    ) -> None:
        """Delete expired data sources."""
        now = int(time.time())
        for key in list(self.data_sources.keys()):
            diff = now - self.data_sources[key].last_used_ts
            if int(diff) > expiration:
                self.data_sources.pop(key)
