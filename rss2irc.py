#!/usr/bin/env python3
"""Fetch RSS and pipe it into IRC bot.

2015/Jul/5 @ Zdenek Styblik <stybla@turnovfree.net>
"""
import argparse
import logging
import os
import pickle
import signal
import stat
import sys
import time
import traceback
from dataclasses import dataclass
from dataclasses import field
from typing import BinaryIO
from typing import Dict
from typing import Tuple

import feedparser
import requests

CACHE_EXPIRATION = 86400  # seconds
DATA_SOURCE_EXPIRATION = 30 * 86400  # seconds
HTTP_TIMEOUT = 30  # seconds


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


def format_message(
    url: str, msg_attrs: Tuple[str, str], handle: str = ""
) -> str:
    """Return pre-formatted message.

    :param url: URL of news item.
    :param msg_attrs: tuple of title and category.
    :param handle: Handle of given feed.
    """
    if not handle:
        return "{:s}\n".format(url)

    if msg_attrs[1]:
        tag = "{:s}-{:s}".format(handle, msg_attrs[1])
    else:
        tag = "{:s}".format(handle)

    return "[{:s}] {:s} | {:s}\n".format(tag, msg_attrs[0], url)


def get_rss(
    logger: logging.Logger,
    url: str,
    timeout: int = HTTP_TIMEOUT,
    extra_headers: Dict = None,
) -> requests.models.Response:
    """Return body of given URL as a string."""
    # Randomize user agent, because CF likes to block for no apparent reason.
    user_agent = "rss2irc_{:d}".format(int(time.time()))
    headers = {"User-Agent": user_agent}
    if extra_headers:
        for key, value in extra_headers.items():
            headers[key] = value

    logger.debug("Get %s", url)
    rsp = requests.get(url, timeout=timeout, headers=headers)
    logger.debug("Got HTTP Status Code: %i", rsp.status_code)
    rsp.raise_for_status()
    return rsp


def main():
    """Fetch RSS feed and post RSS news to IRC."""
    logging.basicConfig(stream=sys.stdout)
    logger = logging.getLogger("rss2irc")
    args = parse_args()
    if args.verbosity:
        logger.setLevel(logging.DEBUG)

    if args.cache_expiration < 0:
        logger.error("Cache expiration can't be less than 0.")
        sys.exit(1)

    if not os.path.exists(args.output):
        logger.error("Ouput '%s' doesn't exist.", args.output)
        sys.exit(1)

    try:
        cache = read_cache(logger, args.cache)
        source = cache.get_source_by_url(args.rss_url)

        rsp = get_rss(
            logger,
            args.rss_url,
            args.rss_http_timeout,
            source.make_caching_headers(),
        )
        if rsp.status_code == 304:
            logger.debug("No new RSS data since the last run")
            write_cache(cache, args.cache)
            sys.exit(0)

        if not rsp.text:
            logger.error("Failed to get RSS from %s", args.rss_url)
            sys.exit(1)

        news = parse_news(rsp.text)
        if not news:
            logger.info("No news?")
            write_cache(cache, args.cache)
            sys.exit(0)

        source.extract_caching_headers(rsp.headers)
        prune_news(logger, cache, news, args.cache_expiration)
        scrub_items(logger, cache)

        if not args.cache_init:
            write_data(logger, news, args.output, args.handle, args.sleep)

        update_items_expiration(cache, news, args.cache_expiration)
        cache.scrub_data_sources()
        write_cache(cache, args.cache)
        # TODO(zstyblik): remove error file
    except Exception:
        logger.debug("%s", traceback.format_exc())
        # TODO(zstyblik):
        # 1. touch error file
        # 2. send error message to the channel
    finally:
        sys.exit(0)


def parse_args() -> argparse.Namespace:
    """Return parsed CLI args."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbosity",
        action="store_true",
        default=False,
        help="Increase logging verbosity.",
    )
    parser.add_argument(
        "--rss-url",
        dest="rss_url",
        type=str,
        required=True,
        help="URL of RSS Feed.",
    )
    parser.add_argument(
        "--rss-http-timeout",
        dest="rss_http_timeout",
        type=int,
        default=HTTP_TIMEOUT,
        help="HTTP Timeout. Defaults to {:d} seconds.".format(HTTP_TIMEOUT),
    )
    parser.add_argument(
        "--handle",
        dest="handle",
        type=str,
        default=None,
        help="IRC handle of this feed.",
    )
    parser.add_argument(
        "--output",
        dest="output",
        type=str,
        required=True,
        help="Where to output formatted news.",
    )
    parser.add_argument(
        "--cache",
        dest="cache",
        type=str,
        default=None,
        help="File which contains cache.",
    )
    parser.add_argument(
        "--cache-expiration",
        dest="cache_expiration",
        type=int,
        default=CACHE_EXPIRATION,
        help="Time, in seconds, for how long to keep items in cache.",
    )
    parser.add_argument(
        "--cache-init",
        dest="cache_init",
        action="store_true",
        default=False,
        help=(
            "Prevents posting news to IRC. This is useful "
            "when bootstrapping new RSS feed."
        ),
    )
    parser.add_argument(
        "--sleep",
        dest="sleep",
        type=int,
        default=2,
        help="Sleep between messages in order to avoid Excess Flood at IRC.",
    )
    return parser.parse_args()


def parse_news(data: str) -> Dict[str, Tuple[str, str]]:
    """Parse-out link and title out of XML."""
    news = {}
    feed = feedparser.parse(data)
    for entry in feed["entries"]:
        link = entry.pop("link", "")
        if not link:
            # If we don't have a link, there is nothing we can do.
            continue

        title = entry.pop("title", "No title")
        category = entry.pop("category", "")
        news[link] = (title, category)

    return news


def prune_news(
    logger: logging.Logger,
    cache: CachedData,
    news: Dict[str, Tuple[str, str]],
    expiration: int = CACHE_EXPIRATION,
) -> None:
    """Prune news which already are in cache."""
    item_expiration = int(time.time()) + expiration
    for key in list(news.keys()):
        if key in cache.items:
            logger.debug("Key %s found in cache", key)
            cache.items[key] = item_expiration
            news.pop(key)


def read_cache(logger: logging.Logger, cache_file: str) -> CachedData:
    """Read file with Py pickle in it."""
    if not cache_file:
        return CachedData()

    try:
        with open(cache_file, "rb") as fhandle:
            cache = pickle.load(fhandle)
    except FileNotFoundError:
        cache = CachedData()
        logger.warning("Cache file '%s' doesn't exist.", cache_file)
    except EOFError:
        # Note: occurred with empty file.
        cache = CachedData()
        logger.debug(
            "Cache file '%s' is probably empty: %s",
            cache_file,
            traceback.format_exc(),
        )

    logger.debug("%s", cache)
    return cache


def signal_handler(signum, frame):
    """Handle SIGALRM signal."""
    raise ValueError


def scrub_items(logger: logging.Logger, cache: CachedData) -> None:
    """Scrub cache and remove expired items."""
    time_now = time.time()
    for key in list(cache.items.keys()):
        try:
            expiration = int(cache.items[key])
        except ValueError:
            logger.error("%s", traceback.format_exc())
            logger.error(
                "Invalid cache entry will be removed: '%s'", cache.items[key]
            )
            cache.items.pop(key)
            continue

        if expiration < time_now:
            logger.debug("URL %s has expired.", key)
            cache.items.pop(key)


def update_items_expiration(
    cache: CachedData,
    news: Dict[str, Tuple[str, str]],
    expiration: int = CACHE_EXPIRATION,
) -> None:
    """Update expiration of items in cache based on news dict."""
    item_expiration = int(time.time()) + expiration
    for key in list(news.keys()):
        cache.items[key] = item_expiration


def write_cache(data: CachedData, cache_file: str) -> None:
    """Dump data into file as a pickle."""
    if not cache_file:
        return

    with open(cache_file, "wb") as fhandle:
        pickle.dump(data, fhandle, pickle.HIGHEST_PROTOCOL)


def write_data(
    logger: logging.Logger,
    data: Dict,
    output: str,
    handle: str = None,
    sleep: int = 2,
) -> None:
    """Write data into file."""
    with open(output, "wb") as fhandle:
        for url in list(data.keys()):
            message = format_message(url, data[url], handle)
            try:
                write_message(logger, fhandle, message)
                time.sleep(sleep)
            except ValueError:
                logger.debug("%s", traceback.format_exc())
                logger.debug("Failed to write %s, %s", url, data[url])
                data.pop(url)


def write_message(
    logger: logging.Logger, fhandle: BinaryIO, message: str
) -> None:
    """Write message into file handle.

    Sets up SIGALRM and raises `ValueError` if alarm is due.
    """
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(5)
    try:
        fhandle_stat = os.fstat(fhandle.fileno())
        is_fifo = stat.S_ISFIFO(fhandle_stat.st_mode)
        if not is_fifo:
            raise ValueError("fhandle is expected to be a FIFO pipe")

        logger.debug("Will write %s", repr(message))
        fhandle.write(message.encode("utf-8"))
        signal.alarm(0)
    except Exception as exception:
        raise exception
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    main()
