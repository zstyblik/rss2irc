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
from typing import BinaryIO
from typing import Dict
from typing import Tuple

import feedparser
import requests

from lib import CachedData
from lib import cli_args
from lib import config_options
from lib import utils
from lib.exceptions import CacheReadError
from lib.exceptions import CacheWriteError
from lib.exceptions import EmptyResponseError
from lib.exceptions import NoNewsError
from lib.exceptions import NotModifiedError


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
    timeout: int = config_options.HTTP_TIMEOUT,
    extra_headers: Dict = None,
) -> requests.models.Response:
    """Return body of given URL as a string.

    :raises EmptyResponseError: raised when HTTP rsp body is empty
    :raises NotModifiedError: raised when HTTP Status Code is 304
    :raises requests.exceptions.BaseHTTPError: raised when HTTP error occurs
    """
    # Randomize user agent, because CF likes to block for no apparent reason.
    user_agent = "rss2irc_{:d}".format(int(time.time()))
    headers = {
        "User-Agent": user_agent,
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        ),
    }
    if extra_headers:
        for key, value in extra_headers.items():
            headers[key] = value

    logger.debug("Make request at URL '%s'.", url)
    rsp = requests.get(url, timeout=timeout, headers=headers)
    logger.debug("Got HTTP Status Code '%i'.", rsp.status_code)
    rsp.raise_for_status()

    if rsp.status_code == 304:
        raise NotModifiedError

    if not rsp.text:
        raise EmptyResponseError

    return rsp


def main():
    """Fetch RSS feed and post RSS news to IRC."""
    args = parse_args()
    logging.basicConfig(level=args.log_level, stream=sys.stdout)
    logger = logging.getLogger("rss2irc")
    logger.setLevel(args.log_level)

    if not os.path.exists(args.output):
        logger.error("Ouput '%s' doesn't exist.", args.output)
        sys.exit(1)

    retcode = 0
    cache = wrap_read_cache(logger, args.cache_file)
    if cache is None:
        retcode = utils.mask_retcode(1, args.mask_errors)
        sys.exit(retcode)

    source = cache.get_source_by_url(args.rss_url)
    try:
        rsp = get_rss(
            logger,
            args.rss_url,
            args.rss_http_timeout,
            source.make_caching_headers(),
        )

        news = parse_news(rsp.text)
        if not news:
            raise NoNewsError

        source.extract_caching_headers(rsp.headers)
        prune_news(logger, cache, news, args.cache_expiration)
        scrub_items(logger, cache)

        if not args.cache_init:
            write_data(logger, news, args.output, args.handle, args.sleep)

        update_items_expiration(cache, news, args.cache_expiration)
        cache.scrub_data_sources()
        source.http_error_count = 0
        retcode = 0
    except NotModifiedError:
        logger.debug("No new RSS data since the last run.")
        update_items_expiration(cache, cache.items, args.cache_expiration)
        source.http_error_count = 0
        retcode = 0
    except EmptyResponseError:
        logger.error("Got empty response from '%s'.", args.rss_url)
        source.http_error_count += 1
        retcode = 1
    except NoNewsError:
        # NOTE(zstyblik): some feeds don't have news unless something is up, eg.
        # AWS RSS feed doesn't have news unless there is a problem.
        logger.info("No news from '%s'?", args.rss_url)
        update_items_expiration(cache, cache.items, args.cache_expiration)
        # NOTE(zstyblik): leave source.http_error_count unchanged
        retcode = 0
    except Exception:
        logger.exception("Unexpected exception has occurred.")
        source.http_error_count += 1
        retcode = 1

    write_retcode = wrap_write_cache(logger, cache, args.cache_file)
    retcode = utils.escalate_retcode(write_retcode, retcode)
    retcode = utils.mask_retcode(retcode, args.mask_errors)
    sys.exit(retcode)


def parse_args() -> argparse.Namespace:
    """Return parsed CLI args."""
    parser = argparse.ArgumentParser()
    generic_args = cli_args.GenericArgsCfg(handle=True, output=True)
    cli_args.add_generic_args(parser, generic_args)
    cli_args.add_cache_file_arg_group(parser)
    cli_args.add_rss_arg_group(parser)
    args = parser.parse_args()
    args.log_level = utils.calc_log_level(args.verbose)

    cli_args.check_cache_expiration_arg(parser, args)
    cli_args.check_sleep_arg(parser, args)
    return args


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
    expiration: int = config_options.CACHE_EXPIRATION,
) -> None:
    """Prune news which already are in cache."""
    item_expiration = int(time.time()) + expiration
    for key in list(news.keys()):
        if key in cache.items:
            logger.debug("Key %s found in cache", key)
            cache.items[key] = item_expiration
            news.pop(key)


def read_cache(logger: logging.Logger, cache_file: str) -> CachedData:
    """Read file with Py pickle in it.

    :raises CacheReadError: raised when unhandled exception occurs
    """
    if not cache_file:
        return CachedData()

    try:
        with open(cache_file, "rb") as fhandle:
            cache = pickle.load(fhandle)
    except FileNotFoundError:
        cache = CachedData()
        logger.warning("Cache file '%s' doesn't exist.", cache_file)
    except EOFError:
        # NOTE(zstyblik): occurred with empty file.
        cache = CachedData()
        logger.debug(
            "Cache file '%s' is probably empty: %s",
            cache_file,
            traceback.format_exc(),
        )
    except Exception as exception:
        raise CacheReadError from exception

    logger.debug("Cache: %s", cache)
    return cache


def scrub_items(logger: logging.Logger, cache: CachedData) -> None:
    """Scrub cache and remove expired items."""
    time_now = time.time()
    for key in list(cache.items.keys()):
        try:
            expiration = int(cache.items[key])
        except ValueError:
            logger.exception(
                "Invalid cache entry will be removed: '%s'", cache.items[key]
            )
            cache.items.pop(key)
            continue

        if expiration < time_now:
            logger.debug("URL %s has expired.", key)
            cache.items.pop(key)


def signal_handler(signum, frame):
    """Handle SIGALRM signal."""
    raise TimeoutError


def update_items_expiration(
    cache: CachedData,
    news: Dict[str, Tuple[str, str]],
    expiration: int = config_options.CACHE_EXPIRATION,
) -> None:
    """Update expiration of items in cache based on news dict."""
    item_expiration = int(time.time()) + expiration
    for key in list(news.keys()):
        cache.items[key] = item_expiration


def wrap_read_cache(logger: logging.Logger, cache_file: str):
    """Call read_cache() and return cached data or log error and return None."""
    cache = None
    try:
        cache = read_cache(logger, cache_file)
    except CacheReadError:
        logger.exception("Error while reading cache file '%s'.", cache_file)
        cache = None

    return cache


def wrap_write_cache(
    logger: logging.Logger,
    cache: CachedData,
    cache_file: str,
) -> int:
    """Call write_cache() and return 0 on success or 1 on error."""
    retcode = 0
    try:
        write_cache(cache, cache_file)
    except CacheWriteError:
        logger.exception(
            "Failed to write data into cache file '%s'.",
            cache_file,
        )
        retcode = 1

    return retcode


def write_cache(data: CachedData, cache_file: str):
    """Dump data into file as a pickle.

    :raises CacheWriteError: raised when unhandled exception occurs
    """
    if not cache_file or data is None:
        return

    try:
        with open(cache_file, "wb") as fhandle:
            pickle.dump(data, fhandle, pickle.HIGHEST_PROTOCOL)
    except Exception as exception:
        raise CacheWriteError from exception


def write_data(
    logger: logging.Logger,
    data: Dict,
    output: str,
    handle: str = None,
    sleep: int = 2,
) -> None:
    """Write data into file."""
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(config_options.PIPE_OPEN_TIMEOUT)
    with open(output, "wb") as fhandle:
        signal.alarm(0)
        for url in list(data.keys()):
            message = format_message(url, data[url], handle)
            try:
                write_message(logger, fhandle, message)
                time.sleep(sleep)
            except (TimeoutError, ValueError):
                logger.debug(
                    "Failed to write '%s'=>'%s' due to exception: %s",
                    url,
                    data[url],
                    traceback.format_exc(),
                )
                data.pop(url)


def write_message(
    logger: logging.Logger, fhandle: BinaryIO, message: str
) -> None:
    """Write message into file handle.

    Sets up SIGALRM and raises `TimeoutError` if alarm is due.
    """
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(config_options.PIPE_WRITE_TIMEOUT)
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
