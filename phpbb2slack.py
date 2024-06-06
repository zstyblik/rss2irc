#!/usr/bin/env python3
"""Fetch RSS feed from phpBB forum and post it to Slack channel.

2017/Nov/15 @ Zdenek Styblik <stybla@turnovfree.net>
"""
import argparse
import logging
import sys
import time
import traceback
from typing import Dict
from typing import List

import feedparser

import rss2irc  # noqa: I202
import rss2slack

CACHE_EXPIRATION = 86400  # seconds
HTTP_TIMEOUT = 30  # seconds


def format_message(
    url: str, msg_attrs: Dict[str, str], handle: str = ""
) -> Dict:
    """Return formatted message as Slack's BlockKit section.

    :raises: `KeyError`
    """
    if handle:
        if "category" in msg_attrs and msg_attrs["category"]:
            tag = "[{:s}-{:s}] ".format(handle, msg_attrs["category"])
        else:
            tag = "[{:s}] ".format(handle)

    else:
        tag = ""

    return {
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": "{:s}<{:s}|{:s}> ({:d})".format(
                tag, url, msg_attrs["title"], msg_attrs["comments_cnt"]
            ),
        },
    }


def get_authors_from_file(logger: logging.Logger, fname: str) -> List[str]:
    """Return list of authors of interest from given file."""
    if not fname:
        return []

    try:
        with open(fname, "rb") as fhandle:
            authors = [
                line.decode("utf-8").strip()
                for line in fhandle.readlines()
                if line.decode("utf-8").strip() != ""
            ]
    except Exception:
        logger.error(traceback.format_exc())
        authors = []

    return authors


def main():
    """Fetch phpBB RSS feed and post RSS news to Slack."""
    logging.basicConfig(stream=sys.stdout, level=logging.ERROR)
    logger = logging.getLogger("phpbb2slack")
    args = parse_args()
    if args.verbosity:
        logger.setLevel(logging.DEBUG)

    if args.cache_expiration < 0:
        logger.error("Cache expiration can't be less than 0.")
        sys.exit(1)

    try:
        slack_token = rss2slack.get_slack_token()
        authors = get_authors_from_file(logger, args.authors_file)
        cache = rss2irc.read_cache(logger, args.cache)
        source = cache.get_source_by_url(args.rss_url)

        rsp = rss2irc.get_rss(
            logger,
            args.rss_url,
            args.rss_http_timeout,
            source.make_caching_headers(),
        )
        if rsp.status_code == 304:
            logger.debug("No new RSS data since the last run")
            rss2irc.write_cache(cache, args.cache)
            sys.exit(0)

        if not rsp.text:
            logger.error("Failed to get RSS from %s", args.rss_url)
            sys.exit(1)

        news = parse_news(rsp.text, authors)
        if not news:
            logger.info("No news?")
            sys.exit(0)

        source.extract_caching_headers(rsp.headers)
        scrub_items(logger, cache)
        prune_news(logger, cache, news, args.cache_expiration)

        slack_client = rss2slack.get_slack_web_client(
            slack_token, args.slack_base_url, args.slack_timeout
        )
        if not args.cache_init:
            for url in list(news.keys()):
                msg_blocks = [format_message(url, news[url], args.handle)]
                try:
                    rss2slack.post_to_slack(
                        logger,
                        msg_blocks,
                        slack_client,
                        args.slack_channel,
                    )
                except ValueError:
                    news.pop(url)
                finally:
                    time.sleep(args.sleep)

        update_items_expiration(cache, news, args.cache_expiration)
        cache.scrub_data_sources()
        rss2irc.write_cache(cache, args.cache)
    except Exception:
        logger.debug(traceback.format_exc())
        # TODO(zstyblik):
        # 1. touch error file
        # 2. send error message to the channel
    finally:
        sys.exit(0)


def parse_args() -> argparse.Namespace:
    """Return parsed CLI args."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--authors-of-interest",
        dest="authors_file",
        type=str,
        default=None,
        help=(
            "Path to file which contains list of authors, one per line. "
            "Only threads which are started by one of the authors on the "
            "list will be pushed."
        ),
    )
    parser.add_argument(
        "--cache",
        dest="cache",
        type=str,
        default=None,
        help="Path to cache file.",
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
        "--handle",
        dest="handle",
        type=str,
        default=None,
        help="Handle/callsign of this feed.",
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
        "--slack-base-url",
        dest="slack_base_url",
        type=str,
        default=rss2slack.SLACK_BASE_URL,
        help="Base URL for Slack client.",
    )
    parser.add_argument(
        "--slack-channel",
        dest="slack_channel",
        type=str,
        required=True,
        help="Name of Slack channel to send formatted news to.",
    )
    parser.add_argument(
        "--slack-timeout",
        dest="slack_timeout",
        type=int,
        default=HTTP_TIMEOUT,
        help="Slack API Timeout. Defaults to {:d} seconds.".format(
            HTTP_TIMEOUT
        ),
    )
    parser.add_argument(
        "--sleep",
        dest="sleep",
        type=int,
        default=2,
        help=(
            "Sleep between messages in order to avoid "
            "possible excess flood/API call rate limit."
        ),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbosity",
        action="store_true",
        default=False,
        help="Increase logging verbosity.",
    )
    return parser.parse_args()


def parse_news(data: str, authors: List[str]) -> Dict:
    """Parse-out link and title out of XML."""
    news = {}
    feed = feedparser.parse(data)
    for entry in feed["entries"]:
        link = entry.pop("link", None)
        if not link:
            # If we don't have a link, there is nothing we can do.
            continue

        author_detail = entry.pop("author_detail", {"name": None})
        if authors and author_detail["name"] not in authors:
            continue

        title = entry.pop("title", "No title")
        category = entry.pop("category", None)
        comments_cnt = entry.pop("slash_comments", 0)
        try:
            comments_cnt = int(comments_cnt)
        except ValueError:
            comments_cnt = 0

        news[link] = {
            "title": title,
            "category": category,
            "comments_cnt": int(comments_cnt),
        }

    return news


def prune_news(
    logger: logging.Logger,
    cache: rss2irc.CachedData,
    news: Dict[str, Dict],
    expiration: int = CACHE_EXPIRATION,
) -> None:
    """Prune news which already are in cache."""
    item_expiration = int(time.time()) + expiration
    for key in list(news.keys()):
        if key not in cache.items:
            continue

        logger.debug("Key %s found in cache", key)
        comments_cached = int(cache.items[key]["comments_cnt"])
        comments_actual = int(news[key]["comments_cnt"])
        if comments_cached == comments_actual:
            cache.items[key]["expiration"] = item_expiration
            news.pop(key)


def scrub_items(logger: logging.Logger, cache: rss2irc.CachedData) -> None:
    """Scrub cache and remove expired items."""
    time_now = int(time.time())
    for key in list(cache.items.keys()):
        try:
            expiration = int(cache.items[key]["expiration"])
        except (KeyError, ValueError):
            logger.error(traceback.format_exc())
            logger.error(
                "Invalid cache entry will be removed: '%s'", cache.items[key]
            )
            cache.items.pop(key)
            continue

        if expiration < time_now:
            logger.debug("URL %s has expired.", key)
            cache.items.pop(key)


def update_items_expiration(
    cache: rss2irc.CachedData, news: Dict, expiration: int
) -> None:
    """Update cache contents."""
    item_expiration = int(time.time()) + expiration
    for key in list(news.keys()):
        cache.items[key] = {
            "expiration": item_expiration,
            "comments_cnt": int(news[key]["comments_cnt"]),
        }


if __name__ == "__main__":
    main()
