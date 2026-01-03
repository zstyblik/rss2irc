#!/usr/bin/env python3
"""Fetch RSS feed from phpBB forum and post it to Slack channel.

2017/Nov/15 @ Zdenek Styblik <stybla@turnovfree.net>
"""
import argparse
import logging
import sys
import time
from typing import Dict
from typing import List

import feedparser

import rss2irc
import rss2slack
from lib import CachedData
from lib import config_options
from lib import utils
from lib.exceptions import CacheReadError
from lib.exceptions import EmptyResponseError
from lib.exceptions import NoNewsError
from lib.exceptions import NotModifiedError
from lib.exceptions import SlackTokenError


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
        logger.exception(
            "Failed to parse authors from file '%s' due to exception.",
            fname,
        )
        authors = []

    return authors


def main():
    """Fetch phpBB RSS feed and post RSS news to Slack."""
    args = parse_args()
    logging.basicConfig(stream=sys.stdout, level=logging.ERROR)
    logger = logging.getLogger("phpbb2slack")
    logger.setLevel(args.log_level)

    cache = None
    retcode = 0
    try:
        slack_token = rss2slack.get_slack_token()
        authors = get_authors_from_file(logger, args.authors_file)
        cache = rss2irc.read_cache(logger, args.cache_file)
        source = cache.get_source_by_url(args.rss_url)

        rsp = rss2irc.get_rss(
            logger,
            args.rss_url,
            args.rss_http_timeout,
            source.make_caching_headers(),
        )
        news = parse_news(rsp.text, authors)
        if not news:
            raise NoNewsError

        source.extract_caching_headers(rsp.headers)
        prune_news(logger, cache, news, args.cache_expiration)
        scrub_items(logger, cache)

        if not args.cache_init:
            slack_client = rss2slack.get_slack_web_client(
                slack_token, args.slack_base_url, args.slack_timeout
            )
            process_news(
                logger,
                news,
                args.handle,
                args.sleep,
                slack_client,
                args.slack_channel,
            )

        update_items_expiration(cache, news, args.cache_expiration)
        cache.scrub_data_sources()
        source.http_error_count = 0
        retcode = 0
    except SlackTokenError:
        logger.exception("Environment variable SLACK_TOKEN must be set.")
        retcode = utils.mask_retcode(1, args.mask_errors)
        sys.exit(retcode)
    except CacheReadError:
        logger.exception(
            "Error while reading cache file '%s'.",
            args.cache_file,
        )
        retcode = utils.mask_retcode(1, args.mask_errors)
        # NOTE(zstyblik): since cache file couldn't be opened, it doesn't make
        # sense writing it. Therefore, call sys.exit().
        sys.exit(retcode)
    except NotModifiedError:
        logger.debug("No new RSS data since the last run.")
        rss2irc.update_items_expiration(
            cache, cache.items, args.cache_expiration
        )
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
        rss2irc.update_items_expiration(
            cache, cache.items, args.cache_expiration
        )
        # NOTE(zstyblik): leave source.http_error_count unchanged
        retcode = 0
    except Exception:
        logger.exception("Unexpected exception has occurred.")
        source.http_error_count += 1
        retcode = 1

    write_retcode = rss2irc.wrap_write_cache(logger, cache, args.cache_file)
    retcode = utils.escalate_retcode(write_retcode, retcode)
    retcode = utils.mask_retcode(retcode, args.mask_errors)
    sys.exit(retcode)


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
        dest="cache_file",
        type=str,
        default=None,
        help="Path to cache file.",
    )
    parser.add_argument(
        "--cache-expiration",
        dest="cache_expiration",
        type=int,
        default=config_options.CACHE_EXPIRATION,
        help=(
            "How long to keep items in cache. "
            "Defaults to %(default)s seconds."
        ),
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
        "--return-error",
        dest="mask_errors",
        action="store_false",
        default=True,
        help=(
            "Return RC > 0 should error occur. "
            "Majority of errors are masked because of cron."
        ),
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
        default=config_options.HTTP_TIMEOUT,
        help="HTTP Timeout. Defaults to %(default)s seconds.",
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
        default=config_options.HTTP_TIMEOUT,
        help="Slack API Timeout. Defaults to %(default)s seconds.",
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
        action="count",
        default=0,
        help="Increase log level verbosity. Can be passed multiple times.",
    )
    args = parser.parse_args()
    args.log_level = utils.calc_log_level(args.verbose)

    if args.cache_expiration < 0:
        parser.error("Cache expiration cannot be less than 0.")

    if args.sleep < 0:
        parser.error("Sleep interval cannot be less than 0.")

    return args


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


def process_news(
    logger: logging.Logger,
    news,
    handle: str,
    sleep: int,
    slack_client,
    slack_channel: str,
):
    """Process news and post it to Slack."""
    for url in list(news.keys()):
        msg_blocks = [format_message(url, news[url], handle)]
        try:
            rss2slack.post_to_slack(
                logger,
                msg_blocks,
                slack_client,
                slack_channel,
            )
        except ValueError:
            news.pop(url)
        finally:
            time.sleep(sleep)


def prune_news(
    logger: logging.Logger,
    cache: CachedData,
    news: Dict[str, Dict],
    expiration: int = config_options.CACHE_EXPIRATION,
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


def scrub_items(logger: logging.Logger, cache: CachedData) -> None:
    """Scrub cache and remove expired items."""
    time_now = int(time.time())
    for key in list(cache.items.keys()):
        try:
            expiration = int(cache.items[key]["expiration"])
        except (KeyError, ValueError):
            logger.exception(
                "Invalid cache entry will be removed: '%s'", cache.items[key]
            )
            cache.items.pop(key)
            continue

        if expiration < time_now:
            logger.debug("URL %s has expired.", key)
            cache.items.pop(key)


def update_items_expiration(
    cache: CachedData, news: Dict, expiration: int
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
