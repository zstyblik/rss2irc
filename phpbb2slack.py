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
from lib import cli_args
from lib import config_options
from lib import utils
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

    retcode = 0
    cache = rss2irc.wrap_read_cache(logger, args.cache_file)
    if cache is None:
        retcode = utils.mask_retcode(1, args.mask_errors)
        sys.exit(retcode)

    source = cache.get_source_by_url(args.rss_url)
    try:
        slack_token = rss2slack.get_slack_token()
        authors = get_authors_from_file(logger, args.authors_file)

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

    write_retcode = rss2irc.wrap_write_cache(logger, cache, args.cache_file)
    retcode = utils.escalate_retcode(write_retcode, retcode)
    retcode = utils.mask_retcode(retcode, args.mask_errors)
    sys.exit(retcode)


def parse_args() -> argparse.Namespace:
    """Return parsed CLI args."""
    parser = argparse.ArgumentParser()
    generic_args = cli_args.GenericArgsCfg(handle=True)
    cli_args.add_generic_args(parser, generic_args)
    cli_args.add_cache_file_arg_group(parser)

    phpbb_group = parser.add_argument_group("phpBB options")
    phpbb_group.add_argument(
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

    cli_args.add_rss_arg_group(parser)
    cli_args.add_slack_arg_group(parser, rss2slack.SLACK_BASE_URL)
    args = parser.parse_args()
    args.log_level = utils.calc_log_level(args.verbose)

    cli_args.check_cache_expiration_arg(parser, args)
    cli_args.check_sleep_arg(parser, args)
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
        msg_block = format_message(url, news[url], handle)
        msg_blocks = [msg_block]
        msg_as_text = msg_block["text"]["text"]
        try:
            rss2slack.post_to_slack(
                logger,
                msg_blocks,
                msg_as_text,
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
