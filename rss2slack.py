#!/usr/bin/env python3
"""Fetch RSS and post it to Slack channel.

2017/Sep/03 @ Zdenek Styblik <stybla@turnovfree.net>
"""
import argparse
import logging
import os
import sys
import time
import traceback
from typing import Dict
from typing import List
from typing import Tuple

from slack import WebClient

import rss2irc
from lib import config_options
from lib import utils
from lib.exceptions import CacheReadError
from lib.exceptions import CacheWriteError
from lib.exceptions import EmptyResponseError
from lib.exceptions import NoNewsError
from lib.exceptions import NotModifiedError
from lib.exceptions import SlackTokenError

SLACK_BASE_URL = WebClient.BASE_URL


def format_message(
    url: str, msg_attrs: Tuple[str, str], handle: str = ""
) -> Dict:
    """Return formatted message as Slack's BlockKit section.

    :param url: URL of news item.
    :param msg_attrs: tuple of title and category.
    :param handle: Handle of given feed.
    """
    if handle:
        if len(msg_attrs) > 1 and msg_attrs[1]:
            tag = "[{:s}-{:s}] ".format(handle, msg_attrs[1])
        else:
            tag = "[{:s}] ".format(handle)

    else:
        tag = ""

    return {
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": "{}<{}|{}>".format(tag, url, msg_attrs[0]),
        },
    }


def get_slack_token() -> str:
    """Get Slack token from ENV variable.

    :raises SlackTokenMissing: raised when env variable SLACK_TOKEN is not set
    """
    slack_token = os.environ.get("SLACK_TOKEN", None)
    if slack_token:
        return slack_token

    raise SlackTokenError("SLACK_TOKEN env variable must be set")


def get_slack_web_client(token: str, base_url: str, timeout: int) -> WebClient:
    """Return instance of Slack Web Client."""
    return WebClient(token, base_url=base_url, timeout=timeout)


def main():
    """Fetch RSS feed and post RSS news to Slack."""
    args = parse_args()
    logging.basicConfig(level=args.log_level, stream=sys.stdout)
    logger = logging.getLogger("rss2slack")
    logger.setLevel(args.log_level)

    cache = None
    retcode = 0
    try:
        slack_token = get_slack_token()
        cache = rss2irc.read_cache(logger, args.cache_file)
        source = cache.get_source_by_url(args.rss_url)

        rsp = rss2irc.get_rss(
            logger,
            args.rss_url,
            args.rss_http_timeout,
            source.make_caching_headers(),
        )
        news = rss2irc.parse_news(rsp.text)
        if not news:
            raise NoNewsError

        source.extract_caching_headers(rsp.headers)
        rss2irc.prune_news(logger, cache, news, args.cache_expiration)
        rss2irc.scrub_items(logger, cache)

        slack_client = get_slack_web_client(
            slack_token,
            base_url=args.slack_base_url,
            timeout=args.slack_timeout,
        )
        if not args.cache_init:
            process_news(
                logger,
                news,
                args.handle,
                args.sleep,
                slack_client,
                args.slack_channel,
            )

        rss2irc.update_items_expiration(cache, news, args.cache_expiration)
        cache.scrub_data_sources()
        source.http_error_count = 0
        retcode = 0
    except SlackTokenError:
        logger.exception("Environment variable SLACK_TOKEN must be set.")
        retcode = utils.mask_retcode(1, args.mask_error)
        sys.exit(retcode)
    except CacheReadError:
        logger.exception(
            "Error while reading cache file '%s'.",
            args.cache_file,
        )
        retcode = utils.mask_retcode(1, args.mask_error)
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
        # source.http_error_count leave unchanged
        retcode = 0
    except Exception:
        logger.exception("Unexpected exception has occurred.")
        source.http_error_count += 1
        retcode = 1

    try:
        rss2irc.write_cache(cache, args.cache_file)
    except CacheWriteError:
        logger.exception(
            "Failed to write data into cache file '%s'.",
            args.cache_file,
        )
        retcode = 1

    retcode = utils.mask_retcode(retcode, args.mask_errors)
    sys.exit(retcode)


def parse_args() -> argparse.Namespace:
    """Return parsed CLI args."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--cache",
        dest="cache_file",
        type=str,
        default=None,
        help="File which contains cache.",
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
        default=SLACK_BASE_URL,
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


def post_to_slack(
    logger: logging.Logger,
    msg_blocks: List,
    slack_client: WebClient,
    slack_channel: str,
) -> None:
    """Post news to Slack channel."""
    try:
        logger.debug("Will post %s", repr(msg_blocks))
        rsp = slack_client.chat_postMessage(
            channel=slack_channel, blocks=msg_blocks
        )
        logger.debug("Response from Slack: %s", rsp)
        if not rsp:
            raise ValueError("Slack response is not OK.")

        is_ok = rsp.get("ok", False)
        if not is_ok:
            raise ValueError("Slack response is not OK.")
    except ValueError:
        logger.debug(
            "Failed to post to Slack due to exception: %s",
            traceback.format_exc(),
        )
        raise


def process_news(
    logger: logging.Logger,
    news: Dict,
    handle: str,
    sleep: int,
    slack_client: WebClient,
    slack_channel: str,
) -> None:
    """Process news and post it to Slack."""
    for url in list(news.keys()):
        msg_blocks = [format_message(url, news[url], handle)]
        try:
            post_to_slack(
                logger,
                msg_blocks,
                slack_client,
                slack_channel,
            )
        except ValueError:
            news.pop(url)
        finally:
            time.sleep(sleep)


if __name__ == "__main__":
    main()
