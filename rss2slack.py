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

import rss2irc
from slack import WebClient

SLACK_BASE_URL = WebClient.BASE_URL


def get_slack_token() -> str:
    """Get Slack token from ENV variable.

    :raises: `ValueError`
    """
    slack_token = os.environ.get('SLACK_TOKEN', None)
    if slack_token:
        return slack_token

    raise ValueError('SLACK_TOKEN must be set.')


def get_slack_web_client(token: str, base_url: str, timeout: int) -> WebClient:
    """Return instance of Slack Web Client."""
    return WebClient(token, base_url=base_url, timeout=timeout)


def main():
    """Fetch RSS feed and post RSS news to Slack."""
    logging.basicConfig(stream=sys.stdout, level=logging.ERROR)
    logger = logging.getLogger('rss2slack')
    args = parse_args()
    if args.verbosity:
        logger.setLevel(logging.DEBUG)

    if args.cache_expiration < 0:
        logger.error("Cache expiration can't be less than 0.")
        sys.exit(1)

    try:
        slack_token = get_slack_token()
        news = {}
        for rss_url in args.rss_urls:
            data = rss2irc.get_rss(logger, rss_url, args.rss_http_timeout)
            if not data:
                logger.error('Failed to get RSS from %s', rss_url)
                sys.exit(1)

            rss2irc.parse_news(data, news)

        if not news:
            logger.info('No news?')
            sys.exit(0)

        cache = rss2irc.read_cache(logger, args.cache)
        rss2irc.scrub_cache(logger, cache)

        for key in list(news.keys()):
            if key in cache:
                logger.debug('Key %s found in cache', key)
                cache[key] = int(time.time()) + args.cache_expiration
                news.pop(key)

        slack_client = get_slack_web_client(
            slack_token, base_url=args.slack_base_url,
            timeout=args.slack_timeout
        )
        if not args.cache_init:
            for url in list(news.keys()):
                message = rss2irc.format_message(url, news[url], args.handle)
                try:
                    post_to_slack(
                        logger, message, slack_client, args.slack_channel,
                    )
                except ValueError:
                    news.pop(url)
                finally:
                    time.sleep(args.sleep)

        expiration = int(time.time()) + args.cache_expiration
        for key in list(news.keys()):
            cache[key] = expiration

        rss2irc.write_cache(cache, args.cache)
        # TODO(zstyblik): remove error file
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
        '--cache',
        dest='cache', type=str, default=None,
        help='File which contains cache.'
    )
    parser.add_argument(
        '--cache-expiration',
        dest='cache_expiration', type=int,
        default=rss2irc.EXPIRATION,
        help='Time, in seconds, for how long to keep items in cache.'
    )
    parser.add_argument(
        '--cache-init',
        dest='cache_init', action='store_true', default=False,
        help='Prevents posting news to IRC. This is useful '
             'when bootstrapping new RSS feed.'
    )
    parser.add_argument(
        '--handle',
        dest='handle', type=str, default=None,
        help='Handle/callsign of this feed.'
    )
    parser.add_argument(
        '--rss-url',
        dest='rss_urls', action='append', required=True,
        help='URL of RSS Feed.'
    )
    parser.add_argument(
        '--rss-http-timeout',
        dest='rss_http_timeout', type=int,
        default=rss2irc.HTTP_TIMEOUT,
        help='HTTP Timeout. Defaults to {:d} seconds.'.format(
            rss2irc.HTTP_TIMEOUT
        )
    )
    parser.add_argument(
        '--slack-base-url',
        dest='slack_base_url', type=str,
        default=SLACK_BASE_URL,
        help='Base URL for Slack client.'
    )
    parser.add_argument(
        '--slack-channel',
        dest='slack_channel', type=str, required=True,
        help='Name of Slack channel to send formatted news to.'
    )
    parser.add_argument(
        '--slack-timeout',
        dest='slack_timeout', type=int,
        default=rss2irc.HTTP_TIMEOUT,
        help='Slack API Timeout. Defaults to {:d} seconds.'.format(
            rss2irc.HTTP_TIMEOUT
        )
    )
    parser.add_argument(
        '--sleep',
        dest='sleep', type=int, default=2,
        help='Sleep between messages in order to avoid '
             'possible excess flood/API call rate limit.'
    )
    parser.add_argument(
        '-v', '--verbose',
        dest='verbosity', action='store_true', default=False,
        help='Increase logging verbosity.'
    )
    return parser.parse_args()


def post_to_slack(
        logger: logging.Logger, message: str,
        slack_client: WebClient, slack_channel: str,
) -> None:
    """Post news to Slack channel."""
    try:
        logger.debug('Will post %s', repr(message))
        slack_client.api_call(
            'chat.postMessage',
            json={
                'channel': slack_channel,
                'text': message,
            },
        )
    except ValueError:
        logger.debug(traceback.format_exc())
        raise


if __name__ == '__main__':
    main()
