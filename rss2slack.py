#!/usr/bin/env python2
"""2017/Sep/03 @ Zdenek Styblik <stybla@turnovfree.net>
Desc: Fetch RSS and post it to slack channel.
"""
import argparse
import logging
import os
import sys
import time
import traceback

from slackclient import SlackClient
import rss2irc


def get_slack_token():
    """Get slack token from ENV variable.

    :rtype: str
    :raises: `ValueError`
    """
    slack_token = os.environ.get('SLACK_TOKEN', None)
    if slack_token:
        return slack_token

    raise ValueError('SLACK_TOKEN must be set.')


def main():
    """Main."""
    logging.basicConfig(stream=sys.stdout, level=logging.ERROR)
    logger = logging.getLogger('rss2slack')
    args = parse_args()
    if args.verbosity:
        logger.setLevel(logging.DEBUG)

    if args.cache_expiration < 0:
        logger.error("Cache expiration can't be less than 0.")
        sys.exit(1)

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

    for key in news.keys():
        if key in cache:
            logger.debug('Key %s found in cache', key)
            cache[key] = int(time.time()) + args.cache_expiration
            news.pop(key)

    slack_client = SlackClient(slack_token)
    if not args.cache_init:
        for url in news.keys():
            message = rss2irc.format_message(url, news[url], args.handle)
            try:
                post_to_slack(
                    logger, message, slack_client, args.slack_channel,
                    args.slack_timeout
                )
            except ValueError:
                news.pop(url)
            finally:
                time.sleep(args.sleep)

    expiration = int(time.time()) + args.cache_expiration
    for key in news.keys():
        cache[key] = expiration

    rss2irc.write_cache(cache, args.cache)


def parse_args():
    """Return parsed CLI args.

    :rtype: `argparse.Namespace`
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--cache',
                        dest='cache', type=str, default=None,
                        help='Path to cache file.')
    parser.add_argument('--cache-expiration',
                        dest='cache_expiration', type=int,
                        default=rss2irc.EXPIRATION,
                        help='Time, in seconds, for how long to keep items '
                             'in cache.')
    parser.add_argument('--cache-init',
                        dest='cache_init', action='store_true', default=False,
                        help='Prevents posting news to IRC. This is useful '
                             'when bootstrapping new RSS feed.')
    parser.add_argument('--handle',
                        dest='handle', type=str, default=None,
                        help='Handle/callsign of this feed.')
    parser.add_argument('--rss-url',
                        dest='rss_urls', action='append', required=True,
                        help='URL of RSS Feed.')
    parser.add_argument('--rss-http-timeout',
                        dest='rss_http_timeout', type=int,
                        default=rss2irc.HTTP_TIMEOUT,
                        help=('HTTP Timeout. Defaults to %i seconds.'
                              % rss2irc.HTTP_TIMEOUT))
    parser.add_argument('--slack-channel',
                        dest='slack_channel', type=str, required=True,
                        help='Name of slack channel to send formatted news '
                             'to.')
    parser.add_argument('--slack-timeout',
                        dest='slack_timeout', type=int,
                        default=rss2irc.HTTP_TIMEOUT,
                        help=('slack API Timeout. Defaults to %i seconds.'
                              % rss2irc.HTTP_TIMEOUT))
    parser.add_argument('--sleep',
                        dest='sleep', type=int, default=2,
                        help='Sleep between messages in order to avoid '
                             'possible excess flood/API call rate limit.')
    parser.add_argument('-v', '--verbose',
                        dest='verbosity', action='store_true', default=False,
                        help='Increase logging verbosity.')
    return parser.parse_args()


def post_to_slack(
        logger, message, slack_client, slack_channel, slack_timeout
):
    """Post news to slack channel.

    :type logger: `logging.Logger`
    :type message: str
    :type slack_client: `slackclient.SlackClient`
    :type slack_channel: str
    :type slack_timeout: int
    """
    try:
        logger.debug('Will post %s', repr(message))
        slack_client.api_call(
            'chat.postMessage', channel=slack_channel,
            text=message.encode('utf-8'), timeout=slack_timeout
        )
    except ValueError:
        logger.debug(traceback.format_exc())
        raise


if __name__ == '__main__':
    main()
