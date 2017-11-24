#!/usr/bin/env python2
"""2017/Nov/15 @ Zdenek Styblik <stybla@turnovfree.net>
Desc: Fetch RSS feed from phpBB forum, or probably forum of any kind, and post
it to slack channel.
"""
import argparse
import logging
import sys
import time
import traceback

from slackclient import SlackClient
import feedparser
import rss2irc
import rss2slack

CACHE_EXPIRATION = 86400  # seconds
HTTP_TIMEOUT = 30  # seconds


def format_message(url, msg_attrs, handle=None):
    """Return pre-formatted message.

    :type url: str
    :type msg_attrs: dict
    :type handle: str
    """
    if handle:
        if msg_attrs['category']:
            tag = '%s-%s' % (handle, msg_attrs['category'])
        else:
            tag = '%s' % handle

        msg = '[%s] %s (%i) | %s\n' % (
            tag, msg_attrs['title'], msg_attrs['comments_cnt'], url
        )
    else:
        msg = '%s\n' % url

    return msg


def get_authors_from_file(logger, fname):
    """Return list of authors of interest from given file.

    :type logger: `logging.Logger`
    :type fname: str

    :rtype: list
    """
    if not fname:
        return []

    try:
        with open(fname, 'r') as fhandle:
            authors = [
                line.strip()
                for line in fhandle.readlines()
                if line.strip() != ''
            ]
    except Exception:
        logger.error(traceback.format_exc())
        authors = []

    return authors


def main():
    """Main."""
    logging.basicConfig(stream=sys.stdout, level=logging.ERROR)
    logger = logging.getLogger('phpbb2slack')
    args = parse_args()
    if args.verbosity:
        logger.setLevel(logging.DEBUG)

    if args.cache_expiration < 0:
        logger.error("Cache expiration can't be less than 0.")
        sys.exit(1)
    elif args.mute_duration < 0:
        logger.error("Mute duration can't be less than 0.")
        sys.exit(1)

    slack_token = rss2slack.get_slack_token()
    authors = get_authors_from_file(logger, args.authors_file)

    news = {}
    for rss_url in args.rss_urls:
        data = rss2irc.get_rss(logger, rss_url, args.rss_http_timeout)
        if not data:
            logger.error('Failed to get RSS from %s', rss_url)
            sys.exit(1)

        parse_news(data, news, authors)

    if not news:
        logger.info('No news?')
        sys.exit(0)

    cache = rss2irc.read_cache(logger, args.cache)
    scrub_cache(logger, cache)

    for key in news.keys():
        if key not in cache:
            continue

        logger.debug('Key %s found in cache', key)
        if int(cache[key]['comments_cnt']) == int(news[key]['comments_cnt']):
            cache[key]['expiration'] = int(time.time()) + args.cache_expiration
            news.pop(key)

    slack_client = SlackClient(slack_token)
    if not args.cache_init:
        for url in news.keys():
            message = format_message(url, news[url], args.handle)
            try:
                rss2slack.post_to_slack(
                    logger, message, slack_client, args.slack_channel,
                    args.slack_timeout
                )
            except ValueError:
                news.pop(url)
            finally:
                time.sleep(args.sleep)

    expiration = int(time.time()) + args.cache_expiration
    update_cache(cache, news, expiration)
    rss2irc.write_cache(cache, args.cache)


def parse_args():
    """Return parsed CLI args.

    :rtype: `argparse.Namespace`
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--authors-of-interest',
        dest='authors_file', type=str, default=None,
        help='Path to file which contains list of authors, one per line. '
             'Only threads which are started by one of the authors on the '
             'list will be pushed.'
    )
    parser.add_argument(
        '--cache',
        dest='cache', type=str, default=None,
        help='Path to cache file.'
    )
    parser.add_argument(
        '--cache-expiration',
        dest='cache_expiration', type=int,
        default=CACHE_EXPIRATION,
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
        default=HTTP_TIMEOUT,
        help='HTTP Timeout. Defaults to %i seconds.' % HTTP_TIMEOUT
    )
    parser.add_argument(
        '--slack-channel',
        dest='slack_channel', type=str, required=True,
        help='Name of slack channel to send formatted news to.'
    )
    parser.add_argument(
        '--slack-timeout',
        dest='slack_timeout', type=int,
        default=HTTP_TIMEOUT,
        help=('slack API Timeout. Defaults to %i seconds.'
              % HTTP_TIMEOUT)
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


def parse_news(data, news, authors):
    """Parse-out link and title out of XML."""
    if not isinstance(news, dict):
        raise ValueError

    feed = feedparser.parse(data)
    for entry in feed['entries']:
        link = entry.pop('link', None)
        title = entry.pop('title', None)
        author_detail = entry.pop('author_detail', {'name': None})
        if (
                not 'link' and
                not 'title'
        ):
            continue

        if authors and author_detail['name'] not in authors:
            continue

        category = entry.pop('category', None)
        comments_cnt = entry.pop('slash_comments', 0)
        try:
            comments_cnt = int(comments_cnt)
        except ValueError:
            comments_cnt = 0

        news[link] = {
            'title': title,
            'category': category,
            'comments_cnt': int(comments_cnt),
        }


def scrub_cache(logger, cache):
    """Scrub cache and remove expired items.

    :type logger: `logging.Logger`
    :type cache: dict
    """
    time_now = int(time.time())
    for key in cache.keys():
        try:
            expiration = int(cache[key]['expiration'])
        except (KeyError, ValueError):
            logger.error(traceback.format_exc())
            logger.error("Invalid cache entry will be removed: '%s'",
                         cache[key])
            cache.pop(key)
            continue

        if expiration < time_now:
            logger.debug('URL %s has expired.', key)
            cache.pop(key)


def update_cache(cache, news, expiration):
    """Update cache contents.

    :type cache: dict
    :type news: dict
    :type expiration: int
    """
    for key in news.keys():
        cache[key] = {
            'expiration': expiration,
            'comments_cnt': int(news[key]['comments_cnt']),
        }


if __name__ == '__main__':
    main()
