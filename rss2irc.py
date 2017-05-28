#!/usr/bin/python2.7
"""2015/Jul/5 @ Zdenek Styblik <stybla@turnovfree.net>
Desc: Fetch RSS and pipe it into IRC bot.
"""
import argparse
import feedparser
import logging
import logging.handlers
import os
import pickle
import requests
import signal
import sys
import time
import traceback

EXPIRATION = 86400

def get_rss(url):
    """Fetch contents of given URL."""
    try:
        rsp = requests.get(url, timeout=30)
        rsp.raise_for_status()
        data = rsp.text
        del rsp
        logging.debug('Got RSS data.')
    except Exception:
        logging.debug('Failed to get RSS data.')
        logging.debug(traceback.format_exc())
        data = None

    return data

def main():
    """Main."""
    logging.basicConfig(stream=sys.stdout)
    logging.getLogger().setLevel(logging.ERROR)
    args = parse_args()
    if args.verbosity:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.cache_expiration < 0:
        logging.error("Cache expiration can't be less than 0.")
        sys.exit(1)

    if not os.path.exists(args.output):
        logging.error("Ouput '%s' doesn't exist.", args.output)
        sys.exit(1)

    news = {}
    for rss_url in args.rss_urls:
        data = get_rss(rss_url)
        if not data:
            logging.error('Failed to get RSS from %s', rss_url)
            sys.exit(1)

        parse_news(data, news)

    if not news:
        logging.info('No news?')
        sys.exit(0)

    cache = read_cache(args.cache)
    for key in news.keys():
        if key in cache:
            logging.debug('Key %s found in cache', key)
            cache[key] = int(time.time()) + args.cache_expiration
            news.pop(key)

    if not args.cache_init:
        write_data(news, args.output, args.handle, args.sleep)

    expiration = int(time.time()) + args.cache_expiration
    for key in news.keys():
        cache[key] = expiration

    write_cache(cache, args.cache)

def parse_args():
    """Return parsed CLI args."""
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose',
                        dest='verbosity', action='store_true', default=False,
                        help='Increase logging verbosity.')
    parser.add_argument('--rss-url',
                        dest='rss_urls', action='append', required=True,
                        help='URL of RSS Feed.')
    parser.add_argument('--handle',
                        dest='handle', type=str, default=None,
                        help='IRC handle of this feed.')
    parser.add_argument('--output',
                        dest='output', type=str, required=True,
                        help='Where to output formatted news.')
    parser.add_argument('--cache',
                        dest='cache', type=str, default=None,
                        help='Path to cache file.')
    parser.add_argument('--cache-expiration',
                        dest='cache_expiration', type=int, default=EXPIRATION,
                        help=('Time, in seconds, for how long to keep items '
                              'in cache.'))
    parser.add_argument('--cache-init',
                        dest='cache_init', action='store_true', default=False,
                        help='Prevents posting news to IRC. This is useful '
                             'when bootstrapping new RSS feed.')
    parser.add_argument('--sleep',
                        dest='sleep', type=int, default=2,
                        help='Sleep between messages in order to avoid '
                        'Excess Flood at IRC.')
    return parser.parse_args()

def parse_news(data, news):
    """Parse-out link and title out of XML."""
    if not isinstance(news, dict):
        raise ValueError

    feed = feedparser.parse(data)
    for entry in feed['entries']:
        link = entry.pop('link', None)
        title = entry.pop('title', None)
        if not 'link' and not 'title':
            continue

        category = entry.pop('category', None)
        news[link] = (title, category)

def read_cache(cache_file):
    """Read file with Py pickle in it."""
    if not cache_file:
        return {}
    elif not os.path.exists(cache_file):
        logging.warn("Cache file '%s' doesn't exist.", cache_file)
        return {}

    with open(cache_file, 'r') as fhandle:
        cache = pickle.load(fhandle)

    logging.debug(cache)
    time_now = time.time()
    for key in cache.keys():
        if int(cache[key]) < time_now:
            logging.debug('URL %s has expired.', key)
            cache.pop(key)

    return cache

def signal_handler(signum, frame):
    """Handle SIGALRM signal."""
    raise ValueError

def write_cache(data, cache_file):
    """Dump data into file as a pickle."""
    if not cache_file:
        return

    with open(cache_file, 'w') as fhandle:
        pickle.dump(data, fhandle)

def write_data(data, output, handle=None, sleep=2):
    """Write data into file."""
    with open(output, 'a') as fhandle:
        for url in data.keys():
            if handle:
                if data[url][1]:
                    tag = '%s-%s' % (handle, data[url][1])
                else:
                    tag = '%s' % handle

                msg = '[%s] %s | %s\n' % (tag, data[url][0], url)
            else:
                msg = '%s\n' % url

            signal.signal(signal.SIGALRM, signal_handler)
            signal.alarm(5)
            try:
                logging.debug('Will write %s', repr(msg))
                fhandle.write(msg.encode('utf-8'))
                signal.alarm(0)
                time.sleep(sleep)
            except ValueError:
                logging.debug(traceback.format_exc())
                logging.debug('Failed to write %s, %s', url, data[url])
                data.pop(url)

            signal.alarm(0)

if __name__ == '__main__':
    main()
