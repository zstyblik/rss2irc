#!/usr/bin/python2.7
"""2015/Jul/5 @ Zdenek Styblik <stybla@turnovfree.net>
Desc: Fetch RSS and pipe it into IRC bot.
"""
import argparse
import logging
import logging.handlers
import os
import pickle
import requests
import signal
import sys
import time
import traceback
import xml.etree.ElementTree as ET

EXPIRATION = 86400

def get_rss(url):
    """Fetch contents of given URL."""
    try:
        rsp = requests.get(url, timeout=30)
        rsp.raise_for_status()
        data = rsp.text
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

    if not os.path.exists(args.output):
        logging.error("Ouput '%s' doesn't exist.", args.output)
        sys.exit(1)

    data = get_rss(args.rss_url)
    if not data:
        logging.error('Failed to get RSS from %s', args.rss_url)
        sys.exit(1)

    news = parse_news(data)
    if not news:
        logging.info('No news?')
        sys.exit(0)

    cache = read_cache(args.cache)
    for key in news.keys():
        if key in cache:
            logging.debug('Key %s found in cache', key)
            cache[key] = int(time.time()) + EXPIRATION
            news.pop(key)

    write_data(news, args.output, args.handle, args.sleep)

    expiration = int(time.time()) + EXPIRATION
    for key in news.iterkeys():
        cache[key] = expiration

    write_cache(cache, args.cache)

def parse_args():
    """Return parsed CLI args."""
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose',
                        dest='verbosity', action='store_true', default=False,
                        help='Increase logging verbosity.')
    parser.add_argument('--rss-url',
                        dest='rss_url', type=str, required=True,
                        help='URL of RSS Feed.')
    parser.add_argument('--handle',
                        dest='handle', type=str, default=None,
                        help='IRC handle of this feed.')
    parser.add_argument('--output',
                        dest='output', type=str, required=True,
                        help='Where to output formatted news.')
    parser.add_argument('--cache',
                        dest='cache', type=str, default=None,
                        help='')
    parser.add_argument('--sleep',
                        dest='sleep', type=int, default=2,
                        help='Sleep between messages in order to avoid '
                        'Excess Flood at IRC.')
    return parser.parse_args()

def parse_news(data):
    """Parse-out link and title out of XML."""
    news = {}
    tree = ET.fromstring(data.encode('utf-8'))
    for item in tree.iter('item'):
        news_item = {}
        for child in item.getchildren():
            if child.tag in ['category', 'link', 'title']:
                news_item[child.tag] = child.text

        if 'link' in news_item and 'title' in news_item:
            link = news_item.pop('link')
            title = news_item.pop('title')
            category = news_item.pop('category', None)
            news[link] = (title, category)

    return news

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
                msg = '%s | %s\n' % (data[url], url)

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