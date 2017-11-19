#!/usr/bin/env python2
"""2017/Nov/18 @ Zdenek Styblik <stybla@turnovfree.net>
Desc: Get GH issues/pull requests and push them to slack.
"""
import argparse
import logging
import os
import pickle
import sys
import time

from slackclient import SlackClient
import requests
import rss2irc
import rss2slack

ALIASES = {
    'issues': 'issue',
    'pulls': 'pr',
}
DEFAULT_GH_URL = 'https://github.com'


def gh_request(logger, uri, timeout=rss2irc.HTTP_TIMEOUT):
    """Make request to GH and return response.

    :type logger: `logging.Logger`
    :type uri: str
    :type timeout: int

    :rtype: dict
    """
    url = 'https://api.github.com/repos/{}'.format(uri)
    logger.debug('Requesting {}'.format(url))
    rsp = requests.get(
        url, headers={'Accept': 'application/vnd.github.v3+json'},
        params={'state': 'open', 'order': 'created'},
        timeout=timeout,
    )
    logger.debug('HTTP Status Code {:d}'.format(rsp.status_code))
    rsp.raise_for_status()
    # Note: Should we want everything, we would have to follow `Link` header
    # provided in/by GH API response.
    logger.debug('RSP Headers: {}'.format(rsp.headers))
    return rsp.json()


def main():
    """Main."""
    logging.basicConfig(stream=sys.stdout, level=logging.ERROR)
    logger = logging.getLogger('gh2slack')
    args = parse_args()
    if args.verbosity:
        logger.setLevel(logging.DEBUG)

    slack_token = rss2slack.get_slack_token()
    uri = '/'.join([args.gh_owner, args.gh_repo, args.gh_section])
    items = gh_request(logger, uri)

    if not items:
        logger.info('No %s for %s/%s.', args.gh_section, args.gh_owner,
                    args.gh_repo)
        sys.exit(0)

    logger.debug('Got %i items from GH.', len(items))
    cache = read_cache(logger, args.cache)
    expiration = int(time.time()) + args.cache_expiration
    to_publish = set()
    for item in items:
        if (
                'html_url' not in item or
                'number' not in item or
                'title' not in item
        ):
            logger.debug("Item doesn't have required fields: %s", item)
            continue

        # Issues and Pulls have a slightly different structure. However, after
        # more than couple of unsuccessful tries, I've given up on link to
        # the origin. Therefore, link is made up in case of pulls.
        if args.gh_section == 'pulls':
            repository_url = 'https://github.com/{}/{}'.format(args.gh_owner,
                                                               args.gh_repo)
        else:
            repository_url = item.get('repository_url', DEFAULT_GH_URL)

        if item['html_url'] in cache:
            cache[item['html_url']]['expiration'] = expiration
            continue

        cache[item['html_url']] = {
            'expiration': expiration,
            'number': item['number'],
            'repository_url': repository_url,
            'title': item['title'],
        }
        to_publish.add(item['html_url'])

    if not args.cache_init and to_publish:
        slack_client = SlackClient(slack_token)
        for html_url in to_publish:
            attrs = cache[html_url]
            message = '[<{}|{}/{}>] <{}|{}#{}> | {}'.format(
                attrs['repository_url'], args.gh_owner, args.gh_repo, html_url,
                ALIASES[args.gh_section], attrs['number'], attrs['title']
            )
            rss2slack.post_to_slack(
                logger, message, slack_client, args.slack_channel,
                args.slack_timeout
            )
            time.sleep(args.sleep)

    rss2irc.write_cache(cache, args.cache)


def parse_args():
    """Return parsed CLI args.

    :rtype: `argparse.Namespace`
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--cache',
        dest='cache', type=str, default=None,
        help='Path to cache file.'
    )
    parser.add_argument(
        '--cache-expiration',
        dest='cache_expiration', type=int,
        default=rss2irc.EXPIRATION,
        help='Time, in seconds, for how long to keep items '
             'in cache.'
    )
    parser.add_argument(
        '--cache-init',
        dest='cache_init', action='store_true', default=False,
        help='Prevents posting news to IRC. This is useful '
             'when bootstrapping new RSS feed.'
    )
    parser.add_argument(
        '--gh-owner',
        dest='gh_owner', required=True, type=str,
        help='Owner/org of the repository to track.'
    )
    parser.add_argument(
        '--gh-repo',
        dest='gh_repo', required=True, type=str,
        help='Repository of owner/org to track.'
    )
    parser.add_argument(
        '--gh-section',
        dest='gh_section', required=True, choices=['issues', 'pulls'],
        help='GH "section" to track.'
    )
    parser.add_argument(
        '--slack-channel',
        dest='slack_channel', type=str, required=True,
        help='Name of slack channel to send formatted news to.'
    )
    parser.add_argument(
        '--slack-timeout',
        dest='slack_timeout', type=int,
        default=rss2irc.HTTP_TIMEOUT,
        help=('slack API Timeout. Defaults to %i seconds.'
              % rss2irc.HTTP_TIMEOUT)
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


def read_cache(logger, cache_file):
    """Read file with Py pickle in it.

    :type logger: `logging.Logger`
    :type cache_file: str

    :rtype: dict
    """
    if not cache_file:
        return {}
    elif not os.path.exists(cache_file):
        logger.warn("Cache file '%s' doesn't exist.", cache_file)
        return {}

    with open(cache_file, 'r') as fhandle:
        cache = pickle.load(fhandle)

    logger.debug(cache)
    time_now = time.time()
    for key in cache.keys():
        if int(cache[key]['expiration']) < time_now:
            logger.debug('URL %s has expired.', key)
            cache.pop(key)

    return cache


if __name__ == '__main__':
    main()
