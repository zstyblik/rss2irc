#!/usr/bin/env python2
"""2017/Nov/18 @ Zdenek Styblik <stybla@turnovfree.net>
Desc: Get GH issues/pull requests and push them to slack.
"""
import argparse
import logging
import re
import sys
import time
import traceback

from slackclient import SlackClient
import requests
import rss2irc
import rss2slack

ALIASES = {
    'issues': 'issue',
    'pulls': 'pr',
}
DEFAULT_GH_URL = 'https://github.com'
RE_LINK_REL_NEXT = re.compile(r'<(?P<next>.*)>; rel="next"')


def assembly_slack_message(logger, owner, repo, section, html_url, cache_item):
    """Return assebled message to be posted on slack.

    :type logger: `logging.Logger`
    :type owner: str
    :type repo: str
    :type section: str
    :type html_url: str
    :type cache_item: dict

    :rtype: str
    """
    try:
        title = cache_item['title'].encode('utf-8')
    except UnicodeEncodeError:
        logger.error('Failed to encode title as UTF-8: %s',
                     repr(title))
        logger.error(traceback.format_exc())
        title = (
            'Unknown title due to UTF-8 exception, {}#{:d}'.format(
                section, cache_item['number']
            )
        )

    try:
        message = '[<{}|{}/{}>] <{}|{}#{:d}> | {}'.format(
            cache_item['repository_url'], owner, repo, html_url,
            ALIASES[section], cache_item['number'], title
        )
    except UnicodeDecodeError:
        logger.error('Failed to assembly message: %s',
                     traceback.format_exc())
        message = (
            '[{}/{}] Failed to assembly message for {}#{:d}'.format(
                owner, repo, section, cache_item['number']
            )
        )

    return message


def gh_request(logger, url, timeout=rss2irc.HTTP_TIMEOUT):
    """Make request GH, follow 'Link' header if present, and return list
    responses.

    :type logger: `logging.Logger`
    :type url: str
    :type timeout: int

    :rtype: list
    """
    logger.debug('Requesting %s', url)
    rsp = requests.get(
        url,
        headers={'Accept': 'application/vnd.github.v3+json'},
        params={'state': 'open', 'sort': 'created'},
        timeout=timeout,
    )
    logger.debug('HTTP Status Code %i', rsp.status_code)
    rsp.raise_for_status()
    logger.debug('RSP Headers: %s', rsp.headers)
    # In order to get everything, we must follow URLs in the 'Link' header as
    # long as there is next one to follow.
    link_header = rsp.headers.get('link', '')
    match = RE_LINK_REL_NEXT.search(link_header)
    if not match:
        return [rsp.json()]

    return (
        [rsp.json()] + gh_request(logger, match.groupdict()['next'], timeout)
    )


def main():
    """Main."""
    logging.basicConfig(stream=sys.stdout, level=logging.ERROR)
    logger = logging.getLogger('gh2slack')
    args = parse_args()
    if args.verbosity:
        logger.setLevel(logging.DEBUG)

    slack_token = rss2slack.get_slack_token()
    url = 'https://api.github.com/repos/{}'.format(
        '/'.join([args.gh_owner, args.gh_repo, args.gh_section])
    )
    pages = gh_request(logger, uri)

    logger.debug('Got %i items from GH.', len(items))
    if not pages:
        logger.info('No %s for %s/%s.', args.gh_section, args.gh_owner,
                    args.gh_repo)
        sys.exit(0)

    cache = rss2irc.read_cache(logger, args.cache)
    scrub_cache(logger, cache)

    expiration = int(time.time()) + args.cache_expiration
    to_publish = set()
    # Note: I have failed to find web link to repo in GH response.
    repository_url = 'https://github.com/{}/{}'.format(args.gh_owner,
                                                       args.gh_repo)
    for page_items in pages:
        for item in page_items:
            if (
                    'html_url' not in item or
                    'number' not in item or
                    'title' not in item
            ):
                logger.debug("Item doesn't have required fields: %s", item)
                continue

            if item['html_url'] in cache:
                cache[item['html_url']]['expiration'] = expiration
                continue

            try:
                item_number = int(item['number'])
            except ValueError:
                logger.error('Failed to convert %s to int.', item['number'])
                item_number = 0

            cache[item['html_url']] = {
                'expiration': expiration,
                'number': item_number,
                'repository_url': repository_url,
                'title': item['title'],
            }
            to_publish.add(item['html_url'])

    if not args.cache_init and to_publish:
        slack_client = SlackClient(slack_token)
        for html_url in to_publish:
            cache_item = cache[html_url]
            try:
                message = assembly_slack_message(
                    logger, args.gh_owner, args.gh_repo, args.gh_section,
                    html_url, cache_item
                )
                rss2slack.post_to_slack(
                    logger, message, slack_client, args.slack_channel,
                    args.slack_timeout
                )
                time.sleep(args.sleep)
            except Exception:
                logger.error(traceback.format_exc())
                cache.pop(html_url)

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


if __name__ == '__main__':
    main()
