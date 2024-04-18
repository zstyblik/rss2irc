#!/usr/bin/env python3
"""Get GH issues/pull requests and post them to Slack.

2017/Nov/18 @ Zdenek Styblik <stybla@turnovfree.net>
"""
import argparse
import logging
import re
import sys
import time
import traceback
from typing import Dict
from typing import List
from typing import Set

import requests

import rss2irc  # noqa: I202
import rss2slack

ALIASES = {
    "issues": "issue",
    "pulls": "pr",
}
DEFAULT_HTTP_PROTO = "https"
DEFAULT_GH_URL = "github.com"
RE_LINK_REL_NEXT = re.compile(r'<(?P<next>.*)>; rel="next"')


def format_message(
    logger: logging.Logger,
    owner: str,
    repo: str,
    section: str,
    html_url: str,
    cache_item: Dict,
) -> Dict:
    """Return formatted message as Slack's BlockKit section."""
    try:
        title = cache_item["title"].encode("utf-8")
    except UnicodeEncodeError:
        logger.error("Failed to encode title as UTF-8: %s", repr(title))
        logger.error(traceback.format_exc())
        title = "Unknown title due to UTF-8 exception, {:s}#{:d}".format(
            section, cache_item["number"]
        )

    try:
        message = "[<{}|{}/{}>] <{}|{}#{:d}> | {:s}".format(
            cache_item["repository_url"],
            owner,
            repo,
            html_url,
            section,
            cache_item["number"],
            title.decode("utf-8"),
        )
    except UnicodeDecodeError:
        logger.error("Failed to format message: %s", traceback.format_exc())
        message = "[{:s}/{:s}] Failed to format message for {:s}#{:d}".format(
            owner, repo, section, cache_item["number"]
        )

    return {
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": message,
        },
    }


def get_gh_api_url(owner: str, repo: str, section: str) -> str:
    """Return assembled GitHub API URL."""
    return "{}://api.{}/repos/{}".format(
        DEFAULT_HTTP_PROTO, DEFAULT_GH_URL, "/".join([owner, repo, section])
    )


def get_gh_repository_url(owner: str, repo: str) -> str:
    """Return assembled GitHub Repository URL."""
    return "{}://{}/{}/{}".format(
        DEFAULT_HTTP_PROTO, DEFAULT_GH_URL, owner, repo
    )


def gh_request(
    logger: logging.Logger, url: str, timeout: int = rss2irc.HTTP_TIMEOUT
) -> List:
    """Return list of responses from GitHub.

    Makes request to GH, follows 'Link' header if present, and returns list
    responses.
    """
    logger.debug("Requesting %s", url)
    rsp = requests.get(
        url,
        headers={"Accept": "application/vnd.github.v3+json"},
        params={"state": "open", "sort": "created"},
        timeout=timeout,
    )
    logger.debug("HTTP Status Code %i", rsp.status_code)
    rsp.raise_for_status()
    logger.debug("RSP Headers: %s", rsp.headers)
    # In order to get everything, we must follow URLs in the 'Link' header as
    # long as there is next one to follow.
    link_header = rsp.headers.get("link", "")
    match = RE_LINK_REL_NEXT.search(link_header)
    if not match:
        return [rsp.json()]

    return [rsp.json()] + gh_request(logger, match.groupdict()["next"], timeout)


def main():
    """Fetch issues/PRs from GitHub and post them to Slack."""
    logging.basicConfig(stream=sys.stdout, level=logging.ERROR)
    logger = logging.getLogger("gh2slack")
    args = parse_args()
    if args.verbosity:
        logger.setLevel(logging.DEBUG)

    try:
        slack_token = rss2slack.get_slack_token()
        url = get_gh_api_url(args.gh_owner, args.gh_repo, args.gh_section)
        pages = gh_request(logger, url)

        logger.debug("Got %i pages from GH.", len(pages))
        if not pages:
            logger.info(
                "No %s for %s/%s.", args.gh_section, args.gh_owner, args.gh_repo
            )
            sys.exit(0)

        cache = rss2irc.read_cache(logger, args.cache)
        scrub_cache(logger, cache)

        # Note: I have failed to find web link to repo in GH response.
        # Therefore, let's create one.
        repository_url = get_gh_repository_url(args.gh_owner, args.gh_repo)
        item_expiration = int(time.time()) + args.cache_expiration
        to_publish = process_page_items(
            logger, cache, pages, item_expiration, repository_url
        )

        if not args.cache_init and to_publish:
            slack_client = rss2slack.get_slack_web_client(
                slack_token, args.slack_base_url, args.slack_timeout
            )
            for html_url in to_publish:
                cache_item = cache.items[html_url]
                try:
                    msg_blocks = [
                        format_message(
                            logger,
                            args.gh_owner,
                            args.gh_repo,
                            ALIASES[args.gh_section],
                            html_url,
                            cache_item,
                        )
                    ]
                    rss2slack.post_to_slack(
                        logger,
                        msg_blocks,
                        slack_client,
                        args.slack_channel,
                    )
                except Exception:
                    logger.error(traceback.format_exc())
                    cache.items.pop(html_url)
                finally:
                    time.sleep(args.sleep)

        rss2irc.write_cache(cache, args.cache)
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
        "--cache",
        dest="cache",
        type=str,
        default=None,
        help="Path to cache file.",
    )
    parser.add_argument(
        "--cache-expiration",
        dest="cache_expiration",
        type=int,
        default=rss2irc.EXPIRATION,
        help="Time, in seconds, for how long to keep items " "in cache.",
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
        "--gh-owner",
        dest="gh_owner",
        required=True,
        type=str,
        help="Owner/org of the repository to track.",
    )
    parser.add_argument(
        "--gh-repo",
        dest="gh_repo",
        required=True,
        type=str,
        help="Repository of owner/org to track.",
    )
    parser.add_argument(
        "--gh-section",
        dest="gh_section",
        required=True,
        choices=["issues", "pulls"],
        help='GH "section" to track.',
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
        default=rss2irc.HTTP_TIMEOUT,
        help="Slack API Timeout. Defaults to {:d} seconds.".format(
            rss2irc.HTTP_TIMEOUT
        ),
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
        dest="verbosity",
        action="store_true",
        default=False,
        help="Increase logging verbosity.",
    )
    return parser.parse_args()


def process_page_items(
    logger: logging.Logger,
    cache: rss2irc.CachedData,
    pages: List,
    expiration: int,
    repository_url: str,
) -> Set:
    """Parse page items, update cache and return items to publish.

    :param pages: list of lists, resp. whatever GH API returns
    """
    to_publish = set()
    page_num = 0
    for page_items in pages:
        page_num += 1
        logger.debug("Page #%i has %i items.", page_num, len(page_items))
        for item in page_items:
            if (
                "html_url" not in item
                or "number" not in item
                or "title" not in item
            ):
                logger.debug("Item doesn't have required fields: %s", item)
                continue

            if item["html_url"] in cache.items:
                cache.items[item["html_url"]]["expiration"] = expiration
                continue

            try:
                item_number = int(item["number"])
            except ValueError:
                logger.error("Failed to convert %s to int.", item["number"])
                item_number = 0

            cache.items[item["html_url"]] = {
                "expiration": expiration,
                "number": item_number,
                "repository_url": repository_url,
                "title": item["title"],
            }
            to_publish.add(item["html_url"])

    return to_publish


def scrub_cache(logger: logging.Logger, cache: rss2irc.CachedData) -> None:
    """Scrub cache and remove expired items."""
    time_now = int(time.time())
    for key in list(cache.items.keys()):
        try:
            expiration = int(cache.items[key]["expiration"])
        except (KeyError, ValueError):
            logger.error(traceback.format_exc())
            logger.error(
                "Invalid cache entry will be removed: '%s'", cache.items[key]
            )
            cache.items.pop(key)
            continue

        if expiration < time_now:
            logger.debug("URL %s has expired.", key)
            cache.items.pop(key)


if __name__ == "__main__":
    main()
