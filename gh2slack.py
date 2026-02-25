#!/usr/bin/env python3
"""Get GH issues/pull requests and post them to Slack.

2017/Nov/18 @ Zdenek Styblik <stybla@turnovfree.net>
"""
import argparse
import logging
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass
from typing import Dict
from typing import List
from typing import Set

import requests

import rss2irc
import rss2slack
from lib import CachedData
from lib import cli_args
from lib import config_options
from lib import utils
from lib.exceptions import SlackTokenError

ALIASES = {
    "issues": "issue",
    "pulls": "pr",
}
DEFAULT_HTTP_PROTO = "https"
DEFAULT_GH_URL = "github.com"
RE_LINK_REL_NEXT = re.compile(r"<(?P<next>.*)>; rel=\"next")


@dataclass
class GHRepoInfo:
    """Class holds information about GitHub repository."""

    repo_owner: str
    repo_name: str
    repo_section: str


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
        logger.exception(
            "Failed to encode title as UTF-8: %s",
            repr(cache_item.get("title", None)),
        )
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
        logger.exception("Failed to format message.")
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


def gh_parse_next_page(link_header: str) -> str:
    """Parse link to the next page from GitHub's Link header."""
    next_page = ""
    for chunk in str(link_header).split('",'):
        match = RE_LINK_REL_NEXT.search(chunk)
        if match:
            next_page = match.groupdict()["next"]
            break

    return next_page


def gh_request(
    logger: logging.Logger, url: str, timeout: int = config_options.HTTP_TIMEOUT
) -> List:
    """Return list of responses from GitHub.

    Makes request to GH, follows 'Link' header if present, and returns list
    responses.
    """
    logger.debug("Requesting %s", url)
    user_agent = "gh2slack-script"
    rsp = requests.get(
        url,
        headers={
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": user_agent,
        },
        params={"state": "open", "sort": "created"},
        timeout=timeout,
    )
    logger.debug("HTTP Status Code %i", rsp.status_code)
    rsp.raise_for_status()
    logger.debug("RSP Headers: %s", rsp.headers)
    # In order to get everything, we must follow URLs in the 'Link' header as
    # long as there is next one to follow.
    link_header = rsp.headers.get("link", "")
    next_page = gh_parse_next_page(str(link_header))
    if not next_page:
        return [rsp.json()]

    # NOTE: 'state' and 'sort' will be added again, therefore let's get rid off
    # them. If we didn't do this, number of params would grow with each
    # recursion.
    parsed = urllib.parse.urlparse(next_page)
    qdict = urllib.parse.parse_qs(parsed.query)
    qdict.pop("state", None)
    qdict.pop("sort", None)
    new_query = urllib.parse.urlencode(qdict, doseq=True)
    parsed = parsed._replace(query=new_query)
    # FIXME(zstyblik): unlimited recursion. This will require some refactoring.
    # However, since nobody is using this, later.
    return [rsp.json()] + gh_request(logger, parsed.geturl(), timeout)


def main():
    """Fetch issues/PRs from GitHub and post them to Slack."""
    args = parse_args()
    logging.basicConfig(stream=sys.stdout, level=logging.ERROR)
    logger = logging.getLogger("gh2slack")
    logger.setLevel(args.log_level)

    retcode = 0
    cache = rss2irc.wrap_read_cache(logger, args.cache_file)
    if cache is None:
        retcode = utils.mask_retcode(1, args.mask_errors)
        sys.exit(retcode)

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

        scrub_items(logger, cache)
        # NOTE(zstyblik): I have failed to find web link to repo in GH response.
        # Therefore, let's create one.
        repository_url = get_gh_repository_url(args.gh_owner, args.gh_repo)
        item_expiration = int(time.time()) + args.cache_expiration
        to_publish = process_page_items(
            logger, cache, pages, item_expiration, repository_url
        )
        gh_data = GHRepoInfo(
            repo_owner=args.gh_owner,
            repo_name=args.gh_repo,
            repo_section=args.gh_section,
        )
        if not args.cache_init and to_publish:
            slack_client = rss2slack.get_slack_web_client(
                slack_token, args.slack_base_url, args.slack_timeout
            )
            process_news(
                logger,
                cache,
                to_publish,
                args.sleep,
                gh_data,
                slack_client,
                args.slack_channel,
            )

        retcode = 0
    except SlackTokenError:
        logger.exception("Environment variable SLACK_TOKEN must be set.")
        retcode = utils.mask_retcode(1, args.mask_errors)
        sys.exit(retcode)
    except Exception:
        logger.exception("Unexpected exception has occurred.")
        retcode = 1

    write_retcode = rss2irc.wrap_write_cache(logger, cache, args.cache_file)
    retcode = utils.escalate_retcode(write_retcode, retcode)
    retcode = utils.mask_retcode(retcode, args.mask_errors)
    sys.exit(retcode)


def parse_args() -> argparse.Namespace:
    """Return parsed CLI args."""
    parser = argparse.ArgumentParser()
    cli_args.add_generic_args(parser)
    cli_args.add_cache_file_arg_group(parser)

    github_group = parser.add_argument_group("GitHub options")
    github_group.add_argument(
        "--gh-owner",
        dest="gh_owner",
        required=True,
        type=str,
        help="Owner/org of the repository to track.",
    )
    github_group.add_argument(
        "--gh-repo",
        dest="gh_repo",
        required=True,
        type=str,
        help="Repository of owner/org to track.",
    )
    github_group.add_argument(
        "--gh-section",
        dest="gh_section",
        required=True,
        choices=["issues", "pulls"],
        help='GH "section" to track.',
    )

    cli_args.add_slack_arg_group(parser, rss2slack.SLACK_BASE_URL)
    args = parser.parse_args()
    args.log_level = utils.calc_log_level(args.verbose)

    cli_args.check_cache_expiration_arg(parser, args)
    cli_args.check_sleep_arg(parser, args)
    return args


def process_news(
    logger: logging.Logger,
    cache: CachedData,
    to_publish: Set[str],
    sleep: int,
    gh_data: GHRepoInfo,
    slack_client,
    slack_channel: str,
):
    """Process new items and post to Slack."""
    for html_url in to_publish:
        cache_item = cache.items[html_url]
        try:
            msg_block = format_message(
                logger,
                gh_data.repo_owner,
                gh_data.repo_name,
                ALIASES[gh_data.repo_section],
                html_url,
                cache_item,
            )
            msg_blocks = [msg_block]
            msg_as_text = msg_block["text"]["text"]
            rss2slack.post_to_slack(
                logger,
                msg_blocks,
                msg_as_text,
                slack_client,
                slack_channel,
            )
        except Exception:
            logger.exception("Exception has occurred while posting to Slack")
            cache.items.pop(html_url)
        finally:
            time.sleep(sleep)


def process_page_items(
    logger: logging.Logger,
    cache: CachedData,
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


if __name__ == "__main__":
    main()
