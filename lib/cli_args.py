#!/usr/bin/env python3
"""Helper functions related to CLI args.

2026/Jan/06 @ Zdenek Styblik
"""
import argparse
from dataclasses import dataclass

from . import config_options


@dataclass
class GenericArgsCfg:
    """Class represents configuration of generic CLI args."""

    handle: bool = False
    output: bool = False


def add_cache_file_arg_group(parser: argparse.ArgumentParser):
    """Add cache related CLI args."""
    cache_file_group = parser.add_argument_group("caching options")
    cache_file_group.add_argument(
        "--cache",
        dest="cache_file",
        type=str,
        default=None,
        help="File which contains cache.",
    )
    cache_file_group.add_argument(
        "--cache-expiration",
        dest="cache_expiration",
        type=int,
        default=config_options.CACHE_EXPIRATION,
        help=(
            "How long to keep items in cache. "
            "Defaults to %(default)s seconds."
        ),
    )
    cache_file_group.add_argument(
        "--cache-init",
        dest="cache_init",
        action="store_true",
        default=False,
        help=(
            "Prevents posting news to IRC. This is useful "
            "when bootstrapping new RSS feed."
        ),
    )


def add_generic_args(
    parser: argparse.ArgumentParser, args_cfg: GenericArgsCfg = None
):
    """Add generic CLI args."""
    if args_cfg and args_cfg.handle:
        parser.add_argument(
            "--handle",
            dest="handle",
            type=str,
            default=None,
            help="Handle/call sign of this feed.",
        )

    if args_cfg and args_cfg.output:
        parser.add_argument(
            "--output",
            dest="output",
            type=str,
            required=True,
            help="Where to output formatted news.",
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
        "--sleep",
        dest="sleep",
        type=int,
        default=2,
        help="Sleep between messages in order to avoid Excess Flood at IRC.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase log level verbosity. Can be passed multiple times.",
    )


def add_rss_arg_group(parser: argparse.ArgumentParser):
    """Add RSS related CLI args."""
    rss_group = parser.add_argument_group("RSS options")
    rss_group.add_argument(
        "--rss-url",
        dest="rss_url",
        type=str,
        required=True,
        help="URL of RSS Feed.",
    )
    rss_group.add_argument(
        "--rss-http-timeout",
        dest="rss_http_timeout",
        type=int,
        default=config_options.HTTP_TIMEOUT,
        help="HTTP Timeout. Defaults to %(default)s seconds.",
    )


def add_slack_arg_group(parser: argparse.ArgumentParser, slack_base_url: str):
    """Add Slack related CLI args."""
    slack_group = parser.add_argument_group("Slack options")
    slack_group.add_argument(
        "--slack-base-url",
        dest="slack_base_url",
        type=str,
        default=slack_base_url,
        help="Base URL for Slack client.",
    )
    slack_group.add_argument(
        "--slack-channel",
        dest="slack_channel",
        type=str,
        required=True,
        help="Name of Slack channel to send formatted news to.",
    )
    slack_group.add_argument(
        "--slack-timeout",
        dest="slack_timeout",
        type=int,
        default=config_options.HTTP_TIMEOUT,
        help="Slack API Timeout. Defaults to %(default)s seconds.",
    )


def check_cache_expiration_arg(
    parser: argparse.ArgumentParser, args: argparse.Namespace
):
    """Check that cache_expiration CLI arg is within range."""
    if args.cache_expiration < 0:
        parser.error("Cache expiration cannot be less than 0.")


def check_sleep_arg(parser: argparse.ArgumentParser, args: argparse.Namespace):
    """Check that sleep CLI arg is within range."""
    if args.sleep < 0:
        parser.error("Sleep interval cannot be less than 0.")
