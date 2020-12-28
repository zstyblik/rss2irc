#!/usr/bin/env python3
"""Read migrated cache file."""
import argparse
import logging
import sys

import rss2irc


def main():
    """Try to read given cache file."""
    args = parse_args()
    logger = logging.getLogger('read-migrated-cache')
    cache = rss2irc.read_cache(logger, args.cache)
    assert isinstance(cache, rss2irc.CachedData)
    assert len(cache.items)
    sys.exit(0)


def parse_args() -> argparse.Namespace:
    """Return parsed CLI args."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--cache',
        dest='cache', type=str, default=None,
        help='File which contains cache.'
    )

    return parser.parse_args()


if __name__ == '__main__':
    main()
