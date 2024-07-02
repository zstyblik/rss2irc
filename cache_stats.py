#!/usr/bin/env python3
"""Cache stats tool.

2024/Jun/11 @ Zdenek Styblik <stybla@turnovfree.net>
"""
import argparse
import logging
import sys
import traceback
from dataclasses import dataclass

import rss2irc
from lib import CachedData

BUCKET_COUNT = 10


@dataclass
class Bucket:
    """Class represents a time range bucket."""

    ts_min: int
    ts_max: int
    count: int


def calc_distribution(
    logger: logging.Logger, cache: CachedData, buckets
) -> int:
    """Calculate item distribution inside cache."""
    keys = list(buckets.keys())
    error_cnt = 0
    for item in cache.items.values():
        try:
            timestamp = get_timestamp(item)
        except (KeyError, TypeError, ValueError):
            error_cnt += 1
            logger.debug("%s", traceback.format_exc())
            continue

        accounted = False
        for key in keys:
            if (
                timestamp >= buckets[key].ts_min
                and timestamp <= buckets[key].ts_max
            ):
                buckets[key].count += 1
                accounted = True

        if not accounted:
            logger.debug("Unaccounted key: %s", timestamp)
            error_cnt += 1

    return error_cnt


def get_timestamp(data) -> int:
    """Convert input data to int.

    :raises: KeyError, TypeError, ValueError
    """
    if isinstance(data, (int, float)):
        return int(data)
    elif isinstance(data, dict):
        if "expiration" not in data:
            raise KeyError("dict has no key 'expiration'")

        return int(data["expiration"])

    raise TypeError("unsupported type '{}'".format(type(data)))


def get_timestamp_minmax(
    logger: logging.Logger, cache: CachedData
) -> (int, int, int):
    """Return timestamp min, max and no. of errors."""
    ts_min = 99999999999
    ts_max = 0
    error_cnt = 0
    for item in cache.items.values():
        try:
            timestamp = get_timestamp(item)
        except (KeyError, TypeError, ValueError):
            error_cnt += 1
            logger.debug("%s", traceback.format_exc())
            continue

        if timestamp < ts_min:
            ts_min = timestamp

        if timestamp > ts_max:
            ts_max = timestamp

    return ts_min, ts_max, error_cnt


def generate_buckets(
    logger: logging.Logger, ts_min: int, ts_max: int, step: int
):
    """Generate time range buckets."""
    buckets = {}
    for i in range(0, BUCKET_COUNT):
        lower = ts_min + i * step
        if i != 0:
            # compensate for overlaps
            lower += 1

        higher = ts_min + (i + 1) * step
        if i + 1 == BUCKET_COUNT:
            # compensate for remainder
            higher = ts_max

        key = (lower, higher)
        buckets[key] = Bucket(ts_min=lower, ts_max=higher, count=0)
        logger.debug("%i:%s:%s", i, key, higher - lower)

    return buckets


def main():
    """Read cache file and print-out stats."""
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)
    logger = logging.getLogger("cache_stats")
    args = parse_args()
    if args.verbosity:
        logger.setLevel(logging.DEBUG)

    cache = rss2irc.read_cache(logger, args.cache)
    logger.info(
        "Number of items in cache '%s' is %d.", args.cache, len(cache.items)
    )
    if not cache.items:
        logger.info("Nothing to do.")
        sys.exit(0)

    ts_min, ts_max, error_cnt = get_timestamp_minmax(logger, cache)
    ts_diff = ts_max - ts_min
    logger.info("Min timestamp %i", ts_min)
    logger.info("Max timestamp %i", ts_max)
    logger.info("Diff timestamp %i", ts_diff)
    logger.info("Error count: %i", error_cnt)
    if ts_diff == 0:
        logger.info("%s:%s%%", (ts_min, ts_max), 100)
        sys.exit(0)

    if ts_diff < 0:
        raise ValueError("Timestamp diff cannot be less than 0")

    step = ts_diff // BUCKET_COUNT
    remainder = ts_diff % BUCKET_COUNT
    logger.info("Step: %s", step)
    logger.info("Remainder: %s", remainder)
    buckets = generate_buckets(logger, ts_min, ts_max, step)
    error_cnt = calc_distribution(logger, cache, buckets)
    logger.info("Error count: %i", error_cnt)
    logger.info("Cache distribution:")
    logger.info("---")
    item_cnt = len(cache.items)
    for key, value in buckets.items():
        pct = round(value.count / item_cnt * 100, 1)
        logger.info("%s:%s%%", key, pct)

    logger.info("---")
    logger.info("All done.")
    sys.exit(0)


def parse_args() -> argparse.Namespace:
    """Return parsed CLI args."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbosity",
        action="store_true",
        default=False,
        help="Increase logging verbosity.",
    )
    parser.add_argument(
        "--cache",
        dest="cache",
        type=str,
        default=None,
        required=True,
        help="File which contains cache.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    main()
