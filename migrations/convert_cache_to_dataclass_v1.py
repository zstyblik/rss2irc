#!/usr/bin/env python3
"""Convert original cache file(simple dict) to data class v1.

Migration:
* disable all 2IRC/2Slack scripts in eg. cron/systemd/runit/etc.
* migrate cache files with this script
* enable 2IRC/2Slack scripts again
* if everything is ok, remove bak files
"""
import argparse
import logging
import pickle
import shutil
import sys
from dataclasses import dataclass, field


@dataclass
class CachedData:
    """CachedData represents locally cached data and state."""

    items: dict = field(default_factory=dict)


def main():
    """Open cache file, convert it and overwrite it.

    Backup file is created in the process. Manual cleanup is required after
    migration.
    """
    logging.basicConfig(stream=sys.stdout)
    logger = logging.getLogger('migrate-to-dataclass')
    args = parse_args()
    if args.verbosity:
        logger.setLevel(logging.DEBUG)

    logger.info("Read cache from file '%s'.", args.cache)
    with open(args.cache, 'rb') as fhandle:
        cache = pickle.load(fhandle)

    if not isinstance(cache, dict):
        logger.error(
            "Cache file '%s' has invalid format, dict is expected.", args.cache
        )
        sys.exit(1)

    bak_file = '{}.bak'.format(args.cache)
    logger.info("Create backup file '%s' from '%s'.", bak_file, args.cache)
    shutil.copy2(args.cache, bak_file)

    new_cache = CachedData()
    for key, value in cache.items():
        new_cache.items[key] = value

    logger.info("Write converted cache into file '%s'.", args.cache)
    with open(args.cache, 'wb') as fhandle:
        pickle.dump(new_cache, fhandle, pickle.HIGHEST_PROTOCOL)

    logger.info("Migration complete and '%s' can be removed.", bak_file)


def parse_args() -> argparse.Namespace:
    """Return parsed CLI args."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-v', '--verbose',
        dest='verbosity', action='store_true', default=False,
        help='Increase logging verbosity.'
    )
    parser.add_argument(
        '--cache',
        dest='cache', type=str, default=None, required=True,
        help='File which contains cache.'
    )
    return parser.parse_args()


if __name__ == '__main__':
    main()
