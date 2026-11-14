#!/usr/bin/env python3
"""Convert cache file from non-src to src version.

This time the problem seems to be that names of (imported) classes have changed.
Therefore, it's necessary to load pickle, adjust class names and save it again.

NOTE(zstyblik): script must be executed inside environment which has rss2irc
installed.

2026/Nov/14 @ Zdenek Styblik <stybla@turnovfree.net>
"""
import argparse
import logging
import pickle
import shutil
import sys


class CustomUnpickler(pickle.Unpickler):
    """Custom unpickler."""

    def find_class(self, module, name):
        """Re-write class names from non-src to src version."""
        if module in ["lib.cached_data", "lib.http_source"]:
            module = "rss2irc.{:s}".format(module)

        return super().find_class(module, name)


def main():
    """Open cache file, convert it, create backup and overwrite original."""
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)
    logger = logging.getLogger("migrate-dataclass-v2-to-v3")
    args = parse_args()

    logger.info("Read cache from file '%s'.", args.cache_file)
    with open(args.cache_file, "rb") as fhandle:
        obj = CustomUnpickler(fhandle).load()

    bak_file = "{}.bak".format(args.cache_file)
    logger.info("Create backup file '%s' from '%s'.", bak_file, args.cache_file)
    shutil.copy2(args.cache_file, bak_file)

    logger.info("Write converted cache into file '%s'.", args.cache_file)
    with open(args.cache_file, "wb") as fhandle:
        pickle.dump(obj, fhandle, pickle.HIGHEST_PROTOCOL)


def parse_args() -> argparse.Namespace:
    """Return parsed CLI args."""
    parser = argparse.ArgumentParser(
        description=(
            "Convert rss2irc cache to v3(src layout). rss2irc must be "
            "installed in the execution environment."
        )
    )
    parser.add_argument(
        "--cache",
        dest="cache_file",
        type=str,
        default=None,
        required=True,
        help="File which contains cache.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    main()
